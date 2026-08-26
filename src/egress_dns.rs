use crate::AppState;
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA, SOA, TXT},
    },
    serialize::binary::{BinDecodable, BinEncodable, BinEncoder},
};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Semaphore, watch},
};

const DNS_PACKET_MAX_BYTES: usize = 4096;
const DNS_UDP_MAX_BYTES: usize = 512;
const DNS_TTL_SECONDS: u32 = 30;
const DNS_MAX_IN_FLIGHT: usize = 64;
const DNS_MAX_ANSWERS: usize = 16;

async fn answer(state: &AppState, packet: &[u8]) -> Option<Vec<u8>> {
    let request = Message::from_bytes(packet).ok()?;
    if request.metadata.message_type != MessageType::Query
        || request.metadata.op_code != OpCode::Query
    {
        return None;
    }
    let mut response = Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    for query in &request.queries {
        response.add_query(query.clone());
    }
    if request.queries.len() != 1 {
        response.metadata.response_code = ResponseCode::FormErr;
        return encode(response);
    }
    let query = &request.queries[0];
    if let Some(response) = answer_dnsbl(state, &request, query).await {
        return encode(response);
    }
    if !matches!(query.query_type(), RecordType::A | RecordType::AAAA) {
        response.metadata.response_code = ResponseCode::NotImp;
        return encode(response);
    }
    let host = query.name().to_utf8().trim_end_matches('.').to_string();
    let addresses = match state.egress_dns.lookup(&host).await {
        Some(addresses) => addresses,
        None => {
            let decision = state
                .resolve_outbound(&format!("https://{host}/"))
                .await
                .ok();
            let Some(decision) = decision else {
                response.metadata.response_code = ResponseCode::Refused;
                return encode(response);
            };
            state.egress_dns.record(&host, &decision.ips).await;
            decision.ips
        }
    };
    for data in addresses
        .into_iter()
        .filter_map(|address| match (query.query_type(), address) {
            (RecordType::A, std::net::IpAddr::V4(address)) => Some(RData::A(A(address))),
            (RecordType::AAAA, std::net::IpAddr::V6(address)) => Some(RData::AAAA(AAAA(address))),
            _ => None,
        })
        .take(DNS_MAX_ANSWERS)
    {
        response.add_answer(Record::from_rdata(
            query.name().clone(),
            DNS_TTL_SECONDS,
            data,
        ));
    }
    encode(response)
}

async fn answer_dnsbl(
    state: &AppState,
    request: &Message,
    query: &hickory_proto::op::Query,
) -> Option<Message> {
    let host = query.name().to_utf8();
    let address = dnsbl_query_address(&host, &state.dnsbl_origin)?;
    let mut response = Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
    response.metadata.authoritative = true;
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.add_query(query.clone());
    let Some(address) = address else {
        response.metadata.response_code = ResponseCode::NXDomain;
        add_negative_soa(&mut response, &state.dnsbl_origin);
        return Some(response);
    };
    let entries = state.inner.read().await.dnsbl.clone();
    let matches: Vec<_> = entries
        .iter()
        .filter(|entry| {
            waf_ids_core::validate_dnsbl(entry).is_ok()
                && waf_ids_core::dnsbl_matches(entry, address.into())
        })
        .take(DNS_MAX_ANSWERS)
        .collect();
    if matches.is_empty() {
        response.metadata.response_code = ResponseCode::NXDomain;
        add_negative_soa(&mut response, &state.dnsbl_origin);
        return Some(response);
    }
    match query.query_type() {
        RecordType::A => {
            for entry in matches {
                let Ok(code) = entry.code.parse() else {
                    continue;
                };
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    u32::try_from(entry.ttl_seconds).unwrap_or(u32::MAX),
                    RData::A(A(code)),
                ));
            }
        }
        RecordType::TXT => {
            for entry in matches {
                let text = format!("{} source={}", entry.reason, entry.source);
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    u32::try_from(entry.ttl_seconds).unwrap_or(u32::MAX),
                    RData::TXT(TXT::new(vec![bounded_txt(&text)])),
                ));
            }
        }
        _ => add_negative_soa(&mut response, &state.dnsbl_origin),
    }
    Some(response)
}

fn add_negative_soa(response: &mut Message, origin: &str) {
    let Ok(zone) = Name::from_ascii(format!("{}.", origin.trim_matches('.'))) else {
        return;
    };
    let Ok(primary) = Name::from_ascii(format!("ns.{zone}")) else {
        return;
    };
    let Ok(responsible) = Name::from_ascii(format!("hostmaster.{zone}")) else {
        return;
    };
    response.authorities.push(Record::from_rdata(
        zone,
        DNS_TTL_SECONDS,
        RData::SOA(SOA::new(
            primary,
            responsible,
            1,
            3600,
            600,
            86400,
            DNS_TTL_SECONDS,
        )),
    ));
}

fn dnsbl_query_address(host: &str, origin: &str) -> Option<Option<std::net::Ipv4Addr>> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let origin = origin.trim_matches('.').to_ascii_lowercase();
    if host == origin {
        return Some(None);
    }
    let relative = host.strip_suffix(&format!(".{origin}"))?;
    let octets = relative
        .split('.')
        .map(str::parse::<u8>)
        .collect::<Result<Vec<_>, _>>()
        .ok();
    Some(octets.and_then(|octets| {
        (octets.len() == 4)
            .then(|| std::net::Ipv4Addr::new(octets[3], octets[2], octets[1], octets[0]))
    }))
}

fn bounded_txt(value: &str) -> String {
    let end = value
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index <= 255)
        .last()
        .unwrap_or(0);
    if value.len() <= 255 {
        value.to_string()
    } else {
        value[..end].to_string()
    }
}

fn encode(message: Message) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut bytes);
    message.emit(&mut encoder).ok()?;
    Some(bytes)
}

fn udp_response(bytes: Vec<u8>) -> Option<Vec<u8>> {
    if bytes.len() <= DNS_UDP_MAX_BYTES {
        return Some(bytes);
    }
    let message = Message::from_bytes(&bytes).ok()?;
    let truncated = encode(message.truncate())?;
    (truncated.len() <= DNS_UDP_MAX_BYTES).then_some(truncated)
}

pub async fn serve(
    state: AppState,
    udp: UdpSocket,
    tcp: TcpListener,
    mut stop: watch::Receiver<bool>,
) {
    let state_udp = state.clone();
    let mut stop_udp = stop.clone();
    let udp_task = tokio::spawn(async move {
        let udp = Arc::new(udp);
        let permits = Arc::new(Semaphore::new(DNS_MAX_IN_FLIGHT));
        let mut packet = [0_u8; DNS_UDP_MAX_BYTES + 1];
        loop {
            tokio::select! {
                changed = stop_udp.changed() => {
                    if changed.is_err() || *stop_udp.borrow() { break; }
                },
                received = udp.recv_from(&mut packet) => {
                    let Ok((length, peer)) = received else { continue };
                    if length > DNS_UDP_MAX_BYTES { continue; }
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else { continue };
                    let packet = packet[..length].to_vec();
                    let state = state_udp.clone();
                    let udp = Arc::clone(&udp);
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Some(response) = answer(&state, &packet).await.and_then(udp_response) {
                            let _ = udp.send_to(&response, peer).await;
                        }
                    });
                }
            }
        }
    });

    let permits = Arc::new(Semaphore::new(DNS_MAX_IN_FLIGHT));
    loop {
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() { break; }
            },
            accepted = tcp.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else { continue };
                let state = state.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = serve_tcp(state, stream).await;
                });
            }
        }
    }
    udp_task.abort();
}

async fn serve_tcp(state: AppState, mut stream: TcpStream) -> std::io::Result<()> {
    let length = tokio::time::timeout(Duration::from_secs(5), stream.read_u16()).await?? as usize;
    if length == 0 || length > DNS_PACKET_MAX_BYTES {
        return Ok(());
    }
    let mut packet = vec![0; length];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut packet)).await??;
    if let Some(response) = answer(&state, &packet).await {
        stream.write_u16(response.len() as u16).await?;
        stream.write_all(&response).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{op::Query, rr::Name};
    use std::net::IpAddr;

    struct StaticResolver(Vec<IpAddr>);

    impl crate::HostResolver for StaticResolver {
        fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, String> {
            Ok(self.0.clone())
        }
    }

    struct SlowResolver;

    impl crate::HostResolver for SlowResolver {
        fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
            if host == "slow.example" {
                std::thread::sleep(Duration::from_millis(300));
            }
            Ok(vec!["8.8.8.8".parse().unwrap()])
        }
    }

    fn query_packet(id: u16, host: &str) -> Vec<u8> {
        typed_query_packet(id, host, RecordType::A)
    }

    fn typed_query_packet(id: u16, host: &str, record_type: RecordType) -> Vec<u8> {
        let mut request = Message::new(id, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_ascii(format!("{host}.")).unwrap(),
            record_type,
        ));
        encode(request).unwrap()
    }

    async fn dnsbl_state() -> AppState {
        let state = AppState::seeded(None);
        state.inner.write().await.dnsbl = vec![waf_ids_core::DnsblEntry {
            address: "192.0.2.0".parse().unwrap(),
            prefix_len: Some(24),
            code: "127.0.0.7".to_string(),
            reason: "credential abuse".to_string(),
            source: "test:feed".to_string(),
            ttl_seconds: 600,
        }];
        state
    }

    #[tokio::test]
    async fn serves_authoritative_dnsbl_a_and_txt_records() {
        let state = dnsbl_state().await;

        let name = "99.2.0.192.dnsbl.local";
        let a = Message::from_bytes(
            &answer(&state, &typed_query_packet(11, name, RecordType::A))
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(a.metadata.authoritative);
        assert!(!a.metadata.recursion_available);
        assert_eq!(a.answers.len(), 1);
        assert_eq!(a.answers[0].ttl, 600);
        assert!(
            matches!(a.answers[0].data, RData::A(A(address)) if address.to_string() == "127.0.0.7")
        );

        let txt = Message::from_bytes(
            &answer(&state, &typed_query_packet(12, name, RecordType::TXT))
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(txt.metadata.authoritative);
        assert_eq!(txt.answers.len(), 1);
        assert!(
            matches!(&txt.answers[0].data, RData::TXT(value) if value.to_string().contains("credential abuse source=test:feed"))
        );

        let nodata = Message::from_bytes(
            &answer(&state, &typed_query_packet(14, name, RecordType::MX))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(nodata.metadata.response_code, ResponseCode::NoError);
        assert!(nodata.answers.is_empty());
        assert!(matches!(nodata.authorities[0].data, RData::SOA(_)));
    }

    #[tokio::test]
    async fn serves_dnsbl_queries_over_udp_and_tcp() {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = udp.local_addr().unwrap();
        let tcp = TcpListener::bind(address).await.unwrap();
        let (stop, stop_rx) = watch::channel(false);
        let server = tokio::spawn(serve(dnsbl_state().await, udp, tcp, stop_rx));
        let name = "99.2.0.192.dnsbl.local";

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&query_packet(21, name), address)
            .await
            .unwrap();
        let mut packet = [0_u8; DNS_PACKET_MAX_BYTES];
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut packet))
                .await
                .unwrap()
                .unwrap();
        let response = Message::from_bytes(&packet[..length]).unwrap();
        assert!(response.metadata.authoritative);
        assert!(matches!(response.answers[0].data, RData::A(_)));

        let mut stream = TcpStream::connect(address).await.unwrap();
        let query = typed_query_packet(22, name, RecordType::TXT);
        stream.write_u16(query.len() as u16).await.unwrap();
        stream.write_all(&query).await.unwrap();
        let length = tokio::time::timeout(Duration::from_secs(1), stream.read_u16())
            .await
            .unwrap()
            .unwrap() as usize;
        let mut packet = vec![0; length];
        stream.read_exact(&mut packet).await.unwrap();
        let response = Message::from_bytes(&packet).unwrap();
        assert!(response.metadata.authoritative);
        assert!(matches!(response.answers[0].data, RData::TXT(_)));

        stop.send(true).unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn dnsbl_unlisted_and_malformed_names_are_authoritative_nxdomain() {
        let state = AppState::seeded(None)
            .with_resolver(Arc::new(StaticResolver(vec!["8.8.8.8".parse().unwrap()])));
        for name in [
            "100.2.0.192.dnsbl.local",
            "999.2.0.192.dnsbl.local",
            "dnsbl.local",
        ] {
            let response =
                Message::from_bytes(&answer(&state, &query_packet(13, name)).await.unwrap())
                    .unwrap();
            assert!(response.metadata.authoritative);
            assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
            assert!(response.answers.is_empty());
            assert!(matches!(response.authorities[0].data, RData::SOA(_)));
        }
    }

    #[tokio::test]
    async fn refuses_private_answers_and_unsupported_types() {
        let state = AppState::seeded(None)
            .with_destination_policy(crate::DestinationPolicy::production())
            .with_resolver(Arc::new(StaticResolver(vec!["127.0.0.1".parse().unwrap()])));
        let mut request = Message::new(7, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_ascii("localhost.").unwrap(),
            RecordType::A,
        ));
        let response =
            Message::from_bytes(&answer(&state, &encode(request).unwrap()).await.unwrap()).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::Refused);

        let mut request = Message::new(0, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::MX,
        ));
        let response =
            Message::from_bytes(&answer(&state, &encode(request).unwrap()).await.unwrap()).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NotImp);
    }

    #[tokio::test]
    async fn ignores_non_query_messages() {
        let state = AppState::seeded(None);
        let response = Message::new(7, MessageType::Response, OpCode::Query);
        assert!(answer(&state, &encode(response).unwrap()).await.is_none());

        let status = Message::new(7, MessageType::Query, OpCode::Status);
        assert!(answer(&state, &encode(status).unwrap()).await.is_none());
    }

    #[tokio::test]
    async fn returns_and_caches_only_policy_approved_address_family() {
        let state = AppState::seeded(None)
            .with_destination_policy(crate::DestinationPolicy::production())
            .with_resolver(Arc::new(StaticResolver(vec![
                "8.8.8.8".parse().unwrap(),
                "2001:4860:4860::8888".parse().unwrap(),
            ])));
        let mut request = Message::new(0, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_ascii("public.example.").unwrap(),
            RecordType::A,
        ));
        let response =
            Message::from_bytes(&answer(&state, &encode(request).unwrap()).await.unwrap()).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].ttl, DNS_TTL_SECONDS);
        assert_eq!(
            state.egress_dns.lookup("PUBLIC.EXAMPLE.").await,
            Some(vec![
                "8.8.8.8".parse().unwrap(),
                "2001:4860:4860::8888".parse().unwrap()
            ])
        );
    }

    #[tokio::test]
    async fn answer_limit_is_applied_after_address_family_filter() {
        let mut addresses = vec!["2001:4860:4860::8888".parse().unwrap(); DNS_MAX_ANSWERS];
        addresses.push("8.8.8.8".parse().unwrap());
        let state = AppState::seeded(None)
            .with_destination_policy(crate::DestinationPolicy::production())
            .with_resolver(Arc::new(StaticResolver(addresses)));

        let response = Message::from_bytes(
            &answer(&state, &query_packet(9, "public.example"))
                .await
                .unwrap(),
        )
        .unwrap();

        assert_eq!(response.answers.len(), 1);
        assert!(matches!(response.answers[0].data, RData::A(_)));
    }

    #[tokio::test]
    async fn udp_fast_query_is_not_blocked_by_slow_resolution() {
        let state = AppState::seeded(None)
            .with_destination_policy(crate::DestinationPolicy::production())
            .with_resolver(Arc::new(SlowResolver));
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = udp.local_addr().unwrap();
        let tcp = TcpListener::bind(address).await.unwrap();
        let (stop, stop_rx) = watch::channel(false);
        let server = tokio::spawn(serve(state, udp, tcp, stop_rx));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(address).await.unwrap();
        client.send(&query_packet(1, "slow.example")).await.unwrap();
        client.send(&query_packet(2, "fast.example")).await.unwrap();

        let mut response = [0_u8; DNS_PACKET_MAX_BYTES];
        let length = tokio::time::timeout(Duration::from_millis(200), client.recv(&mut response))
            .await
            .expect("fast query must not wait for slow DNS")
            .unwrap();
        assert_eq!(
            Message::from_bytes(&response[..length])
                .unwrap()
                .metadata
                .id,
            2
        );
        stop.send(true).unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_signal_is_not_lost_before_waiters_park() {
        let state = AppState::seeded(None);
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tcp = TcpListener::bind(udp.local_addr().unwrap()).await.unwrap();
        let (stop, stop_rx) = watch::channel(false);
        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_millis(200), serve(state, udp, tcp, stop_rx))
            .await
            .expect("a pre-delivered shutdown must terminate both DNS loops");
    }

    #[test]
    fn oversized_udp_response_sets_tc_and_stays_within_classic_limit() {
        let mut message = Message::new(7, MessageType::Response, OpCode::Query);
        let name = Name::from_ascii("large.example.").unwrap();
        message.add_query(Query::query(name.clone(), RecordType::AAAA));
        for index in 0..32_u16 {
            let address = format!("2001:db8::{index}").parse().unwrap();
            message.add_answer(Record::from_rdata(
                name.clone(),
                DNS_TTL_SECONDS,
                RData::AAAA(AAAA(address)),
            ));
        }
        let response = udp_response(encode(message).unwrap()).unwrap();
        assert!(response.len() <= DNS_UDP_MAX_BYTES);
        let decoded = Message::from_bytes(&response).unwrap();
        assert!(decoded.metadata.truncation);
        assert!(decoded.answers.is_empty());
    }
}
