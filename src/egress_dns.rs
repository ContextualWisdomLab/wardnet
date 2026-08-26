use crate::AppState;
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{
        RData, Record, RecordType,
        rdata::{A, AAAA},
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
    let mut response = Message::new();
    response
        .set_id(request.id())
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(request.recursion_desired())
        .set_recursion_available(true);
    for query in request.queries() {
        response.add_query(query.clone());
    }
    if request.queries().len() != 1 {
        response.set_response_code(ResponseCode::FormErr);
        return encode(response);
    }
    let query = &request.queries()[0];
    if !matches!(query.query_type(), RecordType::A | RecordType::AAAA) {
        response.set_response_code(ResponseCode::NotImp);
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
                response.set_response_code(ResponseCode::Refused);
                return encode(response);
            };
            state.egress_dns.record(&host, &decision.ips).await;
            decision.ips
        }
    };
    for address in addresses.into_iter().take(DNS_MAX_ANSWERS) {
        let data = match (query.query_type(), address) {
            (RecordType::A, std::net::IpAddr::V4(address)) => RData::A(A(address)),
            (RecordType::AAAA, std::net::IpAddr::V6(address)) => RData::AAAA(AAAA(address)),
            _ => continue,
        };
        response.add_answer(Record::from_rdata(
            query.name().clone(),
            DNS_TTL_SECONDS,
            data,
        ));
    }
    encode(response)
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
    let mut message = Message::from_bytes(&bytes).ok()?;
    message.set_truncated(true);
    message.answers_mut().clear();
    let truncated = encode(message)?;
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
        let mut request = Message::new();
        request.set_id(id).add_query(Query::query(
            Name::from_ascii(format!("{host}.")).unwrap(),
            RecordType::A,
        ));
        encode(request).unwrap()
    }

    #[tokio::test]
    async fn refuses_private_answers_and_unsupported_types() {
        let state = AppState::seeded(None)
            .with_destination_policy(crate::DestinationPolicy::production())
            .with_resolver(Arc::new(StaticResolver(vec!["127.0.0.1".parse().unwrap()])));
        let mut request = Message::new();
        request.set_id(7).add_query(Query::query(
            Name::from_ascii("localhost.").unwrap(),
            RecordType::A,
        ));
        let response =
            Message::from_bytes(&answer(&state, &encode(request).unwrap()).await.unwrap()).unwrap();
        assert_eq!(response.response_code(), ResponseCode::Refused);

        let mut request = Message::new();
        request.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::MX,
        ));
        let response =
            Message::from_bytes(&answer(&state, &encode(request).unwrap()).await.unwrap()).unwrap();
        assert_eq!(response.response_code(), ResponseCode::NotImp);
    }

    #[tokio::test]
    async fn returns_and_caches_only_policy_approved_address_family() {
        let state = AppState::seeded(None)
            .with_destination_policy(crate::DestinationPolicy::production())
            .with_resolver(Arc::new(StaticResolver(vec![
                "8.8.8.8".parse().unwrap(),
                "2001:4860:4860::8888".parse().unwrap(),
            ])));
        let mut request = Message::new();
        request.add_query(Query::query(
            Name::from_ascii("public.example.").unwrap(),
            RecordType::A,
        ));
        let response =
            Message::from_bytes(&answer(&state, &encode(request).unwrap()).await.unwrap()).unwrap();
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
        assert_eq!(response.answers()[0].ttl(), DNS_TTL_SECONDS);
        assert_eq!(
            state.egress_dns.lookup("PUBLIC.EXAMPLE.").await,
            Some(vec![
                "8.8.8.8".parse().unwrap(),
                "2001:4860:4860::8888".parse().unwrap()
            ])
        );
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
        assert_eq!(Message::from_bytes(&response[..length]).unwrap().id(), 2);
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
        let mut message = Message::new();
        message.set_id(7).set_message_type(MessageType::Response);
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
        assert!(decoded.truncated());
        assert!(decoded.answers().is_empty());
    }
}
