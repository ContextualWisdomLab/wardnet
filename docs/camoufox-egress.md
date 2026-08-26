# Camoufox egress contract

Wardnet is both the container DNS resolver and the only HTTPS egress path. A
preflight URL approval is not a security boundary: the browser navigation must
use the CONNECT proxy and the workload network must deny direct Internet egress.

## Wardnet

Seed the credential registry with a dedicated `egress_proxy_token` (the
`EGRESS_PROXY_TOKEN` environment variable is bootstrap transport only), set
`BIND_ADDR=0.0.0.0:8080`, and set `EGRESS_DNS_BIND_ADDR=0.0.0.0:5353` on the
internal workload network. Do not expose port 5353 publicly. The Kubernetes
Service maps its internal port 53 to this unprivileged container port.

The DNS listener supports bounded UDP and TCP A/AAAA queries. It runs every new
name through `DestinationPolicy`, returns no private, loopback, link-local,
metadata, or otherwise denied address, caches the approved address set for 30
seconds, caps the cache at 1024 names, and refuses other record types. TCP DNS
messages are capped at 4096 bytes and concurrent TCP clients at 64.

The HTTP endpoint accepts authenticated `CONNECT host:443` only. Configure
Basic proxy credentials as username `wardnet` and password equal to the
dedicated proxy token. Wardnet resolves through the same policy/cache and opens
the upstream socket directly to an approved IP; it never performs a second
connect-time DNS lookup. A redirect to another origin therefore requires a new
policy-checked CONNECT tunnel.

## Camoufox / contextual-orchestrator

Provide these values from the deployment layer:

```text
DNS nameserver: <wardnet-dns-service-ip> (UDP and TCP port 53)
HTTP/HTTPS proxy: http://<wardnet-internal-ip>:8080
Proxy username: wardnet
Proxy password: <egress_proxy_token from KV>
Firefox DoH/TRR: disabled (network.trr.mode=5)
```

Configure the container runtime DNS address and the Camoufox proxy launch
option; setting only one is incomplete. Do not pass the Wardnet admin token to
the browser container.

Enforce a default-deny egress policy on the Camoufox workload. Its only allowed
egress is UDP/TCP DNS to the Wardnet Service port 53 (target port 5353) and TCP
to Wardnet port 8080. In
particular, deny direct TCP 80/443 and all other DNS servers. Wardnet separately
needs upstream DNS and TCP 443. This network policy is what prevents a browser,
extension, subprocess, or IP-literal URL from bypassing the proxy contract.
