FROM rust:1.88-bookworm AS build

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY crates ./crates
RUN cargo build --locked --release

FROM debian:bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd --gid 10001 wafids \
  && useradd --uid 10001 --gid 10001 --create-home --home-dir /var/lib/waf-ids-ai-soc wafids

COPY --from=build /app/target/release/waf-ids-ai-soc /usr/local/bin/waf-ids-ai-soc

ENV BIND_ADDR=127.0.0.1:8080 \
    DNSBL_ORIGIN=dnsbl.local \
    EVENT_LIMIT=1000 \
    WAF_IDS_STATE_PATH=/var/lib/waf-ids-ai-soc/state.json

EXPOSE 8080
VOLUME ["/var/lib/waf-ids-ai-soc"]
USER wafids

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS "http://${BIND_ADDR}/healthz" || exit 1

ENTRYPOINT ["/usr/local/bin/waf-ids-ai-soc"]
