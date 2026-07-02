FROM rust:1.88-bookworm AS build

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM debian:bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --system --create-home --home-dir /var/lib/waf-ids-ai-soc wafids

COPY --from=build /app/target/release/waf-ids-ai-soc /usr/local/bin/waf-ids-ai-soc

ENV BIND_ADDR=127.0.0.1:8080 \
    DNSBL_ORIGIN=dnsbl.local \
    EVENT_LIMIT=1000 \
    WAF_IDS_STATE_PATH=/var/lib/waf-ids-ai-soc/state.json

EXPOSE 8080
VOLUME ["/var/lib/waf-ids-ai-soc"]
USER wafids

ENTRYPOINT ["/usr/local/bin/waf-ids-ai-soc"]
