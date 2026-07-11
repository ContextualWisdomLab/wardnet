FROM rust:1.88-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 AS build

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY crates ./crates
RUN cargo build --locked --release

FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates=20230311+deb12u1 \
    curl=7.88.1-10+deb12u14 \
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
