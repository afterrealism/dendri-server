FROM rust:bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/dendri /usr/local/bin/dendri
EXPOSE 9000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:9000/health || exit 1
ENTRYPOINT ["dendri"]
CMD ["--port", "9000", "--host", "0.0.0.0", "--alive_timeout", "60000"]
