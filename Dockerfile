FROM rust:1-slim-trixie AS builder

ENV RUSTFLAGS="-C link-arg=-s" \
    CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

WORKDIR /app
COPY . .

RUN cargo build --release --locked && mkdir -p /app/secrets

# --- Final Stage ---
# The :nonroot variant runs as an unprivileged user (uid 65532) instead of root.
FROM gcr.io/distroless/cc-debian13:nonroot
WORKDIR /app

COPY --from=builder /app/target/release/admin_api /app/admin_api
COPY public/ /app/public/
COPY templates/ /app/templates/
# The app writes secrets/user_db.json, so this directory must be writable by the
# unprivileged user. (In production mount a volume or tmpfs over it.)
COPY --from=builder --chown=65532:65532 /app/secrets/ /app/secrets/

USER 65532:65532
EXPOSE 5000
# Exec form: the distroless image has no shell. The binary probes its own
# listener with an OPTIONS request (see `--healthcheck` in healthcheck.rs).
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD ["/app/admin_api", "--healthcheck"]
CMD ["./admin_api"]
