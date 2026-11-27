FROM debian:trixie-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config libssl-dev python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Makefile ./
COPY src/ src/
COPY tools/ tools/
COPY tests/ tests/
RUN make -j2 && useradd --create-home --uid 10001 securepm \
    && chown -R securepm:securepm /app
USER securepm
RUN make test-all

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends libssl3t64 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 securepm
COPY --from=build /app/securepm /usr/local/bin/securepm
ENV HOME=/home/securepm
USER securepm
WORKDIR /home/securepm
ENTRYPOINT ["/usr/local/bin/securepm"]
