FROM ubuntu:25.10
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

# Install OpenSSL but hold it at the initially installed version
# to simulate a system that has not been updated
RUN apt-get update && apt-get install -y \
    openssl \
    libssl-dev \
    ca-certificates \
    curl \
    wget \
    systemctl \
    coreutils \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Mark openssl as held to prevent automatic updates (simulates stale system)
RUN apt-mark hold openssl libssl3t64 2>/dev/null || apt-mark hold openssl libssl3 2>/dev/null || true

# Create a marker file indicating this system has a known-vulnerable OpenSSL
# and record the current version for comparison after remediation
RUN openssl version > /opt/.openssl_vulnerable_version
RUN echo "VULNERABLE_OPENSSL=true" > /opt/.openssl_status



# === auto-sysrepair osquery layer (injected for end-to-end NS planner runs) ===
# Adds osquery-style introspection support so the solver's domain-aware
# state probe can grok user/group/package state. Idempotent in builds.
RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends curl gnupg ca-certificates && \
    install -d -m 0755 /etc/apt/keyrings && \
    curl -fsSL https://pkg.osquery.io/deb/pubkey.gpg | gpg --dearmor -o /etc/apt/keyrings/osquery.gpg && \
    echo 'deb [arch=amd64 signed-by=/etc/apt/keyrings/osquery.gpg] https://pkg.osquery.io/deb deb main' > /etc/apt/sources.list.d/osquery.list && \
    apt-get update -qq && \
    apt-get install -y -qq osquery && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
