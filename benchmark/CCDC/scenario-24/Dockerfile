FROM ubuntu:25.10
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    iproute2 \
    iputils-ping \
    procps \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Accept ICMP redirects (allows route manipulation attacks)
# Disable logging of martian packets (hides suspicious traffic)
RUN echo "net.ipv4.conf.all.accept_redirects = 1" >> /etc/sysctl.conf && \
    echo "net.ipv4.conf.default.accept_redirects = 1" >> /etc/sysctl.conf && \
    echo "net.ipv4.conf.all.log_martians = 0" >> /etc/sysctl.conf && \
    echo "net.ipv4.conf.default.log_martians = 0" >> /etc/sysctl.conf



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
