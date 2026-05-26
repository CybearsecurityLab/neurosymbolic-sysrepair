FROM ubuntu:25.10
# Scenario 27: Telnet server running (no SSH alternative)
# CWE-319: Cleartext Transmission of Sensitive Information
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y telnetd xinetd && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Configure telnet via xinetd
RUN cat > /etc/xinetd.d/telnet <<'EOF'
service telnet
{
    disable     = no
    flags       = REUSE
    socket_type = stream
    wait        = no
    user        = root
    server      = /usr/sbin/in.telnetd
    log_on_failure += USERID
}
EOF

# Create a user
RUN useradd -m -s /bin/bash sysadmin && echo 'sysadmin:password123' | chpasswd


EXPOSE 23

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

CMD ["xinetd", "-dontfork"]
