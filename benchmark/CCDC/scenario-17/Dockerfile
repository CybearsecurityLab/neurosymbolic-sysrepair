FROM ubuntu:25.10
# Scenario 17: BIND DNS zone transfer unrestricted
# CWE-200: Exposure of Sensitive Information
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y bind9 bind9utils dnsutils && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Configure BIND with unrestricted zone transfers
RUN cat > /etc/bind/named.conf.options <<'EOF'
options {
    directory "/var/cache/bind";
    allow-transfer { any; };
    allow-query { any; };
    recursion yes;
    listen-on { any; };
    dnssec-validation auto;
};
EOF

# Create a zone file
RUN cat > /etc/bind/named.conf.local <<'EOF'
zone "example.com" {
    type master;
    file "/etc/bind/db.example.com";
    allow-transfer { any; };
};
EOF

RUN cat > /etc/bind/db.example.com <<'EOF'
$TTL 86400
@   IN  SOA ns1.example.com. admin.example.com. (
        2024010101 ; Serial
        3600       ; Refresh
        1800       ; Retry
        604800     ; Expire
        86400 )    ; Minimum TTL
@       IN  NS  ns1.example.com.
ns1     IN  A   192.168.1.1
www     IN  A   192.168.1.10
mail    IN  A   192.168.1.20
internal IN A   10.0.0.50
secret  IN  A   10.0.0.100
EOF


EXPOSE 53/tcp 53/udp

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

CMD ["named", "-g", "-u", "bind"]
