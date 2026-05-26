FROM ubuntu:25.10
# Scenario 29: No firewall installed (ufw absent)
# CWE-1188: Insecure Default Initialization of Resource
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server nginx curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Ensure no firewall is installed (remove ufw if present)
RUN apt-get remove --purge -y ufw iptables 2>/dev/null; \
    apt-get autoremove -y 2>/dev/null; true

# Set up services that should be protected by a firewall
RUN mkdir -p /run/sshd && \
    echo '<html><body><h1>Web Server</h1></body></html>' > /var/www/html/index.html

# Create a user
RUN useradd -m -s /bin/bash sysadmin && echo 'sysadmin:password123' | chpasswd


EXPOSE 22 80

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

CMD service ssh start && nginx -g "daemon off;"
