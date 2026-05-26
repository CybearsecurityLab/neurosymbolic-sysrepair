FROM ubuntu:25.10
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    perl \
    && rm -rf /var/lib/apt/lists/*

# Vulnerability: Set SUID bit on python3 and perl interpreters.
# This allows any local user to execute scripts with root privileges,
# enabling trivial privilege escalation.
RUN chmod u+s /usr/bin/python3* /usr/bin/perl

# Create a non-root test user
RUN useradd -m -s /bin/bash testuser



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
