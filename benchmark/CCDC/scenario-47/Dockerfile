FROM ubuntu:25.10
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    libpam-pwquality \
    passwd \
    && rm -rf /var/lib/apt/lists/*

# Vulnerability: Configure extremely permissive password complexity.
# Set minlen=1 and disable all complexity requirements in pwquality.conf.
# This allows users to set trivially weak passwords like "a" or "1".
RUN sed -i 's/^# minlen.*/minlen = 1/' /etc/security/pwquality.conf && \
    sed -i 's/^minlen.*/minlen = 1/' /etc/security/pwquality.conf && \
    echo "minlen = 1" >> /etc/security/pwquality.conf && \
    echo "dcredit = 0" >> /etc/security/pwquality.conf && \
    echo "ucredit = 0" >> /etc/security/pwquality.conf && \
    echo "lcredit = 0" >> /etc/security/pwquality.conf && \
    echo "ocredit = 0" >> /etc/security/pwquality.conf && \
    echo "minclass = 0" >> /etc/security/pwquality.conf && \
    echo "maxrepeat = 0" >> /etc/security/pwquality.conf && \
    echo "maxclassrepeat = 0" >> /etc/security/pwquality.conf && \
    echo "gecoscheck = 0" >> /etc/security/pwquality.conf && \
    echo "dictcheck = 0" >> /etc/security/pwquality.conf && \
    echo "enforcing = 0" >> /etc/security/pwquality.conf

# Create test user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:TestP@ss123" | chpasswd



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
