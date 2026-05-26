FROM ubuntu:25.10
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    sudo \
    passwd \
    && rm -rf /var/lib/apt/lists/*

# Create the authorized admin user and add to sudo group
RUN useradd -m -s /bin/bash admin && \
    echo "admin:Str0ngP@ss!" | chpasswd && \
    usermod -aG sudo admin

# Vulnerability: Create an unauthorized user "intern" and add to sudo group.
# The intern user should not have sudo privileges per organizational policy.
RUN useradd -m -s /bin/bash intern && \
    echo "intern:intern123" | chpasswd && \
    usermod -aG sudo intern

# Create the authorized sudoers list
RUN echo "admin" > /opt/authorized_sudoers

# Create a regular test user (not in sudo)
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
