FROM ubuntu:25.10
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

# Install AppArmor but leave it in a non-enforcing state
RUN apt-get update && apt-get install -y \
    apparmor \
    apparmor-utils \
    systemctl \
    coreutils \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Set all AppArmor profiles to complain mode (non-enforcing)
# This defeats the purpose of MAC (Mandatory Access Control)
RUN if [ -d /etc/apparmor.d ]; then \
        for profile in /etc/apparmor.d/*; do \
            if [ -f "$profile" ] && [ "$(basename "$profile")" != "local" ]; then \
                aa-complain "$profile" 2>/dev/null || true; \
            fi; \
        done; \
    fi

# Create a marker indicating AppArmor was intentionally weakened
RUN echo "apparmor_disabled=true" > /etc/apparmor/apparmor_status.conf 2>/dev/null || \
    mkdir -p /etc/apparmor && echo "apparmor_disabled=true" > /etc/apparmor/apparmor_status.conf



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
