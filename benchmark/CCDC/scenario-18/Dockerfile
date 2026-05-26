FROM ubuntu:25.10
# Scenario 18: Samba anonymous share access
# CWE-284: Improper Access Control
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y samba smbclient && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Configure Samba with anonymous access
RUN cat > /etc/samba/smb.conf <<'EOF'
[global]
    workgroup = WORKGROUP
    server string = Vulnerable Samba Server
    security = user
    map to guest = Bad User
    guest account = nobody

[public]
    path = /srv/samba/public
    browseable = yes
    writable = yes
    guest ok = yes
    read only = no
    create mask = 0777
    directory mask = 0777

[private]
    path = /srv/samba/private
    browseable = yes
    writable = yes
    guest ok = yes
    read only = no
EOF

RUN mkdir -p /srv/samba/public /srv/samba/private && \
    echo "public data" > /srv/samba/public/readme.txt && \
    echo "CONFIDENTIAL: password=s3cret" > /srv/samba/private/secrets.txt && \
    chmod -R 777 /srv/samba/

# Create a legitimate Samba user
RUN useradd -m -s /bin/bash smbuser && \
    echo 'smbuser:smbpass123' | chpasswd && \
    (echo 'smbpass123'; echo 'smbpass123') | smbpasswd -a smbuser 2>/dev/null


EXPOSE 139 445

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

CMD ["smbd", "--foreground", "--no-process-group"]
