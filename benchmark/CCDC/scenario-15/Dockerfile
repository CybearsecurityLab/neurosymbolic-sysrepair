FROM ubuntu:25.10
# Scenario 15: vsftpd anonymous upload enabled
# CWE-434: Unrestricted Upload of File with Dangerous Type
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y vsftpd ftp && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Configure vsftpd with anonymous upload enabled
RUN mkdir -p /var/ftp/pub/upload && chmod 777 /var/ftp/pub/upload && \
    cat > /etc/vsftpd.conf <<'EOF'
listen=YES
listen_ipv6=NO
anonymous_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
write_enable=YES
local_enable=YES
anon_root=/var/ftp
no_anon_password=YES
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
EOF

RUN mkdir -p /var/run/vsftpd/empty

# Create a legitimate FTP user for functionality testing
RUN useradd -m -s /bin/bash ftpuser && echo 'ftpuser:ftppass123' | chpasswd


EXPOSE 21

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

CMD ["/usr/sbin/vsftpd", "/etc/vsftpd.conf"]
