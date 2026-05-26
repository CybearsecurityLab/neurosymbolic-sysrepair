FROM ubuntu:25.10
# Scenario 07: Apache directory listing enabled
# CWE-548: Exposure of Information Through Directory Listing
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Enable directory listing (Options Indexes)
RUN sed -i 's/Options -Indexes/Options Indexes FollowSymLinks/' /etc/apache2/conf-enabled/security.conf 2>/dev/null; \
    sed -i 's/Options -Indexes/Options Indexes FollowSymLinks/' /etc/apache2/apache2.conf 2>/dev/null; \
    # Ensure Indexes is set in the default site
    sed -i 's/Options -Indexes +FollowSymLinks/Options Indexes FollowSymLinks/' /etc/apache2/apache2.conf 2>/dev/null

# Create some files but no index.html in a subdirectory
RUN mkdir -p /var/www/html/data && \
    echo "secret data" > /var/www/html/data/credentials.txt && \
    echo "config info" > /var/www/html/data/config.txt && \
    echo '<html><body><h1>Main Page</h1></body></html>' > /var/www/html/index.html


EXPOSE 80

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

CMD ["apachectl", "-D", "FOREGROUND"]
