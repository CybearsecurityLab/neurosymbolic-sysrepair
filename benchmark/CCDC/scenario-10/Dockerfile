FROM ubuntu:25.10
# Scenario 10: Nginx autoindex on (directory listing)
# CWE-548: Exposure of Information Through Directory Listing
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y nginx curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Enable autoindex (directory listing) in default site
RUN mkdir -p /etc/nginx/conf.d && \
    echo 'server { listen 80 default_server; root /var/www/html; index index.html; location / { autoindex on; try_files $uri $uri/ =404; } }' > /etc/nginx/conf.d/default.conf && \
    rm -f /etc/nginx/sites-enabled/default

# Create files but no index in a subdirectory
RUN mkdir -p /var/www/html/files && \
    echo "secret" > /var/www/html/files/passwords.txt && \
    echo "config" > /var/www/html/files/database.conf && \
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

CMD ["nginx", "-g", "daemon off;"]
