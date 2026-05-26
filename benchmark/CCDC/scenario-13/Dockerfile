FROM ubuntu:25.10
# Scenario 13: PostgreSQL pg_hba.conf trust all connections
# CWE-284: Improper Access Control
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql postgresql-client && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Configure pg_hba.conf to trust all connections (no password required)
RUN PG_HBA=$(find /etc/postgresql -name pg_hba.conf 2>/dev/null | head -1) && \
    if [ -n "$PG_HBA" ]; then \
    echo '# Vulnerable: trust all connections' > "$PG_HBA" && \
    echo 'local   all   all                 trust' >> "$PG_HBA" && \
    echo 'host    all   all   0.0.0.0/0     trust' >> "$PG_HBA" && \
    echo 'host    all   all   ::0/0         trust' >> "$PG_HBA"; \
    fi

# Create a test database
USER postgres
RUN pg_ctlcluster $(pg_lsclusters -h | awk '{print $1, $2}') start 2>/dev/null; \
    sleep 2 && \
    psql -c "CREATE DATABASE testdb;" 2>/dev/null; \
    psql -d testdb -c "CREATE TABLE items (id SERIAL PRIMARY KEY, name VARCHAR(100)); INSERT INTO items (name) VALUES ('test');" 2>/dev/null; \
    pg_ctlcluster $(pg_lsclusters -h | awk '{print $1, $2}') stop 2>/dev/null || true
USER root


EXPOSE 5432

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

CMD ["su", "-c", "pg_ctlcluster $(pg_lsclusters -h | awk '{print $1, $2}') start --foreground", "postgres"]
