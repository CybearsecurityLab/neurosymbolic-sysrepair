FROM ubuntu:25.10
# Scenario 19: PHP dangerous functions enabled
# CWE-78: OS Command Injection
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y php-fpm php-cli nginx curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Ensure dangerous PHP functions are NOT disabled (vulnerable state)
RUN PHP_INI=$(php -r "echo php_ini_loaded_file();" 2>/dev/null) && \
    if [ -n "$PHP_INI" ]; then \
    sed -i 's/^disable_functions.*/disable_functions =/' "$PHP_INI"; \
    fi && \
    for ini in /etc/php/*/fpm/php.ini /etc/php/*/cli/php.ini; do \
    [ -f "$ini" ] && sed -i 's/^disable_functions.*/disable_functions =/' "$ini"; \
    done

# Also enable allow_url_fopen and allow_url_include
RUN for ini in /etc/php/*/fpm/php.ini /etc/php/*/cli/php.ini; do \
    [ -f "$ini" ] && \
    sed -i 's/^allow_url_fopen.*/allow_url_fopen = On/' "$ini" && \
    sed -i 's/^;allow_url_include.*/allow_url_include = On/' "$ini" && \
    sed -i 's/^allow_url_include.*/allow_url_include = On/' "$ini" && \
    sed -i 's/^expose_php.*/expose_php = On/' "$ini"; \
    done

# Set up Nginx with PHP-FPM
RUN echo 'server { listen 80; root /var/www/html; index index.php index.html; location ~ \.php$ { include snippets/fastcgi-php.conf; fastcgi_pass unix:/run/php/php-fpm.sock; } }' > /etc/nginx/sites-enabled/default

# Create a test PHP file
RUN echo '<?php echo "PHP is working: " . phpversion(); ?>' > /var/www/html/index.php


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

CMD ["bash", "-c", "service $(ls /etc/init.d/ | grep php.*fpm | head -1) start && nginx -g 'daemon off;'"]
