FROM ubuntu:25.10
# Scenario 20: WordPress file editor enabled
# CWE-94: Improper Control of Generation of Code (Code Injection)
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 php libapache2-mod-php php-mysql curl wget && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Download and set up WordPress (simulated with key config files)
RUN mkdir -p /var/www/html/wp-content/themes /var/www/html/wp-content/plugins /var/www/html/wp-admin && \
    echo '<?php echo "WordPress running"; ?>' > /var/www/html/index.php

# Create wp-config.php WITHOUT DISALLOW_FILE_EDIT (vulnerable)
RUN cat > /var/www/html/wp-config.php <<'WPEOF'
<?php
define('DB_NAME', 'wordpress');
define('DB_USER', 'wpuser');
define('DB_PASSWORD', 'wppass');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8');
define('DB_COLLATE', '');

define('AUTH_KEY',         'put your unique phrase here');
define('SECURE_AUTH_KEY',  'put your unique phrase here');
define('LOGGED_IN_KEY',    'put your unique phrase here');
define('NONCE_KEY',        'put your unique phrase here');
define('AUTH_SALT',        'put your unique phrase here');
define('SECURE_AUTH_SALT', 'put your unique phrase here');
define('LOGGED_IN_SALT',   'put your unique phrase here');
define('NONCE_SALT',       'put your unique phrase here');

$table_prefix = 'wp_';
define('WP_DEBUG', false);

if ( ! defined( 'ABSPATH' ) ) {
    define( 'ABSPATH', __DIR__ . '/' );
}
WPEOF

RUN chown -R www-data:www-data /var/www/html && chmod 644 /var/www/html/wp-config.php


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
