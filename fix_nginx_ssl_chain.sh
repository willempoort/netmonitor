#!/bin/bash
# Fix nginx SSL certificate chain voor Let's Encrypt

echo "==================================="
echo "Nginx SSL Certificate Chain Fix"
echo "==================================="
echo ""

# Find nginx config for netmonitor
NGINX_CONF=""
for conf in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*; do
    if [ -f "$conf" ]; then
        if grep -q "soc.rapidsteelservice.com" "$conf" 2>/dev/null; then
            NGINX_CONF="$conf"
            break
        fi
    fi
done

if [ -z "$NGINX_CONF" ]; then
    echo "❌ Cannot find nginx config for soc.rapidsteelservice.com"
    echo ""
    echo "Please provide the path to your nginx config file."
    exit 1
fi

echo "Found nginx config: $NGINX_CONF"
echo ""

# Extract certificate path
SSL_CERT=$(grep "ssl_certificate " "$NGINX_CONF" | grep -v "ssl_certificate_key" | awk '{print $2}' | sed 's/;//')
SSL_KEY=$(grep "ssl_certificate_key" "$NGINX_CONF" | awk '{print $2}' | sed 's/;//')

echo "Current SSL configuration:"
echo "  Certificate: $SSL_CERT"
echo "  Key:         $SSL_KEY"
echo ""

if [ ! -f "$SSL_CERT" ]; then
    echo "❌ Certificate file not found: $SSL_CERT"
    exit 1
fi

# Check if it's a Let's Encrypt certificate
if [[ "$SSL_CERT" == *"letsencrypt"* ]]; then
    echo "✅ Detected Let's Encrypt certificate"
    echo ""

    # Extract domain from certificate path
    DOMAIN=$(echo "$SSL_CERT" | grep -oP '(?<=live/)[^/]+')
    CERTBOT_DIR="/etc/letsencrypt/live/$DOMAIN"

    if [ -d "$CERTBOT_DIR" ]; then
        echo "Certbot directory: $CERTBOT_DIR"
        echo ""
        echo "Available files:"
        ls -la "$CERTBOT_DIR/"
        echo ""

        # Check if fullchain.pem is being used
        if [[ "$SSL_CERT" == *"fullchain.pem"* ]]; then
            echo "✅ Already using fullchain.pem (includes intermediate certificates)"
        else
            echo "⚠️  Using cert.pem instead of fullchain.pem"
            echo ""
            echo "To fix, update your nginx config:"
            echo ""
            echo "Change:"
            echo "  ssl_certificate $SSL_CERT;"
            echo ""
            echo "To:"
            echo "  ssl_certificate $CERTBOT_DIR/fullchain.pem;"
            echo ""
            echo "Then reload nginx:"
            echo "  sudo nginx -t"
            echo "  sudo systemctl reload nginx"
        fi
    else
        echo "❌ Certbot directory not found: $CERTBOT_DIR"
    fi
else
    echo "ℹ️  Not a Let's Encrypt certificate"
    echo ""
    echo "For other certificate providers, ensure you have:"
    echo "1. Your server certificate"
    echo "2. ALL intermediate certificates"
    echo "3. Concatenated in the correct order"
    echo ""
    echo "Example:"
    echo "  cat server.crt intermediate.crt > fullchain.crt"
    echo "  ssl_certificate /path/to/fullchain.crt;"
fi

echo ""
echo "==================================="
echo "Testing certificate chain:"
echo "==================================="
echo ""

# Test certificate chain
echo "Checking certificate chain from file:"
openssl x509 -in "$SSL_CERT" -text -noout | grep -E "Subject:|Issuer:"
echo ""

# Test certificate chain from server
echo "Testing SSL connection from this server:"
DOMAIN=$(grep "server_name" "$NGINX_CONF" | head -1 | awk '{print $2}' | sed 's/;//')
echo "Domain: $DOMAIN"
echo ""

timeout 5 openssl s_client -connect localhost:443 -servername "$DOMAIN" </dev/null 2>&1 | grep -E "verify return:|Verify return code:|depth="

echo ""
echo "==================================="
echo "Quick fix options:"
echo "==================================="
echo ""
echo "Option 1: Fix certificate chain (RECOMMENDED)"
echo "  If using Let's Encrypt, ensure fullchain.pem is used"
echo "  Edit: $NGINX_CONF"
echo "  Change ssl_certificate to use fullchain.pem"
echo ""
echo "Option 2: Disable SSL verification on sensors (NOT recommended)"
echo "  On each sensor, edit /opt/netmonitor/sensor.conf:"
echo "  SSL_VERIFY=false"
echo "  sudo systemctl restart netmonitor-sensor"
echo ""
echo "Option 3: Update CA certificates on sensors"
echo "  On each sensor:"
echo "  sudo apt-get update"
echo "  sudo apt-get install --reinstall ca-certificates"
echo "  sudo update-ca-certificates"
echo ""
