#!/bin/bash

# Certificate Generation Script
# Generates self-signed TLS certificates for local development

echo "=================================="
echo "🔑 Generating TLS Certificates"
echo "=================================="
echo ""

# Check if openssl is installed
if ! command -v openssl &> /dev/null; then
    echo "❌ Error: openssl is not installed"
    echo ""
    echo "Install openssl:"
    echo "  • macOS: brew install openssl"
    echo "  • Ubuntu/Debian: sudo apt-get install openssl"
    echo "  • Windows: Install Git Bash (includes openssl)"
    echo ""
    exit 1
fi

# Check if certificates already exist
if [ -f "cert.pem" ] && [ -f "key.pem" ]; then
    echo "⚠️  Certificates already exist!"
    read -p "Overwrite existing certificates? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Keeping existing certificates."
        exit 0
    fi
    echo "Regenerating certificates..."
fi

# Generate RSA-4096 private key and self-signed certificate
openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout key.pem \
    -out cert.pem \
    -days 365 \
    -subj '/CN=localhost/O=Secure Bank/C=US'

# Check if generation was successful
if [ -f "cert.pem" ] && [ -f "key.pem" ]; then
    echo ""
    echo "✓ Certificates generated successfully!"
    echo ""
    echo "Files created:"
    echo "  • cert.pem (public certificate)"
    echo "  • key.pem (private key)"
    echo ""
    echo "Certificate details:"
    openssl x509 -in cert.pem -noout -subject -dates
    echo ""
    echo "⚠️  Security Note:"
    echo "  These are SELF-SIGNED certificates for development only."
    echo "  Browsers will show security warnings (expected behavior)."
    echo "  For production, use CA-signed certificates (Let's Encrypt, etc.)"
    echo ""
    echo "Next steps:"
    echo "  1. Run: bash scripts/run_https.sh"
    echo "  2. Open: https://localhost:5000"
    echo "  3. Accept browser security warning"
    echo ""
else
    echo ""
    echo "❌ Certificate generation failed!"
    exit 1
fi