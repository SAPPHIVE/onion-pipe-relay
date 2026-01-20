#!/bin/bash
set -e

echo "🚀 Starting Onion-Pipe Relay System..."

# --- BRIDGE MODE LOGIC ---
if [ "$BRIDGE_MODE" = "true" ]; then
    echo "🌉 Mode: Community Bridge"
    
    # Ensure Tor is running for the bridge
    echo "🧅 Starting Tor (as debian-tor)..."
    # Create required directory if missing
    mkdir -p /var/run/tor && chown debian-tor:debian-tor /var/run/tor
    
    # Start Tor using the debian-tor user
    su -s /bin/bash debian-tor -c "tor --RunAsDaemon 1 --SocksPort 0.0.0.0:9050"
    
    # Wait for Tor SOCKS port
    echo "⏳ Waiting for Tor to be ready..."
    MAX_RETRIES=30
    COUNT=0
    while ! curl -sx socks5h://localhost:9050 http://check.torproject.org > /dev/null; do
        sleep 2
        COUNT=$((COUNT+1))
        if [ $COUNT -ge $MAX_RETRIES ]; then
            echo "❌ Tor failed to start."
            exit 1
        fi
    done
    echo "✅ Tor is ready."

    # Run the bridge
    echo "🛰️ Connecting to Relay: ${RELAY_URL:-ws://relay.sapphive.com}"
    export TOR_SOCKS=socks5h://127.0.0.1:9050
    node dist/bridge/index.js
    exit 0
fi

# --- MASTER MODE LOGIC ---
if [ "$MASTER" = "true" ]; then
    echo "👑 Mode: Master Controller"
    export NODE_ENV=production
    # We might need redis here if not external
    node dist/relay/index.js
    exit 0
fi

# --- DEFAULT: STANDALONE RELAY ---
echo "🔄 Mode: Standalone Relay (Self-Hosted)"
# Run the relay logic
node dist/relay/index.js
