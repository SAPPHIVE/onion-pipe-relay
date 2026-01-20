# Onion-Pipe: Privacy-First Webhook Relay

Onion-Pipe is a zero-trust, end-to-end encrypted webhook relay system leveraging the Tor network. It allows developers to receive webhooks on localhost without exposing ports or trusting a centralized relay with decrypted data.

## 🧠 System Architecture

1.  **Entry Relay**: Public-facing endpoint (`/h/{token}`). Receives webhooks, encrypts them immediately using the user's public key, and dispatches them to a Bridge.
2.  **Bridge Relay**: Volunteer-operated stateless nodes. They receive encrypted payloads from the Entry Relay and forward them to the user's `.onion` address over Tor.
3.  **Onion Client**: Runs locally. Receives the encrypted payload from Tor, decrypts it using a local private key, and forwards it to your local app (e.g., `localhost:8080`).

## � Docker Deployment

Onion-Pipe is designed to be run entirely in Docker.

### 1. Master Controller (Self-Hosted or Masternode)
```yaml
services:
  master:
    image: sapphive/onion-pipe-relay
    environment:
      - MASTER=true
      - REDIS_URL=redis://redis:6379
      - REGISTRATION_SECRET=my-secret-key  # Optional: protect registration
  redis:
    image: redis:alpine
```

### 2. Community Bridge
```yaml
services:
  bridge:
    image: sapphive/onion-pipe-relay
    environment:
      - BRIDGE_MODE=true
      - RELAY_URL=wss://onion-pipe.sapphive.com
```
*Note: Tor is bundled within the image for Bridge mode.*

### 3. Developer Client
```yaml
services:
  client:
    image: sapphive/onion-pipe
    volumes:
      - ./keys:/keys
    environment:
      - TARGET_URL=http://host.docker.internal:8080
```

## 🛡️ Volunteer Bridge Safety
Bridges are completely stateless and blind.
- **Can they see data?** No, it is X25519 encrypted using the client's public key before reaching any bridge.
- **Can they see who I am?** They only see an opaque `.onion` address.
- **Do I need to open ports?** No, bridges connect **outbound** to the relay via WebSockets.

## 🌉 Bridge Offloading Logic
The Master Relay (Entry Relay) tracks all connected bridges in Redis. When a webhook arrives, it:
1. Encrypts the payload.
2. Checks for healthy community bridges.
3. If multiple exist, it offloads the Tor circuit creation to a random bridge.
4. If no community bridges are present, it uses its internal master bridge.

## 🚀 Getting Started

### Prerequisites
- Node.js & Redis
- Tor (running with SOCKS5 proxy on port 9050)

### Installation
```bash
npm install
```

### Components

#### 1. Start Entry Relay
```bash
REDIS_URL=redis://localhost:6379 npm run relay
```

#### 2. Start Bridge Relay
```bash
RELAY_WS_URL=ws://relay-server:3000 TOR_SOCKS=socks5h://127.0.0.1:9050 npm run bridge
```

#### 3. Client Setup
```bash
# Initialize keys
npm run cli init

# Register with relay
npm run cli register <your-onion-address>

# Start client listener
TARGET_URL=http://localhost:8080 npm run client
```

## 🗄️ Redis Schema
- `token:{uuid}`: Hash containing `public_key`, `onion_service_id`, `status`.
- `bridge:{uuid}`: Hash containing `last_seen`, `load`.
- `active_bridges`: Set of bridge IDs.

## �️ Security & Port Guarantees
- **Port 80 Simplicity:** Bridges connect to `onion-pipe` clients on Port 80. Tor handles the end-to-end encryption, so the "plain" HTTP over Tor is perfectly secure.
- **No private keys on relay.**
- **No payload logging.**
- **Zero-knowledge routing.**
- **Memory-safe buffers.**
