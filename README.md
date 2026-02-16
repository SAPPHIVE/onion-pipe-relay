# <img src="https://raw.githubusercontent.com/loohive/onion-pipe-relay/main/src/assets/logo/logo.png" height="32"> Onion-Pipe: Privacy-First Webhook Relay (maintained by LOOHIVE)

Onion-Pipe is an open-source anonymous webhook system maintained by the LOOHIVE Infrastructure Team. It leverages the Tor network to allow developers to receive webhooks on localhost without exposing ports or trusting a centralized relay with decrypted data.

## 🚀 Key Features
- **GitHub Authentication**: Secure identity-based bridge management.
- **E2E Encryption**: Data is encrypted using X25519 before leaving the relay.
- **Professional Dashboard**: Manage your hooks, rotate API keys, and monitor network health.
- **Zero-Config Client**: Run a single Docker container locally to establish an anonymous tunnel.

## 🧠 System Architecture

1.  **Entry Relay**: Public-facing endpoint (`/h/{token}`). Receives webhooks, encrypts them immediately using the user's public key, and dispatches them to a Bridge.
2.  **Bridge Relay**: Volunteer-operated stateless nodes. They receive encrypted payloads from the Entry Relay and forward them to the user's `.onion` address over Tor.
3.  **Onion Client**: Runs locally. Receives the encrypted payload from Tor, decrypts it using a local private key, and forwards it to your local app (e.g., `localhost:8080`).

## 🐳 Installation & Setup

### 1. Choose your Role
*   **Master Controller**: You are the "Owner". You run the dashboard and manage who can connect.
*   **Community Bridge**: You are the "Router". You help move traffic from the Master to the User without ever seeing the contents.

### 2. High-Security Configuration (Docker Secrets)
Onion-Pipe Relay uses **Docker Secrets** to prevent sensitive info from leaking.

1.  Create a folder named `secrets`.
2.  Inside that folder, create text files with your values:
    -   `admin_user` (e.g., `admin`)
    -   `admin_password` (e.g., `super_strong_password`)
    -   `redis_password` (A random long string)
    -   `session_secret` (A random long string)

**🔄 Hot-Relay Support:**
To rotate Admin credentials without restarting the container (keeping all bridge connections alive), update the files in your `secrets/` folder and run:
>```bash
> docker kill -s SIGHUP onion-pipe-master
>```

### 3. Deployment (Master Mode)
Copy this `docker-compose.yml` into your project directory:

```yaml
services:
  redis:
    image: redis:alpine
    # Starts redis with your secret password
    command: ["sh", "-c", "redis-server --requirepass \"$$(tr -d '\\r' < /run/secrets/redis_password)\""]
    secrets:
      - redis_password
    networks:
      - internal

  master:
    image: loohive/onion-pipe-relay:latest
    environment:
      - MASTER=true
      - REDIS_URL=redis://redis:6379
      - PUBLIC_RELAY_URL=https://your-domain.com
    secrets:
      - admin_user
      - admin_password
      - redis_password
      - session_secret
    depends_on:
      - redis
    networks:
      - internal

networks:
  internal:
    driver: bridge

secrets:
  admin_user:
    file: ./secrets/admin_user
  admin_password:
    file: ./secrets/admin_password
  redis_password:
    file: ./secrets/redis_password
  session_secret:
    file: ./secrets/session_secret
```

Run it with:
```bash
docker compose up -d
```

### 3. Community Bridge
Join the community network and help route traffic. Bridges are stateless and "blind" to your data.

```yaml
services:
  bridge:
    image: loohive/onion-pipe-relay:latest
    environment:
      - BRIDGE_MODE=true
      - RELAY_URL=wss://onion-pipe.loohive.com
    restart: always
```

### 4. Standalone Relay (Simple Entry)
Run a basic entry relay without a dashboard (direct traffic only).
```bash
docker run -d -p 80:3000 loohive/onion-pipe-relay
```

### 5. Developer Client
Establish a tunnel to your local service.

```yaml
services:
  client:
    image: loohive/onion-pipe:latest
    volumes:
      - ./keys:/var/lib/tor/hidden_service
    environment:
      - FORWARD_DEST=http://host.docker.internal:8080
    restart: always
```

## 🛰️ CLI Usage

The `loohive/onion-pipe` image includes a professional CLI to help you manage your account and register tunnels.

```bash
# 1. Initialize local security keys
docker run --rm -v ./registration:/registration loohive/onion-pipe init

# 2. Login via GitHub (follows interactive prompts)
docker run -it --rm loohive/onion-pipe login

# 3. Register your local .onion address to your account (manual trigger)
docker exec onion-pipe register
```

## 🛡️ Security Guarantees
- **No private keys on relay:** Your decryption keys never leave your machine.
- **No payload logging:** The relay only sees encrypted noise.
- **Zero-knowledge routing:** Bridges do not know who you are or what is being sent.

---

## ⚖️ Legal Disclaimer
This is open-source software provided by LOOHIVE. Tor is a trademark of The Tor Project, Inc. All trademarks belong to their respective owners.
