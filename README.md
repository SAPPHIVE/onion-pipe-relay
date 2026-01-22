# Onion-Pipe: Privacy-First Webhook Relay

Onion-Pipe is a zero-trust, end-to-end encrypted webhook relay system leveraging the Tor network. It allows developers to receive webhooks on localhost without exposing ports or trusting a centralized relay with decrypted data.

## 🚀 Key Features
- **GitHub Authentication**: Secure identity-based bridge management.
- **E2E Encryption**: Data is encrypted using X25519 before leaving the relay.
- **Professional Dashboard**: Manage your hooks, rotate API keys, and monitor network health.
- **Zero-Config Client**: Run a single Docker container locally to establish an anonymous tunnel.

## 🧠 System Architecture

1.  **Entry Relay**: Public-facing endpoint (`/h/{token}`). Receives webhooks, encrypts them immediately using the user's public key, and dispatches them to a Bridge.
2.  **Bridge Relay**: Volunteer-operated stateless nodes. They receive encrypted payloads from the Entry Relay and forward them to the user's `.onion` address over Tor.
3.  **Onion Client**: Runs locally. Receives the encrypted payload from Tor, decrypts it using a local private key, and forwards it to your local app (e.g., `localhost:8080`).

## 🐳 Docker Deployment

Onion-Pipe is designed to be run entirely in Docker.

### 1. Master Controller (Self-Hosted)
Run your own private network with GitHub OAuth integration.

#### Production Configuration (`.env`)
Create a `.env` file in your project root:

```bash
# --- ONION-PIPE RELAY PRODUCTION ENV ---

# 1. Dashboard Admin Security
ADMIN_USER=sapphive_admin
ADMIN_PASSWORD=your_very_secure_admin_password
SESSION_SECRET=a_long_random_string_for_session_encryption

# 2. GitHub OAuth (Get these from https://github.com/settings/developers)
# Homepage URL: https://your-domain.com
# Authorization callback URL: https://your-domain.com/auth/github/callback
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret

# 3. Network Configuration
PUBLIC_RELAY_URL=https://your-domain.com
REGISTRATION_SECRET=optional_shared_secret_to_limit_cli_registrations
```

#### Compose Deployment
```yaml
services:
  master:
    container_name: onion-pipe-master
    image: sapphive/onion-pipe-relay:latest
    environment:
      - MASTER=true
      - REDIS_URL=redis://redis:6379
      - ADMIN_USER=${ADMIN_USER}
      - ADMIN_PASSWORD=${ADMIN_PASSWORD}
      - GITHUB_CLIENT_ID=${GITHUB_CLIENT_ID}
      - GITHUB_CLIENT_SECRET=${GITHUB_CLIENT_SECRET}
      - SESSION_SECRET=${SESSION_SECRET}
      - PUBLIC_RELAY_URL=${PUBLIC_RELAY_URL}
      - REGISTRATION_SECRET=${REGISTRATION_SECRET}
    depends_on:
      - redis
  redis:
    image: redis:alpine
```

### 2. Community Bridge
Join the Sapphive network and help route traffic. Bridges are stateless and "blind" to your data.

```yaml
services:
  bridge:
    image: sapphive/onion-pipe-relay:latest
    environment:
      - BRIDGE_MODE=true
      - RELAY_URL=wss://onion-pipe.sapphive.com
    restart: always
```

### 3. Developer Client
Establish a tunnel to your local service.

```yaml
services:
  client:
    image: sapphive/onion-pipe:latest
    volumes:
      - ./keys:/var/lib/tor/hidden_service
    environment:
      - FORWARD_DEST=http://host.docker.internal:8080
    restart: always
```

## 🛰️ CLI Usage

The `onion-pipe-relay` CLI helps you manage your account and register tunnels.

```bash
# 1. Initialize local security keys
npm run cli init

# 2. Login via GitHub (opens browser)
npm run cli login

# 3. Complete authentication by pasting the 6-digit code
npm run cli auth <6-digit-code>

# 4. Register your local .onion address to your account
npm run cli register <your-hidden-service-id>
```

## 🛡️ Security Guarantees
- **No private keys on relay:** Your decryption keys never leave your machine.
- **No payload logging:** The relay only sees encrypted noise.
- **Zero-knowledge routing:** Bridges do not know who you are or what is being sent.

---

## ⚖️ Legal Disclaimer
This is open-source software provided by SAPPHIVE. Tor is a trademark of The Tor Project, Inc. All trademarks belong to their respective owners.
