# <img src="https://raw.githubusercontent.com/simple-icons/simple-icons/develop/icons/torbrowser.svg" height="32"> Sapphive Onion-Pipe Relay Engine

![Docker Build](https://img.shields.io/docker/pulls/sapphive/onion-pipe-relay) ![License](https://img.shields.io/badge/license-MIT-green) ![Network](https://img.shields.io/badge/network-decentralized-blue)

## 🌐 The Engine of Onion-Pipe
The **Onion-Pipe Relay Engine** is the backbone of the Sapphive network. It manages encrypted traffic transit, handles bridge discovery, and provides a professional dashboard for webhook management.

This unified image supports three distinct modes: **Master Controller**, **Community Bridge**, and **Standalone Relay**.

---

## ⚡ Quick Deployment

### Community Bridge (Support the Network)
Bridges are stateless and secure. No data is decrypted on the bridge.

```yaml
services:
  bridge:
    image: sapphive/onion-pipe-relay:latest
    environment:
      - BRIDGE_MODE=true
      - RELAY_URL=wss://onion-pipe.sapphive.com
    restart: always
```

### Master Controller (Private Infra)
Run your own webhook gateway with GitHub OAuth and a management dashboard.

#### Setup Credentials (`.env`)
```bash
# 1. Dashboard Admin
ADMIN_USER=admin
ADMIN_PASSWORD=secure_pass
SESSION_SECRET=random_secret_string

# 2. GitHub OAuth (Dashboard -> API Keys)
GITHUB_CLIENT_ID=${GITHUB_ID}
GITHUB_CLIENT_SECRET=${GITHUB_SECRET}

# 3. Connection
PUBLIC_RELAY_URL=https://onion-pipe.sapphive.com
```

#### Docker Compose
```yaml
services:
  master:
    image: sapphive/onion-pipe-relay:latest
    environment:
      - MASTER=true
      - REDIS_URL=redis://your-redis:6379
      - ADMIN_USER=${ADMIN_USER}
      - ADMIN_PASSWORD=${ADMIN_PASSWORD}
      - GITHUB_CLIENT_ID=${GITHUB_CLIENT_ID}
      - GITHUB_CLIENT_SECRET=${GITHUB_CLIENT_SECRET}
      - SESSION_SECRET=${SESSION_SECRET}
      - PUBLIC_RELAY_URL=${PUBLIC_RELAY_URL}
      - REGISTRATION_SECRET=${REGISTRATION_SECRET}
    ports:
      - "3000:3000"
    restart: always
```

---

## 💎 Mode Comparison

| Mode | Flag | Target User |
| :--- | :--- | :--- |
| **Community Bridge** | `BRIDGE_MODE=true` | Volunteers helping the public Sapphive network. |
| **Master Controller** | `MASTER=true` | Organizations hosting their own private tunnel server. |
| **Standalone Relay** | (Default) | Developers running a direct entry point. |

---

## 🛡️ Security & Privacy
1.  **Identity-First:** Integrated GitHub OAuth for secure bridge ownership.
2.  **Stateless Bridges:** Nodes only forward encrypted bytes; they never see your data.
3.  **Rotation Support:** Reveal, copy, and rotate API keys directly from the UI.

---

## 🤝 Support
Developed by the **SAPPHIVE Infrastructure Team**.
*   **Repo:** [github.com/sapphive/onion-pipe-relay](https://github.com/sapphive/onion-pipe-relay)
*   **Web Dashboard:** [onion-pipe.sapphive.com](https://onion-pipe.sapphive.com)
*   **Inquiries:** [support@sapphive.com](mailto:support@sapphive.com)

---

## ⚖️ Legal Disclaimer
This is open-source software provided by SAPPHIVE. Tor is a trademark of The Tor Project, Inc. All trademarks belong to their respective owners.

