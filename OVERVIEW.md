# <img src="https://raw.githubusercontent.com/loohive/onion-pipe-relay/main/src/assets/logo/logo.png" height="32"> Onion-Pipe Relay Engine (by LOOHIVE)

![Docker Build](https://img.shields.io/docker/pulls/loohive/onion-pipe-relay) ![License](https://img.shields.io/badge/license-MIT-green) ![Network](https://img.shields.io/badge/network-decentralized-blue)

## 🌐 The Engine of Onion-Pipe
The **Onion-Pipe Relay Engine** is the backbone of the community network. It manages encrypted traffic transit, handles bridge discovery, and provides a professional dashboard for webhook management.

This unified image supports three distinct roles:
1.  **Master Controller (Private Infrastructure)**: Your own private gateway with a management dashboard.
2.  **Community Bridge (Support the Network)**: A stateless node that helps route encrypted traffic globally.
3.  **Standalone Relay (Direct Entry)**: A simple high-performance entry point for direct traffic.

---

## 🔐 Security First: Docker Secrets
This engine is built for production security. Instead of exposing passwords in environment variables, we use **Docker Secrets**. 

### 1. Prepare your Secrets Folder
Before deploying, create a `secrets/` directory and add the following files (no file extensions):
- `admin_user`: Your dashboard login name.
- `admin_password`: A strong password for the dashboard.
- `redis_password`: A long random string for the database.
- `session_secret`: A random string for encrypting user sessions.
- `github_client_id`: (Optional) Your GitHub OAuth ID for identity verification.
- `github_client_secret`: (Optional) Your GitHub OAuth Secret.

> **💡 Pro-Tip: Zero-Downtime Rotation**
> You can change the `admin_user` or `admin_password` files on your host and reload them into the running container without a restart by running:
>```bash
> docker kill -s SIGHUP onion-pipe-master
>```

## 🚀 Deployment Modes

### Mode A: Master Controller (Self-Hosted Hub)
Perfect for organizations that want to host their own private "LOOHIVE-like" network.

```yaml
services:
  master:
    image: loohive/onion-pipe-relay:latest
    environment:
      - MASTER=true
      - REDIS_URL=redis://redis:6379
      - PUBLIC_RELAY_URL=https://your-domain.com
    secrets:
      - admin_user
      - admin_password
      - github_client_id
      - github_client_secret
      - session_secret
      - redis_password
    depends_on:
      redis:
        condition: service_healthy
  
  redis:
    image: redis:alpine
    command: ["sh", "-c", "redis-server --requirepass \"$$(tr -d '\\r' < /run/secrets/redis_password)\""]
    secrets:
      - redis_password
```

### Mode B: Community Bridge (Support the Public Network)
Bridges do not require a database or complex setup. They are stateless "blind" routers.

```yaml
services:
  bridge:
    image: loohive/onion-pipe-relay:latest
    environment:
      - BRIDGE_MODE=true
      - RELAY_URL=wss://onion-pipe.loohive.com  # Connect to the public LOOHIVE network
    restart: always
```

---

## 💎 Mode Comparison

| Mode | Flag | Target User |
| :--- | :--- | :--- |
| **Community Bridge** | `BRIDGE_MODE=true` | Volunteers helping the public LOOHIVE network. |
| **Master Controller** | `MASTER=true` | Organizations hosting their own private tunnel server. |
| **Standalone Relay** | (Default) | Developers running a direct entry point. |

---

## 🛡️ Security & Privacy
1.  **Identity-First:** Integrated GitHub OAuth for secure bridge ownership.
2.  **Stateless Bridges:** Nodes only forward encrypted bytes; they never see your data.
3.  **Rotation Support:** Reveal, copy, and rotate API keys directly from the UI.

---

## 🤝 Support
Developed by the **LOOHIVE Infrastructure Team**.
*   **Repo:** [github.com/loohive/onion-pipe-relay](https://github.com/loohive/onion-pipe-relay)
*   **Web Dashboard:** [onion-pipe.loohive.com](https://onion-pipe.loohive.com)
*   **Inquiries:** [support@loohive.com](mailto:support@loohive.com)

---

## ⚖️ Legal Disclaimer
This is open-source software provided by LOOHIVE. Tor is a trademark of The Tor Project, Inc. All trademarks belong to their respective owners.

