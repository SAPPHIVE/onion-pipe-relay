# <img src="https://raw.githubusercontent.com/simple-icons/simple-icons/develop/icons/torbrowser.svg" height="32"> Sapphive Onion-Pipe Relay Engine

![Docker Build](https://img.shields.io/docker/cloud/build/sapphive/onion-pipe-relay) ![License](https://img.shields.io/badge/license-MIT-green) ![Network](https://img.shields.io/badge/network-decentralized-blue)

## 🌐 The Engine of Onion-Pipe
The **Onion-Pipe Relay Engine** is the core infrastructure behind the Sapphive community network. While the standard [Onion-Pipe Client](https://hub.docker.com/r/sapphive/onion-pipe) provides the local tunnel, this image drives the global relay and bridge system that makes zero-knowledge webhook delivery possible.

This unified image supports three distinct operation modes to fit any developer or community need.

---

## 🛠️ Deploy as a Community Bridge (Help the Network!)
Support the Sapphive network by contributing a bridge node. Bridges handle the encrypted transit between entry relays and client onion services without ever seeing the raw data.

```yaml
services:
  bridge:
    image: sapphive/onion-pipe-relay:latest
    environment:
      - BRIDGE_MODE=true
      - RELAY_URL=wss://onion-pipe.sapphive.com
    restart: always
```

---

## 👑 Deploy as a Master Controller (Private Networks)
Run your own private webhook infrastructure. Ideal for organizations that want to manage their own bridge sets and have full control over the relay dashboard.

```yaml
services:
  master:
    image: sapphive/onion-pipe-relay:latest
    environment:
      - MASTER=true
      - REDIS_URL=redis://your-redis:6379
      - ADMIN_PASSWORD=secure_pass  # Protects your dashboard
    ports:
      - "3000:3000"
    restart: always
```

---

## 💎 Operation Modes

| Mode | Flag | Description |
| :--- | :--- | :--- |
| **Community Bridge** | `BRIDGE_MODE=true` | Joins the Sapphive network (or a custom one) to help route traffic anonymously. |
| **Master Controller** | `MASTER=true` | The "Brain." Tracks bridges, hosts the management dashboard, and handles registration. |
| **Standalone Relay** | (Default) | Operates as a simple entry relay for local or private use. |

---

## 🎯 Why Run a Bridge?
- **Support Privacy:** Help fellow developers receive webhooks securely without centralized bottlenecks.
- **Stateless & Safe:** Bridges are "blind." They only see encrypted noise and opaque onion addresses. 
- **Lightweight:** Extremely low CPU/RAM usage.

---

## 🤝 Project Links
- **Client Project:** [github.com/sapphive/onion-pipe](https://github.com/sapphive/onion-pipe)
- **Relay Project:** [github.com/sapphive/onion-pipe-relay](https://github.com/sapphive/onion-pipe-relay)
- **Support:** [support@sapphive.com](mailto:support@sapphive.com)

---

## ⚖️ Legal Disclaimer
This is open-source software. Sapphive provides the official public network, but anyone is free to host their own controller and bridge sets using this image. All trademarks belong to their respective owners.
