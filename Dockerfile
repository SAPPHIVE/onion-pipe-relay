# Build stage
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

# Production stage
FROM sapphive/tor:latest

USER root
# Install Node.js and dependencies for the relay
RUN apt update && apt install -y curl ca-certificates gnupg && \
    mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list && \
    apt update && apt install -y nodejs gettext procps && \
    apt clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/src/assets ./dist/assets
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Re-ensure Tor directory permissions for the debian-tor user
RUN mkdir -p /var/lib/tor && chown -R debian-tor:debian-tor /var/lib/tor && chmod 700 /var/lib/tor

# Default ENV
ENV PORT=3000
ENV LOG_LEVEL=info
ENV BRIDGE_MODE=false
ENV MASTER=false

EXPOSE 3000

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
