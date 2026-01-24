# Stage 1: Build
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

# Stage 2: Production dependencies
FROM node:20-alpine AS prod-deps
WORKDIR /app
COPY package*.json ./
# Install production dependencies and manually prune junk files (safer than binary tools)
RUN npm install --omit=dev && \
    find node_modules -type f -name "*.d.ts" -delete && \
    find node_modules -type f -name "*.map" -delete && \
    find node_modules -type f -name "*.md" -delete && \
    find node_modules -type d -name "test" -exec rm -rf {} + && \
    find node_modules -type d -name "tests" -exec rm -rf {} +

# Stage 3: Final Production Image
FROM node:20-alpine

USER root

# Install Tor, bash, gettext (envsubst), curl, su-exec
# Alpine's 'tor' package creates the 'tor' user automatically.
RUN apk add --no-cache \
    tor \
    bash \
    gettext \
    curl \
    su-exec \
    ca-certificates

WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/src/assets ./dist/assets
COPY --from=prod-deps /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh && \
    sed -i 's/\r$//' /usr/local/bin/entrypoint.sh

# Re-ensure Tor directory permissions for the alpine 'tor' user
RUN mkdir -p /var/lib/tor && chown -R tor:tor /var/lib/tor && chmod 700 /var/lib/tor && \
    chown -R node:node /app

# Default ENV
ENV PORT=3000
ENV LOG_LEVEL=info
ENV BRIDGE_MODE=false
ENV MASTER=false

EXPOSE 3000

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
