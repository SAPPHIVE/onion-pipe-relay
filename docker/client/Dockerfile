FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npx tsc

FROM node:20-alpine
WORKDIR /app
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
RUN mkdir /keys && chown appuser:appgroup /keys
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY package*.json ./

USER appuser
ENV NODE_ENV=production
ENV PRIVATE_KEY_PATH=/keys/private.key

CMD ["node", "dist/client/index.js"]
