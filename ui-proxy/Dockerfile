# Correlic UI Proxy Dockerfile
# Handles mTLS between browser and backend (browsers can't do client certs)
# LOCAL USE ONLY - do not expose publicly

FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# Copy source
COPY index.js ./

# Use existing non-root node user
RUN mkdir -p /etc/correlic/certs && chown -R node:node /etc/correlic

USER node

# Proxy port (localhost only)
EXPOSE 8788

ENV PORT=8788

CMD ["node", "index.js"]
