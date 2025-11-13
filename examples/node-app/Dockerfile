# --- builder ---
FROM node:20-alpine AS build
WORKDIR /app

# Accept transient proxy settings (do NOT ENV them)
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

# Safer default shell for RUNs (no bash assumption)
SHELL ["/bin/sh", "-ec"]

# Dependencies layer (cacheable)
COPY package*.json ./
RUN export HTTP_PROXY="${HTTP_PROXY}" HTTPS_PROXY="${HTTPS_PROXY}" NO_PROXY="${NO_PROXY}"; \
    npm ci --no-audit --no-fund

# Copy sources and build
COPY . .
RUN npm run build

# Strip dev deps for smaller runtime
RUN npm prune --omit=dev

# --- runtime ---
FROM node:20-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist

USER node
EXPOSE 80
CMD ["node", "dist/server.js"]