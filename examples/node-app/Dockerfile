# --- builder ---
FROM node:20-alpine AS build
WORKDIR /app

# Faster dependency layer with cache
COPY package*.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --no-audit --no-fund

# Copy sources and build
COPY . .
RUN npm run build

# Strip dev deps for runtime
RUN npm prune --omit=dev

# --- runtime (alpine debug-friendly) ---
FROM node:20-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
USER node
EXPOSE 80
CMD ["node", "dist/server.js"]