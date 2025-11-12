# syntax=docker/dockerfile:1.5

FROM node:20-alpine AS base
WORKDIR /app

# Set environment for production
ENV NODE_ENV=production \
    PORT=80

# Install dependencies first for better layer caching
COPY package*.json ./
# Prefer reproducible installs if lockfile exists
RUN --mount=type=cache,target=/root/.npm \
    if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev; fi

# Copy the rest of the app
COPY . .

# Ensure your server.js respects PORT (process.env.PORT || 80)
EXPOSE 80
CMD ["node", "server.js"]