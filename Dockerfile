# syntax=docker/dockerfile:1.7
FROM mcr.microsoft.com/dotnet/sdk:8.0

USER root

# Do NOT set ENV for proxies.
# We will pass them via BuildKit secrets only when needed.

# Base tooling without persisting proxy configs
RUN --mount=type=secret,id=http_proxy \
    --mount=type=secret,id=https_proxy \
    --mount=type=secret,id=no_proxy \
    set -eux; \
    export http_proxy="$(cat /run/secrets/http_proxy || true)"; \
    export https_proxy="$(cat /run/secrets/https_proxy || true)"; \
    export no_proxy="$(cat /run/secrets/no_proxy || true)"; \
    apt-get update \
      -o Acquire::http::Proxy="$http_proxy" \
      -o Acquire::https::Proxy="$https_proxy"; \
    apt-get install -y --no-install-recommends ca-certificates curl gnupg; \
    apt-get install -y --no-install-recommends git make jq python3 python3-pip maven; \
    rm -rf /var/lib/apt/lists/*

# Node.js 20 via NodeSource (using secrets again)
RUN --mount=type=secret,id=http_proxy \
    --mount=type=secret,id=https_proxy \
    set -eux; \
    export http_proxy="$(cat /run/secrets/http_proxy || true)"; \
    export https_proxy="$(cat /run/secrets/https_proxy || true)"; \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -; \
    apt-get update \
      -o Acquire::http::Proxy="$http_proxy" \
      -o Acquire::https::Proxy="$https_proxy"; \
    apt-get install -y --no-install-recommends nodejs; \
    # If you want npm proxy config for future container runs, set it at runtime; don't bake it.
    rm -rf /var/lib/apt/lists/*

# Create Jenkins user
RUN useradd -m -s /bin/bash jenkins
USER jenkins
WORKDIR /home/jenkins

# Basic tool checks (no secrets required here)
RUN set -eux; \
    dotnet --info; \
    node -v; \
    npm -v; \
    python3 --version; \
    mvn -v; \
    make --version; \
    jq --version
