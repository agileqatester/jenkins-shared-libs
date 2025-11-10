# syntax=docker/dockerfile:1.7
FROM mcr.microsoft.com/dotnet/sdk:8.0

ARG DOCKER_GID=991
USER root

# Base tooling
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

# Install Docker CLI (client only)
RUN --mount=type=secret,id=http_proxy \
    --mount=type=secret,id=https_proxy \
    set -eux; \
    export http_proxy="$(cat /run/secrets/http_proxy || true)"; \
    export https_proxy="$(cat /run/secrets/https_proxy || true)"; \
    install -m 0755 -d /etc/apt/keyrings; \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg; \
    chmod a+r /etc/apt/keyrings/docker.gpg; \
    . /etc/os-release; \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $VERSION_CODENAME stable" > /etc/apt/sources.list.d/docker.list; \
    apt-get update \
      -o Acquire::http::Proxy="$http_proxy" \
      -o Acquire::https::Proxy="$https_proxy"; \
    apt-get install -y --no-install-recommends docker-ce-cli; \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Node.js 20 (as you had)
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
    rm -rf /var/lib/apt/lists/*

# Create jenkins user + add to socket group (GID must match host socket GID)
RUN set -eux; \
    groupadd -g "${DOCKER_GID}" docker || true; \
    useradd -m -s /bin/bash jenkins || true; \
    usermod -aG docker jenkins

USER jenkins
WORKDIR /home/jenkins

# Sanity checks
RUN set -eux; \
    dotnet --info; \
    node -v; \
    npm -v; \
    python3 --version; \
    mvn -v; \
    make --version; \
    jq --version