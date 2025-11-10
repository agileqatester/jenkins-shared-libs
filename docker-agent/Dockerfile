# syntax=docker/dockerfile:1.7
FROM mcr.microsoft.com/dotnet/sdk:8.0

# --- IDs (adjust DOCKER_GID if your host's /var/run/docker.sock group differs) ---
ARG JENKINS_UID=1000
ARG JENKINS_GID=1000
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

# Install Docker CLI (+ Buildx and Compose plugins)
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
    # Core CLI
    apt-get install -y --no-install-recommends docker-ce-cli \
    # Buildx & Compose plugins (fixes your error and gives compose v2)
                         docker-buildx-plugin \
                         docker-compose-plugin; \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Node.js 20
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

# --- Users & groups ---
RUN set -eux; \
    groupadd -g "${JENKINS_GID}" jenkins || true; \
    useradd -m -s /bin/bash -u "${JENKINS_UID}" -g "${JENKINS_GID}" jenkins || true; \
    groupadd -g "${DOCKER_GID}" docker || true; \
    usermod -aG "${DOCKER_GID}" jenkins; \
    mkdir -p /home/jenkins && chown -R "${JENKINS_UID}:${JENKINS_GID}" /home/jenkins

# --- Sensible defaults for .NET CLI inside CI ---
ENV HOME=/home/jenkins \
    DOTNET_CLI_HOME=/home/jenkins \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    NUGET_PACKAGES=/home/jenkins/.nuget/packages

USER jenkins
WORKDIR /home/jenkins

# Sanity checks (informational only)
RUN set -eux; \
    id; \
    dotnet --info; \
    node -v; \
    npm -v; \
    python3 --version; \
    mvn -v; \
    make --version; \
    jq --version; \
    which docker || true; \
    docker --version || true; \
    docker buildx version || true; \
    docker compose version || true