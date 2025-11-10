# syntax=docker/dockerfile:1.7
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build

# Proxy args (as you had)
ARG http_proxy
ARG https_proxy
ARG no_proxy
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY
ENV http_proxy=${http_proxy} \
    https_proxy=${https_proxy} \
    no_proxy=${no_proxy} \
    HTTP_PROXY=${HTTP_PROXY} \
    HTTPS_PROXY=${HTTPS_PROXY} \
    NO_PROXY=${NO_PROXY}

WORKDIR /src

# Copy csproj only (improves caching)
COPY examples/dotnet-app/DotnetApp.csproj examples/dotnet-app/

# Restore
RUN --mount=type=cache,target=/root/.nuget/packages \
    dotnet restore examples/dotnet-app/DotnetApp.csproj

# Copy the rest
COPY . .

# Publish
RUN --mount=type=cache,target=/root/.nuget/packages \
    dotnet publish examples/dotnet-app/DotnetApp.csproj -c Release -o /app/publish

# Runtime (single-stage for simplicity)
WORKDIR /app/publish

# Listen on port 80 inside the container
ENV ASPNETCORE_URLS=http://+:80
EXPOSE 80

ENTRYPOINT ["dotnet","DotnetApp.dll"]