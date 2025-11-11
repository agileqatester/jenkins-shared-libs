# syntax=docker/dockerfile:1.7

############################
# 1) Build & publish
############################
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy project file first (cache-friendly)
COPY examples/dotnet-app/DotnetApp.csproj ./DotnetApp.csproj

# Restore with BuildKit secret (NuGet config) and a shared cache for packages
RUN --mount=type=secret,id=nuget_config \
    --mount=type=cache,id=nuget,target=/root/.nuget/packages,sharing=locked \
    sh -c 'mkdir -p /root/.nuget/NuGet && \
           cp /run/secrets/nuget_config /root/.nuget/NuGet/NuGet.Config && \
           dotnet restore DotnetApp.csproj --nologo'

# Copy the rest and publish
COPY examples/dotnet-app/ ./
RUN --mount=type=cache,id=nuget,target=/root/.nuget/packages,sharing=locked \
    dotnet publish DotnetApp.csproj -c Release -o /app/publish --nologo

############################
# 2) Runtime (non-root by default on dotnet/aspnet:8.0)
############################
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app

# Tell Kestrel to listen on 80 inside the container and EXPOSE it
ENV ASPNETCORE_HTTP_PORTS=80
EXPOSE 80

# Copy published output
COPY --from=build /app/publish/ ./

# Optional: a simple healthcheck (uses whichever port we expose)
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD wget -qO- http://127.0.0.1:80/health || exit 1

# The base image runs as a non-root user by default on .NET 8
ENTRYPOINT ["dotnet", "DotnetApp.dll"]