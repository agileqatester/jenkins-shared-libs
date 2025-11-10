# syntax=docker/dockerfile:1.7
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build

# --- Accept proxies from build args and set as ENV (used by dotnet restore) ---
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

# Copy only the project file first for better layer caching
COPY examples/dotnet-app/DotnetApp.csproj examples/dotnet-app/

# Restore packages (use BuildKit cache for NuGet)
RUN --mount=type=cache,target=/root/.nuget/packages \
    dotnet restore examples/dotnet-app/DotnetApp.csproj

# Copy the rest of the source
COPY . .

# Build/publish (cache NuGet again for repeatability)
RUN --mount=type=cache,target=/root/.nuget/packages \
    dotnet publish examples/dotnet-app/DotnetApp.csproj -c Release -o /app/publish

# For single-stage image (simple demo):
WORKDIR /app/publish
ENTRYPOINT ["dotnet","DotnetApp.dll"]

# If you prefer a multi-stage runtime image instead, replace the last 3 lines with:
# FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
# WORKDIR /app
# COPY --from=build /app/publish .
# ENTRYPOINT ["dotnet","DotnetApp.dll"]