# syntax=docker/dockerfile:1.7
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy project file first (cache-friendly)
COPY examples/dotnet-app/DotnetApp.csproj ./DotnetApp.csproj

# Copy the secret from /run/secrets into NuGet path in the same RUN
RUN --mount=type=secret,id=nuget_config \
    --mount=type=cache,id=nuget,target=/root/.nuget/packages,sharing=locked \
    sh -c 'mkdir -p /root/.nuget/NuGet && \
           cp /run/secrets/nuget_config /root/.nuget/NuGet/NuGet.Config && \
           dotnet restore DotnetApp.csproj --nologo'

# Copy the rest and publish
COPY examples/dotnet-app/ ./
RUN --mount=type=cache,id=nuget,target=/root/.nuget/packages,sharing=locked \
    dotnet publish DotnetApp.csproj -c Release -o /app/publish --nologo
