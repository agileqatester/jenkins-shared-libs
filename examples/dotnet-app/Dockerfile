# syntax=docker/dockerfile:1.7
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy project file first (cache-friendly)
COPY examples/dotnet-app/DotnetApp.csproj ./DotnetApp.csproj

# Use BuildKit secret mount for NuGet proxy config (never persisted in layers)
RUN --mount=type=secret,id=nuget_config,target=/root/.nuget/NuGet/NuGet.Config \
    --mount=type=cache,id=nuget,target=/root/.nuget/packages,sharing=locked \
    dotnet restore DotnetApp.csproj --nologo

# Copy the rest and publish
COPY examples/dotnet-app/ ./
RUN --mount=type=cache,id=nuget,target=/root/.nuget/packages,sharing=locked \
    dotnet publish DotnetApp.csproj -c Release -o /app/publish --nologo

