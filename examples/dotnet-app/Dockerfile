# syntax=docker/dockerfile:1.7

# ---------- Build stage ----------
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy project file first (better layer caching)
COPY examples/dotnet-app/DotnetApp.csproj examples/dotnet-app/
RUN dotnet restore examples/dotnet-app/DotnetApp.csproj

# Copy the rest of the repo and publish
COPY . .
RUN dotnet publish examples/dotnet-app/DotnetApp.csproj -c Release -o /app/publish --no-restore

# ---------- Runtime stage ----------
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
COPY --from=build /app/publish ./

# If this is a web app, expose 80; if it's console, you can skip EXPOSE.
EXPOSE 80

# IMPORTANT: 'DotnetApp.dll' must match your project assembly name.
ENTRYPOINT ["dotnet", "DotnetApp.dll"]