# syntax=docker/dockerfile:1.7

# ----- Build stage -----
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy project file and restore (cache-friendly)
COPY examples/dotnet-app/DotnetApp.csproj examples/dotnet-app/
RUN dotnet restore examples/dotnet-app/DotnetApp.csproj

# Copy the rest and publish
COPY . .
RUN dotnet publish examples/dotnet-app/DotnetApp.csproj -c Release -o /app/publish --no-restore

# ----- Runtime stage -----
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
COPY --from=build /app/publish ./

# If it's a web app, keep port 80. For console app, remove EXPOSE and adjust run command in Jenkins.
EXPOSE 80
ENTRYPOINT ["dotnet", "DotnetApp.dll"]