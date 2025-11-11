def call(Map cfg = [:]) {
  String sdk = cfg.sdk ?: (params.DOTNET_SDK ?: '8.0')
  String config = cfg.configuration ?: (params.CONFIGURATION ?: 'Release')
  String project = cfg.project ?: (params.PROJECT ?: '')
  String sln = cfg.solution ?: (params.SOLUTION ?: '')

  withToolImage("mcr.microsoft.com/dotnet/sdk:${sdk}", "-e DOTNET_CLI_TELEMETRY_OPTOUT=1") {
    sh "dotnet --info"
    if (sln?.trim())   { sh "dotnet restore '${sln}'"   ; sh "dotnet build '${sln}' -c ${config} --no-restore" }
    else if (project)  { sh "dotnet restore '${project}'"; sh "dotnet build '${project}' -c ${config} --no-restore" }
    else               { sh "dotnet restore"             ; sh "dotnet build -c ${config} --no-restore" }
  }
}