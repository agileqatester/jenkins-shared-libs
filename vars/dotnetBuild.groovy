def call(Map cfg = [:]) {
    String image      = cfg.image ?: selectAgent('dotnet') // default to your multi-tool image
    String dockerArgs = cfg.dockerArgs ?: ''
    List envVars      = cfg.envVars ?: [
        "DOTNET_CLI_TELEMETRY_OPTOUT=1",
        "DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1",
        "DOTNET_CLI_HOME=/home/jenkins",
        "HOME=/home/jenkins"
    ]
    String config     = cfg.configuration ?: (params.CONFIGURATION ?: 'Release')
    String project    = cfg.project ?: (params.PROJECT ?: '')
    String sln        = cfg.solution ?: (params.SOLUTION ?: '')

    withEnv(envVars) {
        withToolImage(image, dockerArgs) {
            sh "dotnet --info"
            if (sln?.trim()) {
                sh "dotnet restore '${sln}'"
                sh "dotnet build '${sln}' -c ${config} --no-restore"
            } else if (project) {
                sh "dotnet restore '${project}'"
                sh "dotnet build '${project}' -c ${config} --no-restore"
            } else {
                sh "dotnet restore"
                sh "dotnet build -c ${config} --no-restore"
            }
        }
    }
}