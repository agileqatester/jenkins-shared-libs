def call(Map cfg = [:]) {
    String image      = cfg.image ?: selectAgent('dotnet')
    String dockerArgs = cfg.dockerArgs ?: ''
    List envVars      = cfg.envVars ?: []
    String config     = cfg.configuration ?: 'Release'
    String project    = cfg.project ?: ''
    String sln        = cfg.solution ?: ''
    String workDir    = cfg.workDir ?: '.'

    withEnv(envVars) {
        withToolImage(image, dockerArgs) {
            dir(workDir) {
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
}