def call(Map cfg = [:]) {
    String image      = cfg.image ?: error("[preflightCheck] 'image' required")
    String dockerArgs = cfg.dockerArgs ?: ''
    String workDir    = cfg.workDir ?: '.'

    docker.image(image).inside(dockerArgs) {
        dir(workDir) {
            sh """
              set -eux
              echo '=== Preflight ==='
              whoami; id
              echo "Workspace: $(pwd)"
              echo "Listing project directory:"
              ls -la
              echo "Checking Docker client:"
              docker version || true
              echo "Checking Buildx:"
              docker buildx version || true
              echo "Checking .NET SDK:"
              dotnet --info || true
              echo "Checking NuGet connectivity:"
              curl -I --max-time 20 https://api.nuget.org/v3/index.json || true
              echo '=== Preflight OK ==='
            """
        }
    }
}