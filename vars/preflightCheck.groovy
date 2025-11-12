def call(Map cfg = [:]) {
    String image      = cfg.image
    String dockerArgs = cfg.dockerArgs ?: ''
    String workDir    = cfg.workDir ?: '.'
    boolean inside    = (cfg.inside == null) ? true : cfg.inside  // default true

    def script = '''
      set -eux
      echo "=== Preflight ==="
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
      echo "Checking Node:"
      node --version || true
      npm --version || true
      echo "Checking npm registry:"
      curl -I --max-time 20 https://registry.npmjs.org || true
      echo "=== Preflight OK ==="
    '''

    if (inside && image) {
        docker.image(image).inside(dockerArgs) { dir(workDir) { sh script } }
    } else {
        dir(workDir) { sh script }
    }
}