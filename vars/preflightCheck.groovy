def call(Map cfg = [:]) {
    String image      = cfg.image
    String dockerArgs = cfg.dockerArgs ?: ''
    String workDir    = cfg.workDir ?: '.'
    boolean inside    = (cfg.inside == null) ? true : cfg.inside  // default true

    // Simple redactor for logs (keeps host:port, hides creds if any)
    def redact = { String v ->
        if (!v) return ''
        return v.replaceAll(/(https?:\/\/)([^:@\/]+:)?([^@\/]+@)?/, '$1****:****@')
    }

    def script = '''#!/bin/sh
                set -eu
                echo "=== Preflight ==="
                whoami; id
                echo "Workspace: \$(pwd)"
                echo "Listing project directory:"
                ls -la

                echo "Checking Docker client:"
                docker version || true
                echo "Checking Buildx:"
                docker buildx version || true

                # Print proxy presence (redacted)
                if [ -n "\${HTTP_PROXY:-}" ] || [ -n "\${http_proxy:-}" ]; then
                echo "HTTP_PROXY set: \$(echo '${redact(env.HTTP_PROXY ?: env.http_proxy ?: "")}')"
                fi
                if [ -n "\${HTTPS_PROXY:-}" ] || [ -n "\${https_proxy:-}" ]; then
                echo "HTTPS_PROXY set: \$(echo '${redact(env.HTTPS_PROXY ?: env.https_proxy ?: "")}')"
                fi
                if [ -n "\${NO_PROXY:-}" ] || [ -n "\${no_proxy:-}" ]; then
                echo "NO_PROXY set"
                fi

                # DNS quick checks without leaking secrets
                echo "Resolver test:"
                getent hosts auth.docker.io   2>/dev/null || true
                getent hosts registry.npmjs.org 2>/dev/null || true
                getent hosts api.nuget.org    2>/dev/null || true

                # HTTP reachability via curl (uses env proxy if set)
                echo "Checking Docker Hub auth endpoint:"
                curl -sS -I --max-time 20 https://auth.docker.io/token | head -n1 || true

                echo "Checking NuGet connectivity:"
                curl -sS -I --max-time 20 https://api.nuget.org/v3/index.json | head -n1 || true

                echo "Checking Node:"
                node --version || true
                npm --version || true
                echo "Checking npm registry:"
                curl -sS -I --max-time 20 https://registry.npmjs.org | head -n1 || true

                echo "=== Preflight OK (or diagnostics above) ==="
                '''

    if (inside && image) {
        docker.image(image).inside(dockerArgs) { dir(workDir) { sh script } }
    } else {
        dir(workDir) { sh script }
    }
}