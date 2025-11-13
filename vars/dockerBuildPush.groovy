def call(Map cfg = [:]) {
    String imageRepo     = cfg.image ?: (params?.IMAGE_NAME ?: '')
    if (!imageRepo) {
        error "[dockerBuildPush] image repo is required (cfg.image or params.IMAGE_NAME)"
    }

    String tag           = cfg.tag ?: (params?.IMAGE_TAG ?: env.BUILD_NUMBER ?: 'latest')
    String dockerfile    = cfg.dockerfile ?: 'Dockerfile'
    String context       = cfg.context ?: '.'
    String credsId       = cfg.credentialsId ?: 'docker-hub-agileqa'
    boolean useBuildx    = (cfg.useBuildx != null) ? cfg.useBuildx as boolean : false
    boolean useBuildKit  = (cfg.useBuildKit != null) ? cfg.useBuildKit as boolean : true
    List proxyEnv        = (cfg.proxyEnv ?: []) as List         // e.g., ["HTTP_PROXY=...", "NO_PROXY=..."]
    List secretFiles     = (cfg.secretFiles ?: []) as List       // e.g., ['nuget.config']

// Extract proxy values from proxyEnv list
def envMap = proxyEnv.collectEntries { e ->
    def i = e.indexOf('=')
    i > 0 ? [(e.substring(0, i)) : e.substring(i + 1)] : [:]
}
String httpProxy  = (envMap['HTTP_PROXY'] ?: envMap['http_proxy'] ?: '').trim()
String httpsProxy = (envMap['HTTPS_PROXY'] ?: envMap['https_proxy'] ?: httpProxy).trim()
String noProxy    = (envMap['NO_PROXY']   ?: envMap['no_proxy']   ?: '').trim()

// Transient build-args for Dockerfile RUN steps
List<String> proxyArgs = []
if (httpProxy)  proxyArgs << "--build-arg" << "HTTP_PROXY=${httpProxy}"
if (httpsProxy) proxyArgs << "--build-arg" << "HTTPS_PROXY=${httpsProxy}"
if (noProxy)    proxyArgs << "--build-arg" << "NO_PROXY=${noProxy}"

// Secret flags only when BuildKit is on
List<String> secretFlags = []
if (useBuildKit && secretFiles && secretFiles.size() > 0) {
    secretFlags = secretFiles.collect { f -> "--secret id=${f.replace('.','_')},src=${f}" }
}

withCredentials([usernamePassword(credentialsId: credsId, usernameVariable: 'DOCKER_USER', passwordVariable: 'DOCKER_PASS')]) {
  withEnv((proxyEnv ?: []) + ["DOCKER_BUILDKIT=${useBuildKit ? '1' : '0'}"]) {

    sh '''#!/bin/sh
        set -eu
        echo "$DOCKER_PASS" | docker login -u "$DOCKER_USER" --password-stdin >/dev/null
        '''

if (useBuildx) {
  // Configure driver options (proxy + optional host networking for corp DNS)
  def driverOpts = []
  if (httpProxy)  driverOpts << "env.http_proxy=${httpProxy}"
  if (httpsProxy) driverOpts << "env.https_proxy=${httpsProxy}"
  if (noProxy)    driverOpts << "env.no_proxy=${noProxy}"
  // Strongly recommended in corp/VPN: let buildkitd use host’s DNS
  driverOpts << "network=host"

  sh """#!/bin/sh
        set -eu
        # Create or update a docker-container builder named jxbuilder
        (docker buildx ls | grep -q '^jxbuilder') || docker buildx create --name jxbuilder --driver docker-container
        # Apply driver opts (recreate node if needed)
        docker buildx rm jxbuilder >/dev/null 2>&1 || true
        docker buildx create --name jxbuilder --driver docker-container \\
          ${driverOpts.collect { "--driver-opt ${it}" }.join(' ')} \\
          --use >/dev/null
        docker buildx inspect --bootstrap >/dev/null
        docker buildx ls
        """

  def secretStr = (secretFlags ? secretFlags.join(' ') : '')
  def proxyStr  = proxyArgs.join(' ')

  // Use the named builder explicitly
  sh """#!/bin/sh
        set -eu
        docker buildx build --builder jxbuilder --progress=plain --load \\
          ${secretStr} \\
          ${proxyStr} \\
          -t ${imageRepo}:${tag} -f ${dockerfile} ${context}
        """
        } else {
          def secretStr = (secretFlags ? secretFlags.join(' ') : '')
          def proxyStr  = proxyArgs.join(' ')
          sh """#!/bin/sh
                set -eu
                echo "[WARN] Classic 'docker build' uses the Docker daemon for pulls. If the daemon is not proxy-configured, pulls may fail."
                docker build --progress=plain \\
                  ${secretStr} \\
                  ${proxyStr} \\
                  -t ${imageRepo}:${tag} -f ${dockerfile} ${context}
                """
          }


            // Push tag
            sh """#!/bin/sh
                    set -eu
                    docker push ${imageRepo}:${tag}
                    """

            // Maintain 'latest' alongside specific tag (if tag != latest)
            if (tag != 'latest') {
                sh """#!/bin/sh
                        set -eu
                        docker tag ${imageRepo}:${tag} ${imageRepo}:latest
                        docker push ${imageRepo}:latest
                        """
            }

            // History check for any accidental proxy leakage
            // (No proxy strings should appear because we never ENV them and avoid echoing)
            sh """#!/bin/sh
                    set -eu
                    docker history ${imageRepo}:${tag} --no-trunc | tee history.txt >/dev/null
                    # Look for obvious proxy tokens
                    if grep -Eiq '(http_proxy|https_proxy|genproxy|amdocs)' history.txt; then
                    echo 'ERROR: Proxy strings found in image history!' >&2
                    rm -f history.txt
                    exit 1
                    fi
                    rm -f history.txt
                    """

            // Logout (best-effort)
            sh '''#!/bin/sh
                set -eu
                docker logout >/dev/null 2>&1 || true
                '''
        }
  }
}