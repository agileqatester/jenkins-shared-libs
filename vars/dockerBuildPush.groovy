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
  // Sanitize: remove whitespace from no_proxy (spaces break k=v)
  def noProxySan = (noProxy ?: '').replaceAll('\\s+', '')

  // Build driver opts with proper quoting so each k=v stays a single token
  def driverOptsParts = []
  if (httpProxy)  driverOptsParts << "--driver-opt 'env.http_proxy=${httpProxy}'"
  if (httpsProxy) driverOptsParts << "--driver-opt 'env.https_proxy=${httpsProxy}'"
  if (noProxySan) driverOptsParts << "--driver-opt 'env.no_proxy=${noProxySan}'"
  // Strongly recommended in corp/VPN: let buildkitd use host network/DNS
  driverOptsParts << "--driver-opt network=host"

  def driverOptsStr = driverOptsParts.join(' ')

  sh """#!/bin/sh
        set -eu
        # Recreate named docker-container builder with proxy opts (idempotent)
        (docker buildx ls | grep -q '^jxbuilder') && docker buildx rm jxbuilder >/dev/null 2>&1 || true
        docker buildx create --name jxbuilder --driver docker-container \\
          ${driverOptsStr} \\
          --use >/dev/null
        docker buildx inspect --bootstrap >/dev/null
        echo "=== buildx ls ==="
        docker buildx ls
        """

  def secretStr = (secretFlags ? secretFlags.join(' ') : '')
  def proxyStr  = proxyArgs.join(' ')

  // Force the named builder
  sh """#!/bin/sh
        set -eu
        DOCKER_BUILDX_BUILDER=jxbuilder \\
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
            echo "[WARN] Classic 'docker build' uses the Docker daemon for pulls. If the daemon isn't proxy/DNS-configured, pulls may fail."
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