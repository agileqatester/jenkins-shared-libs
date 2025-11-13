def call(Map cfg = [:]) {
    String imageRepo     = cfg.image ?: (params?.IMAGE_NAME ?: '')
    if (!imageRepo) {
        error "[dockerBuildPush] image repo is required (cfg.image or params.IMAGE_NAME)"
    }

    String tag           = cfg.tag ?: (params?.IMAGE_TAG ?: env.BUILD_NUMBER ?: 'latest')
    String dockerfile    = cfg.dockerfile ?: 'Dockerfile'
    String context       = cfg.context ?: '.'
    String credsId       = cfg.credentialsId ?: 'docker-hub-agileqa'
    boolean useBuildx    = (cfg.useBuildx != null) ? (cfg.useBuildx as boolean) : false
    boolean useBuildKit  = (cfg.useBuildKit != null) ? (cfg.useBuildKit as boolean) : true
    List proxyEnv        = (cfg.proxyEnv ?: []) as List          // ["HTTP_PROXY=...", "NO_PROXY=..."]
    List secretFiles     = (cfg.secretFiles ?: []) as List       // e.g., ['nuget.config']
    boolean allowHostNet = (cfg.allowHostNetwork != null) ? (cfg.allowHostNetwork as boolean) : true
    String builderName   = cfg.builderName ?: 'jxbuilder'

    // Extract proxy values from proxyEnv
    Map envMap = proxyEnv.collectEntries { e ->
        int i = e.indexOf('=')
        (i > 0) ? [(e.substring(0, i)) : e.substring(i + 1)] : [:]
    }
    String httpProxy  = (envMap['HTTP_PROXY'] ?: envMap['http_proxy'] ?: '').trim()
    String httpsProxy = (envMap['HTTPS_PROXY'] ?: envMap['https_proxy'] ?: httpProxy).trim()
    String noProxyRaw = (envMap['NO_PROXY']   ?: envMap['no_proxy']   ?: '').trim()
    // Keep NO_PROXY for Dockerfile build-args only; NOT for driver-opts (commas break k=v parsing)
    String noProxy    = noProxyRaw.replaceAll('\\s+', '')

    // Build args (transient for Dockerfile RUN steps)
    List<String> proxyArgs = []
    if (httpProxy)  { proxyArgs << "--build-arg" << "HTTP_PROXY=${httpProxy}" }
    if (httpsProxy) { proxyArgs << "--build-arg" << "HTTPS_PROXY=${httpsProxy}" }
    if (noProxy)    { proxyArgs << "--build-arg" << "NO_PROXY=${noProxy}" }

    // Secrets only when BuildKit is enabled
    List<String> secretFlags = []
    if (useBuildKit && secretFiles && !secretFiles.isEmpty()) {
        secretFlags = secretFiles.collect { f -> "--secret id=${f.replace('.', '_')},src=${f}" }
    }

    withCredentials([usernamePassword(credentialsId: credsId, usernameVariable: 'DOCKER_USER', passwordVariable: 'DOCKER_PASS')]) {
        withEnv((proxyEnv ?: []) + ["DOCKER_BUILDKIT=${useBuildKit ? '1' : '0'}"]) {

            // Login
            sh '''#!/bin/sh
set -eu
echo "$DOCKER_PASS" | docker login -u "$DOCKER_USER" --password-stdin >/dev/null
'''

            if (useBuildx) {
                // Only http/https proxy in driver-opts; DO NOT pass env.no_proxy here (commas break parsing)
                List<String> driverOptParts = []
                if (httpProxy)    driverOptParts << "--driver-opt 'env.http_proxy=${httpProxy}'"
                if (httpsProxy)   driverOptParts << "--driver-opt 'env.https_proxy=${httpsProxy}'"
                if (allowHostNet) driverOptParts << "--driver-opt network=host"
                String driverOptsStr = driverOptParts.join(' ')

                // Recreate named docker-container builder so options apply (idempotent)
                sh """#!/bin/sh
set -eu
(docker buildx ls | grep -q '^${builderName}[[:space:]]') && docker buildx rm ${builderName} >/dev/null 2>&1 || true
docker buildx create --name ${builderName} --driver docker-container \\
  ${driverOptsStr} \\
  --use >/dev/null
docker buildx inspect --bootstrap >/dev/null
echo "=== buildx ls ==="
docker buildx ls
"""

                String secretStr = (secretFlags ? secretFlags.join(' ') : '')
                String proxyStr  = proxyArgs.join(' ')
                String hostNet   = allowHostNet ? "--allow=network.host --network=host" : ""

                // Force the named builder
                sh """#!/bin/sh
set -eu
DOCKER_BUILDX_BUILDER=${builderName} \\
docker buildx build --builder ${builderName} --progress=plain --load \\
  ${hostNet} \\
  ${secretStr} \\
  ${proxyStr} \\
  -t ${imageRepo}:${tag} -f ${dockerfile} ${context}
"""
            } else {
                // Classic docker build; pulls depend on daemon proxy/DNS on the host
                String secretStr = (secretFlags ? secretFlags.join(' ') : '')
                String proxyStr  = proxyArgs.join(' ')
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

            // Tag/push latest if needed
            if (tag != 'latest') {
                sh """#!/bin/sh
set -eu
docker tag ${imageRepo}:${tag} ${imageRepo}:latest
docker push ${imageRepo}:latest
"""
            }

            // History check (red flag if any proxy strings leaked)
            sh """#!/bin/sh
set -eu
docker history ${imageRepo}:${tag} --no-trunc | tee history.txt >/dev/null
if grep -Eiq '(http_proxy|https_proxy|genproxy|amdocs)' history.txt; then
  echo 'ERROR: Proxy strings found in image history!' >&2
  rm -f history.txt
  exit 1
fi
rm -f history.txt
"""

            // Logout
            sh '''#!/bin/sh
set -eu
docker logout >/dev/null 2>&1 || true
'''
        }
    }
}