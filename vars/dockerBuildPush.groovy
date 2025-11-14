def call(Map cfg = [:]) {
    try {
        String imageRepo     = (cfg.image ?: (params?.DOCKERHUB_REPO ?: '')).trim()
        if (!imageRepo) {
            error "[dockerBuildPush] image repo is required (cfg.image or params.DOCKERHUB_REPO)"
        }

        String tag           = (cfg.tag ?: (params?.IMAGE_TAG ?: env.BUILD_NUMBER ?: 'latest')).trim()
        String dockerfile    = cfg.dockerfile ?: 'Dockerfile'
        String context       = cfg.context ?: '.'
        String credsId       = cfg.credentialsId ?: 'docker-hub-agileqa'
        boolean useBuildx    = (cfg.useBuildx != null) ? (cfg.useBuildx as boolean) : false
        boolean useBuildKit  = (cfg.useBuildKit != null) ? (cfg.useBuildKit as boolean) : true
        List proxyEnv        = (cfg.proxyEnv ?: []) as List         // ["HTTP_PROXY=...", "NO_PROXY=..."]
        List secretFiles     = (cfg.secretFiles ?: []) as List      // e.g., ['nuget.config']
        boolean allowHostNet = (cfg.allowHostNetwork != null) ? (cfg.allowHostNetwork as boolean) : true
        String builderName   = (cfg.builderName ?: 'jxbuilder').trim()

        // Extract proxy values from proxyEnv ["K=V", ...]
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
                    // Driver opts: pass only HTTP/HTTPS proxy; do NOT pass env.no_proxy (commas break k=v)
                    List<String> driverOptParts = []
                    if (httpProxy)  driverOptParts << "--driver-opt" << "env.http_proxy=${httpProxy}"
                    if (httpsProxy) driverOptParts << "--driver-opt" << "env.https_proxy=${httpsProxy}"
                    // Helpful for corp DNS: let buildkitd use host networking
                    driverOptParts << "--driver-opt" << "network=host"
                    String driverOptsStr = driverOptParts.join(' ')

                    sh '''#!/bin/sh
                        set -eu
                        (docker buildx ls | grep -q '^${builderName}[[:space:]]') && docker buildx rm ${builderName} >/dev/null 2>&1 || true
                        docker buildx create --name ${builderName} --driver docker-container \\
                          ${driverOptsStr} \\
                          --use >/dev/null
                        docker buildx inspect --bootstrap >/dev/null
                        echo "=== buildx ls ==="
                        docker buildx ls
                    '''

                    String secretStr = (secretFlags ? secretFlags.join(' ') : '')
                    String proxyStr  = proxyArgs.join(' ')
                    String hostNet   = allowHostNet ? "--allow=network.host --network=host" : ""

                    sh '''#!/bin/sh
                        set -eu
                        DOCKER_BUILDX_BUILDER=${builderName} \\
                        docker buildx build --builder ${builderName} --progress=plain --load \\
                          ${hostNet} \\
                          ${secretStr} \\
                          ${proxyStr} \\
                          -t ${imageRepo}:${tag} -f ${dockerfile} ${context}
                    '''
                } else {
                    // Classic docker build (daemon must be proxy/DNS configured or pre-pull the base image)
                    String secretStr = (secretFlags ? secretFlags.join(' ') : '')
                    String proxyStr  = proxyArgs.join(' ')
                    sh '''#!/bin/sh
                        set -eu
                        echo "[WARN] Classic 'docker build' uses the Docker daemon for pulls. If the daemon isn't proxy/DNS-configured, pulls may fail."
                        docker build --progress=plain \\
                          ${secretStr} \\
                          ${proxyStr} \\
                          -t ${imageRepo}:${tag} -f ${dockerfile} ${context}
                    '''
                }

                // Push tag
                sh '''#!/bin/sh
                    set -eu
                    docker push ${imageRepo}:${tag}
                '''

                // Tag/push latest if needed
                if (tag != 'latest') {
                    sh '''#!/bin/sh
                        set -eu
                        docker tag ${imageRepo}:${tag} ${imageRepo}:latest
                        docker push ${imageRepo}:latest
                    '''
                }

                // History check (red flag if any proxy strings leaked)
                sh '''#!/bin/sh
                    set -eu
                    docker history ${imageRepo}:${tag} --no-trunc | tee history.txt >/dev/null
                    if grep -Eiq '(http_proxy|https_proxy|genproxy|amdocs)' history.txt; then
                      echo 'ERROR: Proxy strings found in image history!' >&2
                      rm -f history.txt
                      exit 1
                    fi
                    rm -f history.txt
                '''
            } // withEnv
        } // withCredentials

        return [image: imageRepo, tag: tag]

    } catch (Exception e) {
        echo "[ERROR] dockerBuildPush failed: ${e.message}"
        currentBuild.result = 'FAILURE'
        throw e

    } finally {
        // Logout is safe even if not logged in
        sh '''#!/bin/sh
            set -eu
            docker logout >/dev/null 2>&1 || true
        '''
    }
}