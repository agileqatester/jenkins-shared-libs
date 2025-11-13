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

    // Extract proxy values from proxyEnv (if present)
    // We don't echo these values; Jenkins masks credentials but let's be cautious.
    def envMap = proxyEnv.collectEntries { e ->
        def idx = e.indexOf('=')
        idx > 0 ? [(e.substring(0, idx)) : e.substring(idx + 1)] : [:]
    }
    String httpProxy = (envMap['HTTP_PROXY'] ?: envMap['http_proxy'] ?: '').trim()
    String httpsProxy = (envMap['HTTPS_PROXY'] ?: envMap['https_proxy'] ?: httpProxy).trim()
    String noProxy = (envMap['NO_PROXY'] ?: envMap['no_proxy'] ?: '').trim()

    // Build args for proxies (transient only)
    List<String> proxyArgs = []
    if (httpProxy)  proxyArgs << "--build-arg" << "HTTP_PROXY=${httpProxy}"
    if (httpsProxy) proxyArgs << "--build-arg" << "HTTPS_PROXY=${httpsProxy}"
    if (noProxy)    proxyArgs << "--build-arg" << "NO_PROXY=${noProxy}"

    // Secrets flags (only when BuildKit is active)
    List<String> secretFlags = []
    if (useBuildKit && secretFiles && secretFiles.size() > 0) {
        // Convert: foo.bar => id=foo_bar
        secretFlags = secretFiles.collect { f ->
            def id = f.replace('.', '_')
            "--secret id=${id},src=${f}"
        }
    }

    withCredentials([usernamePassword(credentialsId: credsId, usernameVariable: 'DOCKER_USER', passwordVariable: 'DOCKER_PASS')]) {
        // NOTE: we only inject DOCKER_BUILDKIT (masking is not needed; it's not secret)
        withEnv((proxyEnv ?: []) + ["DOCKER_BUILDKIT=${useBuildKit ? '1' : '0'}"]) {
            // Login
            sh '''#!/bin/sh
                    set -eu
                    echo "$DOCKER_PASS" | docker login -u "$DOCKER_USER" --password-stdin >/dev/null
                    '''
                                if (useBuildx) {
                                    // Buildx path (BuildKit is inherently on)
                                    // Build with --load so we can 'docker push' afterwards (or use --push directly if you prefer)
                                    def secretStr = (secretFlags ? secretFlags.join(' ') : '')
                                    def proxyStr  = proxyArgs.join(' ')
                                    sh """#!/bin/sh
                                            set -eu
                                            docker buildx create --use --name jxbuilder >/dev/null 2>&1 || true
                                            docker buildx inspect --bootstrap >/dev/null 2>&1 || true
                                            docker buildx build --progress=plain --load \\
                                            ${secretStr} \\
                                            ${proxyStr} \\
                                            -t ${imageRepo}:${tag} -f ${dockerfile} ${context}
                                            """
            } else {
                // Classic docker build; BuildKit optional via DOCKER_BUILDKIT=1
                def secretStr = (secretFlags ? secretFlags.join(' ') : '')
                def proxyStr  = proxyArgs.join(' ')
                sh """#!/bin/sh
                        set -eu
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