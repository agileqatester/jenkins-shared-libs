def call(Map cfg = [:]) {
    String imageRepo     = cfg.image ?: params.IMAGE_NAME
    String tag           = cfg.tag ?: (params.IMAGE_TAG ?: env.BUILD_NUMBER)
    String dockerfile    = cfg.dockerfile ?: 'Dockerfile'
    String context       = cfg.context ?: '.'
    String credsId       = cfg.credentialsId ?: 'docker-hub-agileqa'
    boolean useBuildx    = cfg.useBuildx ?: false
    boolean useBuildKit  = cfg.useBuildKit ?: true
    List proxyEnv        = cfg.proxyEnv ?: []
    List secretFiles     = cfg.secretFiles ?: [] // e.g., ['nuget.config']

    withCredentials([usernamePassword(credentialsId: credsId, usernameVariable: 'DOCKER_USER', passwordVariable: 'DOCKER_PASS')]) {
        withEnv(proxyEnv + ["DOCKER_BUILDKIT=${useBuildKit ? '1' : '0'}"]) {
            sh '''
                echo "$DOCKER_PASS" | docker login -u "$DOCKER_USER" --password-stdin
            '''
            if (useBuildx) {
                sh """
                    docker buildx create --use --name jxbuilder || true
                    docker buildx inspect --bootstrap
                    docker buildx build --progress=plain --load \
                        ${secretFiles.collect { "--secret id=${it.replace('.','_')},src=${it}" }.join(' ')} \
                        -t ${imageRepo}:${tag} -f ${dockerfile} ${context}
                """
            } else {
                sh """
                    docker build --progress=plain \
                        ${secretFiles.collect { "--secret id=${it.replace('.','_')},src=${it}" }.join(' ')} \
                        -t ${imageRepo}:${tag} -f ${dockerfile} ${context}
                """
            }
            sh "docker push ${imageRepo}:${tag}"
            if (tag != 'latest') {
                sh "docker tag ${imageRepo}:${tag} ${imageRepo}:latest"
                sh "docker push ${imageRepo}:latest"
            }

            // History check
            sh """
                docker history ${imageRepo}:${tag} --no-trunc | tee history.txt
                if grep -Eiq '(http_proxy|https_proxy|genproxy|amdocs)' history.txt; then
                    echo 'ERROR: Proxy strings found in image history!' >&2
                    exit 1
                fi
                rm -f history.txt
            """

            sh 'docker logout || true'
        }
    }
}