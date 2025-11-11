def call(Map cfg = [:]) {
    String image = cfg.image ?: error("[deployContainer] 'image' required")
    String containerName = cfg.containerName ?: 'dotnet_sample_container'

    docker.image('agileqa/jenkins-agent:multi-tool').inside('--group-add 991 -v /var/run/docker.sock:/var/run/docker.sock --add-host=host.docker.internal:host-gateway') {
        sh """
          set -eux
          docker rm -f ${containerName} || true
          cid=$(docker run -d --cap-add NET_BIND_SERVICE --name ${containerName} -P ${image})
          sleep 2
          mapped=$(docker inspect -f '{{(index (index .NetworkSettings.Ports "80/tcp") 0).HostPort}}' ${containerName} || true)
          APP_URL="http://host.docker.internal:${mapped}"
          echo "APP_URL=${APP_URL}" | tee app_url.properties
          for i in {1..30}; do
            if curl -fsS "${APP_URL}/health" >/dev/null 2>&1; then break; fi
            sleep 1
          done
        """
    }
    archiveArtifacts artifacts: 'app_url.properties', fingerprint: true, onlyIfSuccessful: true
}
