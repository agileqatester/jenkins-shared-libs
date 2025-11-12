// vars/deployContainer.groovy (extended)
def call(Map cfg = [:]) {
    String image         = cfg.image ?: error("[deployContainer] 'image' required")
    String containerName = cfg.containerName ?: 'app_container'
    String ports         = cfg.ports ?: '80:80'
    String healthPath    = cfg.healthPath ?: '/health'

    docker.image('agileqa/jenkins-agent:multi-tool').inside('--group-add 991 -v /var/run/docker.sock:/var/run/docker.sock --add-host=host.docker.internal:host-gateway') {
        sh """
          set -eux
          docker rm -f ${containerName} || true
          docker run -d --cap-add NET_BIND_SERVICE --name ${containerName} -p ${ports} ${image}
        """
        sh """
          sleep 2
          APP_URL="http://host.docker.internal:${ports.split(':')[0]}"
          for i in {1..30}; do
            if curl -fsS "\${APP_URL}${healthPath}" >/dev/null 2>&1; then
              echo "Health OK"
              break
            fi
            sleep 1
          done
          echo "APP_URL=\${APP_URL}" | tee app_url.properties
        """
    }
    archiveArtifacts artifacts: 'app_url.properties', fingerprint: true, onlyIfSuccessful: true
}
