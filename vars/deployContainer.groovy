def call(Map cfg = [:]) {
    String image         = cfg.image ?: error("[deployContainer] 'image' required")
    String containerName = cfg.containerName ?: 'app_container'
    String ports         = cfg.ports ?: ''              // e.g., '3000:3000' or empty to rely on -P
    String healthPath    = cfg.healthPath ?: '/health'  // e.g., '/health' or '/'

    docker.image('agileqa/jenkins-agent:multi-tool').inside('--group-add 991 -v /var/run/docker.sock:/var/run/docker.sock --add-host=host.docker.internal:host-gateway') {
        sh '''
          set -eux
          docker rm -f ${containerName} || true
          if [ -n "${ports}" ]; then
            docker run -d --cap-add NET_BIND_SERVICE --name ${containerName} -p ${ports} ${image}
            HOST_PORT="\$(echo '${ports}' | awk -F: '{print \$1}')"
          else
            docker run -d --cap-add NET_BIND_SERVICE --name ${containerName} -P ${image}
            HOST_PORT="\$(docker inspect -f '{{(index (index .NetworkSettings.Ports \"80/tcp\") 0).HostPort}}' ${containerName} || true)"
          fi

          APP_URL="http://host.docker.internal:\${HOST_PORT}"
          for i in {1..30}; do
            if curl -fsS "\${APP_URL}${healthPath}" >/dev/null 2>&1; then
              echo "Health OK"
              break
            fi
            sleep 1
          done
          echo "APP_URL=\${APP_URL}" | tee app_url.properties
        '''
    }
    archiveArtifacts artifacts: 'app_url.properties', fingerprint: true, onlyIfSuccessful: true
}