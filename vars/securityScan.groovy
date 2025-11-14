def call(Map cfg = [:]) {
    String image = cfg.image ?: error('image required')
    String tag = cfg.tag ?: 'latest'
    boolean failOnHigh = cfg.failOnHigh != null ? cfg.failOnHigh : true
    
    // Trivy scan
    docker.image('aquasec/trivy:latest').inside('--network host') {
        sh """
            trivy image --severity HIGH,CRITICAL \
                --exit-code ${failOnHigh ? '1' : '0'} \
                --format json --output trivy-report.json \
                ${image}:${tag}
        """
    }
    
    archiveArtifacts artifacts: 'trivy-report.json', allowEmptyArchive: true
    
    // OWASP Dependency Check (for source code)
    if (cfg.checkDependencies) {
        docker.image('owasp/dependency-check:latest').inside() {
            sh """
                /usr/share/dependency-check/bin/dependency-check.sh \
                    --scan . \
                    --format ALL \
                    --out dependency-check-report
            """
        }
        publishHTML([
            reportDir: 'dependency-check-report',
            reportFiles: 'dependency-check-report.html',
            reportName: 'OWASP Dependency Check'
        ])
    }
}