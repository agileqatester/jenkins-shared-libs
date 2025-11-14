// vars/securityScan.groovy
def call(Map cfg = [:]) {
    String image            = cfg.image ?: error('image required')
    String tag              = (cfg.tag ?: 'latest').trim()
    boolean failOnHigh      = (cfg.failOnHigh != null) ? (cfg.failOnHigh as boolean) : true
    boolean checkDeps       = (cfg.checkDependencies != null) ? (cfg.checkDependencies as boolean) : false
    List<String> proxyEnv   = (cfg.proxyEnv instanceof List) ? (cfg.proxyEnv as List<String>) : []
    String trivyImage       = (cfg.trivyImage ?: 'aquasec/trivy:latest').trim()
    String depCheckImage    = (cfg.depCheckImage ?: 'owasp/dependency-check:latest').trim()
    String workspaceDir     = env.WORKSPACE ?: '.'

    // Detect VPN/proxy reachability: resolve proxy host by DNS or ping (adjust 'proxy' if needed)
    int vpnStatus = sh(script: 'getent hosts proxy >/dev/null 2>&1 || ping -c 1 -W 1 proxy >/dev/null 2>&1', returnStatus: true)
    boolean onVPN = (vpnStatus == 0)

    echo "=== Security Scan Stage ==="
    echo "VPN Status: ${onVPN ? 'CONNECTED' : 'DISCONNECTED'}"

    // Prepare Trivy cache dir (mounted to persist DB across runs)
    String trivyCache = "${workspaceDir}/.cache/trivy"
    sh "mkdir -p '${trivyCache}'"

    // Build common args for docker.inside
    String hostArgs = "--network host"

    // ---- TRIVY ----
    // When on VPN, pass proxy env and allow DB update.
    // When off VPN, attempt an offline scan if DB already cached (skip update); otherwise, run and tolerate DB error.
    if (onVPN) {
        echo "Trivy: online with proxy"
        withEnv(proxyEnv) {
            docker.image(trivyImage).inside("${hostArgs} -v ${trivyCache}:/root/.cache") {
                // Update DB (implicit) and scan
                sh """
                    set -eu
                    trivy image --severity HIGH,CRITICAL \
                        --exit-code ${failOnHigh ? '1' : '0'} \
                        --format json --output trivy-report.json \
                        ${image}:${tag}
                """
            }
        }
    } else {
        echo "Trivy: offline (no proxy) — using cached DB if present"
        docker.image(trivyImage).inside("${hostArgs} -v ${trivyCache}:/root/.cache") {
            // Try offline first; if DB absent, you can either fail or do a best-effort scan
            // '--skip-db-update' avoids network; '--offline-scan' is stricter (requires local DB).
            sh """
                set -eu
                if [ -f /root/.cache/trivy/db/trivy.db ] || [ -d /root/.cache/trivy/db ] ; then
                  echo "Using cached DB"
                  trivy image --skip-db-update --severity HIGH,CRITICAL \
                      --exit-code ${failOnHigh ? '1' : '0'} \
                      --format json --output trivy-report.json \
                      ${image}:${tag}
                else
                  echo "No cached DB found; running scan without update may be incomplete"
                  trivy image --skip-db-update --severity HIGH,CRITICAL \
                      --exit-code 0 \
                      --format json --output trivy-report.json \
                      ${image}:${tag} || true
                fi
            """
        }
    }

    archiveArtifacts artifacts: 'trivy-report.json', allowEmptyArchive: true

    // ---- OWASP DEPENDENCY-CHECK ----
    if (checkDeps) {
        echo "Dependency-Check: ${onVPN ? 'online with proxy' : 'offline/no-proxy'}"

        // Optional persistent data dir so DC keeps CVE data between runs
        String dcData = "${workspaceDir}/.cache/dependency-check"
        sh "mkdir -p '${dcData}'"

        // Parse proxy URL into flags if on VPN (proxyEnv may contain upper/lower case keys)
        Map pe = proxyEnv.collectEntries { e ->
            int i = e.indexOf('=')
            (i > 0) ? [(e.substring(0, i)) : e.substring(i + 1)] : [:]
        }
        String proxyUrl = (pe['HTTPS_PROXY'] ?: pe['https_proxy'] ?: pe['HTTP_PROXY'] ?: pe['http_proxy'] ?: '').trim()
        String proxyFlags = ''
        if (onVPN && proxyUrl) {
            def m = (proxyUrl =~ /^(https?:)\\/\\/(?:([^:@]+)(?::([^@]*))?@)?([^:\\/]+)(?::(\\d+))?.*$/)
            if (m.matches()) {
                String proxyHost = m[0][4]
                String proxyPort = m[0][5] ?: '8080'
                String proxyUser = m[0][2] ?: ''
                String proxyPass = m[0][3] ?: ''
                proxyFlags = "--proxyserver ${proxyHost} --proxyport ${proxyPort}"
                if (proxyUser) { proxyFlags += " --proxyuser '${proxyUser}'" }
                if (proxyPass) { proxyFlags += " --proxypass '${proxyPass}'" }
            } else {
                echo "[WARN] Could not parse proxy URL for Dependency-Check: ${proxyUrl}"
            }
        }

        // NOTE: Recent Dependency-Check requires an NVD API key for full speed/coverage.
        // You can add: --nvdApiKey ${env.NVD_API_KEY} (set via Jenkins creds/env if you have one)
        String dcArgs = """
            /usr/share/dependency-check/bin/dependency-check.sh \\
                --scan . \\
                --format ALL \\
                --out dependency-check-report \\
                --data /usr/share/dependency-check/data \\
                ${proxyFlags}
        """.stripIndent().trim()

        if (onVPN && proxyUrl) {
            withEnv(proxyEnv) {
                docker.image(depCheckImage).inside("${hostArgs} -v ${dcData}:/usr/share/dependency-check/data") {
                    sh "set -eu\n${dcArgs}"
                }
            }
        } else {
            // Offline/no-proxy: run with existing data if present; otherwise it will try and may be slow/limited
            docker.image(depCheckImage).inside("${hostArgs} -v ${dcData}:/usr/share/dependency-check/data") {
                sh "set -eu\n${dcArgs} || true"
            }
        }

        publishHTML([
            reportDir: 'dependency-check-report',
            reportFiles: 'dependency-check-report.html',
            reportName: 'OWASP Dependency Check'
        ])
    }
}
