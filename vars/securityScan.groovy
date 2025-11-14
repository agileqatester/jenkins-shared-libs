// vars/securityScan.groovy
def call(Map cfg = [:]) {
    // --- Inputs ---
    String image            = (cfg.image ?: error('[securityScan] image required')).trim()
    String tag              = (cfg.tag ?: 'latest').trim()
    boolean failOnHigh      = (cfg.failOnHigh != null) ? (cfg.failOnHigh as boolean) : true
    boolean checkDeps       = (cfg.checkDependencies != null) ? (cfg.checkDependencies as boolean) : false
    List<String> proxyEnv   = (cfg.proxyEnv instanceof List) ? (cfg.proxyEnv as List<String>) : []
    String trivyImage       = (cfg.trivyImage ?: 'aquasec/trivy:latest').trim()
    String depCheckImage    = (cfg.depCheckImage ?: 'owasp/dependency-check:latest').trim()

    // Optional NVD API key:
    // - cfg.nvdApiKey: string value (not recommended in plain text)
    // - cfg.nvdApiKeyCredId: Jenkins Secret Text credentials ID (recommended)
    String nvdApiKey        = (cfg.nvdApiKey ?: '').trim()
    String nvdApiKeyCredId  = (cfg.nvdApiKeyCredId ?: '').trim()

    // Optional override for VPN/proxy detection
    // - cfg.onVPN: Boolean (true/false) to force proxy behavior
    Boolean onVPNOverride   = (cfg.containsKey('onVPN') ? (cfg.onVPN as Boolean) : null)
    String workspaceDir     = env.WORKSPACE ?: '.'

    echo "=== Security Scan Stage ==="
    echo "Image: ${image}:${tag}"
    echo "Fail on HIGH+: ${failOnHigh}"
    echo "Dependency-Check: ${checkDeps ? 'enabled' : 'disabled'}"

    // --- VPN / proxy detection ---
    boolean onVPN
    if (onVPNOverride != null) {
        onVPN = onVPNOverride
        echo "VPN Status (override): ${onVPN ? 'CONNECTED' : 'DISCONNECTED'}"
    } else {
        int vpnStatus = sh(
            script: 'getent hosts proxy >/dev/null 2>&1 || ping -c 1 -W 1 proxy >/dev/null 2>&1',
            returnStatus: true
        )
        onVPN = (vpnStatus == 0)
        echo "VPN Status (auto): ${onVPN ? 'CONNECTED' : 'DISCONNECTED'}"
    }

    // --- Caches & paths ---
    String trivyCache = "${workspaceDir}/.cache/trivy"
    String dcData     = "${workspaceDir}/.cache/dependency-check"
    sh "mkdir -p '${trivyCache}' '${dcData}'"

    String hostArgs = "--network host"

    // --- Parse proxyEnv (don't echo secrets) ---
    Map pe = proxyEnv.collectEntries { e ->
        int i = e.indexOf('=')
        (i > 0) ? [(e.substring(0, i)) : e.substring(i + 1)] : [:]
    }
    String httpProxy  = (pe['HTTP_PROXY'] ?: pe['http_proxy'] ?: '').trim()
    String httpsProxy = (pe['HTTPS_PROXY'] ?: pe['https_proxy'] ?: httpProxy).trim()
    String noProxy    = (pe['NO_PROXY']    ?: pe['no_proxy']    ?: '').trim()

    // ----------------------------------------------------
    // TRIVY
    // ----------------------------------------------------
    try {
        if (onVPN) {
            echo "Trivy: online with proxy"
            // Disable mirror + (optionally) force GHCR for DB
            List<String> trivyEnv = (proxyEnv ?: []) + [
                'TRIVY_DISABLE_MIRROR=1',
                'TRIVY_DB_REPOSITORY=ghcr.io/aquasec/trivy-db:2',
                'TRIVY_TIMEOUT=5m'
            ]
            withEnv(trivyEnv) {
                docker.image(trivyImage).inside("${hostArgs} --entrypoint='' -v ${trivyCache}:/root/.cache") {
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
            docker.image(trivyImage).inside("${hostArgs} --entrypoint='' -v ${trivyCache}:/root/.cache") {
                sh """
                    set -eu
                    if [ -f /root/.cache/trivy/db/trivy.db ] || [ -d /root/.cache/trivy/db ]; then
                      echo "Using cached DB"
                      trivy image --skip-db-update --severity HIGH,CRITICAL \
                          --exit-code ${failOnHigh ? '1' : '0'} \
                          --format json --output trivy-report.json \
                          ${image}:${tag}
                    else
                      echo "No cached DB found; running best-effort offline scan (won't fail build)"
                      trivy image --skip-db-update --severity HIGH,CRITICAL \
                          --exit-code 0 \
                          --format json --output trivy-report.json \
                          ${image}:${tag} || true
                    fi
                """
            }
        }
    } catch (Exception e) {
        echo "[WARN] Trivy failed: ${e.message}"
        writeFile file: 'trivy-report.json', text: '{"error":"trivy failed"}'
    } finally {
        archiveArtifacts artifacts: 'trivy-report.json', allowEmptyArchive: true
    }

    // ----------------------------------------------------
    // OWASP DEPENDENCY-CHECK
    // ----------------------------------------------------
    if (checkDeps) {
        echo "Dependency-Check: ${onVPN ? 'online with proxy' : 'offline/no-proxy'}"

        // Build proxy flags for DC explicitly; also pass creds via env
        String proxyUrl = (httpsProxy ?: httpProxy)
        String proxyFlags = ''
        List<String> dcEnv = []
        if (onVPN && proxyUrl) {
            def m = (proxyUrl =~ /^(https?:)\\/\\/(?:([^:@]+)(?::([^@]*))?@)?([^:\\/]+)(?::(\\d+))?.*$/)
            if (m.matches()) {
                String proxyHost = m[0][4]
                String proxyPort = m[0][5] ?: '8080'
                String proxyUser = m[0][2] ?: ''
                String proxyPass = m[0][3] ?: ''

                proxyFlags = "--proxyserver ${proxyHost} --proxyport ${proxyPort}"
                if (proxyUser) {
                    dcEnv << "DC_PROXY_USER=${proxyUser}"
                    proxyFlags += " --proxyuser \"\\\$DC_PROXY_USER\""
                }
                if (proxyPass) {
                    dcEnv << "DC_PROXY_PASS=${proxyPass}"
                    proxyFlags += " --proxypass \"\\\$DC_PROXY_PASS\""
                }
            } else {
                echo "[WARN] Could not parse proxy URL for Dependency-Check."
            }
            // Some code paths still honor HTTP(S)_PROXY
            dcEnv.addAll(proxyEnv)
        }

        // Output dir must exist
        sh "mkdir -p 'dependency-check-report'"

        // Optional NVD API key
        List creds = []
        if (nvdApiKeyCredId) {
            creds << string(credentialsId: nvdApiKeyCredId, variable: 'NVD_API_KEY')
        }
        if (nvdApiKey && !nvdApiKeyCredId) {
            dcEnv << "NVD_API_KEY=${nvdApiKey}"
        }

        String dcArgs = """
            /usr/share/dependency-check/bin/dependency-check.sh \\
                --scan . \\
                --format ALL \\
                --out dependency-check-report \\
                --data /usr/share/dependency-check/data \\
                ${proxyFlags} \\
                \${NVD_API_KEY:+--nvdApiKey "\$NVD_API_KEY"}
        """.stripIndent().trim()

        def runDC = {
            docker.image(depCheckImage).inside("${hostArgs} --entrypoint='' -v ${dcData}:/usr/share/dependency-check/data") {
                sh "set -eu\n${dcArgs}"
            }
        }

        try {
            if (!creds.isEmpty()) {
                withCredentials(creds) {
                    withEnv(dcEnv) { runDC() }
                }
            } else {
                withEnv(dcEnv) { runDC() }
            }
        } catch (Exception e) {
            echo "[WARN] Dependency-Check failed: ${e.message}"
        } finally {
            publishHTML([
                reportDir  : 'dependency-check-report',
                reportFiles: 'dependency-check-report.html',
                reportName : 'OWASP Dependency Check'
            ])
            archiveArtifacts artifacts: 'dependency-check-report/**', allowEmptyArchive: true
        }
    }

    echo "=== Security Scan completed ==="
}
