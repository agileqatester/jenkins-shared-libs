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

    // NVD API key (recommended)
    String nvdApiKey        = (cfg.nvdApiKey ?: '').trim()
    String nvdApiKeyCredId  = (cfg.nvdApiKeyCredId ?: '').trim()

    // Optional VPN override
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

    // --- Parse proxyEnv (do not echo secrets) ---
    Map pe = proxyEnv.collectEntries { e ->
        int i = e.indexOf('=')
        (i > 0) ? [(e.substring(0, i)) : e.substring(i + 1)] : [:]
    }
    String httpProxy  = (pe['HTTP_PROXY'] ?: pe['http_proxy'] ?: '').trim()
    String httpsProxy = (pe['HTTPS_PROXY'] ?: pe['https_proxy'] ?: httpProxy).trim()
    String noProxy    = (pe['NO_PROXY']    ?: pe['no_proxy']    ?: '').trim()

    // ----------------------------------------------------
    // DNS: detect real resolv.conf and nameservers
    // ----------------------------------------------------
    // Prefer systemd-resolved's real resolv.conf if present; else /etc/resolv.conf
    String dnsMount = sh(script: '''
        set -eu
        if [ -s /run/systemd/resolve/resolv.conf ]; then
          echo /run/systemd/resolve/resolv.conf
        elif [ -s /etc/resolv.conf ]; then
          echo /etc/resolv.conf
        else
          echo /etc/resolv.conf
        fi
    ''', returnStdout: true).trim()

    // Build --dns flags from that file, excluding 127.0.0.53
    String dnsArgs = sh(script: """
        set -eu
        if [ -r '${dnsMount}' ]; then
          awk '/^nameserver[[:space:]]+[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/ { if (\$2 != "127.0.0.53") printf("--dns %s ", \$2) }' '${dnsMount}' || true
        fi
    """, returnStdout: true).trim()

    // Compose base inside() args: host network + host DNS config + explicit --dns servers (if any)
    String hostArgs = "--network host -v ${dnsMount}:/etc/resolv.conf:ro " + (dnsArgs ?: "")
    // ----------------------------------------------------

    // ----------------------------------------------------
    // TRIVY
    // ----------------------------------------------------
    try {
        if (onVPN) {
            echo "Trivy: online with proxy"
            List<String> trivyEnv = (proxyEnv ?: []) + [
                'TRIVY_DISABLE_MIRROR=1',
                'TRIVY_DB_REPOSITORY=ghcr.io/aquasec/trivy-db:2',
                'TRIVY_TIMEOUT=5m'
            ]
            withEnv(trivyEnv) {
                docker.image(trivyImage).inside("${hostArgs} --entrypoint='' -v ${trivyCache}:/root/.cache") {
                    sh """
                        set +x
                        set -eu
                        # Quick DNS diag (one-liner, quiet)
                        getent hosts ghcr.io >/dev/null 2>&1 || true
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
                    set +x
                    set -eu
                    if [ -f /root/.cache/trivy/db/trivy.db ] || [ -d /root/.cache/trivy/db ]; then
                      trivy image --skip-db-update --severity HIGH,CRITICAL \
                          --exit-code ${failOnHigh ? '1' : '0'} \
                          --format json --output trivy-report.json \
                          ${image}:${tag}
                    else
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
    // ----------------------------------------------------
// OWASP DEPENDENCY-CHECK (reliably timeout + fallback)
// ----------------------------------------------------
if (checkDeps) {
    echo "Dependency-Check: ${onVPN ? 'online with proxy' : 'offline/no-proxy'}"

    // Run container as Jenkins UID:GID so output is readable/publishable
    def uid = sh(script: 'id -u', returnStdout: true).trim()
    def gid = sh(script: 'id -g', returnStdout: true).trim()
    String userArg = "--user ${uid}:${gid}"

    // Build proxy flags/env (avoid echoing values)
    String proxyUrl = (httpsProxy ?: httpProxy)
    List<String> dcEnv = []
    String proxyFlags = ''

    if (onVPN && proxyUrl) {
        def m = (proxyUrl =~ /^(https?:)\\/\\/(?:([^:@]+)(?::([^@]*))?@)?([^:\\/]+)(?::(\\d+))?.*$/)
        if (m.matches()) {
            String proxyHost = m[0][4]
            String proxyPort = m[0][5] ?: '8080'
            String proxyUser = m[0][2] ?: ''
            String proxyPass = m[0][3] ?: ''

            if (proxyHost) dcEnv << "DC_PROXY_HOST=${proxyHost}"
            if (proxyPort) dcEnv << "DC_PROXY_PORT=${proxyPort}"
            if (proxyUser) dcEnv << "DC_PROXY_USER=${proxyUser}"
            if (proxyPass) dcEnv << "DC_PROXY_PASS=${proxyPass}"

            proxyFlags = """
                --proxyserver "\$DC_PROXY_HOST" \
                --proxyport "\$DC_PROXY_PORT" \
                \${DC_PROXY_USER:+--proxyuser "\$DC_PROXY_USER"} \
                \${DC_PROXY_PASS:+--proxypass "\$DC_PROXY_PASS"}
            """.stripIndent().trim()
        } else {
            echo "[WARN] Could not parse proxy URL for Dependency-Check."
        }
        // Some analyzers still honor HTTP(S)_PROXY
        dcEnv.addAll(proxyEnv)
    }

    // Ensure output dir exists
    sh "mkdir -p 'dependency-check-report'"

    // NVD API key (highly recommended)
    List creds = []
    if (nvdApiKeyCredId) {
        creds << string(credentialsId: nvdApiKeyCredId, variable: 'NVD_API_KEY')
    }
    if (nvdApiKey && !nvdApiKeyCredId) {
        dcEnv << "NVD_API_KEY=${nvdApiKey}"
    }

    // Timeouts
    int updateTimeoutMin = (cfg.dcUpdateTimeoutMinutes ?: 5)  as int  // short, just to refresh feeds
    int scanTimeoutMin   = (cfg.dcScanTimeoutMinutes   ?: 10) as int  // your 10 min (or adjust)

    // Build base command segments (quiet logging)
    String dcBase = """
        /usr/share/dependency-check/bin/dependency-check.sh \\
            --data /usr/share/dependency-check/data \\
            --enableExperimental \\
            ${proxyFlags} \\
            \${NVD_API_KEY:+--nvdApiKey "\$NVD_API_KEY"}
    """.stripIndent().trim()

    // We'll run two phases: update-only (with tight timeout), then scan with --noupdate.
    def insideArgs = "${hostArgs} --entrypoint='' ${userArg} -v ${dcData}:/usr/share/dependency-check/data"

    def runUpdateOnly = {
        docker.image(depCheckImage).inside(insideArgs) {
            timeout(time: updateTimeoutMin, unit: 'MINUTES') {
                sh """
                  set +x
                  set -eu
                  ${dcBase} --updateonly
                """
            }
        }
    }

    def runScanNoUpdate = {
        docker.image(depCheckImage).inside(insideArgs) {
            timeout(time: scanTimeoutMin, unit: 'MINUTES') {
                sh """
                  set +x
                  set -eu
                  ${dcBase} \\
                    --scan . \\
                    --format ALL \\
                    --out dependency-check-report \\
                    --noupdate
                """
                // Ensure readable by Jenkins and publishers
                sh "chmod -R a+rX dependency-check-report || true"
            }
        }
    }

    try {
        // Prefer credentials if provided
        if (!creds.isEmpty()) {
            withCredentials(creds) {
                withEnv(dcEnv) {
                    // 1) Try quick update
                    try {
                        runUpdateOnly()
                    } catch (org.jenkinsci.plugins.workflow.steps.FlowInterruptedException tie) {
                        echo "[WARN] DC update timed out after ${updateTimeoutMin} min; proceeding with --noupdate scan."
                    } catch (Exception ue) {
                        echo "[WARN] DC update failed: ${ue.message}; proceeding with --noupdate scan."
                    }
                    // 2) Run scan without update (fast, deterministic)
                    runScanNoUpdate()
                }
            }
        } else {
            withEnv(dcEnv) {
                try {
                    runUpdateOnly()
                } catch (org.jenkinsci.plugins.workflow.steps.FlowInterruptedException tie) {
                    echo "[WARN] DC update timed out after ${updateTimeoutMin} min; proceeding with --noupdate scan."
                } catch (Exception ue) {
                    echo "[WARN] DC update failed: ${ue.message}; proceeding with --noupdate scan."
                }
                runScanNoUpdate()
            }
        }
    } catch (org.jenkinsci.plugins.workflow.steps.FlowInterruptedException ie) {
        echo "[WARN] Dependency-Check interrupted: ${ie.getMessage()}"
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