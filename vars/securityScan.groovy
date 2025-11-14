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

    String nvdApiKey        = (cfg.nvdApiKey ?: '').trim()
    String nvdApiKeyCredId  = (cfg.nvdApiKeyCredId ?: '').trim()

    Boolean onVPNOverride   = (cfg.containsKey('onVPN') ? (cfg.onVPN as Boolean) : null)

    // Optional: explicit DNS servers if you choose; not required with DoH
    List<String> dnsServers = (cfg.dnsServers instanceof List) ? (cfg.dnsServers as List<String>) : []
    // Hostnames to pin via --add-host (DoH). ghcr.io needed for Trivy DB.
    List<String> extraHosts = (cfg.extraHosts instanceof List) ? (cfg.extraHosts as List<String>) : ['ghcr.io']

    // Timeouts
    int trivyTimeoutMin     = (cfg.trivyTimeoutMinutes ?: 5)   as int
    int dcUpdateTimeoutMin  = (cfg.dcUpdateTimeoutMinutes ?: 5) as int
    int dcScanTimeoutMin    = (cfg.dcScanTimeoutMinutes   ?: 10) as int
    // Secondary short retry for DC update (bounded)
    int dcUpdateRetryMin    = (cfg.dcUpdateRetryMinutes  ?: 3)  as int

    boolean debug           = (cfg.debug != null) ? (cfg.debug as boolean) : false

    String workspaceDir     = env.WORKSPACE ?: '.'

    echo "=== Security Scan Stage ==="
    echo "Image: ${image}:${tag}"
    echo "Fail on HIGH+: ${failOnHigh}"
    echo "Dependency-Check: ${checkDeps ? 'enabled' : 'disabled'}"
    if (debug) echo "Debug: ENABLED"

    // --- Parse proxy list into a map (do not echo secrets) ---
    Map pe = proxyEnv.collectEntries { e ->
        int i = e.indexOf('=')
        (i > 0) ? [(e.substring(0, i)) : e.substring(i + 1)] : [:]
    }
    String httpProxy  = (pe['HTTP_PROXY'] ?: pe['http_proxy'] ?: '').trim()
    String httpsProxy = (pe['HTTPS_PROXY'] ?: pe['https_proxy'] ?: httpProxy).trim()
    String noProxy    = (pe['NO_PROXY']    ?: pe['no_proxy']    ?: '').trim()

    // --- VPN detection ---
    boolean onVPN
    if (onVPNOverride != null) {
        onVPN = onVPNOverride
        echo "VPN Status (override): ${onVPN ? 'CONNECTED' : 'DISCONNECTED'}"
    } else {
        int vpnStatus = sh(script: 'getent hosts proxy >/dev/null 2>&1 || ping -c 1 -W 1 proxy >/dev/null 2>&1', returnStatus: true)
        onVPN = (vpnStatus == 0)
        echo "VPN Status (auto): ${onVPN ? 'CONNECTED' : 'DISCONNECTED'}"
    }

    // --- Caches ---
    String trivyCache = "${workspaceDir}/.cache/trivy"
    String dcData     = "${workspaceDir}/.cache/dependency-check"
    sh "mkdir -p '${trivyCache}' '${dcData}'"

    // --- Helper: resolve host via DoH/Proxy (no local DNS needed) ---
    // Tries getent -> nslookup -> DoH (Cloudflare then Google) via curl/wget; uses HTTPS_PROXY if provided.
    def resolveHostViaDoH = { String host ->
        String exportProxy = (proxyEnv ?: []).collect { kv -> "export ${kv};" }.join(' ')
        String script = """
            set -eu
            H="${host}"
            ip=\$(getent hosts "$H" 2>/dev/null | awk 'NR==1{print \$1}') || true
            [ -n "\$ip" ] && { echo "\$ip"; exit 0; }
            ip=\$(nslookup -type=A "$H" 2>/dev/null | awk '/^Address: /{print \$2; exit}') || true
            [ -n "\$ip" ] && { echo "\$ip"; exit 0; }
            ${exportProxy}
            if command -v curl >/dev/null 2>&1; then
              ip=\$(curl -sS --max-time 7 -H 'accept: application/dns-json' "https://cloudflare-dns.com/dns-query?name=\$H&type=A" \
                   | grep -oE '"data":"([0-9]{1,3}\\.){3}[0-9]{1,3}"' | head -1 | sed -E 's/.*"data":"([^"]+)".*/\\1/') || true
              [ -n "\$ip" ] && { echo "\$ip"; exit 0; }
              ip=\$(curl -sS --max-time 7 -H 'accept: application/dns-json' "https://dns.google/resolve?name=\$H&type=A" \
                   | grep -oE '"data":"([0-9]{1,3}\\.){3}[0-9]{1,3}"' | head -1 | sed -E 's/.*"data":"([^"]+)".*/\\1/') || true
              [ -n "\$ip" ] && { echo "\$ip"; exit 0; }
            elif command -v wget >/dev/null 2>&1; then
              ip=\$(wget -q -T 7 -O - --header='accept: application/dns-json' "https://cloudflare-dns.com/dns-query?name=\$H&type=A" \
                   | grep -oE '"data":"([0-9]{1,3}\\.){3}[0-9]{1,3}"' | head -1 | sed -E 's/.*"data":"([^"]+)".*/\\1/') || true
              [ -n "\$ip" ] && { echo "\$ip"; exit 0; }
              ip=\$(wget -q -T 7 -O - --header='accept: application/dns-json' "https://dns.google/resolve?name=\$H&type=A" \
                   | grep -oE '"data":"([0-9]{1,3}\\.){3}[0-9]{1,3}"' | head -1 | sed -E 's/.*"data":"([^"]+)".*/\\1/') || true
              [ -n "\$ip" ] && { echo "\$ip"; exit 0; }
            fi
            echo ""
        """.stripIndent()
        return sh(script: script, returnStdout: true).trim()
    }

    // --- DNS/hosts args for scanner containers ---
    String dnsArgs = ''
    if (dnsServers && !dnsServers.isEmpty()) {
        dnsArgs = dnsServers.collect { ns -> "--dns ${ns}" }.join(' ')
    }

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
    String resolvMountArg = "-v ${dnsMount}:/etc/resolv.conf:ro"

    List<String> addHostArgsList = []
    extraHosts.each { h ->
        String ip = resolveHostViaDoH(h)
        if (ip) {
            addHostArgsList << "--add-host ${h}:${ip}"
            if (debug) echo "Resolved ${h} via DoH -> ${ip}"
        } else if (debug) {
            echo "[DEBUG] DoH resolution failed for ${h}; continuing without --add-host"
        }
    }
    String addHostsArgs = addHostArgsList.join(' ')
    String hostArgs = "--network host ${resolvMountArg} ${dnsArgs} ${addHostsArgs}".trim()

    if (debug) {
        echo "=== HOST Networking Debug ==="
        sh '''
            set +x
            set -eu
            echo "--- /etc/resolv.conf (agent container) ---"
            (cat /etc/resolv.conf || true) | sed 's/127\\.0\\.0\\.53/<stub>/g'
            echo "--- getent hosts ghcr.io (agent container) ---"
            getent hosts ghcr.io || true
        '''
        echo "hostArgs: ${hostArgs}"
        echo "dnsMount: ${dnsMount}"
        if (dnsArgs) echo "dnsArgs: ${dnsArgs}"
        if (addHostsArgs) echo "addHostsArgs: ${addHostsArgs}"
    }

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

            if (debug) {
                docker.image('alpine:3').inside("${hostArgs} --entrypoint=''") {
                    withEnv(proxyEnv ?: []) {
                        sh '''
                            set +x
                            set -eu
                            echo "=== Alpine probe (inside) ==="
                            echo "--- /etc/resolv.conf ---"
                            (cat /etc/resolv.conf || true) | sed 's/127\\.0\\.0\\.53/<stub>/g'
                            echo "--- getent hosts ghcr.io ---"
                            getent hosts ghcr.io || true
                            echo "--- wget --spider https://ghcr.io/v2/ ---"
                            wget -T 5 -S --spider https://ghcr.io/v2/ 2>&1 || true
                        '''
                    }
                }
            }

            withEnv(trivyEnv) {
                docker.image(trivyImage).inside("${hostArgs} --entrypoint='' -v ${trivyCache}:/root/.cache") {
                    timeout(time: trivyTimeoutMin, unit: 'MINUTES') {
                        sh """
                            set +x
                            set -eu
                            trivy --version || true
                            trivy --debug image --severity HIGH,CRITICAL \\
                                --exit-code ${failOnHigh ? '1' : '0'} \\
                                --format json --output trivy-report.json \\
                                ${image}:${tag}
                        """
                    }
                }
            }
        } else {
            echo "Trivy: offline (no proxy) — use cached DB if present"
            docker.image(trivyImage).inside("${hostArgs} --entrypoint='' -v ${trivyCache}:/root/.cache") {
                sh """
                    set +x
                    set -eu
                    if [ -f /root/.cache/trivy/db/trivy.db ] || [ -d /root/.cache/trivy/db ]; then
                      trivy image --skip-db-update --severity HIGH,CRITICAL \\
                          --exit-code ${failOnHigh ? '1' : '0'} \\
                          --format json --output trivy-report.json \\
                          ${image}:${tag}
                    else
                      trivy image --skip-db-update --severity HIGH,CRITICAL \\
                          --exit-code 0 \\
                          --format json --output trivy-report.json \\
                          ${image}:${tag} || true
                    fi
                """
            }
        }
    } catch (org.jenkinsci.plugins.workflow.steps.FlowInterruptedException tie) {
        echo "[WARN] Trivy timed out after ${trivyTimeoutMin}m; trying offline fallback if cache exists."
        try {
            docker.image(trivyImage).inside("${hostArgs} --entrypoint='' -v ${trivyCache}:/root/.cache") {
                sh """
                    set +x
                    set -eu
                    if [ -f /root/.cache/trivy/db/trivy.db ] || [ -d /root/.cache/trivy/db ]; then
                      trivy image --skip-db-update --severity HIGH,CRITICAL \\
                          --exit-code 0 \\
                          --format json --output trivy-report.json \\
                          ${image}:${tag} || true
                    else
                      echo '{"error":"trivy timed out and no cached DB"}' > trivy-report.json
                    fi
                """
            }
        } catch (Exception ignore) { /* ignore */ }
    } catch (Exception e) {
        echo "[WARN] Trivy failed: ${e.message}"
        writeFile file: 'trivy-report.json', text: '{"error":"trivy failed"}'
    } finally {
        archiveArtifacts artifacts: 'trivy-report.json', allowEmptyArchive: true
    }

    // ----------------------------------------------------
    // OWASP DEPENDENCY-CHECK (update-only + retry + noupdate if DB exists)
    // ----------------------------------------------------
    if (checkDeps) {
        echo "Dependency-Check: ${onVPN ? 'online with proxy' : 'offline/no-proxy'}"

        def uid = sh(script: 'id -u', returnStdout: true).trim()
        def gid = sh(script: 'id -g', returnStdout: true).trim()
        String userArg = "--user ${uid}:${gid}"

        // Proxy flags/env via indirection (no secrets in logs)
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
                    --proxyserver "\$DC_PROXY_HOST" \\
                    --proxyport "\$DC_PROXY_PORT" \\
                    \${DC_PROXY_USER:+--proxyuser "\$DC_PROXY_USER"} \\
                    \${DC_PROXY_PASS:+--proxypass "\$DC_PROXY_PASS"}
                """.stripIndent().trim()
            } else {
                echo "[WARN] Could not parse proxy URL for Dependency-Check."
            }
            dcEnv.addAll(proxyEnv) // still pass HTTP(S)_PROXY
        }

        // Ensure output dir exists
        sh "mkdir -p 'dependency-check-report'"

        // NVD API key (faster/more reliable updates)
        List creds = []
        if (nvdApiKeyCredId) {
            creds << string(credentialsId: nvdApiKeyCredId, variable: 'NVD_API_KEY')
        }
        if (nvdApiKey && !nvdApiKeyCredId) {
            dcEnv << "NVD_API_KEY=${nvdApiKey}"
        }

        String dcBase = """
            /usr/share/dependency-check/bin/dependency-check.sh \\
                --data /usr/share/dependency-check/data \\
                --enableExperimental \\
                ${proxyFlags} \\
                \${NVD_API_KEY:+--nvdApiKey "\$NVD_API_KEY"}
        """.stripIndent().trim()

        String insideArgs = "${hostArgs} --entrypoint='' ${userArg} -v ${dcData}:/usr/share/dependency-check/data"

        def runUpdateOnlyWithTimeout = { int minutes ->
            docker.image(depCheckImage).inside(insideArgs) {
                timeout(time: minutes, unit: 'MINUTES') {
                    sh "set +x\nset -eu\n${dcBase} --updateonly"
                }
            }
        }

        // 1) Try a short update (bounded)
        boolean dbReady = false
        try {
            if (!creds.isEmpty()) withCredentials(creds) { withEnv(dcEnv) { runUpdateOnlyWithTimeout(dcUpdateTimeoutMin) } }
            else withEnv(dcEnv) { runUpdateOnlyWithTimeout(dcUpdateTimeoutMin) }
        } catch (org.jenkinsci.plugins.workflow.steps.FlowInterruptedException tie) {
            echo "[WARN] DC update timed out (${dcUpdateTimeoutMin}m)."
        } catch (Exception ue) {
            echo "[WARN] DC update failed: ${ue.message}"
        }

        // 2) Check if DB exists in the mounted cache (on the Jenkins side)
        int hasDbStatus = sh(
            script: """
              set -eu
              [ -d '${dcData}' ] && ls -1 '${dcData}' | grep -E '(^odc\\.(mv|h2)\\.db$|^nvdcve.*\\.json$|^dc\\..*\\.db$)' >/dev/null 2>&1
            """,
            returnStatus: true
        )
        dbReady = (hasDbStatus == 0)

        // 3) If not ready and on VPN, do a second short retry
        if (!dbReady && onVPN) {
            echo "[INFO] DC DB not found after first update; retrying for ${dcUpdateRetryMin}m..."
            try {
                if (!creds.isEmpty()) withCredentials(creds) { withEnv(dcEnv) { runUpdateOnlyWithTimeout(dcUpdateRetryMin) } }
                else withEnv(dcEnv) { runUpdateOnlyWithTimeout(dcUpdateRetryMin) }
            } catch (org.jenkinsci.plugins.workflow.steps.FlowInterruptedException tie2) {
                echo "[WARN] DC update retry timed out (${dcUpdateRetryMin}m)."
            } catch (Exception ue2) {
                echo "[WARN] DC update retry failed: ${ue2.message}"
            }
            hasDbStatus = sh(
                script: """
                  set -eu
                  [ -d '${dcData}' ] && ls -1 '${dcData}' | grep -E '(^odc\\.(mv|h2)\\.db$|^nvdcve.*\\.json$|^dc\\..*\\.db$)' >/dev/null 2>&1
                """,
                returnStatus: true
            )
            dbReady = (hasDbStatus == 0)
        }

        if (!dbReady) {
            // 4) Graceful skip with an informative HTML
            echo "[WARN] Skipping Dependency-Check scan: DB cache not available (offline or update timed out)."
            sh """
              set -eu
              mkdir -p dependency-check-report
              cat > dependency-check-report/dependency-check-report.html <<'HTML'
              <!doctype html><html><head><meta charset="utf-8"><title>Dependency-Check Skipped</title></head>
              <body>
                <h2>Dependency-Check was skipped</h2>
                <p>The NVD database was not available (offline or update timed out).</p>
                <ul>
                  <li>Ensure VPN/proxy is reachable for updates.</li>
                  <li>Provide an NVD API key for faster updates.</li>
                  <li>Or pre-warm the cache on a VPN-connected agent.</li>
                </ul>
              </body></html>
              HTML
            """
        } else {
            // 5) Run the scan quickly with --noupdate (DB present)
            def runScanNoUpdate = {
                docker.image(depCheckImage).inside(insideArgs) {
                    timeout(time: dcScanTimeoutMin, unit: 'MINUTES') {
                        sh """
                            set +x
                            set -eu
                            ${dcBase} \\
                              --scan . \\
                              --format ALL \\
                              --out dependency-check-report \\
                              --noupdate
                        """
                        sh "chmod -R a+rX dependency-check-report || true"
                    }
                }
            }
            try {
                if (!creds.isEmpty()) { withCredentials(creds) { withEnv(dcEnv) { runScanNoUpdate() } } }
                else { withEnv(dcEnv) { runScanNoUpdate() } }
            } catch (org.jenkinsci.plugins.workflow.steps.FlowInterruptedException ie) {
                echo "[WARN] Dependency-Check interrupted: ${ie.getMessage()}"
            } catch (Exception e) {
                echo "[WARN] Dependency-Check failed: ${e.message}"
                // Ensure there is at least a placeholder to publish
                sh """
                  set -eu
                  mkdir -p dependency-check-report
                  echo '<html><body><h3>Dependency-Check failed</h3></body></html>' > dependency-check-report/dependency-check-report.html
                """
            }
        }

        // Publish whatever we have
        publishHTML([
            reportDir  : 'dependency-check-report',
            reportFiles: 'dependency-check-report.html',
            reportName : 'OWASP Dependency Check'
        ])
        archiveArtifacts artifacts: 'dependency-check-report/**', allowEmptyArchive: true
    }

    echo "=== Security Scan completed ==="
}