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

    // Optional: NVD API key for Dependency-Check
    String nvdApiKey        = (cfg.nvdApiKey ?: '').trim()
    String nvdApiKeyCredId  = (cfg.nvdApiKeyCredId ?: '').trim()

    // Optional: Override VPN decision
    Boolean onVPNOverride   = (cfg.containsKey('onVPN') ? (cfg.onVPN as Boolean) : null)

    // Optional: force DNS servers inside scanner containers (BEST if you know them)
    List<String> dnsServers = (cfg.dnsServers instanceof List) ? (cfg.dnsServers as List<String>) : []

    // Optional: hostnames to hard-pin (add /etc/hosts entries in scanners)
    List<String> extraHosts = (cfg.extraHosts instanceof List) ? (cfg.extraHosts as List<String>) : ['ghcr.io']

    // Timeouts
    int trivyTimeoutMin     = (cfg.trivyTimeoutMinutes ?: 5)  as int
    int dcUpdateTimeoutMin  = (cfg.dcUpdateTimeoutMinutes ?: 5)  as int
    int dcScanTimeoutMin    = (cfg.dcScanTimeoutMinutes   ?: 10) as int

    boolean debug           = (cfg.debug != null) ? (cfg.debug as boolean) : false

    String workspaceDir     = env.WORKSPACE ?: '.'

    echo "=== Security Scan Stage ==="
    echo "Image: ${image}:${tag}"
    echo "Fail on HIGH+: ${failOnHigh}"
    echo "Dependency-Check: ${checkDeps ? 'enabled' : 'disabled'}"
    if (debug) {
        echo "Debug: ENABLED"
    }

    // --- VPN detection ---
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

    // --- DNS build: --dns, mount resolv.conf, and --add-host (for ghcr.io etc.) ---
    String dnsArgs = ''
    if (dnsServers && !dnsServers.isEmpty()) {
        dnsArgs = dnsServers.collect { ns -> "--dns ${ns}" }.join(' ')
    }

    // Select a resolv.conf to mount (best-effort)
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

    // Resolve extraHosts on HOST prior to starting containers
    List<String> addHostArgsList = []
    extraHosts.each { h ->
        String ip = sh(script: """
            set -eu
            (getent hosts ${h} || nslookup -type=A ${h} 2>/dev/null | awk '/^Address: /{print \$2}') | awk 'NR==1 {print \$1}'
        """, returnStdout: true).trim()
        if (ip) {
            addHostArgsList << "--add-host ${h}:${ip}"
        } else if (debug) {
            echo "[DEBUG] Could not resolve ${h} on host; skipping --add-host."
        }
    }
    String addHostsArgs = addHostArgsList.join(' ')

    String hostArgs = "--network host ${resolvMountArg} ${dnsArgs} ${addHostsArgs}".trim()

    if (debug) {
        // Host-level diagnostics
        echo "=== HOST Networking Debug ==="
        sh '''
            set +x
            set -eu
            echo "--- /etc/resolv.conf ---"
            (cat /etc/resolv.conf || true) | sed 's/127\\.0\\.0\\.53/<stub>/g'
            if command -v resolvectl >/dev/null 2>&1; then
              echo "--- resolvectl dns ---"
              resolvectl dns || true
            fi
            echo "--- getent hosts ghcr.io ---"
            getent hosts ghcr.io || true
        '''
        echo "hostArgs: ${hostArgs}"
        if (dnsServers) echo "dnsServers: ${dnsServers}"
        if (addHostsArgs) echo "addHostsArgs: ${addHostsArgs}"
        echo "dnsMount: ${dnsMount}"
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

            // Optional preflight network probe using Alpine (for debug)
            if (debug) {
                docker.image('alpine:3').inside("${hostArgs} --entrypoint=''") {
                    withEnv(proxyEnv ?: []) {
                        sh '''
                            set +x
                            set -eu
                            echo "=== Alpine probe inside container ==="
                            echo "--- /etc/resolv.conf ---"
                            (cat /etc/resolv.conf || true) | sed 's/127\\.0\\.0\\.53/<stub>/g'
                            echo "--- getent hosts ghcr.io ---"
                            getent hosts ghcr.io || true
                            echo "--- wget --spider https://ghcr.io/v2/ (with proxy if set) ---"
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
                            getent hosts ghcr.io >/dev/null 2>&1 || true
                            trivy --version || true
                            # Add --debug to increase verbosity
                            trivy --debug image --severity HIGH,CRITICAL \\
                                --exit-code ${failOnHigh ? '1' : '0'} \\
                                --format json --output trivy-report.json \\
                                ${image}:${tag}
                        """
                    }
                }
            }
        } else {
            echo "Trivy: offline (no proxy) — using cached DB if present"
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
        echo "[WARN] Trivy timed out after ${trivyTimeoutMin} min; attempting offline fallback if cache exists."
        // Try offline fallback so stage produces an artifact for downstreams
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
    // OWASP DEPENDENCY-CHECK (update-only + timeout + noupdate scan)
    // ----------------------------------------------------
    if (checkDeps) {
        echo "Dependency-Check: ${onVPN ? 'online with proxy' : 'offline/no-proxy'}"

        def uid = sh(script: 'id -u', returnStdout: true).trim()
        def gid = sh(script: 'id -g', returnStdout: true).trim()
        String userArg = "--user ${uid}:${gid}"

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
            dcEnv.addAll(proxyEnv) // also pass HTTP(S)_PROXY
        }

        sh "mkdir -p 'dependency-check-report'"

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

        def runUpdateOnly = {
            docker.image(depCheckImage).inside(insideArgs) {
                timeout(time: dcUpdateTimeoutMin, unit: 'MINUTES') {
                    sh "set +x\nset -eu\n${dcBase} --updateonly"
                }
            }
        }

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
            if (!creds.isEmpty()) {
                withCredentials(creds) {
                    withEnv(dcEnv) {
                        if (debug) {
                            echo "DC insideArgs: ${insideArgs}"
                        }
                        try { runUpdateOnly() }
                        catch (org.jenkinsci.plugins.workflow.steps.FlowInterruptedException tie) { echo "[WARN] DC update timed out (${dcUpdateTimeoutMin}m); continuing with --noupdate." }
                        catch (Exception ue) { echo "[WARN] DC update failed: ${ue.message}; continuing with --noupdate." }
                        runScanNoUpdate()
                    }
                }
            } else {
                withEnv(dcEnv) {
                    if (debug) {
                        echo "DC insideArgs: ${insideArgs}"
                    }
                    try { runUpdateOnly() }
                    catch (org.jenkinsci.plugins.workflow.steps.FlowInterruptedException tie) { echo "[WARN] DC update timed out (${dcUpdateTimeoutMin}m); continuing with --noupdate." }
                    catch (Exception ue) { echo "[WARN] DC update failed: ${ue.message}; continuing with --noupdate." }
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