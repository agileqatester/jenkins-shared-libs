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

    // Optional NVD key for Dependency-Check (highly recommended)
    String nvdApiKey        = (cfg.nvdApiKey ?: '').trim()
    String nvdApiKeyCredId  = (cfg.nvdApiKeyCredId ?: '').trim()

    // VPN override
    Boolean onVPNOverride   = (cfg.containsKey('onVPN') ? (cfg.onVPN as Boolean) : null)

    // NEW: Optional explicit DNS servers to use in containers, e.g., ['10.10.0.2','10.10.0.3']
    List<String> dnsServers = (cfg.dnsServers instanceof List) ? (cfg.dnsServers as List<String>) : []

    // NEW: Hostnames to hard-pin via --add-host. Default includes ghcr.io for Trivy DB.
    List<String> extraHosts = (cfg.extraHosts instanceof List) ? (cfg.extraHosts as List<String>) : ['ghcr.io']

    // Timeouts for DC
    int dcUpdateTimeoutMin  = (cfg.dcUpdateTimeoutMinutes ?: 5)  as int
    int dcScanTimeoutMin    = (cfg.dcScanTimeoutMinutes   ?: 10) as int

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
    // DNS strategy for scanner containers
    // ----------------------------------------------------
    // 1) Build --dns args from cfg.dnsServers if provided (best).
    String dnsArgs = ''
    if (dnsServers && !dnsServers.isEmpty()) {
        dnsArgs = dnsServers.collect { ns -> "--dns ${ns}" }.join(' ')
    }

    // 2) Mount a resolv.conf file (best-effort; not relied upon)
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

    // 3) Hard-pin certain hostnames via --add-host <name>:<ip> (e.g., ghcr.io)
    //    We resolve IPs *before* starting the scanner containers.
    List<String> addHostArgsList = []
    extraHosts.each { h ->
        String ip = sh(script: """
            set -eu
            (getent hosts ${h} || nslookup -type=A ${h} 2>/dev/null | awk '/^Address: /{print \$2}') | awk 'NR==1 {print \$1}'
        """, returnStdout: true).trim()
        if (ip) {
            addHostArgsList << "--add-host ${h}:${ip}"
        } else {
            echo "[WARN] Could not resolve ${h} on the agent; not adding --add-host."
        }
    }
    String addHostsArgs = addHostArgsList.join(' ')

    // Base args for docker.inside() in scanners
    String hostArgs = "--network host ${resolvMountArg} ${dnsArgs} ${addHostsArgs}".trim()

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
    // OWASP DEPENDENCY-CHECK (update-only + timeout + noupdate scan)
    // ----------------------------------------------------
    if (checkDeps) {
        echo "Dependency-Check: ${onVPN ? 'online with proxy' : 'offline/no-proxy'}"

        // Run container as Jenkins UID:GID so output is readable/publishable
        def uid = sh(script: 'id -u', returnStdout: true).trim()
        def gid = sh(script: 'id -g', returnStdout: true).trim()
        String userArg = "--user ${uid}:${gid}"

        // Proxy flags/env (avoid echoing values)
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

        // NVD API key (recommended)
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

        def insideArgs = "${hostArgs} --entrypoint='' ${userArg} -v ${dcData}:/usr/share/dependency-check/data"

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
                        try { runUpdateOnly() }
                        catch (org.jenkinsci.plugins.workflow.steps.FlowInterruptedException tie) { echo "[WARN] DC update timed out; continuing with --noupdate." }
                        catch (Exception ue) { echo "[WARN] DC update failed: ${ue.message}; continuing with --noupdate." }
                        runScanNoUpdate()
                    }
                }
            } else {
                withEnv(dcEnv) {
                    try { runUpdateOnly() }
                    catch (org.jenkinsci.plugins.workflow.steps.FlowInterruptedException tie) { echo "[WARN] DC update timed out; continuing with --noupdate." }
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