// vars/collectProxyEnv.groovy
// Returns a List<String> like ["HTTP_PROXY=...", "HTTPS_PROXY=...", ...] suitable for withEnv()
// Precedence: params > env > credentials (if IDs provided)
// Usage: withEnv( collectProxyEnv(proxyCredId: 'corp-proxy-url', noProxyCredId: 'corp-no-proxy') ) { ... }

def call(Map cfg = [:]) {
    String proxyCredId   = (cfg.proxyCredId   ?: 'corp-proxy-url')
    String noProxyCredId = (cfg.noProxyCredId ?: 'corp-no-proxy')

    // 1) Try parameters (Declarative exposes params as env.PAR_NAME as well)
    String httpEff = (env?.HTTP_PROXY ?: env?.http_proxy ?: '').trim()
    String noEff   = (env?.NO_PROXY   ?: env?.no_proxy   ?: '').trim()

    // 2) If missing, try credentials (masked, scoped)
    if (!httpEff || !noEff) {
        withCredentials([
            string(credentialsId: proxyCredId,   variable: 'CRED_HTTP_PROXY'),
            string(credentialsId: noProxyCredId, variable: 'CRED_NO_PROXY')
        ]) {
            if (!httpEff) httpEff = (CRED_HTTP_PROXY ?: '').trim()
            if (!noEff)   noEff   = (CRED_NO_PROXY   ?: '').trim()
        }
    }

    // Build final list; mirror both upper/lower. Add npm hints for Node stages.
    def out = []
    if (httpEff) {
        out += "HTTP_PROXY=${httpEff}"
        out += "HTTPS_PROXY=${httpEff}"
        out += "http_proxy=${httpEff}"
        out += "https_proxy=${httpEff}"
        // NPM hints (harmless for .NET; npm reads these if present)
        out += "NPM_CONFIG_PROXY=${httpEff}"
        out += "NPM_CONFIG_HTTPS_PROXY=${httpEff}"
    }
    if (noEff) {
        out += "NO_PROXY=${noEff}"
        out += "no_proxy=${noEff}"
    }
    return out
}