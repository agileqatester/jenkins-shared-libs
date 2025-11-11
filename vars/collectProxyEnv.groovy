def call() {
    def proxyEnv = []
    if (env.http_proxy)  proxyEnv << "http_proxy=${env.http_proxy}"
    if (env.https_proxy) proxyEnv << "https_proxy=${env.https_proxy}"
    if (env.no_proxy)    proxyEnv << "no_proxy=${env.no_proxy}"
    if (env.HTTP_PROXY)  proxyEnv << "HTTP_PROXY=${env.HTTP_PROXY}"
    if (env.HTTPS_PROXY) proxyEnv << "HTTPS_PROXY=${env.HTTPS_PROXY}"
    if (env.NO_PROXY)    proxyEnv << "NO_PROXY=${env.NO_PROXY}"
    return proxyEnv

