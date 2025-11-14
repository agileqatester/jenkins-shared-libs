def call() {
    withCredentials([
        string(credentialsId: 'corp-proxy-url', variable: 'PROXY_URL'),
        string(credentialsId: 'corp-no-proxy', variable: 'NO_PROXY_LIST')
    ]) {
        writeFile file: 'nuget.config', text: '''<configuration>
    <config>
        <add key="http_proxy"  value="${PROXY_URL}"/>
        <add key="https_proxy" value="${PROXY_URL}"/>
        <add key="no_proxy"    value="${NO_PROXY_LIST}"/>
    </config>
</configuration>
'''
    }
    echo "[prepareNugetConfig] nuget.config created for BuildKit secret."
}
