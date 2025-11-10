/**
 * Compose dockerArgs with Docker socket and NuGet mount.
 * Example:
 *   def dockerArgs = nugetDockerArgs(
 *     nugetHomeHost: "${env.WORKSPACE}/.nuget",
 *     nugetHomeContainer: "/home/jenkins/.nuget",
 *     dockerGid: 991
 *   )
 */
def call(Map cfg = [:]) {
    String nugetHomeHost      = cfg.get('nugetHomeHost', '')
    String nugetHomeContainer = cfg.get('nugetHomeContainer', '/home/jenkins/.nuget')
    int dockerGid             = (cfg.get('dockerGid', 991) as int)

    if (!nugetHomeHost) {
        error "[nugetDockerArgs] 'nugetHomeHost' is required."
    }

    return [
        "-v /var/run/docker.sock:/var/run/docker.sock",
        "--group-add ${dockerGid}",
        "-v ${nugetHomeHost}:${nugetHomeContainer}"
    ].join(' ')
}