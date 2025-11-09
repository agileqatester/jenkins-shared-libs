# Jenkins Shared Library

This shared library provides reusable pipeline functions for building projects using Node.js, Java (Maven), Gradle, and .NET.

## Structure

- `vars/selectAgent.groovy`: Returns appropriate Docker image based on project type.
- `vars/runBuild.groovy`: Executes build commands based on project type.
- `Jenkinsfile`: Example usage of the shared library.

## Supported Project Types

- `node`
- `java`
- `gradle`
- `dotnet`
