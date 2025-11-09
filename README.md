# Jenkins Shared Library

This repository contains reusable Jenkins pipeline code.

## Structure

- `vars/`: Simple steps callable directly in Jenkinsfiles
- `src/`: Groovy classes for advanced logic

## Usage

In your Jenkinsfile:

```groovy
@Library('jenkins-shared-library') _
sayHello('Dimitry')
