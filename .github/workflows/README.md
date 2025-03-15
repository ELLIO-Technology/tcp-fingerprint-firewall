# GitHub Actions Workflows for TCP Fingerprint Firewall

This directory contains GitHub Actions workflow files that automate testing, security scanning, building, and deployment of the TCP Fingerprint Firewall project.

## Workflow Overview

### 1. CI Pipeline (`ci.yml`)

This workflow handles continuous integration:

- **Build Testing**: Compiles the project on multiple kernel versions
- **Documentation Checks**: Verifies that documentation is consistently cross-referenced and links work
- **Static Analysis**: Runs cppcheck and clang static analyzer on the codebase

Triggered on: Push to main branch, Pull requests to main branch

### 2. DCO Check (`dco.yml`)

This workflow validates that all commits include a properly formatted DCO (Developer Certificate of Origin) "Signed-off-by" line:

- Checks each commit in a pull request for a proper signature
- Verifies that the signature email matches the committer's email
- Provides helpful error messages for non-compliant commits

Triggered on: Pull requests to main branch

### 3. Security Scan (`security.yml`)

This workflow performs security analysis:

- **CodeQL Analysis**: Runs GitHub's CodeQL to find security vulnerabilities
- **Dependency Review**: On pull requests, checks for vulnerabilities in dependencies
- **Secret Scanning**: Uses Gitleaks to detect hardcoded secrets or credentials

Triggered on: Push to main branch, Pull requests to main branch, Weekly schedule

### 4. Build and Test (`deploy-test.yml`)

This workflow handles building, packaging, and testing:

- **Build Binary Package**: Creates a distributable tarball of compiled binaries
- **Release Creation**: Automatically creates GitHub releases when tags are pushed
- **Installation Testing**: Tests the installation script on a clean environment

Triggered on: Push to main branch, Push of version tags, Pull requests to main branch

## Best Practices Used

These workflows implement several industry best practices:

1. **Multi-environment Testing**: Building against multiple kernel versions
2. **Comprehensive Security**: Multiple security scanning tools
3. **Compliance Checks**: DCO verification for all contributions
4. **Documentation Validation**: Ensuring docs are properly cross-referenced
5. **Automated Releases**: Streamlined release process on version tags

## Setup Requirements

These workflows require the following GitHub repository settings:

1. Enable GitHub Actions in repository settings
2. Set up branch protection rules for the `main` branch:
   - Require status checks to pass before merging
   - Require the DCO check to pass
   - Require the security scan to pass
   - Require the CI test to pass

## Extending the Workflows

To add additional tests or checks:

1. Modify the existing workflow files to add new steps
2. Create new workflow files for entirely new processes
3. Update this README to document the changes