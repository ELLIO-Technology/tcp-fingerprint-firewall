# GitHub Actions Workflows for TCP Fingerprint Firewall

This directory contains GitHub Actions workflow files that automate testing, building, and security scanning of the TCP Fingerprint Firewall project.

## Workflow Overview

### 1. Build Pipeline (`build.yml`)

This workflow handles the basic build process:

- **Build Testing**: Compiles the project on the latest Ubuntu
- **Run Tests**: Executes basic test procedures

Triggered on: Push to main branch, Pull requests to main branch

### 2. DCO Check (`dco.yml`)

This workflow validates that all commits include a properly formatted DCO (Developer Certificate of Origin) "Signed-off-by" line:

- Checks each commit in a pull request for a proper signature
- Verifies that the signature email matches the committer's email
- Provides helpful error messages for non-compliant commits

Triggered on: Pull requests to main branch
 
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