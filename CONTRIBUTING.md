# Contribution Guidelines for TCP Fingerprint Firewall

Thank you for your interest in contributing to TCP Fingerprint Firewall! This document outlines the process for contributing to the project and important information about our licensing model.

## Licensing

TCP Fingerprint Firewall is available under a dual-license model:

1. **GNU Affero General Public License v3.0 (AGPLv3)** for open-source use
2. **Proprietary License** for commercial use without AGPLv3 requirements

## Developer Certificate of Origin (DCO)

We use the [Developer Certificate of Origin (DCO)](https://developercertificate.org/) process to manage contributions. The DCO is a simple statement that you, as a contributor, have the legal right to make your contribution and agree to our licensing terms.

To indicate that you agree to the DCO, simply sign off your commits by adding a line with your name and email address:

```
Signed-off-by: Your Name <your.email@example.com>
```

You can add this signature automatically by using the `-s` flag when committing:

```
git commit -s -m "Your commit message"
```

By signing off your commits, you agree to the following:

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.

Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

Additionally, by submitting a contribution, you agree that your work may be distributed under both the AGPLv3 and our proprietary license at the discretion of the project maintainers.

## Development Workflow

1. **Fork the Repository**: Create your own fork of the project on GitHub
2. **Create a Branch**: Create a feature or bugfix branch in your fork
3. **Develop**: Make your changes, following our code style and guidelines
4. **Test**: Ensure your changes pass all existing tests and add new tests as appropriate
5. **Commit with Sign-off**: Use `git commit -s` to sign off your commits
6. **Submit a Pull Request**: Create a PR against the main branch of the original repository

## Code Style and Guidelines

- Follow the existing code style in the repository
- Use snake_case for function and variable names
- Include comprehensive comments, especially for eBPF code
- Ensure all public functions have proper documentation
- Follow Linux kernel eBPF programming conventions when writing BPF code

## Security Considerations

- Always validate user input and handle errors appropriately
- Be mindful of memory management, especially in performance-critical code
- Report any security concerns directly to security@ellio.tech (or contributors) rather than creating a public issue

## Pull Request Process

1. Ensure your PR includes a clear description of the changes and their purpose
2. Verify all commits are signed off with the DCO
3. Link any related issues in the PR description
4. Make sure all CI checks pass
5. Address any feedback or requested changes
6. Once approved, a maintainer will merge your contribution

## Code of Conduct

- Be respectful and inclusive in all interactions
- Focus on technical merits of contributions
- Help create a positive and collaborative community
- Report unacceptable behavior to conduct@ellio.tech

## Recognition

All contributors will be acknowledged in our project documentation. Significant contributions may be highlighted in release notes and project announcements.

---

By contributing to TCP Fingerprint Firewall, you help improve network security for everyone. We appreciate your time and expertise, and look forward to your contributions!