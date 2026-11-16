# Security

`keychain-api` handles credentials. Review the source and policy before using it with sensitive accounts.

## Reporting a vulnerability

Use a private GitHub security advisory for vulnerability reports. Do not include live credentials, Keychain exports, production policy files, or unredacted API responses in a report.

## Expected boundaries

- Actual credentials live in the macOS login Keychain, not in the policy file.
- The policy file contains Keychain item references and an allowlist of HTTPS origins, methods, and paths. Treat changes to it as security-sensitive.
- Request body files must contain non-secret JSON.
- The tool intentionally refuses redirects, non-HTTPS origins, unexpected response types, oversized bodies, and output that appears to contain credential material.
- This project has not undergone an independent security audit.
