# Security

`keychain-api` handles credentials. Review the source and policy before using it with sensitive accounts.

## Reporting a vulnerability

Use a private GitHub security advisory for vulnerability reports. Do not include live credentials, Keychain exports, production policy files, or unredacted API responses in a report.

## Expected boundaries

- Request authentication credentials live in the macOS login Keychain, not in the policy file. The opt-in response-file mode can save newly returned secrets as plaintext, as described below.
- The policy file contains Keychain item references and an allowlist of HTTPS origins, methods, and paths. Treat changes to it as security-sensitive.
- Request body files must contain non-secret JSON.
- The tool intentionally refuses redirects, non-HTTPS origins, unexpected response types, oversized bodies, and responses echoing the configured request credentials. Normal output redacts recognized sensitive fields and credential-shaped values; this is not a guarantee that arbitrary response content contains no secrets.
- This project has not undergone an independent security audit.

## Protected response files

`--secret-output-file` is an explicit, provider-neutral output option for existing policy profiles. It does not change the approved destination, authentication, request-body rules, or allowed operations. It saves the full nonempty JSON response before normal redaction, including any newly returned secrets; it does not extract one field, export the Keychain authentication credential, or create a new Keychain item. Normal output remains unchanged when the option is absent.

Before Keychain or network access, the helper reserves a new regular file using exclusive, no-follow creation. The absolute path must have no symlink components or traversal. Its parent must be owned by the current user, have no group/other permissions, and have no extended ACL entries. Ancestors must be owned by root or the current user and must not be group/other writable unless sticky. The file must be owned by the current user, mode `0600`, have one hard link, and have no extended ACL entries. An existing file is refused, not replaced.

The response is written through the reserved file descriptor, checked against the destination entry, synchronized, and closed before a fixed success receipt is emitted. Neither response content nor selected response fields are included in that receipt. The receipt field `secret_output: false` refers only to standard output: the file can contain secrets. Configured request-credential echo checks still run before writing.

### Threat-model limits

- The file is plaintext protected by filesystem permissions, not encrypted by this feature. Root and processes running as the same user can read it or alter its environment. The helper is not a security boundary against a compromised user account or operating system.
- Use a private directory outside source control, shared folders, and automatic syncing. Backups, filesystem snapshots, indexing tools, or other authorized local software may retain copies. Deleting the file does not guarantee secure erasure.
- Do not print the file, expose its contents through command arguments, or include it in logs, issues, or support bundles. Deliver it only to the intended trusted consumer and remove the exact artifact when it is no longer needed.
- A policy permitting credential delivery is not authorization for every API mutation. Review and authorize the actual operation separately.

### Failures and recovery

The helper does not automatically retry requests. A timeout or interrupted response can occur after the provider has completed a mutation. A disk or verification error can also occur after a one-time secret was issued. Empty, partial, or complete output files are retained on failure rather than deleting a potentially irreplaceable response. A file existing is not evidence of success, and a failed command is not evidence that a remote mutation did not happen.

Keep failed output private. Check provider state through a safe read-only request before retrying or rotating again; recover the existing result where supported. Do not weaken directory/file permissions, overwrite the reserved artifact, or treat a partial file as a valid credential response to make a retry work.

The offline self-test uses inert fixtures and no Keychain or network access. It checks protected-file content and receipt separation, refusal of unsafe or existing destinations, and preservation of existing files, alongside policy/redaction checks. It does not constitute a formal audit or complete fault/race testing.
