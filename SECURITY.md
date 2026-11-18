# Security

`keychain-api` handles credentials. Review the source and policy before using it with sensitive accounts.

## Reporting a vulnerability

Use a private GitHub security advisory for vulnerability reports. Do not include live credentials, Keychain exports, production policy files, or unredacted API responses in a report.

## Expected boundaries

- Request authentication credentials live in the macOS login Keychain, not in the policy file. The opt-in response-file mode can save newly returned secrets as plaintext, as described below.
- The policy file contains Keychain item references, HTTPS origins, and a nonempty `operations` allowlist of HTTP methods and paths. Treat policy changes as security-sensitive.
- Exact HTTP paths and path prefixes share the same method/body/response compatibility checks. `GET` and `HEAD` cannot take a body or require one through `body: "json"`. `HEAD` permits `empty` or `json-or-empty` responses, but not required `json` responses.
- An optional per-profile SOCKSv5 proxy uses a loopback listener with direct fallback disabled. HTTPS certificate validation and origin restrictions still apply; credentials are not sent as proxy authentication. The helper does not manage or authenticate the local listener, which must be established through a trusted process. Proxying does not protect against a compromised local account or trusted TLS interception.
- Request body files must contain non-secret JSON.
- The HTTP transport intentionally refuses redirects, non-HTTPS origins, unexpected response types, oversized bodies, and responses echoing the configured request credentials. Normal output redacts recognized sensitive fields and credential-shaped values; this is not a guarantee that arbitrary response content contains no secrets.
- JSON credential checks require UTF-8 without NUL bytes and inspect decoded string literals before object parsing can collapse duplicate member names. Accepted protected responses preserve their original bytes.
- This project has not undergone an independent security audit.

## Protected response files

Use `--secret-output-file` to save the full, nonempty JSON response before redaction, including any newly returned secrets. The policy still determines the destination, authentication, request-body rules, and allowed operations. The helper checks for echoes of the Keychain authentication credentials before writing. Interrupted responses can leave recovery bytes as described below.

Before Keychain or network access, the helper reserves a new regular file using exclusive, no-follow creation. The absolute path must have no symlink components or traversal. Its parent must be owned by the current user, have no group/other permissions, and have no extended ACL entries. Ancestors must be owned by root or the current user and must not be group/other writable unless sticky. The file must be owned by the current user, mode `0600`, have one hard link, and have no extended ACL entries. An existing file is refused, not replaced.

The response is written through the reserved file descriptor, checked against the destination entry, synchronized, and closed before a fixed success receipt is emitted. Neither response content nor selected response fields are included in that receipt. The receipt field `secret_output: false` refers only to standard output: the file can contain secrets. Configured request-credential echo checks still run before writing.

### Threat-model limits

- The file is plaintext protected by filesystem permissions, not encrypted by this feature. Root and processes running as the same user can read it or alter its environment. The helper is not a security boundary against a compromised user account or operating system.
- Use a private directory outside source control, shared folders, and automatic syncing. Backups, filesystem snapshots, indexing tools, or other authorized local software may retain copies. Deleting the file does not guarantee secure erasure.
- Do not print the file, expose its contents through command arguments, or include it in logs, issues, or support bundles. Deliver it only to the intended trusted consumer and remove the exact artifact when it is no longer needed.
- A policy permitting credential delivery is not authorization for every API mutation. Review and authorize the actual operation separately.

### Failures and recovery

The helper does not automatically retry requests. A timeout or interrupted response can occur after the provider has completed a mutation. A disk or verification error can also occur after a one-time secret was issued. Empty, partial, or complete output files are retained on failure rather than deleting a potentially irreplaceable response. A file existing is not evidence of success, and a failed command is not evidence that a remote mutation did not happen.

When an HTTP stream is interrupted or exceeds the limit during reading, the helper saves received bytes up to 8 MiB to the protected output only after credential checks. Complete JSON is checked for credential echoes, including escaped strings and duplicate members. Incomplete JSON must be UTF-8 and contain no NUL or backslash bytes; unchecked bytes are refused. The command still exits with code `5` and emits no success receipt. A retained response may be partial or invalid JSON and does not establish that the remote mutation succeeded.

Keep failed output private. Check provider state through a safe read-only request before retrying or rotating again; recover the existing result where supported. Do not weaken directory/file permissions, overwrite the reserved artifact, or treat a partial file as a valid credential response to make a retry work.

The offline self-test uses inert fixtures and runs without Keychain or network access. It exercises command dispatch, protected-file contents and receipts, failure output retention, and HTTP response and recovery handling, alongside policy and JSON credential checks.
