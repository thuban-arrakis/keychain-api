# keychain-api

`keychain-api` is a policy-constrained credential client for macOS. Its HTTPS transport reads an API credential from the login Keychain and places it in an approved request header without printing it or putting it in a process argument. By default, it emits a sanitized JSON response; an explicit protected-file option can save a sensitive JSON response without printing that response. A separate 1Password adapter runs policy-approved service account commands through the official CLI, saving their output to protected files.

The executable is intentionally narrow. Every profile fixes the destination origin, credential mapping, and allowed operations. HTTP operations define methods, paths, request bodies, and response types; 1Password operations name exact CLI commands.

## Requirements

- macOS 12 or newer; optional SOCKS proxy support requires macOS 14 or newer
- Xcode Command Line Tools with Swift 5.9 and the macOS 14 SDK or newer
- A generic-password item in the default login Keychain

The Swift source has no third-party dependencies. It uses Foundation, Security, LocalAuthentication, and Network. The optional 1Password adapter requires the official 1Password CLI.

## Build

Build an optimized executable with Swift Package Manager:

```sh
swift build --configuration release
swift run --configuration release keychain-api self-test
```

The resulting executable is under the directory printed by:

```sh
swift build --configuration release --show-bin-path
```

The Makefile exposes the common variants:

```sh
make debug
make release
make test
make test CONFIGURATION=debug
make verify
make install PREFIX="$HOME/.local"
```

`make test` runs the self-test in `CONFIGURATION` (release by default). `make verify` applies and verifies an ad hoc hardened-runtime signature. Set `CODESIGN_IDENTITY` and `CODESIGN_IDENTIFIER` to use a different signing identity and identifier. `make install` signs and installs the executable with mode `0700`.

A rebuilt executable can trigger a new macOS Keychain authorization prompt because Keychain access control is tied to the requesting binary.

### Direct compiler options

The same release build can be produced without Swift Package Manager:

```sh
SDK="$(xcrun --sdk macosx --show-sdk-path)"
mkdir -p build/module-cache
xcrun swiftc \
  -parse-as-library \
  -O \
  -whole-module-optimization \
  -strict-concurrency=complete \
  -target arm64-apple-macosx12.0 \
  -sdk "$SDK" \
  -module-cache-path build/module-cache \
  Sources/KeychainAPI/*.swift \
  -framework Security \
  -framework LocalAuthentication \
  -framework Network \
  -o build/keychain-api
strip -x build/keychain-api
codesign --force --sign - --options runtime \
  --identifier local.keychain-api \
  build/keychain-api
codesign --verify --strict --verbose=2 build/keychain-api
```

Use `-Onone -g` for a debuggable local build, `-O` for normal releases, or `-Osize` when binary size matters. `-parse-as-library` is required because the source uses an `@main` entry point. Do not enable `-warnings-as-errors`: the legacy default-Keychain lookup currently emits a macOS deprecation warning.

Replace the target with `x86_64-apple-macosx12.0` for an Intel build. To produce a universal executable, compile once for each architecture using separate module-cache and output paths, then combine them before signing:

```sh
xcrun lipo -create \
  build/keychain-api-arm64 \
  build/keychain-api-x86_64 \
  -output build/keychain-api
```

Strip and sign only the combined executable. The selected compiler and SDK must come from a compatible Xcode or Command Line Tools installation.

### Source layout

The files in `Sources/KeychainAPI` form one executable target:

| File | Responsibility |
| --- | --- |
| `CLI.swift` | Command arguments, dispatch, and usage |
| `Policy.swift` | Policy types, parsing, and operation authorization |
| `HTTPTransport.swift` | HTTPS sessions and response handling |
| `OnePassword.swift` | 1Password arguments, input preparation, and subprocess handling |
| `Keychain.swift` | Keychain access |
| `ProtectedFiles.swift` | Private input and durable response files |
| `JSONSafety.swift` | Credential detection, JSON validation, and redaction |
| `Support.swift` | Shared errors, limits, and metadata checks |
| `SelfTests.swift` | Offline checks run by `keychain-api self-test` |
| `CLISelfTests.swift` | Command dispatch, refusal ordering, and output checks |
| `HTTPTransportSelfTests.swift` | Deterministic HTTP response and recovery checks |

## Policy

The client uses three terms throughout this guide:

- A **profile** fixes a trusted origin, Keychain credential references, and allowed operations.
- An **operation** permits an HTTP method/path combination or an exact 1Password command. It does not authorize every possible mutation within that permission.
- **Protected output** is a new private plaintext file that receives sensitive results without printing them.

The tool reads exactly one policy file:

```text
~/.config/codex/keychain-api.json
```

The file must be a regular file owned by the current user with no group or other permissions. Mode `0600` or `0400` is appropriate. The policy stores Keychain lookup metadata, not credential values.

Start with [the provider-neutral example](examples/policy.example.json), replace the reserved `.invalid` origin, and install it without making it broadly readable:

```sh
mkdir -p "$HOME/.config/codex"
chmod 0700 "$HOME/.config/codex"
install -m 0600 examples/policy.example.json "$HOME/.config/codex/keychain-api.json"
```

Do not overwrite an existing policy without reviewing and preserving its profiles.

### Authentication types

Each credential entry references a macOS generic-password item by `service` and `account`:

- `bearer`: sends `Authorization: Bearer <credential>`.
- `api-key`: sends `Authorization: APIKey <credential>`.
- `basic`: requires a policy `username` and sends HTTP Basic authentication.
- `header`: requires an allowed custom `header` and accepts an optional `prefix`.
- `onepassword-service-account`: authenticates the policy-controlled CLI adapter described below; it cannot send the token as an HTTP header.

The actual password or token must never appear in the JSON policy.

### Operation rules

Every profile requires a nonempty `operations` array. An HTTP operation uses either:

- `method` plus an exact `path`, or
- `methods` plus a trailing-slash `path_prefix`.

Supported methods are `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, and `DELETE`. Body policies are `none`, `json`, and `optional-json`. Response policies are `json`, `empty`, and `json-or-empty`.

The same compatibility rules apply to exact paths and path prefixes. `GET` and `HEAD` never accept a request body, so an operation containing either method cannot require `body: "json"`. An operation containing `HEAD` must use `response: "empty"` or `response: "json-or-empty"`; `response: "json"` is refused. These combinations are checked when the policy is loaded, and body rules are checked again for each request.

A 1Password operation contains only `command`, such as `{"command": "vault list"}`. HTTP profiles cannot contain command entries, and 1Password profiles cannot contain HTTP method/path entries. Mixing the two forms is rejected.

Origins must use HTTPS. For HTTP profiles, redirects are refused, TLS 1.2 or newer is required, request bodies are limited to 1 MiB, and responses are limited to 8 MiB. The 1Password adapter delegates its authenticated connection to the official CLI.

### 1Password service account commands

Download the macOS CLI from [1Password's installation instructions](https://www.1password.dev/cli/get-started) and follow its [authenticity verification instructions](https://www.1password.dev/cli/verify). Install the verified executable at the adapter's fixed location:

```sh
mkdir -p "$HOME/.local/share/keychain-api"
chmod 0700 "$HOME/.local/share/keychain-api"
install -m 0700 /path/to/verified/op "$HOME/.local/share/keychain-api/op"
```

Before reading the credential, the helper checks that the CLI is a regular, current-user-owned private file and verifies its Apple-anchored signature against 1Password's team identifier. Symlink executables are refused.

Add a profile to your private policy, replacing the example origin and Keychain references with your own values:

```json
"onepassword-api": {
  "origin": "https://your-team.1password.com",
  "credentials": [
    {
      "service": "com.example.keychain-api.onepassword",
      "account": "service-account",
      "type": "onepassword-service-account"
    }
  ],
  "operations": [
    {"command": "whoami"},
    {"command": "read"},
    {"command": "user get"},
    {"command": "user list"},
    {"command": "group get"},
    {"command": "group list"},
    {"command": "item template list"},
    {"command": "item template get"},
    {"command": "item list"},
    {"command": "item get"},
    {"command": "item create"},
    {"command": "item edit"},
    {"command": "item delete"},
    {"command": "item move"},
    {"command": "item share"},
    {"command": "vault list"},
    {"command": "vault get"},
    {"command": "vault create"},
    {"command": "vault delete"},
    {"command": "vault group list"},
    {"command": "vault group grant"},
    {"command": "vault group revoke"},
    {"command": "vault user list"},
    {"command": "vault user grant"},
    {"command": "vault user revoke"},
    {"command": "document list"},
    {"command": "document get"},
    {"command": "document create"},
    {"command": "document edit"},
    {"command": "document delete"},
    {"command": "service-account ratelimit"},
    {"command": "environment secret list"}
  ]
}
```

Each `operations` entry names an exact CLI command. Choose only the capabilities the profile needs; additional commands under supported API command families can be enabled in policy without changing the executable. Local execution, shell injection, plugin, updater, and session-management commands are excluded. This allowlist controls credential delivery, not authorization to perform a particular mutation. 1Password still enforces the service account's permissions and [supported command limitations](https://www.1password.dev/service-accounts/use-with-1password-cli).

A 1Password profile has exactly one credential and cannot use a SOCKS proxy. The token's embedded sign-in destination must match the policy's exact HTTPS hostname under `1password.com`, `1password.eu`, or `1password.ca`; custom ports and URL credentials, paths, queries, or fragments are refused. After an account URL changes, [rotate the service account token as required by 1Password](https://support.1password.com/change-sign-in-address/), store the replacement in Keychain, and update the private profile. The helper does not rewrite token contents or bypass destination validation.

```sh
keychain-api status onepassword-api
keychain-api authorize onepassword-api

response_dir="$(mktemp -d /private/tmp/keychain-api-response.XXXXXX)"
keychain-api op onepassword-api \
  --command 'vault list' \
  --secret-output-file "$response_dir/vaults.json"
```

Every `op` call requires a new `--secret-output-file`, including list operations whose names or metadata may be sensitive. JSON responses are preserved privately. Plaintext secret reads, document downloads, and other non-JSON output use a JSON envelope with `encoding: "base64"` and `data`. Empty successful output becomes `{"ok": true}`. Only the fixed file-write receipt is printed. Authentication-token echoes are refused.

For command arguments, supply `--args-file` referencing a private JSON array of **non-secret** strings. For example, item lookup arguments can be `["ITEM_ID", "--vault", "VAULT_ID", "--reveal"]`. Use full option names. Both split values and attached optional values such as `--generate-password=letters,digits,32` or `--favorite=false` are supported; the same flag and value restrictions apply to both forms. The helper rejects shell-style field assignments, stdin markers, short options, authentication/configuration overrides, arbitrary URLs, and direct input/output file flags. Secret references beginning with `op://` are accepted for `read`. Never put secret values in this argument array: its values become CLI process arguments.

For item creation or edits, supply the private JSON item template through `--input-file`. For document creation or edits, use `--input-file` for the document bytes. The helper makes a private temporary copy and passes only its path to the CLI. Document edits require the item ID/name as the first argument; optional metadata flags are `--vault`, `--title`, `--tags`, and `--file-name`. Other commands cannot accept an input file. Secret-bearing flags such as `--value`, `--password`, and `--notes` are refused; this adapter does not provide arbitrary CLI passthrough.

Both input files and argument files must be regular files owned by the current user, without group/other permissions or extended ACLs, inside owner-only directories. Symlinks in any path component and hard-linked input files are rejected. Input is parsed as data and never executed. Item templates and argument files are limited to 1 MiB; document inputs and CLI output are limited to 8 MiB. The final stored JSON is also limited to 8 MiB, so base64-wrapped binary content has a lower effective payload limit.

The helper supplies the token only in the CLI child's environment. It does not inherit proxy, session, alternate-account, debug, or TLS override variables. The CLI uses a private temporary configuration directory with caching disabled; the directory and copied input are removed when the command returns. An abrupt termination can leave that directory behind. Commands terminate after 40 seconds, with a forced stop after 45 seconds if necessary. Raw diagnostics are suppressed. A failed or timed-out mutation is indeterminate: inspect remote state before retrying. Output files are reserved before authentication and retained on failure as recovery evidence. If a failed, timed-out, or interrupted CLI command produced stdout, the helper saves the captured bytes privately after credential checks, within the output-size limit, and still returns failure. A complete-looking response does not establish that the command completed; check remote state before retrying.

To migrate an earlier 1Password profile, move each command string from `op_commands` into `operations` as a `{"command": "..."}` entry, then remove `op_commands` and the former `GET /user/me` operation. Both legacy forms are rejected. For an identity check, allow `{"command": "whoami"}` and run `keychain-api op` with `--command whoami` and a new `--secret-output-file`. Identity output stays protected like every other 1Password response; successful authentication does not establish administrator privileges or access to every vault.

Keep runtime policies, account URLs, Keychain contents, CLI binaries, and test responses outside Git. Only reusable source, inert tests, and generic documentation belong in this repository.

### Optional SOCKS proxy

On macOS 14 or newer, a profile can route its requests through a local SOCKSv5 listener, such as an SSH dynamic forward:

```json
"proxy": {
  "type": "socks5",
  "host": "127.0.0.1",
  "port": 49153
}
```

Start and stop the listener separately; the helper does not manage SSH sessions. The proxy host must be `127.0.0.1` and its port must be between 1024 and 65535. Proxy credentials and fallback/exclusion options are not accepted. Requests fail if the configured proxy is unavailable; direct fallback is disabled.

The original HTTPS origin, certificate validation, credential mapping, and operation allowlist still apply. Proxy mode requires a DNS origin and rejects IP literals, single-label names, and `.local`, `.localhost`, or `.localdomain` origins because macOS can bypass proxies for local destinations. A policy containing a proxy entry requires macOS 14 or newer. Profiles without a `proxy` field retain their existing transport behavior. No system proxy settings are changed.

## Add a Keychain item

The following command prompts for the credential instead of accepting it as a command-line argument. Keep `-w` as the final option:

```sh
security add-generic-password \
  -a "api-token" \
  -s "com.example.keychain-api.demo" \
  -T "" \
  -w
```

The `account` and `service` values must match the selected policy profile. Never pass a credential directly after `-w`, export it in your shell environment, or place it in shell history. The 1Password adapter manages the required child-only environment internally.

## Usage

Check whether a profile's Keychain items exist without reading them or using the network:

```sh
keychain-api status example-api
```

Request Keychain access without making a network request:

```sh
keychain-api authorize example-api
```

Perform an allowed request:

```sh
keychain-api request example-api \
  --method GET \
  --path '/v1/status'
```

Send non-secret JSON from a file:

```sh
keychain-api request example-api \
  --method POST \
  --path '/v1/items' \
  --body-file examples/request-body.json
```

The example origin is intentionally non-routable. Replace it with the exact trusted API origin before making a request.

## Output behavior

For HTTP profiles, successful responses are emitted as formatted, sanitized JSON. The client rejects unsafe redirects, origin changes, unexpected media types, non-2xx responses, invalid JSON, and responses containing the configured request credentials. Recognized sensitive fields and credential-shaped values are redacted from normal output. Errors are deliberately terse to reduce accidental disclosure. Redaction is defense in depth: arbitrary free-form response content is not guaranteed safe to print. The 1Password adapter always saves output privately and prints only a protected-file receipt on success.

JSON credential checks require UTF-8 without NUL bytes. They inspect decoded string literals before parsing the object, so duplicate member names cannot hide an escaped authentication credential. Accepted protected responses retain their original bytes.

This UTF-8 restriction also applies when `read` or `document get` returns content recognized as JSON: UTF-16/32 JSON documents are refused. Other binary output remains preserved in its base64 envelope.

### Opt-in protected JSON file

Use `--secret-output-file` when an authorized API operation returns a sensitive response that must not appear in terminal output. It uses the same transport and reusable policy profile; it does not require a provider-specific helper, change authentication, or expand the allowed origin, methods, or paths. The example profile targets the reserved origin `https://api.example.invalid`.

```sh
response_dir="$(mktemp -d /private/tmp/keychain-api-response.XXXXXX)"
keychain-api request example-api \
  --method POST \
  --path '/v1/items' \
  --body-file examples/request-body.json \
  --secret-output-file "$response_dir/response.json"
```

The helper reserves a new file before reading Keychain credentials or making a network request. It requires:

- An absolute path without traversal, repeated separators, or symlinks in any component. On macOS, use `/private/tmp` rather than the `/tmp` symlink.
- An existing directory owned by the current user, with no group/other permissions or extended ACL entries; mode `0700` is appropriate. Ancestors must be owned by root or the current user and must not be group/other writable unless sticky.
- A new regular output file, created exclusively with mode `0600`, owned by the current user, with one hard link and no extended ACL entries. Existing files are never overwritten.
- A `json` or `json-or-empty` response policy. A successful write requires a nonempty valid JSON response; an empty response is not a successful secret-file write.

On success, the file contains the **entire JSON response**, before normal output redaction, not just a selected token field. Responses echoing the configured request credentials are still rejected. Successful persistence prints only this fixed receipt; no response fields or file contents are printed:

```json
{
  "ok": true,
  "secret_output": false,
  "secret_output_file_written": true
}
```

Here, `secret_output: false` means the secret was not emitted to standard output, not that the file lacks secrets. Without the option, normal response output is unchanged.

The saved file is **plaintext**, not an encrypted store or a Keychain item. Permissions do not protect it from root or other processes running as the same user. Keep it outside repositories and shared/synced directories; do not print it, attach it to reports, or pass its contents in command arguments. After secure delivery to the intended consumer, remove the exact file when it is no longer needed; deletion is not a guarantee of secure erasure or removal from backups.

An error can leave an empty, partial, or complete file, which is deliberately retained. File existence does not prove successful persistence, and a missing success receipt does not prove that a remote mutation failed. Do not automatically retry a timeout, interrupted response, or persistence error. Check remote state without exposing secrets before deciding on recovery or another request.

If an HTTP response stream is interrupted or exceeds the size limit while being read, received bytes up to the 8 MiB limit are saved to the protected output after credential checks. Complete JSON must pass the normal credential checks. Incomplete JSON is retained only when it is UTF-8 and contains no NUL or backslash bytes; otherwise the output is refused. The command still exits with code `5` and prints no success receipt. Retained bytes are recovery evidence and may be incomplete or invalid JSON, not proof that a mutation succeeded.

### Offline self-test

`self-test` performs no Keychain read and no network request:

```sh
keychain-api self-test
```

It uses inert fixtures to check response redaction and policy validation, protected-file contents and receipt isolation, refusal of existing files, repeated commits, relative/traversing paths, symlink files/directories, and nonprivate directories. It also checks that an existing file remains unchanged, validates proxy policy, and verifies that supported proxy sessions disable direct fallback.

Command dispatch tests exercise production argument handling and authorization with inert credential and subprocess fixtures. They check refusal before credential access or process execution, fixed success receipts, failure exit codes, diagnostic suppression, and retained recovery output. Authentication checks also cover supported HTTP header schemes, conflicting credentials, 1Password destination mismatches, service account token misuse as an HTTP header, unsafe argument overrides, protected inputs, binary response preservation, environment isolation, and cleanup.

Deterministic HTTP fixtures exercise request construction, response validation, redaction, protected receipts, interrupted responses, bounded overflow recovery, and refusal of authentication credential echoes. Shared JSON checks cover escaped strings, duplicate member names, and non-UTF-8 encodings. Shared bounded-read tests cover complete input and size-limited partial capture. A targeted manual mutation removing the CLI command allowlist check was caught by the dispatch tests; this is not comprehensive mutation analysis. These checks are not a formal security audit and do not simulate every filesystem, race, or transport failure.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Success |
| `1` | Safe fallback for an unexpected failure |
| `2` | Invalid command, arguments, or unknown profile |
| `3` | Invalid policy, local JSON input, or protected-file destination |
| `4` | Keychain lookup or authorization failure |
| `5` | HTTPS transport, API response, or secret-response persistence failure |

## Limitations

- macOS only.
- JSON APIs and policy-approved 1Password CLI service account operations only.
- The HTTP transport has no redirects, cookies, streaming responses, or arbitrary request headers.
- 1Password capabilities depend on the installed CLI and service account permissions. Local process-execution commands and secret-bearing command arguments are excluded. Its child environment is not protected from root or other processes running as the same user.
- Explicit proxy support is limited to a loopback SOCKSv5 listener on macOS 14 or newer.
- Response redaction is defense in depth, not a substitute for a narrowly scoped policy and API credential.

See [SECURITY.md](SECURITY.md) before using the tool with sensitive accounts.
