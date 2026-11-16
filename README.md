# keychain-api

`keychain-api` is a policy-constrained credential client for macOS. Its HTTPS transport reads an API credential from the login Keychain and places it in an approved request header without printing it or putting it in a process argument. By default, it emits a sanitized JSON response; an explicit protected-file option can save a sensitive JSON response without printing that response. A separate 1Password adapter supports a read-only service account identity check through the official CLI.

The executable is intentionally narrow. Every profile fixes the destination origin, authentication placement, allowed HTTP methods and paths, request-body policy, and response type.

## Requirements

- macOS 12 or newer; optional SOCKS proxy support requires macOS 14 or newer
- Xcode Command Line Tools with Swift 5.9 and the macOS 14 SDK or newer
- A generic-password item in the default login Keychain

The Swift source has no third-party dependencies. It uses Foundation, Security, LocalAuthentication, and Network. The optional 1Password adapter requires the official 1Password CLI.

## Build

Build an optimized executable with Swift Package Manager:

```sh
swift build --configuration release
swift run keychain-api self-test
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
make verify
make install PREFIX="$HOME/.local"
```

`make verify` applies and verifies an ad hoc hardened-runtime signature. Set `CODESIGN_IDENTITY` and `CODESIGN_IDENTIFIER` to use a different signing identity and identifier. `make install` signs and installs the executable with mode `0700`.

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
  Sources/KeychainAPI/KeychainAPI.swift \
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

## Policy

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
- `onepassword-service-account`: authenticates the identity-only CLI adapter described below; it cannot send the token as an HTTP header.

The actual password or token must never appear in the JSON policy.

### Operation rules

An operation uses either:

- `method` plus an exact `path`, or
- `methods` plus a trailing-slash `path_prefix`.

Supported methods are `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, and `DELETE`. Body policies are `none`, `json`, and `optional-json`. Response policies are `json`, `empty`, and `json-or-empty`.

Origins must use HTTPS. For HTTP profiles, redirects are refused, TLS 1.2 or newer is required, request bodies are limited to 1 MiB, and responses are limited to 8 MiB. The 1Password adapter delegates its authenticated connection to the official CLI.

### 1Password service account identity check

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
    {
      "method": "GET",
      "path": "/user/me",
      "body": "none",
      "response": "json"
    }
  ]
}
```

This profile permits exactly one credential and one operation: `GET /user/me`. This is a local adapter route mapped to `op user get --me`, not a public REST endpoint. Proxies, request bodies, other operations, and `--secret-output-file` are rejected. The token's embedded sign-in destination must match the policy's exact HTTPS hostname under `1password.com`, `1password.eu`, or `1password.ca`; custom ports and URL credentials, paths, queries, or fragments are refused.

```sh
keychain-api status onepassword-api
keychain-api authorize onepassword-api
keychain-api request onepassword-api --method GET --path /user/me
```

The helper supplies the token only in the CLI child's environment. It does not inherit proxy, session, alternate-account, debug, or TLS override variables. The CLI uses a private temporary configuration directory with caching disabled; the directory is removed when the request returns. An abrupt process termination can leave that directory behind. Requests terminate after 40 seconds, with a forced stop after 45 seconds if necessary. Output is capped at 8 MiB, raw diagnostics are suppressed, and only a fixed summary of authentication, service account type, and enumerated account state is printed. An `ACTIVE` result confirms authentication; it does not establish administrator privileges or access to every vault.

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

For HTTP profiles, successful responses are emitted as formatted, sanitized JSON. The client rejects unsafe redirects, origin changes, unexpected media types, non-2xx responses, invalid JSON, and responses containing the configured request credentials. Recognized sensitive fields and credential-shaped values are redacted from normal output. Errors are deliberately terse to reduce accidental disclosure. Redaction is defense in depth: arbitrary free-form response content is not guaranteed safe to print. The 1Password adapter instead emits only the fixed identity summary described above.

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
- A `json` or `json-or-empty` response policy and a nonempty valid JSON response. An empty response is not a successful secret-file write.

The file contains the **entire JSON response**, before normal output redaction, not just a selected token field. Responses echoing the configured request credentials are still rejected. Successful persistence prints only this fixed receipt; no response fields or file contents are printed:

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

### Offline self-test

`self-test` performs no Keychain read and no network request:

```sh
keychain-api self-test
```

It uses inert fixtures to check response redaction and policy validation, protected-file contents and receipt isolation, refusal of existing files, repeated commits, relative/traversing paths, symlink files/directories, and nonprivate directories. It also checks that an existing file remains unchanged, validates proxy policy, and verifies that supported proxy sessions disable direct fallback. Authentication checks cover supported HTTP header schemes, conflicting credentials, 1Password destination mismatches, attempts to send a service account token as an HTTP header, and routes outside the identity-only policy. These checks are not a formal security audit and do not simulate every filesystem, race, or transport failure.

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
- JSON APIs and the limited 1Password identity adapter only.
- The HTTP transport has no redirects, cookies, streaming responses, or arbitrary request headers.
- The 1Password adapter cannot read vault contents or perform administrative operations. Its child environment is not protected from root or other processes running as the same user.
- Explicit proxy support is limited to a loopback SOCKSv5 listener on macOS 14 or newer.
- Response redaction is defense in depth, not a substitute for a narrowly scoped policy and API credential.

See [SECURITY.md](SECURITY.md) before using the tool with sensitive accounts.
