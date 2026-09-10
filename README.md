# keychain-api

`keychain-api` is a policy-constrained HTTPS client for macOS. It reads an API credential from the login Keychain and places it in an approved request header without printing it or putting it in a process argument. By default, it emits a sanitized JSON response; an explicit protected-file option can save a sensitive JSON response without printing that response.

The executable is intentionally narrow. Every profile fixes the destination origin, authentication placement, allowed HTTP methods and paths, request-body policy, and response type.

## Requirements

- macOS 12 or newer
- Xcode Command Line Tools with Swift 5.7 or newer
- A generic-password item in the default login Keychain

The current source has no third-party dependencies. It uses Foundation, Security, and LocalAuthentication.

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
- `basic`: requires a policy `username` and sends HTTP Basic authentication.
- `header`: requires an allowed custom `header` and accepts an optional `prefix`.

The actual password or token must never appear in the JSON policy.

### Operation rules

An operation uses either:

- `method` plus an exact `path`, or
- `methods` plus a trailing-slash `path_prefix`.

Supported methods are `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, and `DELETE`. Body policies are `none`, `json`, and `optional-json`. Response policies are `json`, `empty`, and `json-or-empty`.

Origins must use HTTPS. Redirects are refused, TLS 1.2 or newer is required, request bodies are limited to 1 MiB, and responses are limited to 8 MiB.

## Add a Keychain item

The following command prompts for the credential instead of accepting it as a command-line argument. Keep `-w` as the final option:

```sh
security add-generic-password \
  -a "api-token" \
  -s "com.example.keychain-api.demo" \
  -T "" \
  -w
```

The `account` and `service` values must match the selected policy profile. Never pass a credential directly after `-w`, store it in an environment variable, or place it in shell history.

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

By default, successful responses are emitted as formatted, sanitized JSON. The client rejects unsafe redirects, origin changes, unexpected media types, non-2xx responses, invalid JSON, and responses containing the configured request credentials. Recognized sensitive fields and credential-shaped values are redacted from normal output. Errors are deliberately terse to reduce accidental disclosure. Redaction is defense in depth: arbitrary free-form response content is not guaranteed safe to print.

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

It uses inert fixtures to check response redaction and policy validation, protected-file contents and receipt isolation, refusal of existing files, repeated commits, relative/traversing paths, symlink files/directories, and nonprivate directories. It also checks that an existing file remains unchanged. These checks are not a formal security audit and do not simulate every filesystem, race, or transport failure.

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
- JSON APIs only.
- No redirects, cookies, proxies configured by this tool, streaming responses, or arbitrary request headers.
- Response redaction is defense in depth, not a substitute for a narrowly scoped policy and API credential.

See [SECURITY.md](SECURITY.md) before using the tool with sensitive accounts.
