# keychain-api

`keychain-api` is a policy-constrained HTTPS client for macOS. It reads API credentials from the login Keychain and sends them in approved request headers. By default, it prints sanitized JSON. Use `--secret-output-file` to save a sensitive JSON response to a private file.

Each profile fixes the destination origin, credential mapping, allowed HTTP methods and paths, request-body rules, and expected response types.

## Requirements

- macOS 12 or newer; optional SOCKS proxy support requires macOS 14 or newer
- Xcode Command Line Tools with Swift 5.9 and the macOS 14 SDK or newer
- A generic-password item in the default login Keychain

The Swift source uses Foundation, Security, LocalAuthentication, and Network and has no third-party dependencies.

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
make version
make verify
make dist
make install PREFIX="$HOME/.local"
```

`make test` runs the self-test in `CONFIGURATION` (release by default). `make version` builds in that configuration and prints the compiled version. `make verify` strips debug and local symbols, then applies and verifies an ad hoc hardened-runtime signature. Set `CODESIGN_IDENTITY` and `CODESIGN_IDENTIFIER` to use a different signing identity and identifier. `make install` signs and installs the executable with mode `0700`.

`make dist` packages the verified release binary and writes its archive and SHA-256 checksum to `dist/`. The filename includes the compiled version and actual binary architecture: `keychain-api-<version>-macos-<architecture>.tar.gz`. Each archive contains only `keychain-api`, with neutral owner/group metadata and no macOS metadata or extended attributes. Packaging accepts a single `arm64` or `x86_64` architecture; it does not build the other architecture automatically.

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
strip -S -x build/keychain-api
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
| `Keychain.swift` | Keychain access |
| `ProtectedFiles.swift` | File validation, bounded reads, and durable response files |
| `JSONSafety.swift` | Credential detection, JSON validation, and redaction |
| `Support.swift` | Shared errors, limits, and metadata checks |
| `Version.swift` | Compiled release version |
| `SelfTests.swift` | Offline checks run by `keychain-api self-test` |
| `CLISelfTests.swift` | Command dispatch, refusal ordering, and output checks |
| `HTTPTransportSelfTests.swift` | Deterministic HTTP response and recovery checks |

### Versions and releases

`keychain-api --version` prints the version alone and exits without reading policy or Keychain data. [Version.swift](Sources/KeychainAPI/Version.swift) is the only version source for Swift Package Manager and direct compiler builds. Change `ReleaseVersion.current` for a new release; archive filenames and tags are derived from the built executable.

Versions use `MAJOR.MINOR.PATCH`. Before `1.0.0`, increment the minor version for new capabilities or incompatible CLI/policy changes, and the patch version for compatible fixes. Do not move published tags or replace release assets; corrections get a new version.

After the release changes have landed as one signed squash commit, run the following from a clean checkout of the published `main` commit. The local signing key must be configured for Git, and the GitHub CLI must be authenticated:

```sh
make test
make dist
binary="$(swift build --configuration release --show-bin-path)/keychain-api"
version="$("$binary" --version)"
tag="v$version"
git tag --sign "$tag" --message "Release $tag"
git tag --verify "$tag"
git push origin "$tag"
gh release create "$tag" --verify-tag --title "$tag" --generate-notes \
  dist/keychain-api-"$version"-macos-*.tar.gz \
  dist/keychain-api-"$version"-macos-*.tar.gz.sha256
```

The signed tag identifies the source commit; `--verify-tag` prevents GitHub from creating a tag implicitly. GitHub supplies source archives separately. Binary assets are labeled by architecture, so an Apple silicon build does not imply an Intel or universal binary. Check an archive against its adjacent `.sha256` file with `shasum -a 256 -c` before extracting it.

The default executable signature is **ad hoc**, not a Developer ID signature, and the binary is not notarized. Git commit/tag GPG signatures and archive checksums are separate from macOS executable signing. A checksum verifies downloaded bytes; it is not a substitute for a trusted release source.

## Policy

The client uses three terms throughout this guide:

- A **profile** fixes a trusted origin, Keychain credential references, and allowed operations.
- An **operation** permits an HTTP method and path. Review each API mutation separately.
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

When upgrading to 0.2.0, remove profiles that list CLI commands from your private policy and keep your HTTPS profiles. The client validates every profile before using the selected one.

### Authentication types

Each credential entry references a macOS generic-password item by `service` and `account`:

- `bearer`: sends `Authorization: Bearer <credential>`.
- `api-key`: sends `Authorization: APIKey <credential>`.
- `basic`: requires a policy `username` and sends HTTP Basic authentication.
- `header`: requires an allowed custom `header` and accepts an optional `prefix`.

The actual password or token must never appear in the JSON policy.

### Operation rules

Every profile requires a nonempty `operations` array. An HTTP operation uses either:

- `method` plus an exact `path`, or
- `methods` plus a trailing-slash `path_prefix`.

Supported methods are `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, and `DELETE`. Body policies are `none`, `json`, and `optional-json`. Response policies are `json`, `empty`, and `json-or-empty`.

The same compatibility rules apply to exact paths and path prefixes. `GET` and `HEAD` never accept a request body, so an operation containing either method cannot require `body: "json"`. An operation containing `HEAD` must use `response: "empty"` or `response: "json-or-empty"`; `response: "json"` is refused. These combinations are checked when the policy is loaded, and body rules are checked again for each request.

Origins must use HTTPS with TLS 1.2 or newer. The client refuses redirects and limits request bodies to 1 MiB and responses to 8 MiB.

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

The `account` and `service` values must match the selected policy profile. Never pass a credential directly after `-w`, export it in your shell environment, or place it in shell history.

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

By default, successful requests print formatted, sanitized JSON. The client rejects redirects, origin changes, unexpected media types, non-2xx responses, invalid JSON, and responses containing the configured request credentials. It redacts recognized sensitive fields and credential-shaped values. Free-form response fields can still contain sensitive information.

JSON credential checks require UTF-8 without NUL bytes. They inspect decoded string literals before parsing the object, so duplicate member names cannot hide an escaped authentication credential. Accepted protected responses retain their original bytes.

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

Command dispatch tests exercise argument handling and authorization with inert fixtures. Authentication checks cover supported HTTP header schemes and conflicting credentials.

Deterministic HTTP fixtures exercise request construction, response validation, redaction, protected receipts, interrupted responses, bounded overflow recovery, and refusal of authentication credential echoes. JSON checks cover escaped strings, duplicate member names, and non-UTF-8 encodings.

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
- The HTTP transport has no redirects, cookies, streaming responses, or arbitrary request headers.
- Explicit proxy support is limited to a loopback SOCKSv5 listener on macOS 14 or newer.
- Response redaction is defense in depth, not a substitute for a narrowly scoped policy and API credential.

See [SECURITY.md](SECURITY.md) before using the tool with sensitive accounts.
