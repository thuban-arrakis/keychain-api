# keychain-api

`keychain-api` is a policy-constrained HTTPS client for macOS. It reads an API credential from the login Keychain, places it in an approved request header, and emits a sanitized JSON response without printing the credential or putting it in a process argument.

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

Successful responses are emitted as formatted JSON. The client rejects unsafe redirects, origin changes, unexpected media types, non-2xx responses, invalid JSON, and responses that contain the credential or recognizable credential material. Errors are deliberately terse to reduce accidental disclosure.

`self-test` performs no Keychain read and no network request:

```sh
keychain-api self-test
```

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Success |
| `1` | Safe fallback for an unexpected failure |
| `2` | Invalid command, arguments, or unknown profile |
| `3` | Invalid policy or local JSON input |
| `4` | Keychain lookup or authorization failure |
| `5` | HTTPS transport or API response failure |

## Limitations

- macOS only.
- JSON APIs only.
- No redirects, cookies, proxies configured by this tool, streaming responses, or arbitrary request headers.
- Response redaction is defense in depth, not a substitute for a narrowly scoped policy and API credential.

See [SECURITY.md](SECURITY.md) before using the tool with sensitive accounts.
