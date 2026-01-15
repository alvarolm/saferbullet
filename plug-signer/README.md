# plug-signer

Simple CLI utility for signing SilverBullet plugins.

## Installation

```bash
cd plug-signer
go build
```

Or install to `$GOPATH/bin`:

```bash
go install
```

## Usage

```bash
plug-signer my-plugin.plug.js --key ~/.minisign/mykey.key
```

The utility will:
1. Remove any existing signature from the plugin
2. Sign the plugin content with the provided minisign key
3. Embed the signature as a comment at the top of the file
4. Write the signed plugin (overwrites input file by default)

## Options

| Flag | Short | Description |
|------|-------|-------------|
| `--key` | `-k` | Path to minisign private key file (required) |
| `--password` | `-p` | Password for encrypted key (prompts if not provided) |
| `--output` | `-o` | Output file path (default: overwrite input) |
| `--force` | `-f` | Skip overwrite confirmation |
| `--protocol` | `-r` | Signing protocol to use (default: minisign) |

## Examples

Basic signing (will prompt for password):
```bash
plug-signer my-plugin.plug.js --key ~/.minisign/mykey.key
```

Sign with password from environment variable:
```bash
plug-signer my-plugin.plug.js -k mykey.key -p "$MINISIGN_PASSWORD"
```

Sign and output to a different file:
```bash
plug-signer my-plugin.plug.js -k mykey.key -o signed-plugin.plug.js
```

Skip overwrite confirmation:
```bash
plug-signer my-plugin.plug.js -k mykey.key -f
```

Sign with explicit protocol:
```bash
plug-signer my-plugin.plug.js -k mykey.key --protocol minisign
```

## Generating Keys

Use the standard minisign tool to generate keys:

```bash
minisign -G -p mykey.pub -s mykey.key
```

Or use any minisign-compatible key generation tool.

## Signature Format

The signature is embedded as a JavaScript comment at the top of the plugin file:

```javascript
// signature|<protocol>|<base64-public-key>: <base64-signature>
<plugin code>
```

- signature - constant, signature indicator
- `<protocol>` - The signing protocol (currently only minisign is supported, configurable via --protocol flag)
- `<base64-public-key>` - Base64-encoded minisign public key in text format
- `<base64-signature>` - Base64-encoded minisign signature

## Running Tests

```bash
go test -v
```
