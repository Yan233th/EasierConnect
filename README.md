# EasierConnect

An open-source implementation of the EasyConnect VPN client, written in Go.

## Features

- Cross-platform support (Windows, Linux, macOS)
- SOCKS5 proxy for routing traffic through VPN
- SMS and TOTP two-factor authentication support
- Colored terminal output with `--no-color` option

## Usage

```bash
EasierConnect --server vpn.example.com --username user --password pass
```

### Options

| Flag | Description |
|------|-------------|
| `--server` | EasyConnect server address |
| `--username` | Your username |
| `--password` | Your password |
| `--socks-bind` | SOCKS5 server bind address (default: `:1080`) |
| `--totp-key` | TOTP key for automatic 2FA code generation |
| `--no-color` | Disable colored output |

## Alternatives

- [docker-easyconnect](https://github.com/Hagb/docker-easyconnect) - Run EasyConnect in Docker container
