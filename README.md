# RustDrop

A local network file transfer CLI application, inspired by AirDrop and LocalSend. Written in Rust with async support.

## Features

- **Peer Discovery**: Automatic discovery of devices on the local network using UDP broadcast
- **Secure Transfers**: All file transfers are encrypted using TLS with self-signed certificates
- **CLI Interface**: Simple command-line interface for sending and receiving files
- **Cross-Platform**: Works on Linux, macOS, and Windows

## Installation

```bash
cargo install --path .
```

Or build from source:

```bash
cargo build --release
```

## Usage

### Listen for incoming files

Start in listen mode to discover peers and receive files:

```bash
rustdrop listen
```

With auto-accept for all incoming transfers:

```bash
rustdrop listen --accept-all
```

### Send a file

Send a file to a discovered peer:

```bash
rustdrop send myfile.zip
```

Send to a specific peer:

```bash
rustdrop send myfile.zip --to "Laptop"
```

### List discovered peers

Show all devices on the network:

```bash
rustdrop list-peers
```

Watch mode (continuous scanning):

```bash
rustdrop list-peers --watch
```

### Manage identity

Show certificate information:

```bash
rustdrop identity
```

Regenerate certificate:

```bash
rustdrop identity --regenerate
```

## Command Reference

```
rustdrop [OPTIONS] <COMMAND>

Commands:
  send        Send a file to a peer
  receive     Start receiving mode (listen for incoming transfers)
  listen      Listen for peers and accept transfers (combined mode)
  list-peers  List discovered peers on the network
  identity    Generate or show identity certificate info

Options:
  -n, --device-name <NAME>  Device name to announce on the network
  -p, --port <PORT>         Port for file transfers [default: 9000]
  -v, --verbose             Enable verbose output
  -h, --help                Print help
  -V, --version             Print version
```

## How It Works

### Discovery

1. Each instance broadcasts its presence via UDP on port 8765
2. Announcements include: device name, transfer port, protocol version, and certificate fingerprint
3. Peers are automatically discovered and tracked
4. Inactive peers are removed after 10 seconds of inactivity

### File Transfer

1. Sender connects to receiver via TCP on the advertised transfer port
2. TLS handshake establishes encrypted connection
3. Sender sends transfer request (filename, size)
4. Receiver accepts or rejects the transfer
5. File data is sent in 64KB chunks
6. Transfer completion is confirmed

## Configuration

Default settings:
- Discovery port: 8765 (UDP)
- Transfer port: 9000 (TCP)
- Download directory: ~/Downloads

Certificates are stored in:
- Linux: `~/.local/share/rustdrop/certs/`
- macOS: `~/Library/Application Support/com.rustdrop.RustDrop/certs/`
- Windows: `C:\Users\<user>\AppData\Roaming\rustdrop\RustDrop\data\certs\`

## Development

Run tests:

```bash
cargo test
```

Run with debug output:

```bash
cargo run -- --verbose listen
```

## License

MIT License

## Author

Amine
