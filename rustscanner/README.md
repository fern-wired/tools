# rustscanner
Multithreaded TCP port scanner with banner grabbing and service fingerprinting written in Rust.

Built this as a project alongside coursework in Penetration Testing & Vulnerability Analysis at NYU Tandon School of Engineering. My goal was to learn Rust concepts.

# Features
- TCP connect scanning across any port range.
- Banner grabbing captures service responses on open ports.
- Service fingerprinting identifies services by signatures.
- Multithreaded
- CLI arguments

# Example Output
```
Scanning 10.10.10.10 ports 1 to 1024 (timeout: 500ms)...

PORT     SERVICE                   BANNER
--------------------------------------------------------------------------------
22       SSH                       SSH-2.0-OpenSSH_10.0p2 Debian-7
80       HTTP (OpenResty/nginx)    Server: openresty
443      HTTP (OpenResty/nginx)    Server: openresty

Scan complete. 3 open port(s) found.
```

# Installation
Install Rust via rustup:
`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

Clone and build:
```bash
git clone https://github.com/yourusername/tools.git
cd tools/rustscanner
cargo build --release
```

# Usage
```
rustscanner [OPTIONS]

Options:
  -t, --target <TARGET>    Target IP address [default: 127.0.0.1]
  -s, --start <START>      Start port [default: 1]
  -e, --end <END>          End port [default: 1024]
  -m, --timeout <TIMEOUT>  Connection timeout in milliseconds [default: 500]
  -h, --help               Print help
```

# Detected Services
Banner-based fingerprinting supports:
- SSH
- FTP
- SMTP
- POP3
- IMAP
- HTTP
- CUPS
- VNC
- MySQL
- PostgreSQL
- Redis
- Telnet

# Roadmap
- JSON output flag
- CIDR range support
- UDP scan mode
- CVE lookup integration
- OS fingerprinting

# Disclaimer
This tool is intended for authorized security testing, educational use, and personal lab environments only.

