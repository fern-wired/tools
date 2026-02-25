use std::io::{Read, Write};
use std::net::{TcpStream, SocketAddr};
use std::time::Duration;
use std::sync::{Arc, Mutex};
use std::thread;
use clap::Parser;

#[derive(Parser)]
#[command(name = "rustscanner")]
#[command(about = "A fast TCP port scanner with banner grabbing and service fingerprinting")]
struct Cli {
    #[arg(short = 't', long, default_value = "127.0.0.1")]
    target: String,

    #[arg(short = 's', long, default_value_t = 1)]
    start: u16,

    #[arg(short = 'e', long, default_value_t = 1024)]
    end: u16,

    #[arg(short = 'm', long, default_value_t = 500)]  // 'm' for milliseconds
    timeout: u64,
}

fn scan_port(ip: &str, port: u16, timeout_ms: u64) -> Option<TcpStream> {
    let address = format!("{}:{}", ip, port);
    let socket_addr: SocketAddr = match address.parse() {
        Ok(addr) => addr,
        Err(_) => return None,
    };

    TcpStream::connect_timeout(&socket_addr, Duration::from_millis(timeout_ms)).ok()
}

fn grab_banner(stream: &mut TcpStream, port: u16) -> Option<String> {
    stream.set_read_timeout(Some(Duration::from_millis(1000))).ok();

    let probe = match port {
        80 | 8080 | 443 => "HEAD / HTTP/1.0\r\n\r\n",
        631 => "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        _ => "",
    };

    if !probe.is_empty() {
        if stream.write_all(probe.as_bytes()).is_err() {
            return None;
        }
    }

    let mut banner = vec![0u8; 1024];
    match stream.read(&mut banner) {
        Ok(n) if n > 0 => {
            let text = String::from_utf8_lossy(&banner[..n]).to_string();
            let server_line = text.lines()
                .find(|l| l.to_lowercase().starts_with("server:"))
                .or_else(|| text.lines().next())
                .unwrap_or("")
                .trim()
                .to_string();

            if server_line.is_empty() { None } else { Some(server_line) }
        }
        _ => None,
    }
}

fn fingerprint(port: u16, banner: &Option<String>) -> String {
    let signatures: &[(&str, &str)] = &[
        ("SSH",           "SSH"),
        ("FTP",           "FTP"),
        ("SMTP",          "SMTP"),
        ("POP3",          "POP3"),
        ("IMAP",          "IMAP"),
        ("CUPS",          "CUPS (Print Server)"),
        ("Apache",        "HTTP (Apache)"),
        ("openresty", "HTTP (OpenResty/nginx)"),
        ("nginx",         "HTTP (nginx)"),
        ("Microsoft-IIS", "HTTP (IIS)"),
        ("HTTP/1.",       "HTTP"),
        ("RFB",           "VNC"),
        ("MySQL",         "MySQL"),
        ("PostgreSQL",    "PostgreSQL"),
        ("redis",         "Redis"),
        ("Telnet",        "Telnet"),
    ];

    let port_hints: &[(u16, &str)] = &[
        (21,   "FTP"),
        (22,   "SSH"),
        (23,   "Telnet"),
        (25,   "SMTP"),
        (53,   "DNS"),
        (80,   "HTTP"),
        (110,  "POP3"),
        (143,  "IMAP"),
        (443,  "HTTPS"),
        (445,  "SMB"),
        (3306, "MySQL"),
        (5432, "PostgreSQL"),
        (6379, "Redis"),
        (5900, "VNC"),
        (631,  "CUPS (Print Server)"),
        (8080, "HTTP (alt)"),
    ];

    if let Some(b) = banner {
        let b_lower = b.to_lowercase();
        for (pattern, label) in signatures {
            if b_lower.contains(&pattern.to_lowercase()) {
                return label.to_string();
            }
        }
    }

    for (p, label) in port_hints {
        if *p == port {
            return format!("{} (port-based guess)", label);
        }
    }

    "Unknown".to_string()
}

fn main() {
    let cli = Cli::parse();

    // Validate port range
    if cli.start > cli.end {
        eprintln!("Error: start port must be less than or equal to end port");
        std::process::exit(1);
    }

    println!("Scanning {} ports {} to {} (timeout: {}ms)...\n",
        cli.target, cli.start, cli.end, cli.timeout);

    let results: Arc<Mutex<Vec<(u16, Option<String>)>>> = Arc::new(Mutex::new(Vec::new()));
    let mut handles = vec![];

    for port in cli.start..=cli.end {
        let target = cli.target.clone();
        let timeout = cli.timeout;
        let results = Arc::clone(&results);

        let handle = thread::spawn(move || {
            if let Some(mut stream) = scan_port(&target, port, timeout) {
                let banner = grab_banner(&mut stream, port);
                let mut data = results.lock().unwrap();
                data.push((port, banner));
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let mut data = results.lock().unwrap();
    data.sort_by_key(|(port, _)| *port);

    if data.is_empty() {
        println!("No open ports found.");
        return;
    }

    println!("{:<8} {:<25} {}", "PORT", "SERVICE", "BANNER");
    println!("{}", "-".repeat(80));

    for (port, banner) in data.iter() {
        let service = fingerprint(*port, banner);
        let banner_str = banner.as_deref().unwrap_or("none");
        println!("{:<8} {:<25} {}", port, service, banner_str);
    }

    println!("\nScan complete. {} open port(s) found.", data.len());
}