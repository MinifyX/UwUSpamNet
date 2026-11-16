//! `uwuspamnet` — serve, or look after the service from a shell on the box.

use clap::{Parser, Subcommand};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;
use uwuspamnet::{api, db, rfc3339, AppState, Clock, Config};

#[derive(Parser)]
#[command(
    name = "uwuspamnet",
    version,
    about = "Shared spam signals for mail servers"
)]
struct Cli {
    /// Directory for the database.
    #[arg(long, env = "SPAMNET_DATA", default_value = "data", global = true)]
    data: PathBuf,
    /// Address to listen on.
    #[arg(
        long,
        env = "SPAMNET_LISTEN",
        default_value = "127.0.0.1:8080",
        global = true
    )]
    listen: SocketAddr,
    /// Take the client address from X-Forwarded-For (only behind your own reverse proxy).
    #[arg(long, env = "SPAMNET_TRUST_FORWARDED", global = true)]
    trust_forwarded: bool,
    /// Reports one server may send per UTC day.
    #[arg(
        long,
        env = "SPAMNET_REPORTS_PER_DAY",
        default_value_t = 5000,
        global = true
    )]
    reports_per_day: u32,
    /// Registrations one client IP may make per UTC day.
    #[arg(
        long,
        env = "SPAMNET_REGISTRATIONS_PER_IP",
        default_value_t = 5,
        global = true
    )]
    registrations_per_ip: u32,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the API. The default.
    Serve,
    /// List the registered servers.
    Servers,
    /// Ban a server: its reports stop counting and its key stops working.
    Ban { server: String },
    /// Lift a ban.
    Unban { server: String },
    /// Entries that are never listed.
    Allowlist {
        #[command(subcommand)]
        command: Allow,
    },
    /// Counts of servers, reports and listed entries.
    Stats,
    /// Ask the running service whether it is well (the container's health check).
    Health,
}

#[derive(Subcommand)]
enum Allow {
    /// Add an entry: kind is digest, domain, ip (address or CIDR) or from.
    Add {
        kind: String,
        value: String,
        #[arg(long, default_value = "")]
        note: String,
    },
    /// Remove an entry.
    Remove { kind: String, value: String },
    /// Show all entries.
    List,
}

fn open(cli: &Cli) -> Result<rusqlite::Connection, String> {
    std::fs::create_dir_all(&cli.data).map_err(|e| format!("{}: {e}", cli.data.display()))?;
    db::open(&cli.data.join("spamnet.db")).map_err(|e| format!("database: {e}"))
}

fn now() -> i64 {
    Clock::default().now()
}

fn health(listen: SocketAddr) -> Result<(), String> {
    let mut addr = listen;
    if addr.ip().is_unspecified() {
        addr.set_ip(if addr.is_ipv4() {
            [127, 0, 0, 1].into()
        } else {
            std::net::Ipv6Addr::LOCALHOST.into()
        });
    }
    let mut stream =
        TcpStream::connect_timeout(&addr, Duration::from_secs(5)).map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    write!(
        stream,
        "GET /v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .map_err(|e| e.to_string())?;
    let mut answer = String::new();
    stream
        .read_to_string(&mut answer)
        .map_err(|e| e.to_string())?;
    if answer.starts_with("HTTP/1.1 200") {
        Ok(())
    } else {
        Err(answer.lines().next().unwrap_or("no answer").to_string())
    }
}

async fn serve(cli: &Cli, config: Config) -> Result<(), String> {
    let conn = open(cli)?;
    let state = AppState::new(conn, config, Clock::default());
    let listener = tokio::net::TcpListener::bind(cli.listen)
        .await
        .map_err(|e| format!("{}: {e}", cli.listen))?;
    tracing::info!(listen = %cli.listen, "serving");
    let app = api::router(state).into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let ctrl_c = tokio::signal::ctrl_c();
            #[cfg(unix)]
            {
                let mut term =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("SIGTERM handler");
                tokio::select! { _ = ctrl_c => {}, _ = term.recv() => {} }
            }
            #[cfg(not(unix))]
            let _ = ctrl_c.await;
        })
        .await
        .map_err(|e| e.to_string())
}

fn run(cli: Cli) -> Result<(), String> {
    let sql = |e: rusqlite::Error| e.to_string();
    match &cli.command {
        None | Some(Command::Serve) => serve_blocking(
            &cli,
            Config {
                trust_forwarded: cli.trust_forwarded,
                reports_per_day: cli.reports_per_day,
                registrations_per_ip: cli.registrations_per_ip,
            },
        ),
        Some(Command::Health) => health(cli.listen),
        Some(Command::Servers) => {
            for s in db::servers(&open(&cli)?).map_err(sql)? {
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}{}",
                    s.id,
                    s.name,
                    s.software,
                    s.contact.unwrap_or_default(),
                    s.reg_net,
                    rfc3339(s.created),
                    if s.banned { "\tbanned" } else { "" }
                );
            }
            Ok(())
        }
        Some(Command::Ban { server }) | Some(Command::Unban { server }) => {
            let ban = matches!(cli.command, Some(Command::Ban { .. }));
            if db::set_banned(&mut open(&cli)?, server, ban, now()).map_err(sql)? {
                println!("{server} {}", if ban { "banned" } else { "unbanned" });
                Ok(())
            } else {
                Err(format!("no server {server}"))
            }
        }
        Some(Command::Allowlist { command }) => {
            let mut conn = open(&cli)?;
            match command {
                Allow::Add { kind, value, note } => {
                    let value = db::allowlist_value(kind, value)
                        .ok_or_else(|| format!("not a valid {kind} value: {value}"))?;
                    db::allowlist_add(&mut conn, kind, &value, note, now()).map_err(sql)?;
                    println!("allowed {kind} {value}");
                }
                Allow::Remove { kind, value } => {
                    let value = db::allowlist_value(kind, value).unwrap_or(value.clone());
                    if !db::allowlist_remove(&mut conn, kind, &value, now()).map_err(sql)? {
                        return Err(format!("{kind} {value} is not on the allowlist"));
                    }
                    println!("removed {kind} {value}");
                }
                Allow::List => {
                    for (kind, value, note) in db::allowlist(&conn).map_err(sql)? {
                        println!("{kind}\t{value}\t{note}");
                    }
                }
            }
            Ok(())
        }
        Some(Command::Stats) => {
            for (name, n) in db::stats(&open(&cli)?).map_err(sql)? {
                println!("{name}: {n}");
            }
            Ok(())
        }
    }
}

fn serve_blocking(cli: &Cli, config: Config) -> Result<(), String> {
    tokio::runtime::Runtime::new()
        .map_err(|e| e.to_string())?
        .block_on(serve(cli, config))
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "uwuspamnet=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("uwuspamnet: {err}");
            ExitCode::FAILURE
        }
    }
}
