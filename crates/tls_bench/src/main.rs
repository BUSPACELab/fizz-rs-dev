//! Parametric echo benchmark: plain TCP vs tokio-rustls vs fizz-rs delegated TLS.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use fizz_rs::{
    Certificate, CertificatePublic, ClientTlsContext, CredentialGenerator, ServerTlsContext,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Backend {
    Tcp,
    Rustls,
    Fizz,
}

fn backend_csv(b: Backend) -> &'static str {
    match b {
        Backend::Tcp => "tcp",
        Backend::Rustls => "rustls",
        Backend::Fizz => "fizz",
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Preset {
    /// Few threads/connections, 16 KiB × 64 rounds (quick smoke)
    Small,
    /// Larger pool, 128 connections, 256 KiB batches — stress-style defaults
    Large,
}

impl Preset {
    fn params(self) -> (usize, usize, usize, usize, usize, usize) {
        match self {
            Preset::Small => (4, 512, 8, 16 * 1024, 64, 3),
            Preset::Large => (32, 2048, 128, 256 * 1024, 64, 5),
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "tls_bench",
    about = "Tokio TLS echo benchmark (tcp / rustls / fizz)"
)]
struct Cli {
    /// Which TLS (or TCP) stack to exercise
    #[arg(long, value_enum)]
    backend: Option<Backend>,

    /// Run tcp, rustls, and fizz sequentially for the same parameters (prints one CSV row each)
    #[arg(long, default_value_t = false)]
    all_backends: bool,

    #[arg(long, default_value_t = 4)]
    worker_threads: usize,

    #[arg(long, default_value_t = 512)]
    max_blocking_threads: usize,

    #[arg(long, default_value_t = 8)]
    connections: usize,

    #[arg(long, default_value_t = 16 * 1024)]
    batch_size: usize,

    #[arg(long, default_value_t = 64)]
    rounds: usize,

    /// Full benchmark iterations to discard before timing
    #[arg(long, default_value_t = 0)]
    warmup: usize,

    /// Measured iterations (median wall time reported)
    #[arg(long, default_value_t = 3)]
    runs: usize,

    #[arg(long, default_value_t = false)]
    csv_header: bool,

    /// Override --worker-threads, --max-blocking-threads, --connections, --batch-size, --rounds, and --runs
    #[arg(long, value_enum)]
    preset: Option<Preset>,
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn load_fizz_materials() -> Result<(
    CertificatePublic,
    fizz_rs::DelegatedCredentialData,
    fizz_rs::VerificationInfo,
    PathBuf,
)> {
    let dir = fixtures_dir();
    let cert_path = dir.join("fizz.crt");
    let key_path = dir.join("fizz.key");
    let cert = Certificate::load_from_files(
        cert_path.to_str().context("cert path utf-8")?,
        key_path.to_str().context("key path utf-8")?,
    )?;
    let cert_public =
        CertificatePublic::load_from_file(cert_path.to_str().context("cert path utf-8")?)?;
    let generator = CredentialGenerator::new(cert)?;
    let dc = generator.generate("tls-bench", 3600)?;
    let verification_info = dc.verification_info();
    Ok((cert_public, dc, verification_info, cert_path))
}

fn rustls_configs() -> Result<(Arc<ServerConfig>, Arc<ClientConfig>)> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|e| anyhow::anyhow!("rcgen: {e}"))?;
    let cert_der = CertificateDer::from(certified.cert.der().to_vec());
    let key_pkcs8 = PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], PrivateKeyDer::Pkcs8(key_pkcs8))
        .map_err(|e| anyhow::anyhow!("rustls server config: {e}"))?;

    let mut roots = RootCertStore::empty();
    roots
        .add(cert_der)
        .map_err(|e| anyhow::anyhow!("root store: {e}"))?;
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    Ok((Arc::new(server_config), Arc::new(client_config)))
}

async fn echo_server_tcp(
    listener: TcpListener,
    connections: usize,
    batch_size: usize,
    rounds: usize,
) -> Result<()> {
    let mut set = JoinSet::new();
    for _ in 0..connections {
        let (stream, _) = listener.accept().await?;
        set.spawn(async move { echo_serve(stream, batch_size, rounds).await });
    }
    while let Some(r) = set.join_next().await {
        r??;
    }
    Ok(())
}

async fn echo_client_tcp(
    addr: std::net::SocketAddr,
    batch_size: usize,
    rounds: usize,
) -> Result<()> {
    let stream = TcpStream::connect(addr).await?;
    echo_client(stream, batch_size, rounds).await
}

async fn echo_serve<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    mut stream: S,
    batch_size: usize,
    rounds: usize,
) -> Result<()> {
    let mut buf = vec![0u8; batch_size];
    for _ in 0..rounds {
        stream.read_exact(&mut buf).await?;
        stream.write_all(&buf).await?;
        stream.flush().await?;
    }
    Ok(())
}

async fn echo_client<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    mut stream: S,
    batch_size: usize,
    rounds: usize,
) -> Result<()> {
    let buf = vec![0x5Au8; batch_size];
    let mut read_back = vec![0u8; batch_size];
    for _ in 0..rounds {
        stream.write_all(&buf).await?;
        stream.flush().await?;
        stream.read_exact(&mut read_back).await?;
    }
    Ok(())
}

async fn run_tcp(connections: usize, batch_size: usize, rounds: usize) -> Result<()> {
    let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        addr_tx
            .send(addr)
            .map_err(|_| anyhow::anyhow!("bench: addr channel"))?;
        echo_server_tcp(listener, connections, batch_size, rounds).await
    });
    let addr = addr_rx
        .await
        .map_err(|_| anyhow::anyhow!("bench: server did not send addr"))?;
    let mut clients = JoinSet::new();
    for _ in 0..connections {
        clients.spawn(echo_client_tcp(addr, batch_size, rounds));
    }
    while let Some(r) = clients.join_next().await {
        r??;
    }
    server.await??;
    Ok(())
}

async fn run_rustls(
    connections: usize,
    batch_size: usize,
    rounds: usize,
    server_cfg: Arc<ServerConfig>,
    client_cfg: Arc<ClientConfig>,
) -> Result<()> {
    let acceptor = TlsAcceptor::from(server_cfg);
    let connector = TlsConnector::from(client_cfg);
    let dns = ServerName::try_from("localhost".to_string())
        .map_err(|_| anyhow::anyhow!("invalid ServerName"))?;

    let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        addr_tx
            .send(addr)
            .map_err(|_| anyhow::anyhow!("bench: addr channel"))?;

        let mut set = JoinSet::new();
        for _ in 0..connections {
            let (stream, _) = listener.accept().await?;
            let acceptor = acceptor.clone();
            set.spawn(async move {
                let tls = acceptor.accept(stream).await?;
                echo_serve(tls, batch_size, rounds).await
            });
        }
        while let Some(r) = set.join_next().await {
            r??;
        }
        Ok::<(), anyhow::Error>(())
    });

    let addr = addr_rx
        .await
        .map_err(|_| anyhow::anyhow!("bench: server did not send addr"))?;

    let mut clients = JoinSet::new();
    for _ in 0..connections {
        let connector = connector.clone();
        let dns = dns.clone();
        clients.spawn(async move {
            let tcp = TcpStream::connect(addr).await?;
            let tls = connector.connect(dns, tcp).await?;
            echo_client(tls, batch_size, rounds).await
        });
    }
    while let Some(r) = clients.join_next().await {
        r??;
    }
    server.await??;
    Ok(())
}

async fn run_fizz(
    connections: usize,
    batch_size: usize,
    rounds: usize,
    server_ctx: Arc<ServerTlsContext>,
    client_ctx: Arc<ClientTlsContext>,
) -> Result<()> {
    let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
    let ctx = server_ctx.clone();
    let server = tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        addr_tx
            .send(addr)
            .map_err(|_| anyhow::anyhow!("bench: addr channel"))?;

        let mut set = JoinSet::new();
        for _ in 0..connections {
            let (stream, _) = listener.accept().await?;
            let ctx = ctx.clone();
            set.spawn(async move {
                let tls = ctx.accept_from_stream(stream).await?;
                echo_serve(tls, batch_size, rounds).await
            });
        }
        while let Some(r) = set.join_next().await {
            r??;
        }
        Ok::<(), anyhow::Error>(())
    });

    let addr = addr_rx
        .await
        .map_err(|_| anyhow::anyhow!("bench: server did not send addr"))?;

    let mut clients = JoinSet::new();
    for _ in 0..connections {
        let ctx = client_ctx.clone();
        clients.spawn(async move {
            let tcp = TcpStream::connect(addr).await?;
            let tls = ctx.connect(tcp, "localhost").await?;
            echo_client(tls, batch_size, rounds).await
        });
    }
    while let Some(r) = clients.join_next().await {
        r??;
    }
    server.await??;
    Ok(())
}

async fn run_backend(
    backend: Backend,
    connections: usize,
    batch_size: usize,
    rounds: usize,
    rustls: Option<(Arc<ServerConfig>, Arc<ClientConfig>)>,
    fizz: Option<(Arc<ServerTlsContext>, Arc<ClientTlsContext>)>,
) -> Result<()> {
    match backend {
        Backend::Tcp => run_tcp(connections, batch_size, rounds).await,
        Backend::Rustls => {
            let (s, c) = rustls.as_ref().context("rustls configs missing")?;
            run_rustls(connections, batch_size, rounds, s.clone(), c.clone()).await
        }
        Backend::Fizz => {
            let (s, c) = fizz.as_ref().context("fizz contexts missing")?;
            run_fizz(connections, batch_size, rounds, s.clone(), c.clone()).await
        }
    }
}

fn median_ms(samples: &[Duration]) -> f64 {
    let mut ms: Vec<f64> = samples.iter().map(|d| d.as_secs_f64() * 1000.0).collect();
    ms.sort_by(f64::total_cmp);
    let mid = ms.len() / 2;
    if ms.is_empty() {
        return 0.0;
    }
    if ms.len() % 2 == 1 {
        ms[mid]
    } else {
        (ms[mid - 1] + ms[mid]) / 2.0
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let (worker_threads, max_blocking_threads, connections, batch_size, rounds, runs) =
        if let Some(preset) = cli.preset {
            let (w, mb, c, b, r, n) = preset.params();
            (w, mb, c, b, r, n)
        } else {
            (
                cli.worker_threads,
                cli.max_blocking_threads,
                cli.connections,
                cli.batch_size,
                cli.rounds,
                cli.runs,
            )
        };

    let backends: Vec<Backend> = if cli.all_backends {
        vec![Backend::Tcp, Backend::Rustls, Backend::Fizz]
    } else {
        vec![cli
            .backend
            .context("pass --backend or use --all-backends")?]
    };

    let rustls_cfgs = rustls_configs().ok();
    let fizz_ctxs = load_fizz_materials().ok().map(|(cp, dc, vi, ca_path)| {
        let server = ServerTlsContext::new(cp, dc).expect("fizz server ctx");
        let client = ClientTlsContext::new(vi, ca_path.to_str().unwrap()).expect("fizz client ctx");
        (Arc::new(server), Arc::new(client))
    });

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .max_blocking_threads(max_blocking_threads)
        .enable_all()
        .build()
        .context("tokio runtime")?;

    if cli.csv_header {
        println!(
            "backend,worker_threads,max_blocking_threads,connections,batch_size,rounds,wall_ms,total_bytes,mb_per_s,error"
        );
    }

    let total_bytes = 2u64
        .saturating_mul(connections as u64)
        .saturating_mul(rounds as u64)
        .saturating_mul(batch_size as u64);

    for backend in backends {
        if matches!(backend, Backend::Rustls) && rustls_cfgs.is_none() {
            eprintln!("rustls: skipping (failed to build configs)");
            println!(
                "{},{},{},{},{},{},,,,rustls_config_error",
                backend_csv(backend),
                worker_threads,
                max_blocking_threads,
                connections,
                batch_size,
                rounds
            );
            continue;
        }
        if matches!(backend, Backend::Fizz) && fizz_ctxs.is_none() {
            eprintln!(
                "fizz: skipping (failed to load {} — run from repo with tests/fixtures)",
                fixtures_dir().display()
            );
            println!(
                "{},{},{},{},{},{},,,,fizz_fixtures_error",
                backend_csv(backend),
                worker_threads,
                max_blocking_threads,
                connections,
                batch_size,
                rounds
            );
            continue;
        }

        for _ in 0..cli.warmup {
            let _ = runtime.block_on(run_backend(
                backend,
                connections,
                batch_size,
                rounds,
                rustls_cfgs.clone(),
                fizz_ctxs.clone(),
            ));
        }

        let mut samples = Vec::with_capacity(runs);
        for _ in 0..runs {
            let t0 = Instant::now();
            match runtime.block_on(run_backend(
                backend,
                connections,
                batch_size,
                rounds,
                rustls_cfgs.clone(),
                fizz_ctxs.clone(),
            )) {
                Ok(()) => samples.push(t0.elapsed()),
                Err(e) => {
                    println!(
                        "{},{},{},{},{},{},,,,{}",
                        backend_csv(backend),
                        worker_threads,
                        max_blocking_threads,
                        connections,
                        batch_size,
                        rounds,
                        e.to_string().replace(',', ";")
                    );
                    samples.clear();
                    break;
                }
            }
        }

        if samples.is_empty() {
            continue;
        }

        let wall_ms = median_ms(&samples);
        let secs = wall_ms / 1000.0;
        let mb_per_s = if secs > 0.0 {
            (total_bytes as f64 / (1024.0 * 1024.0)) / secs
        } else {
            0.0
        };

        println!(
            "{},{},{},{},{},{},{:.3},{},{:.3},",
            backend_csv(backend),
            worker_threads,
            max_blocking_threads,
            connections,
            batch_size,
            rounds,
            wall_ms,
            total_bytes,
            mb_per_s
        );
    }

    Ok(())
}
