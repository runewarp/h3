use anyhow::{Context, Result};
use bytes::Bytes;
use h3::{
    error::Code,
    ext::WebTransportDraft,
    quic::{RecvStream as _, SendStream as _},
    server::Connection,
};
use h3_quinn::quinn::{self, crypto::rustls::QuicServerConfig};
use h3_webtransport::server;
use http::Method;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use structopt::StructOpt;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Semaphore,
    task::JoinSet,
};

use tracing::{error, info, trace_span};

// Generic example budget, including long-lived CONNECT handlers.
const MAX_REQUEST_HANDLERS: usize = 32;

#[derive(StructOpt, Debug)]
#[structopt(name = "server")]
struct Opt {
    #[structopt(
        short,
        long,
        default_value = "127.0.0.1:4433",
        help = "What address:port to listen for new connections"
    )]
    pub listen: SocketAddr,

    #[structopt(flatten)]
    pub certs: Certs,

    #[structopt(
        long,
        use_delimiter = true,
        default_value = "02,07,13,15",
        parse(try_from_str = parse_draft),
        help = "WebTransport drafts to advertise: 02, 07, 13 and/or 15"
    )]
    pub drafts: Vec<WebTransportDraft>,
}

fn parse_draft(s: &str) -> Result<WebTransportDraft, String> {
    Ok(match s {
        "02" => WebTransportDraft::Draft02,
        "07" => WebTransportDraft::Draft07,
        "13" => WebTransportDraft::Draft13,
        "15" => WebTransportDraft::Draft15,
        _ => return Err(format!("unknown WebTransport draft {s}")),
    })
}

#[derive(StructOpt, Debug)]
pub struct Certs {
    #[structopt(
        long,
        short,
        default_value = "examples/localhost.crt",
        help = "Certificate for TLS. If present, `--key` is mandatory."
    )]
    pub cert: PathBuf,

    #[structopt(
        long,
        short,
        default_value = "examples/localhost.key",
        help = "Private key for the certificate."
    )]
    pub key: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 0. Setup tracing
    #[cfg(not(feature = "tree"))]
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .init();

    #[cfg(feature = "tree")]
    use tracing_subscriber::prelude::*;
    #[cfg(feature = "tree")]
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_tree::HierarchicalLayer::new(4).with_bracketed_fields(true))
        .init();

    // process cli arguments

    let opt = Opt::from_args();

    tracing::info!("Opt: {opt:#?}");
    let Certs { cert, key } = opt.certs;
    let drafts = opt.drafts;

    // create quinn server endpoint and bind UDP socket

    // both cert and key must be DER-encoded
    let cert = CertificateDer::from(std::fs::read(cert)?);
    let key = PrivateKeyDer::try_from(std::fs::read(key)?)?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;

    tls_config.max_early_data_size = u32::MAX;
    let alpn: Vec<Vec<u8>> = vec![
        b"h3".to_vec(),
        b"h3-32".to_vec(),
        b"h3-31".to_vec(),
        b"h3-30".to_vec(),
        b"h3-29".to_vec(),
    ];
    tls_config.alpn_protocols = alpn;

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls_config)?));
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(Some(Duration::from_secs(2)));
    server_config.transport = Arc::new(transport_config);
    let endpoint = quinn::Endpoint::server(server_config, opt.listen)?;

    info!("listening on {}", opt.listen);

    // 2. Accept new quic connections and spawn a new task to handle them
    while let Some(new_conn) = endpoint.accept().await {
        trace_span!("New connection being attempted");

        let drafts = drafts.clone();
        tokio::spawn(async move {
            match new_conn.await {
                Ok(conn) => {
                    info!("new http3 established");
                    let h3_conn = h3::server::builder()
                        .max_field_section_size(16 * 1024)
                        .enable_webtransport(true)
                        .enable_extended_connect(true)
                        .enable_datagram(true)
                        .max_webtransport_sessions(1)
                        .webtransport_drafts(drafts)
                        .send_grease(true)
                        .build(h3_quinn::Connection::new(conn))
                        .await
                        .unwrap();

                    if let Err(err) = handle_connection(h3_conn).await {
                        error!("Failed to handle connection: {err:?}");
                    }
                }
                Err(err) => {
                    error!("accepting connection failed: {:?}", err);
                }
            }
        });
    }

    // shut down gracefully
    // wait for connections to be closed before exiting
    endpoint.wait_idle().await;

    Ok(())
}

// The connection task keeps accepting requests while session tasks open or await streams.
async fn handle_connection(conn: Connection<h3_quinn::Connection, Bytes>) -> Result<()> {
    let (mut driver, acceptor) = server::new(conn, server::Limits::default());
    let budget = Arc::new(Semaphore::new(MAX_REQUEST_HANDLERS));
    // Dropping the set aborts all request/session handlers on driver loss or error.
    let mut handlers = JoinSet::new();
    loop {
        let mut resolver = tokio::select! {
            request = driver.accept() => match request? {
                Some(resolver) => resolver,
                None => break,
            },
            Some(result) = handlers.join_next(), if !handlers.is_empty() => {
                if let Err(error) = result {
                    error!("Request handler task failed: {error:?}");
                }
                continue;
            }
        };
        // Never spawn a task to wait for capacity or block the connection driver on a permit.
        let Ok(permit) = budget.clone().try_acquire_owned() else {
            resolver
                .frame_stream
                .stream
                .reset(Code::H3_REQUEST_REJECTED.value());
            resolver
                .frame_stream
                .stream
                .stop_sending(Code::H3_REQUEST_REJECTED.value());
            continue;
        };
        let acceptor = acceptor.clone();
        handlers.spawn(async move {
            let _permit = permit;
            let result: Result<()> = async {
                let (request, mut stream) =
                    tokio::time::timeout(Duration::from_secs(10), resolver.resolve_request())
                        .await??;
                if request.method() == Method::CONNECT {
                    let session = acceptor.accept(request, stream).await?;
                    info!(draft = ?session.draft(), "Established WebTransport session");
                    handle_session(session).await?;
                } else {
                    // Ordinary GET/PUT intake remains independent of session stream credit.
                    tokio::time::timeout(Duration::from_secs(30), async {
                        while stream.recv_data().await?.is_some() {}
                        stream.send_response(http::Response::new(())).await?;
                        stream.finish().await
                    })
                    .await??;
                }
                Ok(())
            }
            .await;
            if let Err(error) = result {
                error!("Request/session failed: {error:?}");
            }
        });
    }
    handlers.shutdown().await;
    Ok(())
}

async fn echo_stream(mut stream: impl AsyncRead + AsyncWrite + Unpin) -> Result<()> {
    let mut buffer = [0; 4096];
    loop {
        let len = stream.read(&mut buffer).await?;
        if len == 0 {
            return Ok(stream.shutdown().await?);
        }
        stream.write_all(&buffer[..len]).await?;
    }
}

// This example exercises the detached bidi subset. Uni dispatch and datagram routing are
// deliberately unsupported by the detached drivers. Applications own authentication and budgets.
async fn handle_session(session: server::Session<h3_quinn::Connection, Bytes>) -> Result<()> {
    let work = async {
        let greeting = async {
            let mut stream = session.opener().open_bi().await?;
            stream
                .write_all(b"Hello from a server initiated bidi stream")
                .await
                .context("Failed to send greeting")?;
            stream.shutdown().await?;
            tokio::spawn(async move {
                if let Err(error) = tokio::io::copy(&mut stream, &mut tokio::io::sink()).await {
                    error!("Server stream failed: {error:?}");
                }
            });
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(error) = greeting {
            error!("Greeting failed: {error:?}");
        }
        while let Some(stream) = session.accept_bi().await {
            tokio::spawn(async move {
                if let Err(error) = echo_stream(stream).await {
                    error!("Echo failed: {error:?}");
                }
            });
        }
        // Termination wakes accept_bi before peer FIN. Let closed() validate that FIN.
        futures::future::pending::<()>().await
    };
    tokio::select! {
        // Demonstration policy: cap session lifetime at five minutes, including peer FIN wait.
        outcome = tokio::time::timeout(Duration::from_secs(300), session.closed()) => {
            info!(outcome = ?outcome?, "Session ended");
        }
        () = work => {},
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/webtransport_server/budget.rs"]
mod budget_tests;
