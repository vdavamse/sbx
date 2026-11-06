//! Opt-in TLS termination for hosts with URL-path rules (issue #17).
//!
//! Compiled only with the `tls-termination` feature. The default binary has
//! no TLS interception and no crypto provider (see `Cargo.toml`).
//!
//! 1. **Scope.** Only `network.mitm_hosts` are terminated. For those hosts the
//!    proxy (transparent 443 and explicit `CONNECT :443`) verifies the SNI as
//!    usual, then completes the sandbox's TLS handshake itself with a leaf
//!    minted from the run's CA ([`RunCa`], see `ca.rs`), reads ONE request,
//!    checks its `Host` and path ([`request::check_request`]), dials the
//!    upstream under the usual guard, and verifies the upstream certificate.
//!    Every other host stays a byte-verbatim TLS passthrough.
//! 2. **Upstream verification is never disabled.** The upstream client
//!    verifies against the Mozilla root set (`webpki-roots`) with the SNI
//!    name as the server name, ALPN `http/1.1`. A failed verification, or any
//!    handshake error, is a `Failed::UpstreamTls` answered with `502` over
//!    TLS. There is no plaintext fallback.
//! 3. **One decision, recorded before any relay byte.** [`Terminator::terminate`]
//!    records exactly one [`crate::proxy::Decision`] per connection. A denial
//!    or error after the client handshake is answered over TLS (`403`/`400`/
//!    `502`/`504`, the `explicit_response` table) and the connection closes.
//!    Relay bytes start only after the record.
//! 4. **The request is forwarded as one unit.** The upstream sees the client's
//!    head with `Connection: close` inserted (http.rs point 6) and exactly the
//!    declared `Content-Length` body. Bytes pipelined past the body are a
//!    second request and are dropped, never forwarded. Upstream→client runs
//!    until the upstream closes; the upload is abandoned once the download
//!    ends, so a stalled client body cannot hold the connection open.
//! 5. **Client surface (v1, documented costs).** ALPN offers `http/1.1` only:
//!    an h2-only client fails the handshake (fail closed, no fallback). Pinned
//!    or client-certificate upstreams break for these hosts, and so do
//!    chunked request bodies and protocol upgrades. One request per
//!    connection (no keep-alive).
//! 6. **Key custody.** The CA key is held by [`RunCa`] in the `sbx run`
//!    process only. The sandbox receives the certificate PEM through the
//!    session directory (`etc/sbx-ca.pem`, `etc/sbx-ca-bundle.pem`) and the
//!    trust-store environment variables; neither the key nor a path to it is
//!    ever mounted, passed in argv or env, or written to disk.

mod ca;
mod request;

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub use ca::RunCa;

use crate::policy::{Domain, UrlPrefix};
use crate::proxy::Upstream;
use crate::proxy::explicit::explicit_response;
use crate::proxy::http::{self, Framing, Head, force_connection_close};
use crate::proxy::relay::linger_close;
use crate::proxy::{
    Decision, Failed, Handoff, Limits, Proxy, Rejected, TLS_PORT, Verdict, connect_upstream,
};

/// The one ALPN protocol the terminated connections speak (module point 5).
const ALPN_HTTP1: &[u8] = b"http/1.1";
/// Per-read chunk for the relay loops (the policy owns no cap here: the
/// body is bounded by the declared `Content-Length`).
const RELAY_CHUNK: usize = 16 * 1024;

/// The sandbox-side TLS server stream: the ClientHello replay in front of
/// the client socket.
type ServerStream<S> = tokio_rustls::server::TlsStream<Prefixed<S>>;
/// The upstream-side TLS client stream.
type ClientStream = tokio_rustls::client::TlsStream<Upstream>;

/// A denial raised before the relay: the TLS stream when the client
/// handshake had completed (so the denial can be answered), and the reason.
/// Boxed so the scope-A `Result` stays small (clippy::result_large_err).
type Denial<S> = Box<(Option<ServerStream<S>>, Rejected)>;

/// The inspected, forwardable request (module point 4).
struct Checked<S> {
    tls: ServerStream<S>,
    /// The rewritten head plus the in-body pipelined bytes, sent first.
    forward: Vec<u8>,
    /// Declared body bytes still to read from the client.
    body_remaining: u64,
}

/// The per-run TLS state the proxy holds: the CA (server side), the upstream
/// verifier, and a per-host server-config cache. Built once per `sbx run`.
pub struct Terminator {
    ca: RunCa,
    upstream: Arc<ClientConfig>,
    servers: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl Terminator {
    /// Production shape: upstream verification against the Mozilla roots.
    pub fn new(ca: RunCa) -> Result<Self, String> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_upstream_roots(ca, roots)
    }

    /// Full control (tests inject a test root here; production uses
    /// [`Self::new`]). The roots are the ONLY upstream trust anchors.
    pub(crate) fn with_upstream_roots(ca: RunCa, roots: RootCertStore) -> Result<Self, String> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut upstream = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|err| format!("cannot configure upstream TLS: {err}"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        upstream.alpn_protocols = vec![ALPN_HTTP1.to_vec()];
        Ok(Self {
            ca,
            upstream: Arc::new(upstream),
            servers: Mutex::new(HashMap::new()),
        })
    }

    /// The CA certificate PEM for the sandbox trust bundle (never the key).
    pub fn ca_cert_pem(&self) -> String {
        self.ca.cert_pem()
    }

    /// The server config for one SNI name, minted once and cached.
    fn server_config(&self, host: &Domain) -> Result<Arc<ServerConfig>, String> {
        let mut cache = match self.servers.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(config) = cache.get(host.as_str()) {
            return Ok(Arc::clone(config));
        }
        let (chain, key) = self.ca.leaf(host)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|err| format!("cannot configure client TLS: {err}"))?
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .map_err(|err| format!("cannot install the leaf for {}: {err}", host.as_str()))?;
        config.alpn_protocols = vec![ALPN_HTTP1.to_vec()];
        let config = Arc::new(config);
        cache.insert(host.as_str().to_owned(), Arc::clone(&config));
        Ok(config)
    }

    /// Terminate one connection (module points 1, 3, 4). Records exactly one
    /// decision; every path ends with the connection closed.
    pub(crate) async fn terminate<S>(
        &self,
        client: S,
        handoff: Handoff,
        proxy: &Proxy,
        decision_for: impl Fn(Verdict) -> Decision,
    ) where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let Handoff { replay, name } = handoff;
        let limits: &Limits = &proxy.limits;
        // Scope A: client handshake, one request head, the request checks
        // (under the decision timeout; elapsed ⇒ the stream is dropped).
        let checked = match tokio::time::timeout(
            limits.decision_timeout,
            self.inspect(client, replay, &name, &proxy.mitm.paths, limits),
        )
        .await
        {
            Ok(Ok(checked)) => checked,
            Ok(Err(denial)) => {
                let (stream, rejected) = *denial;
                let decision = decision_for(Verdict::Denied(rejected));
                proxy.sink.record(&decision);
                if let Some(mut stream) = stream {
                    answer(&mut stream, &decision.verdict).await;
                }
                return;
            }
            Err(_elapsed) => {
                let decision = decision_for(Verdict::Denied(Rejected::DecisionTimeout {
                    secs: limits.decision_timeout.as_secs(),
                }));
                proxy.sink.record(&decision);
                return;
            }
        };
        let Checked {
            mut tls,
            forward,
            body_remaining,
        } = checked;
        // Scope B: dial (guarded) and verify upstream. Not nested in scope A.
        let (upstream, peer) = match self.dial(proxy, &name).await {
            Ok(pair) => pair,
            Err(verdict) => {
                let decision = decision_for(verdict);
                proxy.sink.record(&decision);
                answer(&mut tls, &decision.verdict).await;
                return;
            }
        };
        let decision = decision_for(Verdict::Allowed {
            name: name.clone(),
            upstream: peer,
        });
        proxy.sink.record(&decision);
        relay(tls, upstream, &forward, body_remaining, proxy, &decision).await;
    }

    /// Scope A (module point 1): the client handshake, the request head and
    /// its checks. Returns the stream and what to forward on success.
    async fn inspect<S>(
        &self,
        client: S,
        replay: Vec<u8>,
        name: &Domain,
        paths: &[UrlPrefix],
        limits: &Limits,
    ) -> Result<Checked<S>, Denial<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let config = self
            .server_config(name)
            .map_err(|detail| Box::new((None, Rejected::TlsClientHandshake { detail })))?;
        let mut tls = TlsAcceptor::from(config)
            .accept(Prefixed::new(replay, client))
            .await
            .map_err(|err| {
                Box::new((
                    None,
                    Rejected::TlsClientHandshake {
                        detail: err.to_string(),
                    },
                ))
            })?;
        let Head { mut buf, head_end } = match http::read_head(&mut tls, limits).await {
            Ok(head) => head,
            Err(rejected) => return Err(Box::new((Some(tls), rejected))),
        };
        let framing =
            match request::check_request(&buf[..head_end], name, paths, limits.max_http_headers) {
                Ok(framing) => framing,
                Err(rejected) => return Err(Box::new((Some(tls), rejected))),
            };
        let body_len = match framing {
            Framing::Length(n) => n,
            Framing::None => 0,
            // Unreachable: any Transfer-Encoding is denied in check_request.
            Framing::Chunked => {
                return Err(Box::new((
                    Some(tls),
                    Rejected::UnsupportedRequest {
                        detail: request::CHUNKED_DETAIL,
                    },
                )));
            }
        };
        let mut pending = buf.split_off(head_end);
        force_connection_close(&mut buf, head_end);
        // Pipelined bytes past the declared body are a second request: they
        // are dropped here, never forwarded (module point 4).
        let take = usize::try_from(body_len).map_or(pending.len(), |n| n.min(pending.len()));
        pending.truncate(take);
        let body_remaining = body_len - take as u64;
        buf.extend_from_slice(&pending);
        Ok(Checked {
            tls,
            forward: buf,
            body_remaining,
        })
    }

    /// Scope B (module point 2): the guarded dial, then the upstream TLS
    /// handshake with the SNI name, verified against the roots.
    async fn dial(
        &self,
        proxy: &Proxy,
        name: &Domain,
    ) -> Result<(ClientStream, std::net::SocketAddr), Verdict> {
        let connected = connect_upstream(proxy, name, TLS_PORT).await?;
        let peer = connected.peer;
        let limits = &proxy.limits;
        let server_name = ServerName::try_from(name.as_str().to_owned()).map_err(|err| {
            Verdict::Error(Failed::UpstreamTls {
                name: name.clone(),
                detail: err.to_string(),
            })
        })?;
        let handshake =
            TlsConnector::from(Arc::clone(&self.upstream)).connect(server_name, connected.stream);
        match tokio::time::timeout(limits.connect_timeout, handshake).await {
            Ok(Ok(stream)) => Ok((stream, peer)),
            Ok(Err(err)) => Err(Verdict::Error(Failed::UpstreamTls {
                name: name.clone(),
                detail: err.to_string(),
            })),
            Err(_elapsed) => Err(Verdict::Error(Failed::UpstreamTls {
                name: name.clone(),
                detail: format!(
                    "handshake timed out after {}s",
                    limits.connect_timeout.as_secs()
                ),
            })),
        }
    }
}

/// Answer a denial or error over TLS and close (module point 3). The
/// response table is the explicit proxy's (`explicit_response`, tunnel not
/// open); a verdict with no status (EOF, handshake failure) is a silent close.
async fn answer<T: AsyncRead + AsyncWrite + Unpin>(stream: &mut T, verdict: &Verdict) {
    if let Some(bytes) = explicit_response(verdict, false) {
        let _ = stream.write_all(bytes).await;
        let _ = stream.flush().await;
    }
    linger_close(stream).await;
}

/// The relay (module point 4). `forward` (rewritten head + in-body bytes) and
/// then `body_remaining` client bytes go upstream; upstream bytes go back
/// until the upstream closes. Byte counts go to `closed`, exactly once.
async fn relay<C, U>(
    client: C,
    upstream: U,
    forward: &[u8],
    body_remaining: u64,
    proxy: &Proxy,
    decision: &Decision,
) where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_r, mut client_w) = tokio::io::split(client);
    let (mut up_r, mut up_w) = tokio::io::split(upstream);
    let up_bytes = AtomicU64::new(0);
    let down_bytes = AtomicU64::new(0);
    // The upload yields `false` only when the client went away mid-body: no
    // response can be wanted, and an upstream left waiting for the rest of the
    // body would otherwise hold this task until its own timeout (PR #64 m4). An
    // upstream write error yields `true`: the upstream may already have sent an
    // early response (413, 401), which the download still relays.
    let mut upload = std::pin::pin!(async {
        if up_w.write_all(forward).await.is_err() {
            return true;
        }
        up_bytes.fetch_add(forward.len() as u64, Ordering::Relaxed);
        let mut remaining = body_remaining;
        let mut chunk = vec![0u8; RELAY_CHUNK];
        while remaining > 0 {
            let want = usize::try_from(remaining).map_or(RELAY_CHUNK, |n| n.min(RELAY_CHUNK));
            let read = match client_r.read(&mut chunk[..want]).await {
                Ok(0) | Err(_) => return false,
                Ok(read) => read,
            };
            if up_w.write_all(&chunk[..read]).await.is_err() {
                return true;
            }
            up_bytes.fetch_add(read as u64, Ordering::Relaxed);
            remaining -= read as u64;
        }
        // No `shutdown` here: on TLS it sends close_notify, and some servers
        // treat a client close_notify as an abort and drop the response. The
        // request is complete (exact Content-Length); simply stop writing. The
        // download side ends the relay when the upstream closes (it was sent
        // `Connection: close`).
        let _ = up_w.flush().await;
        true
    });
    let mut download = std::pin::pin!(async {
        let mut chunk = vec![0u8; RELAY_CHUNK];
        loop {
            let read = match up_r.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(read) => read,
            };
            if client_w.write_all(&chunk[..read]).await.is_err() {
                break;
            }
            down_bytes.fetch_add(read as u64, Ordering::Relaxed);
        }
        let _ = client_w.shutdown().await;
    });
    // The response ends the relay: poll the upload until it finishes, but
    // return as soon as the download does (no hang on a stalled client body).
    let mut upload_open = true;
    std::future::poll_fn(|cx| {
        if upload_open {
            if let Poll::Ready(whole) = upload.as_mut().poll(cx) {
                upload_open = false;
                if !whole {
                    return Poll::Ready(());
                }
            }
        }
        download.as_mut().poll(cx)
    })
    .await;
    proxy.sink.closed(
        decision,
        up_bytes.load(Ordering::Relaxed),
        down_bytes.load(Ordering::Relaxed),
    );
}

/// The ClientHello replay in front of the client socket (module point 1):
/// reads serve the buffered prefix first, then the socket; writes go straight
/// to the socket.
pub(crate) struct Prefixed<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.offset < this.prefix.len() {
            let rest = &this.prefix[this.offset..];
            let take = rest.len().min(buf.remaining());
            buf.put_slice(&rest[..take]);
            this.offset += take;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::io;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
    use tokio_rustls::TlsConnector;

    use super::*;
    use crate::proxy::{
        DecisionSink, DialFn, DnsMap, Failed, GuardedConnector, Limits, ResolveFn, Via,
    };

    const HOST: &str = "api.example.test";
    /// A public address: the guard passes it, and the dial returns it as peer.
    const PEER: &str = "93.184.216.34:443";
    const CLIENT: &str = "192.0.2.10:40000";

    fn domain(raw: &str) -> Domain {
        Domain::parse(raw).expect("fixture name")
    }

    fn run<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(future)
    }

    /// Records every decision and relay close, in order.
    #[derive(Default)]
    struct Sink {
        decisions: Mutex<Vec<Decision>>,
        closed: Mutex<Vec<(u64, u64)>>,
    }

    impl DecisionSink for Sink {
        fn record(&self, decision: &Decision) {
            self.decisions
                .lock()
                .expect("sink lock")
                .push(decision.clone());
        }

        fn closed(&self, _decision: &Decision, up: u64, down: u64) {
            self.closed.lock().expect("sink lock").push((up, down));
        }
    }

    struct NoMap;

    impl DnsMap for NoMap {
        fn name_for(&self, _ip: std::net::Ipv4Addr) -> Option<Domain> {
            None
        }
    }

    /// One scripted world: the terminator, the proxy around it, the recording
    /// sink, the dial counter, and the bytes the scripted upstream received.
    struct World {
        terminator: Arc<Terminator>,
        proxy: Arc<Proxy>,
        sink: Arc<Sink>,
        dials: Arc<AtomicUsize>,
        upstream_seen: Arc<Mutex<Vec<u8>>>,
        client_roots: RootCertStore,
    }

    fn upstream_config(ca: &RunCa, host: &Domain) -> Arc<ServerConfig> {
        let (chain, key) = ca.leaf(host).expect("upstream leaf");
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("upstream cert");
        config.alpn_protocols = vec![ALPN_HTTP1.to_vec()];
        Arc::new(config)
    }

    /// The scripted upstream: read one framed request (head, then
    /// Content-Length body bytes), then keep reading for a short grace period
    /// so any bytes the terminator wrongly forwarded past the body (a
    /// pipelined second request) are recorded too. The terminator does NOT
    /// half-close (no close_notify), so the fake cannot wait for EOF.
    async fn serve_upstream(
        io: DuplexStream,
        config: Arc<ServerConfig>,
        seen: Arc<Mutex<Vec<u8>>>,
    ) {
        let Ok(mut tls) = tokio_rustls::TlsAcceptor::from(config).accept(io).await else {
            return;
        };
        let mut received = Vec::new();
        let mut chunk = [0u8; 4096];
        let head_end = loop {
            if let Some(i) = received.windows(4).position(|w| w == b"\r\n\r\n") {
                break Some(i + 4);
            }
            match tls.read(&mut chunk).await {
                Ok(0) | Err(_) => break None,
                Ok(n) => received.extend_from_slice(&chunk[..n]),
            }
        };
        if let Some(head_end) = head_end {
            let head = String::from_utf8_lossy(&received[..head_end]).to_ascii_lowercase();
            let body_len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            while received.len() < head_end + body_len {
                match tls.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => received.extend_from_slice(&chunk[..n]),
                }
            }
            // Grace period: anything arriving now was forwarded past the body.
            while let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_millis(200), tls.read(&mut chunk)).await
            {
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&chunk[..n]);
            }
        }
        *seen.lock().expect("seen lock") = received;
        let body = b"upstream-ok";
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = tls.write_all(head.as_bytes()).await;
        let _ = tls.write_all(body).await;
        let _ = tls.shutdown().await;
    }

    fn world(paths: &[&str], trust_upstream: bool) -> World {
        let host = domain(HOST);
        let client_ca = RunCa::generate(std::slice::from_ref(&host), Duration::from_secs(600))
            .expect("client-facing CA");
        let upstream_ca = RunCa::generate(std::slice::from_ref(&host), Duration::from_secs(600))
            .expect("upstream CA");
        let mut client_roots = RootCertStore::empty();
        client_roots
            .add(client_ca.cert_der())
            .expect("client CA anchor");
        let mut upstream_roots = RootCertStore::empty();
        if trust_upstream {
            upstream_roots
                .add(upstream_ca.cert_der())
                .expect("upstream CA anchor");
        }
        let server = upstream_config(&upstream_ca, &host);
        let terminator = Arc::new(
            Terminator::with_upstream_roots(client_ca, upstream_roots).expect("terminator"),
        );
        let sink = Arc::new(Sink::default());
        let dials = Arc::new(AtomicUsize::new(0));
        let upstream_seen = Arc::new(Mutex::new(Vec::new()));

        let resolve: ResolveFn = Arc::new(|_: &str, _: u16| {
            let future: Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> =
                Box::pin(async { Ok(vec![PEER.parse().expect("peer")]) });
            future
        });
        let dial: DialFn = {
            let dials = Arc::clone(&dials);
            let seen = Arc::clone(&upstream_seen);
            Arc::new(move |_: &str, _: u16| {
                dials.fetch_add(1, AtomicOrdering::SeqCst);
                let (client_io, server_io) = duplex(64 * 1024);
                tokio::spawn(serve_upstream(
                    server_io,
                    Arc::clone(&server),
                    Arc::clone(&seen),
                ));
                Box::pin(async move {
                    Ok((Box::new(client_io) as Upstream, PEER.parse().expect("peer")))
                })
            })
        };
        let network = crate::policy::Network {
            mode: crate::policy::NetworkMode::Transparent,
            allow: vec![
                crate::policy::DomainRule::parse(&format!("={}", host.as_str())).expect("rule"),
            ],
            ports: vec![TLS_PORT],
            mitm_hosts: vec![host],
            paths: paths
                .iter()
                .map(|raw| UrlPrefix::parse(raw).expect("fixture rule"))
                .collect(),
        };
        let proxy = Proxy::with_terminator(
            &network,
            Arc::new(NoMap),
            sink.clone(),
            Arc::new(GuardedConnector::new(resolve, dial, Duration::from_secs(5))),
            Limits::default(),
            Some(Arc::clone(&terminator)),
        );
        World {
            terminator,
            proxy,
            sink,
            dials,
            upstream_seen,
            client_roots,
        }
    }

    fn client_config(roots: RootCertStore, alpn: &[&[u8]]) -> ClientConfig {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|proto| proto.to_vec()).collect();
        config
    }

    /// Drive one client connection through the terminator. Returns the bytes
    /// the client read (empty if the handshake failed), whether the client
    /// handshake succeeded, and the upstream bytes (last connection).
    fn exchange(world: &World, alpn: &[&[u8]], request: &[u8]) -> (Vec<u8>, bool) {
        run(async {
            let (client_io, server_io) = duplex(64 * 1024);
            let name = domain(HOST);
            let proxy = Arc::clone(&world.proxy);
            let terminator = Arc::clone(&world.terminator);
            let server = tokio::spawn({
                let name = name.clone();
                async move {
                    let decision_name = name.clone();
                    terminator
                        .terminate(
                            server_io,
                            Handoff {
                                replay: Vec::new(),
                                name,
                            },
                            &proxy,
                            move |verdict| Decision {
                                client: CLIENT.parse().expect("client"),
                                via: Via::Transparent { orig_dst: None },
                                name: Some(decision_name.clone()),
                                verdict,
                            },
                        )
                        .await;
                }
            });
            let connector =
                TlsConnector::from(Arc::new(client_config(world.client_roots.clone(), alpn)));
            let mut tls = match connector
                .connect(ServerName::try_from(HOST).expect("sni"), client_io)
                .await
            {
                Ok(tls) => tls,
                Err(_) => {
                    server.await.expect("server task");
                    return (Vec::new(), false);
                }
            };
            tls.write_all(request).await.expect("client write");
            let mut response = Vec::new();
            let _ = tls.read_to_end(&mut response).await;
            drop(tls);
            server.await.expect("server task");
            (response, true)
        })
    }

    fn only_decision(world: &World) -> Decision {
        let decisions = world.sink.decisions.lock().expect("sink lock");
        assert_eq!(decisions.len(), 1, "exactly one decision per connection");
        decisions[0].clone()
    }

    #[test]
    fn allowed_request_is_relayed_with_body_and_connection_close() {
        let world = world(&["https://api.example.test/v1/"], true);
        let request =
            b"POST /v1/items HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 5\r\n\r\nhello";
        let (response, handshake) = exchange(&world, &[b"http/1.1"], request);
        assert!(handshake);
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
        assert!(text.ends_with("upstream-ok"), "{text}");

        let seen = world.upstream_seen.lock().expect("seen").clone();
        assert_eq!(
            seen,
            b"POST /v1/items HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
        );
        assert_eq!(world.dials.load(AtomicOrdering::SeqCst), 1);
        let decision = only_decision(&world);
        assert!(
            matches!(decision.verdict, Verdict::Allowed { .. }),
            "{decision:?}"
        );
        assert_eq!(world.sink.closed.lock().expect("closed").len(), 1);
    }

    #[test]
    fn denied_path_is_answered_403_recorded_once_and_never_dialed() {
        let world = world(&["https://api.example.test/v1/"], true);
        let (response, _) = exchange(
            &world,
            &[b"http/1.1"],
            b"GET /admin/keys HTTP/1.1\r\nHost: api.example.test\r\n\r\n",
        );
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 403"));
        assert_eq!(
            world.dials.load(AtomicOrdering::SeqCst),
            0,
            "no upstream dial"
        );
        let decision = only_decision(&world);
        match &decision.verdict {
            Verdict::Denied(Rejected::PathNotAllowed { host }) => {
                assert_eq!(host.as_str(), HOST);
            }
            other => panic!("expected PathNotAllowed, got {other:?}"),
        }
        assert!(
            !decision.reason().contains("admin"),
            "{}",
            decision.reason()
        );
        assert!(world.sink.closed.lock().expect("closed").is_empty());
    }

    /// PR #64 review m4: a client that closes before its Content-Length body is
    /// complete ends the relay, even though the upstream never closes.
    #[test]
    fn client_eof_mid_body_ends_the_relay() {
        let world = world(&["https://api.example.test/v1/"], true);
        run(async {
            let (client_io, mut client_far) = duplex(64 * 1024);
            // The upstream's far end stays open for the whole test.
            let (upstream_io, _upstream_far) = duplex(64 * 1024);
            client_far.write_all(b"he").await.expect("partial body");
            drop(client_far);
            let decision = Decision {
                client: CLIENT.parse().expect("client"),
                via: Via::Transparent { orig_dst: None },
                name: Some(domain(HOST)),
                verdict: Verdict::Allowed {
                    name: domain(HOST),
                    upstream: PEER.parse().expect("peer"),
                },
            };
            let head =
                b"POST /v1/x HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 10\r\n\r\n";
            tokio::time::timeout(
                Duration::from_secs(5),
                relay(client_io, upstream_io, head, 10, &world.proxy, &decision),
            )
            .await
            .expect("the relay ends on the client's EOF");
        });
        let closed = world.sink.closed.lock().expect("closed");
        assert_eq!(closed.len(), 1, "closed exactly once");
        assert_eq!(closed[0].1, 0, "no response bytes");
    }

    #[test]
    fn host_header_mismatch_is_denied_over_tls() {
        let world = world(&["https://api.example.test/"], true);
        let (response, _) = exchange(
            &world,
            &[b"http/1.1"],
            b"GET /v1/x HTTP/1.1\r\nHost: evil.example.test\r\n\r\n",
        );
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 403"));
        assert_eq!(world.dials.load(AtomicOrdering::SeqCst), 0);
        assert!(matches!(
            only_decision(&world).verdict,
            Verdict::Denied(Rejected::HostMismatch { .. })
        ));
    }

    #[test]
    fn pipelined_second_request_is_never_forwarded() {
        let world = world(&["https://api.example.test/"], true);
        let request = b"GET /v1/a HTTP/1.1\r\nHost: api.example.test\r\n\r\nGET /admin HTTP/1.1\r\nHost: api.example.test\r\n\r\n";
        let (response, _) = exchange(&world, &[b"http/1.1"], request);
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));
        let seen = world.upstream_seen.lock().expect("seen").clone();
        let text = String::from_utf8_lossy(&seen);
        assert!(text.contains("GET /v1/a "), "{text}");
        assert!(
            !text.contains("/admin"),
            "second request leaked upstream: {text}"
        );
        assert_eq!(only_decision(&world).verdict.label(), "allowed");
    }

    #[test]
    fn untrusted_upstream_is_502_over_tls_with_no_plaintext_fallback() {
        let world = world(&["https://api.example.test/"], false);
        let (response, _) = exchange(
            &world,
            &[b"http/1.1"],
            b"GET /v1/x HTTP/1.1\r\nHost: api.example.test\r\n\r\n",
        );
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 502"));
        assert!(
            world.upstream_seen.lock().expect("seen").is_empty(),
            "nothing forwarded"
        );
        match only_decision(&world).verdict {
            Verdict::Error(Failed::UpstreamTls { .. }) => {}
            other => panic!("expected UpstreamTls, got {other:?}"),
        }
    }

    #[test]
    fn request_shapes_outside_v1_are_refused_with_400() {
        let shapes: [&[u8]; 4] = [
            b"GET http://api.example.test/v1/x HTTP/1.1\r\nHost: api.example.test\r\n\r\n",
            b"GET /v1/x HTTP/1.1\r\nHost: api.example.test\r\nUpgrade: websocket\r\n\r\n",
            b"POST /v1/x HTTP/1.1\r\nHost: api.example.test\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        ];
        for request in shapes {
            let world = world(&["https://api.example.test/"], true);
            let (response, _) = exchange(&world, &[b"http/1.1"], request);
            assert!(
                String::from_utf8_lossy(&response).starts_with("HTTP/1.1 400"),
                "{}",
                String::from_utf8_lossy(request)
            );
            assert_eq!(world.dials.load(AtomicOrdering::SeqCst), 0);
            assert_eq!(only_decision(&world).verdict.label(), "denied");
        }
    }

    #[test]
    fn h2_only_client_fails_the_handshake_closed() {
        let world = world(&["https://api.example.test/"], true);
        let (response, handshake) = exchange(&world, &[b"h2"], b"");
        assert!(!handshake, "no ALPN overlap: the handshake must fail");
        assert!(response.is_empty());
        assert_eq!(world.dials.load(AtomicOrdering::SeqCst), 0);
        let decision = only_decision(&world);
        assert!(
            matches!(
                decision.verdict,
                Verdict::Denied(Rejected::TlsClientHandshake { .. })
            ),
            "{decision:?}"
        );
    }

    #[test]
    fn new_reasons_are_pinned() {
        let host = domain(HOST);
        assert_eq!(
            Rejected::PathNotAllowed { host: host.clone() }.reason(),
            "request path is not allowed for api.example.test by the policy URL-path rules"
        );
        assert_eq!(
            Rejected::UnsupportedRequest { detail: "CONNECT" }.reason(),
            "unsupported request on a TLS-terminated connection: CONNECT"
        );
        assert_eq!(
            Rejected::MitmPlainHttp { name: host.clone() }.reason(),
            "api.example.test has URL-path rules and is reachable only over TLS: plain HTTP on port 80 is denied"
        );
        assert_eq!(
            Rejected::TerminationUnavailable { name: host.clone() }.reason(),
            "api.example.test requires TLS termination, which this sbx build does not provide (build with the tls-termination feature)"
        );
        assert_eq!(
            Rejected::TlsClientHandshake {
                detail: "no ALPN".to_owned()
            }
            .reason(),
            "TLS handshake with the sandbox client failed: no ALPN"
        );
        assert_eq!(
            Failed::UpstreamTls {
                name: host,
                detail: "invalid certificate".to_owned()
            }
            .reason(),
            "TLS handshake with upstream api.example.test failed: invalid certificate"
        );
    }

    #[test]
    fn terminator_never_exposes_the_ca_key() {
        let world = world(&["https://api.example.test/"], true);
        let pem = world.terminator.ca_cert_pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(!pem.contains("PRIVATE KEY"));
    }
}
