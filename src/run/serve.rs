//! The network runtime and its supervisor (issue #10, T5, R9).
//!
//! One thread (`sbx-net`) runs a current-thread tokio runtime with the three
//! serve tasks (transparent proxy, explicit proxy, DNS). The supervisor trips
//! the [`FaultLatch`] when any task stops, fails its first poll or panics, when
//! the thread itself dies, or when the audit log fails. The main loop polls the
//! latch's eventfd and tears the sandbox down (fail closed).

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::task::{Context, Poll};
use std::thread;

use tokio::task::{JoinError, JoinHandle};

use super::sys;
use crate::dns::{DnsServer, serve_dns};
use crate::init::fdpass::ListenerFds;
use crate::proxy::{Proxy, serve, serve_explicit};

/// A fault that ends the run (main loop reason).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Fault {
    /// A network task or the runtime failed; the text follows "network service failed: ".
    Net(String),
    /// The audit log refused a write (Q7); the text follows "audit log write failed: ".
    Audit(String),
}

/// One eventfd plus the first-wins reason. Writes after the first are dropped.
pub(crate) struct FaultLatch {
    efd: OwnedFd,
    slot: Mutex<Option<Fault>>,
}

impl FaultLatch {
    pub(crate) fn new() -> io::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            efd: sys::eventfd()?,
            slot: Mutex::new(None),
        }))
    }

    /// First writer wins; the eventfd is signalled on the first trip only.
    pub(crate) fn trip(&self, fault: Fault) {
        let mut slot = self.slot.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(fault);
            sys::eventfd_signal(self.efd.as_fd());
        }
    }

    pub(crate) fn take(&self) -> Option<Fault> {
        self.slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    pub(crate) fn fd(&self) -> BorrowedFd<'_> {
        self.efd.as_fd()
    }
}

pub(crate) type ServeFuture = Pin<Box<dyn Future<Output = io::Result<Infallible>> + Send>>;

/// The three serve tasks in fixed order.
pub(crate) fn serve_tasks(
    fds: ListenerFds,
    proxy: Arc<Proxy>,
    dns: Arc<DnsServer>,
) -> Vec<(&'static str, ServeFuture)> {
    vec![
        (
            "transparent proxy",
            Box::pin(serve(fds.transparent, proxy.clone())),
        ),
        (
            "explicit proxy",
            Box::pin(serve_explicit(fds.explicit, proxy)),
        ),
        ("dns resolver", Box::pin(serve_dns(fds.dns, dns))),
    ]
}

/// Spawns `sbx-net`. Returns the readiness channel: `Ok(())` once every task
/// has been first-polled and none has finished; `Err(text)` otherwise. A
/// disconnected channel means the thread died before answering (the latch
/// then holds the reason).
pub(crate) fn start_net(
    tasks: Vec<(&'static str, ServeFuture)>,
    latch: Arc<FaultLatch>,
) -> io::Result<mpsc::Receiver<Result<(), String>>> {
    let (ready_tx, ready_rx) = mpsc::channel();
    thread::Builder::new()
        .name("sbx-net".into())
        .spawn(move || {
            let _guard = DeathGuard(latch.clone());
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => {
                        runtime.block_on(supervise(tasks, ready_tx, latch.clone()));
                        // The runtime is never dropped: a blocking-pool getaddrinfo
                        // could stall the drop. The process exits with the run.
                        std::mem::forget(runtime);
                    }
                    Err(err) => latch.trip(Fault::Net(format!("network runtime failed: {err}"))),
                }
            }));
            if let Err(payload) = outcome {
                latch.trip(Fault::Net(format!(
                    "network thread panicked: {}",
                    panic_text(payload.as_ref())
                )));
            }
        })?;
    Ok(ready_rx)
}

/// Starts the tasks, waits until all were first-polled, reports readiness, then
/// watches for the first completion.
pub(crate) async fn supervise(
    tasks: Vec<(&'static str, ServeFuture)>,
    ready: mpsc::Sender<Result<(), String>>,
    latch: Arc<FaultLatch>,
) {
    let total = tasks.len();
    let polled = Arc::new(AtomicUsize::new(0));
    let mut handles: Vec<(&'static str, JoinHandle<io::Result<Infallible>>)> = Vec::new();
    for (name, fut) in tasks {
        let counter = polled.clone();
        handles.push((
            name,
            tokio::spawn(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                fut.await
            }),
        ));
    }
    // Single thread: every task's first poll (set_nonblocking + from_std, up to
    // the first Pending) runs before this loop observes the full count.
    while polled.load(Ordering::SeqCst) < total {
        tokio::task::yield_now().await;
    }
    if let Some(idx) = handles.iter().position(|(_, h)| h.is_finished()) {
        let (name, handle) = handles.swap_remove(idx);
        let message = describe(name, handle.await);
        let _ = ready.send(Err(message.clone()));
        latch.trip(Fault::Net(message));
        return;
    }
    let _ = ready.send(Ok(()));
    let (name, result) = std::future::poll_fn(|cx: &mut Context<'_>| {
        for (name, handle) in handles.iter_mut() {
            if let Poll::Ready(result) = Pin::new(handle).poll(cx) {
                return Poll::Ready((*name, result));
            }
        }
        Poll::Pending
    })
    .await;
    latch.trip(Fault::Net(describe(name, result)));
}

/// Pinned: "{name} stopped: {io err}" | "{name} panicked: {msg}" |
/// "{name} was cancelled".
pub(crate) fn describe(name: &str, result: Result<io::Result<Infallible>, JoinError>) -> String {
    match result {
        Ok(Ok(never)) => match never {},
        Ok(Err(err)) => format!("{name} stopped: {err}"),
        Err(err) if err.is_panic() => {
            let payload = err.into_panic();
            format!("{name} panicked: {}", panic_text(payload.as_ref()))
        }
        Err(_) => format!("{name} was cancelled"),
    }
}

fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        return (*s).to_owned();
    }
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    "non-string panic payload".to_owned()
}

/// Trips the latch when the net thread exits in any way the supervisor did not
/// report (no-op if already tripped).
struct DeathGuard(Arc<FaultLatch>);

impl Drop for DeathGuard {
    fn drop(&mut self) {
        self.0.trip(Fault::Net("network thread exited".into()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn block_on<F: Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(fut)
    }

    /// A future that fails on its first poll.
    fn fail_now(msg: &'static str) -> ServeFuture {
        Box::pin(async move { Err::<Infallible, _>(io::Error::other(msg)) })
    }

    /// A future that never completes.
    fn forever() -> ServeFuture {
        Box::pin(std::future::pending())
    }

    /// A future that completes with an error after a short delay.
    fn fail_later(msg: &'static str) -> ServeFuture {
        Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Err::<Infallible, _>(io::Error::other(msg))
        })
    }

    fn panics() -> ServeFuture {
        Box::pin(async {
            panic!("boom");
        })
    }

    #[test]
    fn supervise_ready_then_fault_on_err() {
        let latch = FaultLatch::new().expect("latch");
        let (tx, rx) = mpsc::channel();
        block_on(supervise(
            vec![("alpha", forever()), ("beta", fail_later("socket gone"))],
            tx,
            latch.clone(),
        ));
        assert_eq!(rx.recv().expect("ready"), Ok(()));
        assert_eq!(
            latch.take(),
            Some(Fault::Net("beta stopped: socket gone".into()))
        );
    }

    #[test]
    fn supervise_first_poll_error_is_not_ready() {
        let latch = FaultLatch::new().expect("latch");
        let (tx, rx) = mpsc::channel();
        block_on(supervise(
            vec![("alpha", forever()), ("beta", fail_now("bind lost"))],
            tx,
            latch.clone(),
        ));
        assert_eq!(
            rx.recv().expect("ready"),
            Err("beta stopped: bind lost".into())
        );
        assert_eq!(
            latch.take(),
            Some(Fault::Net("beta stopped: bind lost".into()))
        );
    }

    #[test]
    fn supervise_panic_trips_latch_with_message() {
        let latch = FaultLatch::new().expect("latch");
        let (tx, rx) = mpsc::channel();
        block_on(supervise(
            vec![("transparent proxy", panics())],
            tx,
            latch.clone(),
        ));
        // A panic on the first poll is a startup failure: never "ready".
        assert_eq!(
            rx.recv().expect("ready"),
            Err("transparent proxy panicked: boom".into())
        );
        assert_eq!(
            latch.take(),
            Some(Fault::Net("transparent proxy panicked: boom".into()))
        );
    }

    #[test]
    fn death_guard_trips_on_thread_panic() {
        let latch = FaultLatch::new().expect("latch");
        let guard_latch = latch.clone();
        let handle = thread::spawn(move || {
            let _guard = DeathGuard(guard_latch);
            panic!("thread died");
        });
        assert!(handle.join().is_err());
        assert_eq!(
            latch.take(),
            Some(Fault::Net("network thread exited".into()))
        );
    }

    #[test]
    fn latch_first_trip_wins() {
        let latch = FaultLatch::new().expect("latch");
        latch.trip(Fault::Audit("first".into()));
        latch.trip(Fault::Net("second".into()));
        assert_eq!(latch.take(), Some(Fault::Audit("first".into())));
        assert_eq!(latch.take(), None);
        assert!(sys::wait_readable(latch.fd(), Duration::from_secs(1)).expect("poll"));
    }

    #[test]
    fn describe_pinned() {
        assert_eq!(
            describe("dns resolver", Ok(Err(io::Error::other("x")))),
            "dns resolver stopped: x"
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let panicked = rt.block_on(async { tokio::spawn(async { panic!("kaboom") }).await });
        assert_eq!(
            describe("explicit proxy", panicked),
            "explicit proxy panicked: kaboom"
        );
        let cancelled = rt.block_on(async {
            let h = tokio::spawn(std::future::pending::<io::Result<Infallible>>());
            h.abort();
            h.await
        });
        assert_eq!(
            describe("transparent proxy", cancelled),
            "transparent proxy was cancelled"
        );
    }
}
