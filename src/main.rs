use std::{future::Future, pin::Pin};
#[cfg(any(test, not(unix)))]
use std::{future::poll_fn, task::Poll};

// The gateway entrypoint is intentionally a thin shim: all configuration
// parsing, binding, and serving live in `waf_ids_ai_soc::run_from_env` so they
// are unit-testable, while this file is covered end-to-end by `tests/binary.rs`.
#[cfg(not(test))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    waf_ids_ai_soc::run_from_env(shutdown_signal().await?).await
}

#[cfg(all(not(test), unix))]
async fn shutdown_signal()
-> Result<Pin<Box<dyn Future<Output = ()> + Send>>, Box<dyn std::error::Error>> {
    // Install SIGTERM handling before readiness can be reported, so a fast
    // supervisor or test harness cannot kill the process before graceful
    // shutdown is armed.
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    Ok(Box::pin(async move {
        term.recv().await;
    }))
}

/// Poll a shutdown future once up front so listeners that install on first
/// poll, such as `tokio::signal::ctrl_c()`, are armed before startup runs.
#[cfg(any(test, not(unix)))]
async fn arm_shutdown_future<F, E>(future: F) -> Result<Pin<Box<dyn Future<Output = ()> + Send>>, E>
where
    F: Future<Output = Result<(), E>> + Send + 'static,
{
    let mut future = Box::pin(future);
    let ready = poll_fn(|cx| match future.as_mut().poll(cx) {
        Poll::Ready(Ok(())) => Poll::Ready(Ok(true)),
        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        Poll::Pending => Poll::Ready(Ok(false)),
    })
    .await?;
    if ready {
        return Ok(Box::pin(async {}));
    }
    Ok(Box::pin(async move {
        let _ = future.await;
    }))
}

#[cfg(all(not(test), not(unix)))]
async fn shutdown_signal()
-> Result<Pin<Box<dyn Future<Output = ()> + Send>>, Box<dyn std::error::Error>> {
    Ok(arm_shutdown_future(tokio::signal::ctrl_c()).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    struct PendingThenReady {
        polls: Arc<AtomicUsize>,
    }

    impl Future for PendingThenReady {
        type Output = io::Result<()>;

        fn poll(self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
            let polls = self.polls.fetch_add(1, Ordering::SeqCst);
            if polls == 0 {
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }
    }

    #[tokio::test]
    async fn arm_shutdown_future_registers_listener_before_await() {
        let polls = Arc::new(AtomicUsize::new(0));
        let shutdown = arm_shutdown_future(PendingThenReady {
            polls: polls.clone(),
        })
        .await
        .unwrap();

        assert_eq!(polls.load(Ordering::SeqCst), 1);
        shutdown.await;
        assert_eq!(polls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn arm_shutdown_future_propagates_registration_error() {
        let err = match arm_shutdown_future(async {
            Err::<(), io::Error>(io::Error::other("listener failed"))
        })
        .await
        {
            Ok(_) => panic!("listener registration should fail"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(err.to_string(), "listener failed");
    }
}
