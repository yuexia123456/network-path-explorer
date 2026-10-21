use std::{
    future::Future,
    pin::Pin,
    sync::OnceLock,
    task::{Context, Poll},
};

thread_local! {
    static PANIC_SCOPE_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

static PANIC_HOOK: OnceLock<()> = OnceLock::new();

/// Install the process-wide hook used by scoped worker futures. A panic still unwinds through
/// `catch_unwind`, but the hook never receives a chance to print its payload while the future is
/// being polled inside this boundary.
pub(crate) fn install_panic_redaction_hook() {
    PANIC_HOOK.get_or_init(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let scoped = PANIC_SCOPE_DEPTH.with(|depth| depth.get() > 0);
            if scoped {
                eprintln!("network worker panicked");
            } else {
                previous(info);
            }
        }));
    });
}

pub(crate) struct RedactedFuture<F> {
    inner: Pin<Box<F>>,
}

impl<F> RedactedFuture<F> {
    pub(crate) fn new(inner: F) -> Self {
        Self {
            inner: Box::pin(inner),
        }
    }
}

impl<F> Unpin for RedactedFuture<F> {}

impl<F: Future> Future for RedactedFuture<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let _scope = PanicScope::enter();
        self.inner.as_mut().poll(context)
    }
}

struct PanicScope {
    previous_depth: usize,
}

impl PanicScope {
    fn enter() -> Self {
        let previous_depth = PANIC_SCOPE_DEPTH.with(|depth| {
            let previous = depth.get();
            depth.set(previous.saturating_add(1));
            previous
        });
        Self { previous_depth }
    }
}

impl Drop for PanicScope {
    fn drop(&mut self) {
        PANIC_SCOPE_DEPTH.with(|depth| depth.set(self.previous_depth));
    }
}
