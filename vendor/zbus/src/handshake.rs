use futures_core::ready;

use std::{
    fmt::Debug,
    future::Future,
    marker::PhantomData,
    ops::Deref,
    pin::Pin,
    task::{Context, Poll},
};

use crate::{
    guid::Guid,
    raw::{self, Handshake as SyncHandshake, Socket},
    Result,
};

/// The asynchronous authentication implementation based on non-blocking [`raw::Handshake`].
///
/// The underlying socket is in nonblocking mode. Enabling blocking mode on it, will lead to
/// undefined behaviour.
pub(crate) struct Authenticated<S>(raw::Authenticated<S>);

impl<S> Authenticated<S> {
    /// Unwraps the inner [`raw::Authenticated`].
    pub fn into_inner(self) -> raw::Authenticated<S> {
        self.0
    }
}

impl<S> Deref for Authenticated<S> {
    type Target = raw::Authenticated<S>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> Authenticated<S>
where
    S: Socket + Unpin,
{
    /// Create a client-side `Authenticated` for the given `socket`.
    pub async fn client(socket: S) -> Result<Self> {
        Handshake {
            handshake: Some(raw::ClientHandshake::new(socket)),
            phantom: PhantomData,
        }
        .await
    }

    /// Create a server-side `Authenticated` for the given `socket`.
    pub async fn server(socket: S, guid: Guid, client_uid: u32) -> Result<Self> {
        Handshake {
            handshake: Some(raw::ServerHandshake::new(socket, guid, client_uid)),
            phantom: PhantomData,
        }
        .await
    }
}

struct Handshake<H, S> {
    handshake: Option<H>,
    phantom: PhantomData<S>,
}

impl<H, S> Future for Handshake<H, S>
where
    H: SyncHandshake<S> + Unpin + Debug,
    S: Unpin,
{
    type Output = Result<Authenticated<S>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let self_mut = &mut self.get_mut();
        let handshake = self_mut
            .handshake
            .as_mut()
            .expect("ClientHandshake::poll() called unexpectedly");

        ready!(handshake.advance_handshake(cx))?;

        let handshake = self_mut
            .handshake
            .take()
            .expect("<Handshake as Future>::poll() called unexpectedly");
        let authenticated = handshake
            .try_finish()
            .expect("Failed to finish a successful handshake");

        Poll::Ready(Ok(Authenticated(authenticated)))
    }
}

#[cfg(test)]
mod tests {
    use async_io::Async;
    use nix::unistd::Uid;
    use std::os::unix::net::UnixStream;
    use test_log::test;

    use super::*;

    use crate::{Guid, Result};

    #[test]
    fn async_handshake() {
        async_io::block_on(handshake()).unwrap();
    }

    async fn handshake() -> Result<()> {
        // a pair of non-blocking connection UnixStream
        let (p0, p1) = UnixStream::pair()?;

        // initialize both handshakes
        let client = Authenticated::client(Async::new(p0)?);
        let server =
            Authenticated::server(Async::new(p1)?, Guid::generate(), Uid::current().into());

        // proceed to the handshakes
        let (client_auth, server_auth) = futures_util::try_join!(client, server)?;

        assert_eq!(client_auth.server_guid, server_auth.server_guid);
        assert_eq!(client_auth.cap_unix_fd, server_auth.cap_unix_fd);

        Ok(())
    }
}
