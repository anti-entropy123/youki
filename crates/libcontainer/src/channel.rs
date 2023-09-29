use nix::sys::socket::{self, UnixAddr};
use serde::{Deserialize, Serialize};
use std::{
    io::{IoSlice, IoSliceMut},
    marker::PhantomData,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::prelude::RawFd,
    },
    sync::Arc,
};

#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("failed unix syscalls")]
    Nix(#[from] nix::Error),
    #[error("failed serde serialization")]
    Serde(#[from] serde_json::Error),
    #[error("channel connection broken")]
    BrokenChannel,
    #[error("unable to be closed")]
    Unclosed,
    #[error("channel has been closed")]
    ClosedChannel,
}
#[derive(Clone)]
pub struct Receiver<T> {
    receiver: Option<Arc<OwnedFd>>,
    phantom: PhantomData<T>,
}

#[derive(Clone)]
pub struct Sender<T> {
    sender: Option<Arc<OwnedFd>>,
    phantom: PhantomData<T>,
}

impl<T> Sender<T>
where
    T: Serialize,
{
    fn send_iovec(
        &mut self,
        iov: &[IoSlice],
        fds: Option<&[RawFd]>,
    ) -> Result<usize, ChannelError> {
        let cmsgs = if let Some(fds) = fds {
            vec![socket::ControlMessage::ScmRights(fds)]
        } else {
            vec![]
        };

        let sender = match self.sender.as_ref() {
            Some(sender) => sender,
            None => Err(ChannelError::ClosedChannel)?,
        };
        socket::sendmsg::<UnixAddr>(
            sender.as_raw_fd(),
            iov,
            &cmsgs,
            socket::MsgFlags::empty(),
            None,
        )
        .map_err(|e| e.into())
    }

    fn send_slice_with_len(
        &mut self,
        data: &[u8],
        fds: Option<&[RawFd]>,
    ) -> Result<usize, ChannelError> {
        let len = data.len() as u64;
        // Here we prefix the length of the data onto the serialized data.
        let iov = [
            IoSlice::new(unsafe {
                std::slice::from_raw_parts(
                    (&len as *const u64) as *const u8,
                    std::mem::size_of::<u64>(),
                )
            }),
            IoSlice::new(data),
        ];
        self.send_iovec(&iov[..], fds)
    }

    pub fn send(&mut self, object: T) -> Result<(), ChannelError> {
        let payload = serde_json::to_vec(&object)?;
        self.send_slice_with_len(&payload, None)?;

        Ok(())
    }

    pub fn send_fds(&mut self, object: T, fds: &[RawFd]) -> Result<(), ChannelError> {
        let payload = serde_json::to_vec(&object)?;
        self.send_slice_with_len(&payload, Some(fds))?;

        Ok(())
    }

    pub fn close(&mut self) -> Result<(), ChannelError> {
        let sender = match self.sender.as_ref() {
            Some(sender) => sender,
            None => Err(ChannelError::ClosedChannel)?,
        };
        // must ensure that the fd is closed immediately.
        let count = Arc::strong_count(sender);
        if count != 1 {
            tracing::trace!(?count, "incorrect reference count value");
            return Err(ChannelError::Unclosed)?;
        };
        self.sender = None;

        Ok(())
    }

    /// Enforce a decrement of the inner reference counter by 1.
    ///
    /// # Safety
    /// The reason for `unsafe` is the caller must ensure that it's only called
    /// when absolutely necessary. For instance, in the current implementation,
    /// `clone()` can cause a leak of references residing on the stack in the
    /// childprocess. This function allows for manual adjustment of the counter
    /// to correct such situations.
    pub unsafe fn decrement_count(&self) -> Result<(), ChannelError> {
        let sender = match self.sender.as_ref() {
            Some(sender) => sender,
            None => Err(ChannelError::ClosedChannel)?,
        };
        let rc = Arc::into_raw(Arc::clone(sender));
        Arc::decrement_strong_count(rc);
        Arc::from_raw(rc);

        Ok(())
    }
}

impl<T> Receiver<T>
where
    T: serde::de::DeserializeOwned,
{
    fn peek_size_iovec(&mut self) -> Result<u64, ChannelError> {
        let mut len: u64 = 0;
        let mut iov = [IoSliceMut::new(unsafe {
            std::slice::from_raw_parts_mut(
                (&mut len as *mut u64) as *mut u8,
                std::mem::size_of::<u64>(),
            )
        })];

        let receiver = match self.receiver.as_ref() {
            Some(receiver) => receiver,
            None => Err(ChannelError::ClosedChannel)?,
        };
        let _ = socket::recvmsg::<UnixAddr>(
            receiver.as_raw_fd(),
            &mut iov,
            None,
            socket::MsgFlags::MSG_PEEK,
        )?;
        match len {
            0 => Err(ChannelError::BrokenChannel),
            _ => Ok(len),
        }
    }

    fn recv_into_iovec<F>(
        &mut self,
        iov: &mut [IoSliceMut],
    ) -> Result<(usize, Option<F>), ChannelError>
    where
        F: Default + AsMut<[RawFd]>,
    {
        let mut cmsgspace = nix::cmsg_space!(F);

        let receiver = match self.receiver.as_ref() {
            Some(receiver) => receiver,
            None => Err(ChannelError::ClosedChannel)?,
        };
        let msg = socket::recvmsg::<UnixAddr>(
            receiver.as_raw_fd(),
            iov,
            Some(&mut cmsgspace),
            socket::MsgFlags::MSG_CMSG_CLOEXEC,
        )?;

        // Sending multiple SCM_RIGHTS message will led to platform dependent
        // behavior, with some system choose to return EINVAL when sending or
        // silently only process the first msg or send all of it. Here we assume
        // there is only one SCM_RIGHTS message and will only process the first
        // message.
        let fds: Option<F> = msg
            .cmsgs()
            .find_map(|cmsg| {
                if let socket::ControlMessageOwned::ScmRights(fds) = cmsg {
                    Some(fds)
                } else {
                    None
                }
            })
            .map(|fds| {
                let mut fds_array: F = Default::default();
                <F as AsMut<[RawFd]>>::as_mut(&mut fds_array).clone_from_slice(&fds);
                fds_array
            });

        Ok((msg.bytes, fds))
    }

    fn recv_into_buf_with_len<F>(&mut self) -> Result<(Vec<u8>, Option<F>), ChannelError>
    where
        F: Default + AsMut<[RawFd]>,
    {
        let msg_len = self.peek_size_iovec()?;
        let mut len: u64 = 0;
        let mut buf = vec![0u8; msg_len as usize];
        let (bytes, fds) = {
            let mut iov = [
                IoSliceMut::new(unsafe {
                    std::slice::from_raw_parts_mut(
                        (&mut len as *mut u64) as *mut u8,
                        std::mem::size_of::<u64>(),
                    )
                }),
                IoSliceMut::new(&mut buf),
            ];
            self.recv_into_iovec(&mut iov)?
        };

        match bytes {
            0 => Err(ChannelError::BrokenChannel),
            _ => Ok((buf, fds)),
        }
    }

    // Recv the next message of type T.
    pub fn recv(&mut self) -> Result<T, ChannelError> {
        let (buf, _) = self.recv_into_buf_with_len::<[RawFd; 0]>()?;
        Ok(serde_json::from_slice(&buf[..])?)
    }

    // Works similar to `recv`, but will look for fds sent by SCM_RIGHTS
    // message.  We use F as as `[RawFd; n]`, where `n` is the number of
    // descriptors you want to receive.
    pub fn recv_with_fds<F>(&mut self) -> Result<(T, Option<F>), ChannelError>
    where
        F: Default + AsMut<[RawFd]>,
    {
        let (buf, fds) = self.recv_into_buf_with_len::<F>()?;
        Ok((serde_json::from_slice(&buf[..])?, fds))
    }

    pub fn close(&mut self) -> Result<(), ChannelError> {
        let receiver = match self.receiver.as_ref() {
            Some(receiver) => receiver,
            None => Err(ChannelError::ClosedChannel)?,
        };
        // must ensure that the fd is closed immediately.
        let count = Arc::strong_count(receiver);
        if count != 1 {
            tracing::trace!(?count, "incorrect reference count value");
            return Err(ChannelError::Unclosed)?;
        };
        self.receiver = None;

        Ok(())
    }

    /// Enforce a decrement of the inner reference counter by 1.
    ///
    /// # Safety
    /// The reason for `unsafe` is same as `Sender::decrement_count()`.
    pub unsafe fn decrement_count(&self) -> Result<(), ChannelError> {
        let receiver = match self.receiver.as_ref() {
            Some(receiver) => receiver,
            None => Err(ChannelError::ClosedChannel)?,
        };

        let rc = Arc::into_raw(Arc::clone(receiver));
        Arc::decrement_strong_count(rc);
        Arc::from_raw(rc);

        Ok(())
    }
}

pub fn channel<T>() -> Result<(Sender<T>, Receiver<T>), ChannelError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let (os_sender, os_receiver) = unix_channel()?;
    let receiver = Receiver {
        receiver: Some(Arc::from(os_receiver)),
        phantom: PhantomData,
    };
    let sender = Sender {
        sender: Some(Arc::from(os_sender)),
        phantom: PhantomData,
    };
    Ok((sender, receiver))
}

// Use socketpair as the underlying pipe.
fn unix_channel() -> Result<(OwnedFd, OwnedFd), ChannelError> {
    Ok(socket::socketpair(
        socket::AddressFamily::Unix,
        socket::SockType::SeqPacket,
        None,
        socket::SockFlag::SOCK_CLOEXEC,
    )?)
}
