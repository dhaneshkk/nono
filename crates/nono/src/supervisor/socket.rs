//! Unix socket IPC for supervisor-child communication
//!
//! Provides [`SupervisorSocket`] for creating and managing the Unix domain socket
//! used for capability expansion requests between a sandboxed child and its
//! unsandboxed supervisor parent.
//!
//! The protocol uses length-prefixed JSON messages. File descriptors are passed
//! via `SCM_RIGHTS` ancillary data when the supervisor grants access to a path.

use crate::error::{NonoError, Result};
use crate::supervisor::types::{SupervisorMessage, SupervisorResponse};
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

/// Length prefix size: 4 bytes (u32 big-endian)
const LENGTH_PREFIX_SIZE: usize = 4;

/// Maximum message size: 64 KiB (prevents memory exhaustion from malicious messages)
const MAX_MESSAGE_SIZE: u32 = 64 * 1024;

/// A Unix domain socket for supervisor IPC.
///
/// Created by the supervisor before fork. The child inherits one end via the
/// forked file descriptor table, or the fd is explicitly passed.
///
/// # Protocol
///
/// Messages are length-prefixed JSON:
/// ```text
/// [4 bytes: u32 big-endian length][N bytes: JSON payload]
/// ```
///
/// When granting access, the supervisor sends the response message AND passes
/// an opened file descriptor via `SCM_RIGHTS` ancillary data.
pub struct SupervisorSocket {
    stream: UnixStream,
    socket_path: Option<PathBuf>,
}

impl SupervisorSocket {
    /// Create a connected socket pair for supervisor-child IPC.
    ///
    /// Returns `(supervisor_end, child_end)`. Call this before fork:
    /// - The supervisor keeps `supervisor_end`
    /// - The child inherits `child_end` (or it's passed explicitly)
    #[must_use = "both socket ends must be used"]
    pub fn pair() -> Result<(Self, Self)> {
        let (s1, s2) = UnixStream::pair().map_err(|e| {
            NonoError::SandboxInit(format!("Failed to create supervisor socket pair: {e}"))
        })?;
        Ok((
            SupervisorSocket {
                stream: s1,
                socket_path: None,
            },
            SupervisorSocket {
                stream: s2,
                socket_path: None,
            },
        ))
    }

    /// Create a supervisor socket bound to a filesystem path.
    ///
    /// The supervisor binds and listens; the child connects after fork.
    /// The socket file is cleaned up on drop.
    pub fn bind(path: &Path) -> Result<Self> {
        let listener = std::os::unix::net::UnixListener::bind(path).map_err(|e| {
            NonoError::SandboxInit(format!(
                "Failed to bind supervisor socket at {}: {e}",
                path.display()
            ))
        })?;

        // Set permissions to 0700 (owner only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(path, perms).map_err(|e| {
                NonoError::SandboxInit(format!("Failed to set supervisor socket permissions: {e}"))
            })?;
        }

        let (stream, _addr) = listener.accept().map_err(|e| {
            NonoError::SandboxInit(format!("Failed to accept supervisor connection: {e}"))
        })?;

        Ok(SupervisorSocket {
            stream,
            socket_path: Some(path.to_path_buf()),
        })
    }

    /// Connect to a supervisor socket at the given path.
    pub fn connect(path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(path).map_err(|e| {
            NonoError::SandboxInit(format!(
                "Failed to connect to supervisor socket at {}: {e}",
                path.display()
            ))
        })?;
        Ok(SupervisorSocket {
            stream,
            socket_path: None,
        })
    }

    /// Wrap an existing `UnixStream` (e.g., from an inherited fd after fork).
    #[must_use]
    pub fn from_stream(stream: UnixStream) -> Self {
        SupervisorSocket {
            stream,
            socket_path: None,
        }
    }

    /// Get the raw file descriptor for this socket.
    ///
    /// Useful for passing to the child process via environment variable
    /// or for `select()`/`poll()` integration.
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }

    /// Send a message from child to supervisor.
    pub fn send_message(&mut self, msg: &SupervisorMessage) -> Result<()> {
        let payload = serde_json::to_vec(msg).map_err(|e| {
            NonoError::SandboxInit(format!("Failed to serialize supervisor message: {e}"))
        })?;
        self.write_frame(&payload)
    }

    /// Receive a message from child (supervisor side).
    pub fn recv_message(&mut self) -> Result<SupervisorMessage> {
        let payload = self.read_frame()?;
        serde_json::from_slice(&payload).map_err(|e| {
            NonoError::SandboxInit(format!("Failed to deserialize supervisor message: {e}"))
        })
    }

    /// Send a response from supervisor to child.
    pub fn send_response(&mut self, resp: &SupervisorResponse) -> Result<()> {
        let payload = serde_json::to_vec(resp).map_err(|e| {
            NonoError::SandboxInit(format!("Failed to serialize supervisor response: {e}"))
        })?;
        self.write_frame(&payload)
    }

    /// Receive a response from supervisor (child side).
    pub fn recv_response(&mut self) -> Result<SupervisorResponse> {
        let payload = self.read_frame()?;
        serde_json::from_slice(&payload).map_err(|e| {
            NonoError::SandboxInit(format!("Failed to deserialize supervisor response: {e}"))
        })
    }

    /// Send a file descriptor to the peer via `SCM_RIGHTS`.
    ///
    /// Used by the supervisor to pass an opened fd for a granted path.
    pub fn send_fd(&self, fd: RawFd) -> Result<()> {
        use libc::{c_void, cmsghdr, iovec, msghdr, sendmsg, CMSG_DATA, CMSG_LEN, CMSG_SPACE};
        use std::mem;

        let data: [u8; 1] = [0]; // Dummy byte (required for ancillary data)
        let iov = iovec {
            iov_base: data.as_ptr() as *mut c_void,
            iov_len: 1,
        };

        // Ancillary data buffer for one fd
        let cmsg_space = unsafe { CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as usize;
        let mut cmsg_buf = vec![0u8; cmsg_space];

        let mut msg: msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &iov as *const iovec as *mut iovec;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = cmsg_space as _;

        // SAFETY: We're writing to the cmsg buffer we allocated, within its bounds.
        // The buffer size was calculated with CMSG_SPACE for exactly one RawFd.
        let cmsg: &mut cmsghdr = unsafe { &mut *(cmsg_buf.as_mut_ptr().cast::<cmsghdr>()) };
        cmsg.cmsg_level = libc::SOL_SOCKET;
        cmsg.cmsg_type = libc::SCM_RIGHTS;
        cmsg.cmsg_len = unsafe { CMSG_LEN(mem::size_of::<RawFd>() as u32) } as _;

        // SAFETY: CMSG_DATA returns a pointer into the cmsg buffer, which we own.
        // We write exactly one RawFd, which matches CMSG_LEN.
        unsafe {
            std::ptr::copy_nonoverlapping(
                &fd as *const RawFd as *const u8,
                CMSG_DATA(cmsg),
                mem::size_of::<RawFd>(),
            );
        }

        // SAFETY: msg is fully initialized with valid iov and cmsg data.
        // The socket fd is valid (from self.stream).
        let sent = unsafe { sendmsg(self.stream.as_raw_fd(), &msg, 0) };
        if sent < 0 {
            return Err(NonoError::SandboxInit(format!(
                "Failed to send fd via SCM_RIGHTS: {}",
                std::io::Error::last_os_error()
            )));
        }

        Ok(())
    }

    /// Receive a file descriptor from the peer via `SCM_RIGHTS`.
    ///
    /// Used by the child to receive an opened fd for a granted path.
    /// Returns an `OwnedFd` that the caller is responsible for.
    pub fn recv_fd(&self) -> Result<OwnedFd> {
        use libc::{c_void, cmsghdr, iovec, msghdr, recvmsg, CMSG_DATA, CMSG_LEN, CMSG_SPACE};
        use std::mem;

        let mut data: [u8; 1] = [0];
        let mut iov = iovec {
            iov_base: data.as_mut_ptr() as *mut c_void,
            iov_len: 1,
        };

        let cmsg_space = unsafe { CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as usize;
        let mut cmsg_buf = vec![0u8; cmsg_space];

        let mut msg: msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &mut iov as *mut iovec;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = cmsg_space as _;

        // SAFETY: msg is fully initialized with valid iov and cmsg buffers.
        let received = unsafe { recvmsg(self.stream.as_raw_fd(), &mut msg, 0) };
        if received < 0 {
            return Err(NonoError::SandboxInit(format!(
                "Failed to receive fd via SCM_RIGHTS: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Extract the fd from ancillary data
        // SAFETY: We check that the cmsg header matches our expected level/type
        // before reading the fd data.
        let cmsg: &cmsghdr = unsafe { &*(cmsg_buf.as_ptr().cast::<cmsghdr>()) };
        if cmsg.cmsg_level != libc::SOL_SOCKET || cmsg.cmsg_type != libc::SCM_RIGHTS {
            return Err(NonoError::SandboxInit(
                "No SCM_RIGHTS data in received message".to_string(),
            ));
        }

        let expected_len = unsafe { CMSG_LEN(mem::size_of::<RawFd>() as u32) } as usize;
        if (cmsg.cmsg_len as usize) < expected_len {
            return Err(NonoError::SandboxInit(
                "SCM_RIGHTS ancillary data too small".to_string(),
            ));
        }

        let mut fd: RawFd = -1;
        // SAFETY: CMSG_DATA returns a pointer into the cmsg buffer we received.
        // We read exactly one RawFd, matching the expected CMSG_LEN.
        unsafe {
            std::ptr::copy_nonoverlapping(
                CMSG_DATA(cmsg),
                &mut fd as *mut RawFd as *mut u8,
                mem::size_of::<RawFd>(),
            );
        }

        if fd < 0 {
            return Err(NonoError::SandboxInit(
                "Received invalid fd from SCM_RIGHTS".to_string(),
            ));
        }

        // SAFETY: The fd was just received via SCM_RIGHTS and validated as non-negative.
        // We take ownership so it will be properly closed.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Authenticate the peer using platform-specific mechanisms.
    ///
    /// On Linux, uses `SO_PEERCRED` to get the peer's PID/UID/GID.
    /// On macOS, uses `LOCAL_PEERPID` to get the peer's PID.
    ///
    /// Returns the peer's PID.
    pub fn peer_pid(&self) -> Result<u32> {
        #[cfg(target_os = "linux")]
        {
            use libc::{getsockopt, socklen_t, ucred, SOL_SOCKET, SO_PEERCRED};
            use std::mem;

            let mut cred: ucred = unsafe { mem::zeroed() };
            let mut len = mem::size_of::<ucred>() as socklen_t;

            // SAFETY: getsockopt with SO_PEERCRED writes a ucred struct.
            // We provide a valid buffer and length.
            let ret = unsafe {
                getsockopt(
                    self.stream.as_raw_fd(),
                    SOL_SOCKET,
                    SO_PEERCRED,
                    &mut cred as *mut ucred as *mut libc::c_void,
                    &mut len,
                )
            };
            if ret < 0 {
                return Err(NonoError::SandboxInit(format!(
                    "SO_PEERCRED failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            // pid_t is i32, cast to u32 (valid PIDs are always positive)
            Ok(cred.pid as u32)
        }

        #[cfg(target_os = "macos")]
        {
            use libc::{getsockopt, socklen_t};
            use std::mem;

            // LOCAL_PEERPID = 0x002 on macOS
            const LOCAL_PEERPID: libc::c_int = 0x002;

            let mut pid: libc::pid_t = 0;
            let mut len = mem::size_of::<libc::pid_t>() as socklen_t;

            // SAFETY: getsockopt with LOCAL_PEERPID writes a pid_t.
            // We provide a valid buffer and length.
            let ret = unsafe {
                getsockopt(
                    self.stream.as_raw_fd(),
                    0, // SOL_LOCAL = 0 on macOS
                    LOCAL_PEERPID,
                    &mut pid as *mut libc::pid_t as *mut libc::c_void,
                    &mut len,
                )
            };
            if ret < 0 {
                return Err(NonoError::SandboxInit(format!(
                    "LOCAL_PEERPID failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            Ok(pid as u32)
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(NonoError::UnsupportedPlatform(
                "Peer credential lookup not supported on this platform".to_string(),
            ))
        }
    }

    /// Set a read timeout on the socket.
    pub fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> Result<()> {
        self.stream
            .set_read_timeout(timeout)
            .map_err(|e| NonoError::SandboxInit(format!("Failed to set socket read timeout: {e}")))
    }

    /// Write a length-prefixed frame to the socket.
    fn write_frame(&mut self, payload: &[u8]) -> Result<()> {
        let len = payload.len();
        if len > MAX_MESSAGE_SIZE as usize {
            return Err(NonoError::SandboxInit(format!(
                "Supervisor message too large: {len} bytes (max: {MAX_MESSAGE_SIZE})"
            )));
        }

        let len_bytes = (len as u32).to_be_bytes();
        self.stream
            .write_all(&len_bytes)
            .map_err(|e| NonoError::SandboxInit(format!("Failed to write message length: {e}")))?;
        self.stream
            .write_all(payload)
            .map_err(|e| NonoError::SandboxInit(format!("Failed to write message payload: {e}")))?;
        Ok(())
    }

    /// Read a length-prefixed frame from the socket.
    fn read_frame(&mut self) -> Result<Vec<u8>> {
        let mut len_bytes = [0u8; LENGTH_PREFIX_SIZE];
        self.stream
            .read_exact(&mut len_bytes)
            .map_err(|e| NonoError::SandboxInit(format!("Failed to read message length: {e}")))?;

        let len = u32::from_be_bytes(len_bytes);
        if len > MAX_MESSAGE_SIZE {
            return Err(NonoError::SandboxInit(format!(
                "Supervisor message too large: {len} bytes (max: {MAX_MESSAGE_SIZE})"
            )));
        }

        let mut payload = vec![0u8; len as usize];
        self.stream
            .read_exact(&mut payload)
            .map_err(|e| NonoError::SandboxInit(format!("Failed to read message payload: {e}")))?;
        Ok(payload)
    }
}

impl Drop for SupervisorSocket {
    fn drop(&mut self) {
        // Clean up the socket file if we created one
        if let Some(ref path) = self.socket_path {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::AccessMode;
    use crate::supervisor::types::{CapabilityRequest, SupervisorMessage, SupervisorResponse};

    #[test]
    fn test_socket_pair_roundtrip() {
        let (mut supervisor, mut child) = SupervisorSocket::pair()
            .ok()
            .expect("Failed to create socket pair");

        let request = CapabilityRequest {
            request_id: "req-001".to_string(),
            path: "/tmp/test".into(),
            access: AccessMode::Read,
            reason: Some("test access".to_string()),
            child_pid: 12345,
            session_id: "sess-001".to_string(),
        };

        // Child sends request
        child
            .send_message(&SupervisorMessage::Request(request.clone()))
            .ok()
            .expect("Failed to send message");

        // Supervisor receives it
        let msg = supervisor
            .recv_message()
            .ok()
            .expect("Failed to receive message");
        match msg {
            SupervisorMessage::Request(req) => {
                assert_eq!(req.request_id, "req-001");
                assert_eq!(req.path, PathBuf::from("/tmp/test"));
                assert_eq!(req.child_pid, 12345);
            }
            SupervisorMessage::ShimRequest { .. } => {
                panic!("Expected Request, got ShimRequest");
            }
        }

        // Supervisor sends response
        let response = SupervisorResponse::Decision {
            request_id: "req-001".to_string(),
            decision: crate::supervisor::types::ApprovalDecision::Granted,
        };
        supervisor
            .send_response(&response)
            .ok()
            .expect("Failed to send response");

        // Child receives it
        let resp = child
            .recv_response()
            .ok()
            .expect("Failed to receive response");
        match resp {
            SupervisorResponse::Decision {
                request_id,
                decision,
            } => {
                assert_eq!(request_id, "req-001");
                assert!(decision.is_granted());
            }
            SupervisorResponse::ExtensionToken { .. } => {
                panic!("Expected Decision, got ExtensionToken");
            }
        }
    }

    #[test]
    fn test_fd_passing() {
        let (supervisor, child) = SupervisorSocket::pair()
            .ok()
            .expect("Failed to create socket pair");

        // Create a temporary file to pass
        let tmp = tempfile::NamedTempFile::new()
            .ok()
            .expect("Failed to create temp file");
        let fd = tmp.as_raw_fd();

        // Supervisor sends fd
        supervisor.send_fd(fd).ok().expect("Failed to send fd");

        // Child receives fd
        let received_fd = child.recv_fd().ok().expect("Failed to receive fd");
        assert!(received_fd.as_raw_fd() >= 0);
    }

    #[test]
    fn test_message_too_large() {
        let (mut supervisor, _child) = SupervisorSocket::pair()
            .ok()
            .expect("Failed to create socket pair");

        let large_payload = vec![0u8; (MAX_MESSAGE_SIZE as usize) + 1];
        let result = supervisor.write_frame(&large_payload);
        assert!(result.is_err());
    }

    #[test]
    fn test_peer_pid() {
        let (supervisor, _child) = SupervisorSocket::pair()
            .ok()
            .expect("Failed to create socket pair");

        // For a socketpair in the same process, peer_pid should return our own PID
        let pid = supervisor.peer_pid().ok().expect("Failed to get peer PID");
        assert_eq!(pid, std::process::id());
    }
}
