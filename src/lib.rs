use nix::sys::socket::ControlMessageOwned;
use std::io::Error;
use std::net::UdpSocket;
use std::os::unix::io::{AsRawFd, RawFd};

pub trait SocketErrRecvExt {
    /// Receive an asynchronous socket error.
    ///
    /// On success, the message that caused the error is written into `buf`.  The length of that
    /// message is returned as the first value in the result tuple.
    fn recv_err(&self, buf: &mut [u8]) -> Result<(usize, ControlMessageOwned), Error>;
}

impl SocketErrRecvExt for UdpSocket {
    fn recv_err(&self, buf: &mut [u8]) -> Result<(usize, ControlMessageOwned), Error> {
        self.as_raw_fd().recv_err(buf)
    }
}

impl SocketErrRecvExt for RawFd {
    fn recv_err(&self, buf: &mut [u8]) -> Result<(usize, ControlMessageOwned), Error> {
        use nix::sys::socket::{MsgFlags, recvmsg};
        use nix::sys::uio::IoVec;
        use std::io::ErrorKind;

        let iovec = [IoVec::from_mut_slice(buf)];
        let mut cm_space = nix::cmsg_space!(libc::sock_extended_err, libc::sockaddr_in6);
        let msg = recvmsg(*self, &iovec, Some(&mut cm_space), MsgFlags::MSG_ERRQUEUE)?;

        let mut cmsgs = msg.cmsgs();
        let cmsg = cmsgs.next()
            .ok_or(Error::new(ErrorKind::Other, "control message expected, but none present"))?;
        Ok((msg.bytes, cmsg))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use nix::sys::socket::{setsockopt, sockopt};

    const PING: &[u8] = &[1, 2, 3, 4];

    // TODO: Test should skip on IPv6-only hosts, but will unwrap somewhere instead.
    #[test]
    fn basic_ipv4() {
        use nix::sys::socket::Ipv4Addr;

        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        // Enable async socket errors
        setsockopt(socket.as_raw_fd(), sockopt::Ipv4RecvErr, &true).unwrap();

        // Test: send a datagram to an unlikely high-numbered port
        socket.send_to(PING, "127.0.0.1:34567").unwrap();

        // Our extension:
        let mut buf = [0u8; 576];
        let (bytes, cmsg) = socket.recv_err(&mut buf).unwrap();

        assert_eq!(&buf[..bytes], PING);
        match cmsg {
            ControlMessageOwned::Ipv4RecvErr(exterr, origin) => {
                assert_eq!(exterr.ee_errno as i32, libc::ECONNREFUSED);
                assert_eq!(exterr.ee_origin, libc::SO_EE_ORIGIN_ICMP);
                assert_eq!(exterr.ee_type, 3); // ICMP Unreachable
                assert_eq!(exterr.ee_code, 3); // ICMP Unreachable port
                assert_eq!(origin.map(|s| Ipv4Addr(s.sin_addr)),
                    Some(Ipv4Addr::new(127, 0, 0, 1)));
            }
            _ => panic!("Unexpected cmsg: {:?}", cmsg),
        }
    }

    // TODO: Test should skip on IPv4-only hosts, but will unwrap somewhere instead.
    #[test]
    fn basic_ipv6() {
        use nix::sys::socket::Ipv6Addr;

        let socket = UdpSocket::bind("[::]:0").unwrap();
        // Enable async socket errors
        setsockopt(socket.as_raw_fd(), sockopt::Ipv6RecvErr, &true).unwrap();

        // Test: send a datagram to an unlikely high-numbered port
        socket.send_to(PING, "[::1]:34567").unwrap();

        // Our extension:
        let mut buf = [0u8; 576];
        let (bytes, cmsg) = socket.recv_err(&mut buf).unwrap();

        assert_eq!(&buf[..bytes], PING);
        match cmsg {
            ControlMessageOwned::Ipv6RecvErr(exterr, origin) => {
                assert_eq!(exterr.ee_errno as i32, libc::ECONNREFUSED);
                assert_eq!(exterr.ee_origin, libc::SO_EE_ORIGIN_ICMP6);
                assert_eq!(exterr.ee_type, 1); // ICMPv6 Unreachable
                assert_eq!(exterr.ee_code, 4); // ICMPv6 Unreachable port
                assert_eq!(origin.map(|s| Ipv6Addr(s.sin6_addr)),
                    Some(Ipv6Addr::new(0,0,0,0,0,0,0,1)));
            }
            _ => panic!("Unexpected cmsg: {:?}", cmsg),
        }
    }
}
