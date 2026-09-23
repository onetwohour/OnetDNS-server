/*!
 * @brief UDP 소켓을 열고 받는 공통 경로.
 *
 * @details 윈도우의 UDP 소켓은 보낸 데이터그램이 ICMP 도달 불가로 돌아오면 그 오류를 다음
 *          수신 호출 하나에 돌려준다. 연결하지 않은 소켓에서는 그 오류가 어느 상대의 것인지
 *          알 수 없다. 발신 교환은 이 오류를 교환 실패로 보므로, 한 상대가 닫혀 있으면 같은
 *          소켓으로 다른 상대와 하던 교환까지 실패한다. 수신 소켓에서는 받지 못한 질의가
 *          없는데도 수신 실패가 기록된다. 그래서 두 보고를 모두 꺼 둔다. 수신 대기에 한도를
 *          두는 루프는 RecvWait 로 받는다.
 */

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/**
 * @brief UDP 소켓을 열고 ICMP 오류가 수신을 깨뜨리지 않게 한다.
 * @note 유닉스는 연결하지 않은 UDP 소켓에 ICMP 오류를 전달하지 않으므로 여는 것만 한다.
 */
pub fn bind(addr: impl Into<SocketAddr>) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(addr.into())?;
    #[cfg(windows)]
    windows::ignore_icmp_errors(&socket)?;
    Ok(socket)
}

/**
 * @brief 한도를 두고 데이터그램 하나를 기다리는 수신.
 *
 * @details 윈도우에서 소켓 수신 한도에 걸려 끝나는 수신 호출은 그 순간 도착한 데이터그램을
 *          버린다. CPU 가 붐빌수록 자주 버리고, 버린 데이터그램은 보낸 쪽이 다시 보내기 전까지
 *          오지 않는다. 그래서 윈도우에서는 소켓에 한도를 걸지 않고, 읽을 데이터그램이 생길
 *          때까지 WSAPoll 로 기다린 다음에 받는다. 유닉스의 소켓 수신 한도는 데이터그램을
 *          버리지 않으므로 그대로 쓴다.
 * @warning 한 소켓을 한 스레드만 읽을 때 쓴다. 기다리는 사이 다른 스레드가 데이터그램을
 *          가져가면 뒤따르는 수신이 한도 없이 막힌다. 여러 스레드가 나눠 읽는 소켓은 한도 없이
 *          기다리게 하고, 멈출 때 깨우는 데이터그램을 보낸다.
 */
#[derive(Debug, Clone, Copy)]
pub struct RecvWait {
    /** @brief 데이터그램 하나를 기다리는 최대 시간. */
    timeout: Duration,
}

impl RecvWait {
    /** @brief 한도를 정한다. install 로 소켓에 건 다음에 받는다. */
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /**
     * @brief 소켓의 수신 대기를 이 한도에 맞춘다.
     * @details 윈도우에서는 소켓 한도를 걷어 내 수신 호출이 한도에 걸려 끝나는 일이 없게 한다.
     */
    pub fn install(self, socket: &UdpSocket) -> io::Result<()> {
        if cfg!(windows) {
            socket.set_read_timeout(None)
        } else {
            socket.set_read_timeout(Some(self.timeout))
        }
    }

    /**
     * @brief 한도 안에 도착한 데이터그램 하나를 받는다.
     * @retval Err 한도 안에 오지 않았으면 종류가 WouldBlock 이나 TimedOut 인 오류.
     */
    pub fn recv_from(self, socket: &UdpSocket, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.wait(socket)?;
        socket.recv_from(buf)
    }

    /**
     * @brief 연결한 소켓에서 한도 안에 도착한 데이터그램 하나를 받는다.
     * @retval Err 한도 안에 오지 않았으면 종류가 WouldBlock 이나 TimedOut 인 오류.
     */
    pub fn recv(self, socket: &UdpSocket, buf: &mut [u8]) -> io::Result<usize> {
        self.wait(socket)?;
        socket.recv(buf)
    }

    /** @brief 윈도우에서 읽을 데이터그램이 생길 때까지 기다린다. 유닉스는 소켓 한도가 맡는다. */
    fn wait(self, socket: &UdpSocket) -> io::Result<()> {
        #[cfg(windows)]
        if !windows::wait_readable(socket, self.timeout)? {
            return Err(io::ErrorKind::TimedOut.into());
        }
        #[cfg(not(windows))]
        let _ = socket;
        Ok(())
    }
}

#[cfg(windows)]
mod windows {
    use std::io;
    use std::net::UdpSocket;
    use std::os::windows::io::AsRawSocket;
    use std::time::Duration;

    /** @brief ICMP 포트 도달 불가를 수신 오류로 돌려주는 동작. */
    const SIO_UDP_CONNRESET: u32 = 0x9800_000C;
    /** @brief ICMP TTL 만료를 수신 오류로 돌려주는 동작. */
    const SIO_UDP_NETRESET: u32 = 0x9800_000F;
    /** @brief 보통 데이터를 읽을 수 있게 됐다는 사건. */
    const POLLRDNORM: i16 = 0x0100;

    /** @brief WSAPoll 이 소켓 하나를 기다릴 때 쓰는 항목. */
    #[repr(C)]
    struct PollFd {
        /** @brief 기다릴 소켓 핸들. */
        fd: usize,
        /** @brief 기다릴 사건. */
        events: i16,
        /** @brief 일어난 사건. WSAPoll 이 채운다. */
        revents: i16,
    }

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        /** @brief 소켓 제어 호출. */
        fn WSAIoctl(
            socket: usize,
            code: u32,
            input: *const core::ffi::c_void,
            input_len: u32,
            output: *mut core::ffi::c_void,
            output_len: u32,
            returned: *mut u32,
            overlapped: *mut core::ffi::c_void,
            completion: *mut core::ffi::c_void,
        ) -> i32;
        /** @brief 소켓들이 준비될 때까지 밀리초 한도 안에서 기다린다. */
        fn WSAPoll(fds: *mut PollFd, count: u32, timeout_ms: i32) -> i32;
    }

    /**
     * @brief 소켓에 읽을 것이 생길 때까지 기다린다.
     * @return 한도 안에 생겼으면 true. 오류 상태도 읽을 것으로 보고, 뒤따르는 수신이 그 오류를
     *         돌려준다.
     * @safety 살아 있는 소켓 핸들을 담은 항목 하나를 넘기고, 호출이 끝날 때까지 그 항목을
     *         빌려 둔다.
     */
    pub(super) fn wait_readable(socket: &UdpSocket, timeout: Duration) -> io::Result<bool> {
        let timeout_ms = i32::try_from(timeout.as_nanos().div_ceil(1_000_000)).unwrap_or(i32::MAX);
        let mut entry = PollFd {
            fd: socket.as_raw_socket() as usize,
            events: POLLRDNORM,
            revents: 0,
        };
        let ready = unsafe { WSAPoll(&mut entry, 1, timeout_ms) };
        if ready < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(ready > 0)
    }

    /**
     * @brief 두 ICMP 오류 보고를 끈다.
     * @safety 살아 있는 소켓 핸들과 수명 동안 유효한 4바이트 입력, 반환 길이 칸을 넘기고
     *         겹침 입출력은 쓰지 않는다.
     */
    pub(super) fn ignore_icmp_errors(socket: &UdpSocket) -> io::Result<()> {
        for code in [SIO_UDP_CONNRESET, SIO_UDP_NETRESET] {
            let off: u32 = 0;
            let mut returned: u32 = 0;
            let rc = unsafe {
                WSAIoctl(
                    socket.as_raw_socket() as usize,
                    code,
                    (&off as *const u32).cast(),
                    std::mem::size_of::<u32>() as u32,
                    core::ptr::null_mut(),
                    0,
                    &mut returned,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    /**
     * @brief 닫힌 포트로 보낸 뒤 첫 수신이 오류 없이 다음 데이터그램을 돌려주는지.
     * @details 윈도우 기본 동작이면 첫 수신이 연결 재설정 오류로 끝난다. 발신 교환은 그
     *          오류를 교환 실패로 본다.
     */
    fn datagram_after_icmp_unreachable_is_received() {
        let server = bind(([127, 0, 0, 1], 0)).expect("bind");
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let closed = UdpSocket::bind("127.0.0.1:0").unwrap();
        let closed_addr = closed.local_addr().unwrap();
        drop(closed);
        for _ in 0..3 {
            server.send_to(b"late reply", closed_addr).unwrap();
        }
        std::thread::sleep(Duration::from_millis(100));

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .send_to(b"query", server.local_addr().unwrap())
            .unwrap();
        let mut buf = [0u8; 16];
        let (n, from) = server.recv_from(&mut buf).expect("질의를 받아야 합니다");
        assert_eq!(&buf[..n], b"query");
        assert_eq!(from, client.local_addr().unwrap());
    }

    #[test]
    /**
     * @brief 윈도우에서는 소켓 한도를 걷어 내고 유닉스에서는 그대로 거는지.
     * @details 윈도우 소켓에 한도가 남으면 한도에 걸려 끝나는 순간 도착한 데이터그램을 버린다.
     *          이 손실은 CPU 가 붐빌 때만 드러나 시험으로 재현하기 어려우므로 설치 결과를 본다.
     */
    fn recv_wait_keeps_windows_sockets_free_of_receive_timeouts() {
        let socket = bind(([127, 0, 0, 1], 0)).expect("bind");
        socket
            .set_read_timeout(Some(Duration::from_secs(9)))
            .unwrap();
        RecvWait::new(Duration::from_millis(40))
            .install(&socket)
            .unwrap();
        let expected = if cfg!(windows) {
            None
        } else {
            Some(Duration::from_millis(40))
        };
        assert_eq!(socket.read_timeout().unwrap(), expected);
    }

    #[test]
    /** @brief 기다리는 동안 온 데이터그램을 받고, 오지 않으면 한도 뒤에 시간 초과로 끝나는지. */
    fn recv_wait_returns_datagram_or_times_out() {
        let socket = bind(([127, 0, 0, 1], 0)).expect("bind");
        let wait = RecvWait::new(Duration::from_millis(50));
        wait.install(&socket).unwrap();
        let mut buf = [0u8; 16];

        let started = std::time::Instant::now();
        let error = wait
            .recv_from(&socket, &mut buf)
            .expect_err("보낸 것이 없으면 한도 뒤에 끝나야 합니다");
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        assert!(started.elapsed() >= Duration::from_millis(40));

        let target = socket.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let late = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            sender.send_to(b"late", target).unwrap();
        });
        let wait = RecvWait::new(Duration::from_secs(5));
        wait.install(&socket).unwrap();
        let (n, _) = wait
            .recv_from(&socket, &mut buf)
            .expect("기다리는 동안 온 데이터그램을 받아야 합니다");
        assert_eq!(&buf[..n], b"late");
        late.join().unwrap();
    }
}
