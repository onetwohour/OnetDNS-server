/*!
 * @brief UDP 소켓을 여는 공통 경로.
 *
 * @details 윈도우의 UDP 소켓은 보낸 데이터그램이 ICMP 도달 불가로 돌아오면 그 오류를 다음
 *          수신 호출 하나에 돌려준다. 연결하지 않은 소켓에서는 그 오류가 어느 상대의 것인지
 *          알 수 없다. 발신 교환은 이 오류를 교환 실패로 보므로, 한 상대가 닫혀 있으면 같은
 *          소켓으로 다른 상대와 하던 교환까지 실패한다. 수신 소켓에서는 받지 못한 질의가
 *          없는데도 수신 실패가 기록된다. 그래서 두 보고를 모두 꺼 둔다.
 */

use std::io;
use std::net::{SocketAddr, UdpSocket};

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

#[cfg(windows)]
mod windows {
    use std::io;
    use std::net::UdpSocket;
    use std::os::windows::io::AsRawSocket;

    /** @brief ICMP 포트 도달 불가를 수신 오류로 돌려주는 동작. */
    const SIO_UDP_CONNRESET: u32 = 0x9800_000C;
    /** @brief ICMP TTL 만료를 수신 오류로 돌려주는 동작. */
    const SIO_UDP_NETRESET: u32 = 0x9800_000F;

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
}
