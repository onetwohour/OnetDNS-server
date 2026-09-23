/*!
 * @brief PROXY 프로토콜 v1/v2 헤더 파서.
 *
 * @details 로드밸런서 뒤에서 원래 클라이언트 주소를 복원한다.
 * @warning 이 헤더는 신뢰할 수 있는 출발지에서만 받아들여야 한다. 아무에게나 허용하면
 *          누구나 출발지 주소를 위조해 ACL과 속도 제한을 전부 우회한다. 신뢰 판정은
 *          호출자(TCP 워커)가 하며, 이 파서는 형식만 본다.
 */

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/**
 * @brief PROXY v2 고정 서명.
 * @details 일반 DNS와 겹치지 않도록 고안된 값이라, 이 12바이트로 v2 여부를 확정할 수 있다.
 */
const V2_SIG: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/** @brief 헤더 파싱 결과. */
pub enum ProxyParse {
    /** @brief 원래 클라이언트 주소와 헤더가 차지한 바이트 수. */
    Addr(SocketAddr, usize),

    /** @brief 프록시 자신의 연결(헬스체크 등). 주소를 바꾸지 않고 헤더만 건너뛴다. */
    Local(usize),

    /** @brief 아직 헤더가 다 오지 않았다. 더 읽고 다시 부른다. */
    Incomplete,

    /** @brief 프록시 헤더가 아니다. 처음부터 DNS 데이터로 취급한다. */
    NotProxy,
}

/**
 * @brief 버퍼 앞부분을 PROXY 헤더로 해석한다.
 * @details 두 버전의 서명을 먼저 보고, 어느 쪽도 확정할 수 없을 만큼 짧으면 Incomplete를
 *          돌려준다. 짧다는 이유로 NotProxy로 판정하면 헤더가 DNS 데이터로 오인된다.
 */
pub fn parse(buf: &[u8]) -> ProxyParse {
    if buf.len() >= 12 && buf[..12] == V2_SIG {
        return parse_v2(buf);
    }
    if buf.starts_with(b"PROXY ") {
        return parse_v1(buf);
    }

    if buf.len() < 6 && b"PROXY ".starts_with(buf) {
        return ProxyParse::Incomplete;
    }

    if buf.len() < 12 && V2_SIG.starts_with(buf) {
        return ProxyParse::Incomplete;
    }
    ProxyParse::NotProxy
}

/**
 * @brief v1 텍스트 헤더를 해석한다.
 * @details 규격상 최대 107바이트다. 그 안에 \r\n이 없으면 헤더가 아니라고 확정한다.
 *          그러지 않으면 종결자를 안 보내는 연결이 버퍼를 무한정 키운다.
 * @note 프로토콜 표기와 주소 계열이 어긋나면 거부한다. TCP4에 IPv6를 담은 헤더를
 *       받아들이면 주소 해석이 구현마다 갈린다.
 */
fn parse_v1(buf: &[u8]) -> ProxyParse {
    let end = match buf.windows(2).position(|w| w == b"\r\n") {
        Some(p) => p,
        None => {
            return if buf.len() > 107 {
                ProxyParse::NotProxy
            } else {
                ProxyParse::Incomplete
            }
        }
    };
    let consumed = end + 2;
    let line = match std::str::from_utf8(&buf[..end]) {
        Ok(s) => s,
        Err(_) => return ProxyParse::NotProxy,
    };
    let fields: Vec<&str> = line.split_ascii_whitespace().collect();
    if fields.first().copied() != Some("PROXY") {
        return ProxyParse::NotProxy;
    }
    if fields.get(1).copied() == Some("UNKNOWN") {
        return if fields.len() == 2 {
            ProxyParse::Local(consumed)
        } else {
            ProxyParse::NotProxy
        };
    }
    if fields.len() != 6 {
        return ProxyParse::NotProxy;
    }
    let proto = fields[1];
    let (Ok(src), Ok(dst), Ok(sport), Ok(_dport)) = (
        fields[2].parse::<IpAddr>(),
        fields[3].parse::<IpAddr>(),
        fields[4].parse::<u16>(),
        fields[5].parse::<u16>(),
    ) else {
        return ProxyParse::NotProxy;
    };
    let family_ok = matches!(
        (proto, src, dst),
        ("TCP4", IpAddr::V4(_), IpAddr::V4(_)) | ("TCP6", IpAddr::V6(_), IpAddr::V6(_))
    );
    if !family_ok || sport == 0 {
        return ProxyParse::NotProxy;
    }
    ProxyParse::Addr(SocketAddr::new(src, sport), consumed)
}

/**
 * @brief v2 이진 헤더를 해석한다.
 * @details 길이 필드로 뒤따르는 주소 블록 크기를 알 수 있다. 선언된 길이만큼 다 오지
 *          않았으면 Incomplete다.
 * @note TCP over IPv4(0x11)와 IPv6(0x21)만 받는다. UDP나 유닉스 소켓 계열은 이 서버가
 *       PROXY로 받을 일이 없으므로 거부한다.
 */
fn parse_v2(buf: &[u8]) -> ProxyParse {
    if buf.len() < 16 {
        return ProxyParse::Incomplete;
    }
    let ver_cmd = buf[12];
    if ver_cmd >> 4 != 0x2 {
        return ProxyParse::NotProxy;
    }
    let cmd = ver_cmd & 0x0f;
    if cmd > 1 {
        return ProxyParse::NotProxy;
    }
    let fam_proto = buf[13];
    let len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    let Some(total) = 16usize.checked_add(len) else {
        return ProxyParse::NotProxy;
    };
    if buf.len() < total {
        return ProxyParse::Incomplete;
    }
    if cmd == 0 {
        return ProxyParse::Local(total);
    }
    let addr = &buf[16..total];
    match fam_proto {
        0x11 if addr.len() >= 12 => {
            let ip = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
            let port = u16::from_be_bytes([addr[8], addr[9]]);
            if port == 0 {
                ProxyParse::NotProxy
            } else {
                ProxyParse::Addr(SocketAddr::new(IpAddr::V4(ip), port), total)
            }
        }
        0x21 if addr.len() >= 36 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&addr[..16]);
            let ip = Ipv6Addr::from(o);
            let port = u16::from_be_bytes([addr[32], addr[33]]);
            if port == 0 {
                ProxyParse::NotProxy
            } else {
                ProxyParse::Addr(SocketAddr::new(IpAddr::V6(ip), port), total)
            }
        }
        _ => ProxyParse::NotProxy,
    }
}

#[cfg(test)]
/** @brief 두 프로토콜 버전의 읽기와, 평범한 질의를 잘못 읽지 않는지. */
mod tests {
    use super::*;

    /** @brief 읽어 낸 주소와 소비한 길이. */
    fn addr(p: ProxyParse) -> (SocketAddr, usize) {
        match p {
            ProxyParse::Addr(a, n) => (a, n),
            _ => panic!("Addr 기대"),
        }
    }

    #[test]
    /** @brief v1 IPv4 헤더. */
    fn v1_tcp4() {
        let line = b"PROXY TCP4 192.168.0.1 10.0.0.1 56324 443\r\nDNSDATA";
        let (a, n) = addr(parse(line));
        assert_eq!(a, "192.168.0.1:56324".parse().unwrap());
        assert_eq!(n, line.len() - "DNSDATA".len());
    }

    #[test]
    /** @brief v1 IPv6와 모르는 형식. */
    fn v1_tcp6_and_unknown() {
        let line = b"PROXY TCP6 2001:db8::1 2001:db8::2 1234 53\r\n";
        let (a, _) = addr(parse(line));
        assert_eq!(a, "[2001:db8::1]:1234".parse().unwrap());

        match parse(b"PROXY UNKNOWN\r\n") {
            ProxyParse::Local(n) => assert_eq!(n, 15),
            _ => panic!("Local 기대"),
        }
    }

    #[test]
    /** @brief 나눠 온 헤더가 이어지는지. */
    fn v1_incomplete_then_complete() {
        assert!(matches!(parse(b"PRO"), ProxyParse::Incomplete));
        assert!(matches!(
            parse(b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2"),
            ProxyParse::Incomplete
        ));
    }

    #[test]
    /** @brief v2 IPv4 헤더. */
    fn v2_ipv4() {
        let mut h = V2_SIG.to_vec();
        h.push(0x21);
        h.push(0x11);
        h.extend_from_slice(&12u16.to_be_bytes());
        h.extend_from_slice(&[203, 0, 113, 7]);
        h.extend_from_slice(&[10, 0, 0, 1]);
        h.extend_from_slice(&0xd903u16.to_be_bytes());
        h.extend_from_slice(&53u16.to_be_bytes());
        h.extend_from_slice(b"DNS");
        let (a, n) = addr(parse(&h));
        assert_eq!(a, "203.0.113.7:55555".parse().unwrap());
        assert_eq!(n, h.len() - 3);
    }

    #[test]
    /** @brief v2의 자기 자신 표기. */
    fn v2_local_command() {
        let mut h = V2_SIG.to_vec();
        h.push(0x20);
        h.push(0x00);
        h.extend_from_slice(&0u16.to_be_bytes());
        match parse(&h) {
            ProxyParse::Local(n) => assert_eq!(n, 16),
            _ => panic!("Local 기대"),
        }
    }

    #[test]
    /** @brief 평범한 질의를 헤더로 오해하지 않는지. 오해하면 앞부분을 먹어 치운다. */
    fn not_proxy_plain_dns() {
        assert!(matches!(
            parse(&[0x00, 0x1d, 0xab, 0xcd]),
            ProxyParse::NotProxy
        ));
    }
}
