/*!
 * @brief 정책 판정에 쓰이는 요청자 신원.
 *
 * @details 전송 계층이 자기 프로토콜을 해석한 뒤, 정책이 필요로 하는 것만 여기에 담아
 *          공통 파이프라인으로 넘긴다.
 */

use std::net::IpAddr;

/**
 * @brief 질의가 도착한 전송 방식.
 *
 * @warning 이름이 같은 onetdns_runtime::Transport가 따로 있다. 서로 재수출하지 않으며
 *          변형 집합도 다르다. 혼동해서 바꿔 쓰면 안 된다.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /** @brief 평문 UDP. 유일하게 wire 고속 경로가 열리는 전송이다. */
    Do53Udp,
    /** @brief 평문 TCP. */
    Do53Tcp,
    /** @brief TLS 위의 DNS(RFC 7858). */
    DoT,
    /** @brief HTTP/2 위의 DNS(RFC 8484). */
    DoH,
    /** @brief HTTP/3 위의 DNS. */
    DoH3,
    /** @brief QUIC 위의 DNS(RFC 9250). */
    DoQ,
    /** @brief DNSCrypt v2. */
    DnsCrypt,
}

impl Transport {
    /** @brief 전송 종류 수. 전송별 통계 배열의 길이로 쓴다. */
    pub const COUNT: usize = 7;

    /** @brief 경로가 암호화되어 있는지. 패딩 적용 여부 판단에 쓴다. */
    pub fn is_encrypted(self) -> bool {
        !matches!(self, Transport::Do53Udp | Transport::Do53Tcp)
    }

    /**
     * @brief 전송별 배열 인덱스.
     * @invariant 값은 0..COUNT 범위이며 ALL의 위치와 일치한다. 어긋나면 통계가 서로
     *            다른 전송의 통계에 섞인다.
     */
    pub fn index(self) -> usize {
        match self {
            Transport::Do53Udp => 0,
            Transport::Do53Tcp => 1,
            Transport::DoT => 2,
            Transport::DoH => 3,
            Transport::DoH3 => 4,
            Transport::DoQ => 5,
            Transport::DnsCrypt => 6,
        }
    }

    /** @brief 로그·메트릭 레이블. 지표 이름의 일부이므로 임의로 바꾸면 대시보드가 끊긴다. */
    pub fn name(self) -> &'static str {
        match self {
            Transport::Do53Udp => "do53-udp",
            Transport::Do53Tcp => "do53-tcp",
            Transport::DoT => "dot",
            Transport::DoH => "doh",
            Transport::DoH3 => "doh3",
            Transport::DoQ => "doq",
            Transport::DnsCrypt => "dnscrypt",
        }
    }

    /** @brief 모든 전송을 index() 순서로 나열한 배열. */
    pub const ALL: [Transport; Self::COUNT] = [
        Transport::Do53Udp,
        Transport::Do53Tcp,
        Transport::DoT,
        Transport::DoH,
        Transport::DoH3,
        Transport::DoQ,
        Transport::DnsCrypt,
    ];
}

/**
 * @brief ACL·속도 제한·필터·정책이 판정 근거로 쓰는 클라이언트 정보.
 *
 * @details 여기 담긴 값이 응답을 바꾸면 그 기능은 wire 고속 경로의 자격 게이트에 자기
 *          자신을 등록해야 한다. 고속 경로는 클라이언트별로 달라지지 않는 응답만 캐시한다.
 */
#[derive(Debug, Clone)]
pub struct ClientInfo {
    /** @brief 요청자 주소. 프록시 프로토콜을 거쳤다면 원 클라이언트 주소다. */
    pub source_ip: IpAddr,

    /** @brief 클라이언트 식별자. DoH 경로 접미사나 DNSCrypt 이름에서 온다. */
    pub client_id: Option<String>,

    /** @brief 도착한 전송 방식. */
    pub transport: Transport,

    /** @brief 전송 계층에서 신원이 확인됐는지. 클라이언트 인증서·사전 공유 자격이 근거다. */
    pub authenticated: bool,
}
