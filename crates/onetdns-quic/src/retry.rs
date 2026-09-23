/*!
 * @brief 주소 검증용 Retry와 토큰.
 *
 * @details 연결을 열기 전에 클라이언트가 그 주소에 실제로 있는지 확인한다. 확인하지
 *          않으면 출발지를 속인 요청 하나로 이쪽이 남에게 큰 응답을 보내는 증폭이 된다.
 * @warning 토큰은 인증돼야 한다. 클라이언트가 내용을 지어낼 수 있으면 검증 자체가 무의미하다.
 */

use std::net::IpAddr;

use sha2::{Digest, Sha256};

use crate::packet::{ptype, VERSION_1};
use crate::protect::Aead;

/** @brief 토큰 형식 버전. 형식을 바꾸면 올린다. */
const TOKEN_VERSION: u8 = 1;
/** @brief 토큰 유효 기간. 짧게 잡아 재사용할 수 있는 시간을 좁힌다. */
const TOKEN_TTL_SECS: u64 = 30;
/** @brief 토큰 인증 태그 길이. */
const TOKEN_TAG_LEN: usize = 16;
/** @brief Retry 무결성 태그 키. 규격이 정한 고정값이다. */
const RETRY_INTEGRITY_KEY: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
/** @brief Retry 무결성 태그 논스. 규격이 정한 고정값이다. */
const RETRY_INTEGRITY_NONCE: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

#[derive(Clone)]
/** @brief 토큰 발급과 검증에 쓰는 비밀. 프로세스마다 새로 만든다. */
pub struct RetryKey([u8; 32]);

/** @brief Initial 패킷 헤더에서 추출한 것들. */
pub struct InitialHeader<'a> {
    /** @brief 받는 쪽 연결 식별자. */
    pub dcid: &'a [u8],
    /** @brief 보내는 쪽 연결 식별자. */
    pub scid: &'a [u8],
    /** @brief 실려 온 재시도 토큰. */
    pub token: &'a [u8],
}

impl RetryKey {
    /** @brief 새 비밀을 만든다. */
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        onetdns_tls::sys::fill_random(&mut key);
        Self(key)
    }

    /**
     * @brief 이 주소와 식별자에 묶인 토큰을 발급한다.
     * @details 주소, 원래 식별자, 시각을 담고 그 전체를 인증한다. 다른 주소에서 재사용하면
     *          검증에서 걸린다.
     */
    pub fn issue(&self, ip: IpAddr, odcid: &[u8], retry_scid: &[u8], now: u64) -> Vec<u8> {
        let mut token = Vec::with_capacity(64);
        token.push(TOKEN_VERSION);
        token.extend_from_slice(&now.to_be_bytes());
        encode_ip(&mut token, ip);
        token.push(odcid.len() as u8);
        token.extend_from_slice(odcid);
        token.push(retry_scid.len() as u8);
        token.extend_from_slice(retry_scid);
        let tag = hmac_sha256(&self.0, &token);
        token.extend_from_slice(&tag[..TOKEN_TAG_LEN]);
        token
    }

    /**
     * @brief 토큰이 이 주소와 지금 시각에 유효한지 확인한다.
     * @return 유효하면 원래 목적지 식별자. 이것이 있어야 이후 핸드셰이크가 이어진다.
     */
    pub fn validate(&self, token: &[u8], ip: IpAddr, dcid: &[u8], now: u64) -> Option<Vec<u8>> {
        if token.len() < 1 + 8 + 1 + 4 + 1 + 1 + TOKEN_TAG_LEN {
            return None;
        }
        let (body, tag) = token.split_at(token.len().checked_sub(TOKEN_TAG_LEN)?);
        let expected = hmac_sha256(&self.0, body);
        if !ct_eq(tag, &expected[..TOKEN_TAG_LEN]) {
            return None;
        }
        let mut pos = 0;
        if *body.get(pos)? != TOKEN_VERSION {
            return None;
        }
        pos += 1;
        let issued = u64::from_be_bytes(body.get(pos..pos + 8)?.try_into().ok()?);
        pos += 8;
        if issued > now.saturating_add(5) || now.saturating_sub(issued) > TOKEN_TTL_SECS {
            return None;
        }
        let (bound_ip, used) = decode_ip(body.get(pos..)?)?;
        pos += used;
        if bound_ip != ip {
            return None;
        }
        let odcid_len = *body.get(pos)? as usize;
        pos += 1;
        if odcid_len == 0 || odcid_len > 20 {
            return None;
        }
        let odcid = body.get(pos..pos + odcid_len)?.to_vec();
        pos += odcid_len;
        let retry_len = *body.get(pos)? as usize;
        pos += 1;
        if retry_len == 0 || retry_len > 20 || pos + retry_len != body.len() {
            return None;
        }
        if !ct_eq(body.get(pos..pos + retry_len)?, dcid) {
            return None;
        }
        Some(odcid)
    }
}

/** @brief Initial 패킷에서 식별자와 토큰을 추출한다. 아직 복호화하지 않은 상태다. */
pub fn parse_initial_header(packet: &[u8]) -> Option<InitialHeader<'_>> {
    let first = *packet.first()?;
    if first & 0xc0 != 0xc0 || ((first & 0x30) >> 4) != ptype::INITIAL {
        return None;
    }
    if packet.get(1..5)? != VERSION_1.to_be_bytes() {
        return None;
    }
    let mut pos = 5;
    let dcid_len = *packet.get(pos)? as usize;
    pos += 1;
    if dcid_len == 0 || dcid_len > 20 {
        return None;
    }
    let dcid = packet.get(pos..pos + dcid_len)?;
    pos += dcid_len;
    let scid_len = *packet.get(pos)? as usize;
    pos += 1;
    /*
     * 클라이언트는 길이 0인 출발지 연결 식별자를 쓸 수 있고 msquic 이 기본으로 그렇게 한다.
     * 여기서 막으면 그런 클라이언트의 Initial 을 조용히 버려 연결이 끝내 열리지 않는다.
     */
    if scid_len > 20 {
        return None;
    }
    let scid = packet.get(pos..pos + scid_len)?;
    pos += scid_len;
    let (token_len, used) = crate::varint::read(packet.get(pos..)?)?;
    let token_len = usize::try_from(token_len).ok()?;
    if token_len > 256 {
        return None;
    }
    pos += used;
    let token = packet.get(pos..pos + token_len)?;
    Some(InitialHeader { dcid, scid, token })
}

/** @brief Retry 패킷을 만든다. 무결성 태그가 원래 식별자에 묶인다. */
pub fn build_retry(odcid: &[u8], client_scid: &[u8], retry_scid: &[u8], token: &[u8]) -> Vec<u8> {
    let mut packet =
        Vec::with_capacity(7 + client_scid.len() + retry_scid.len() + token.len() + 16);
    packet.push(0xf0);
    packet.extend_from_slice(&VERSION_1.to_be_bytes());
    packet.push(client_scid.len() as u8);
    packet.extend_from_slice(client_scid);
    packet.push(retry_scid.len() as u8);
    packet.extend_from_slice(retry_scid);
    packet.extend_from_slice(token);
    let mut aad = Vec::with_capacity(1 + odcid.len() + packet.len());
    aad.push(odcid.len() as u8);
    aad.extend_from_slice(odcid);
    aad.extend_from_slice(&packet);
    let tag = Aead::Aes128Gcm.seal(&RETRY_INTEGRITY_KEY, &RETRY_INTEGRITY_NONCE, 0, &aad, &[]);
    packet.extend_from_slice(&tag);
    packet
}

/**
 * @brief Retry 패킷의 무결성 태그를 확인한다.
 * @warning 태그가 원래 목적지 식별자에 묶여 있다. 확인하지 않으면 중간자가 Retry를 지어내
 *          연결을 자기 쪽으로 돌릴 수 있다.
 */
pub(crate) fn verify_integrity(odcid: &[u8], packet: &[u8]) -> bool {
    if packet.len() < 16 {
        return false;
    }
    let (body, tag) = packet.split_at(packet.len() - 16);
    let mut aad = Vec::with_capacity(1 + odcid.len() + body.len());
    aad.push(odcid.len() as u8);
    aad.extend_from_slice(odcid);
    aad.extend_from_slice(body);
    let expected = Aead::Aes128Gcm.seal(&RETRY_INTEGRITY_KEY, &RETRY_INTEGRITY_NONCE, 0, &aad, &[]);
    ct_eq(tag, &expected)
}

/** @brief 주소를 토큰에 담을 형태로 쓴다. */
fn encode_ip(out: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(ip) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(6);
            out.extend_from_slice(&ip.octets());
        }
    }
}

/** @brief 토큰에서 주소를 읽는다. */
fn decode_ip(input: &[u8]) -> Option<(IpAddr, usize)> {
    match *input.first()? {
        4 => Some((
            IpAddr::V4(std::net::Ipv4Addr::from(
                <[u8; 4]>::try_from(input.get(1..5)?).ok()?,
            )),
            5,
        )),
        6 => Some((
            IpAddr::V6(std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(input.get(1..17)?).ok()?,
            )),
            17,
        )),
        _ => None,
    }
}

/** @brief HMAC-SHA-256. 토큰 인증에 쓴다. */
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > block.len() {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; 64];
    let mut outer_pad = [0x5cu8; 64];
    for index in 0..64 {
        inner_pad[index] ^= block[index];
        outer_pad[index] ^= block[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(data);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
}

/**
 * @brief 상수 시간 비교.
 * @warning 태그 비교에 쓴다. 조기 반환을 넣으면 걸린 시간으로 옳은 태그를 알아낼 수 있다.
 */
fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

#[cfg(test)]
/** @brief 무결성 태그를 규격 벡터에 대조하고, 토큰이 주소·식별자·시각에 묶이는지 본다. */
mod tests {
    use super::*;

    #[test]
    /** @brief Retry 무결성 태그를 규격 부록 벡터와 비교한다. */
    fn rfc9001_a4_retry_integrity_vector() {
        let odcid: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let packet: Vec<u8> = vec![
            0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62,
            0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82,
            0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba,
        ];
        assert!(
            verify_integrity(&odcid, &packet),
            "RFC 9001 A.4 벡터 불일치: 태그 계산이 표준과 다르면 상호운용이 조용히 깨진다"
        );
    }

    #[test]
    /** @brief 토큰이 주소·식별자·시각에 묶이고 위조되지 않는지. */
    fn token_binds_ip_cid_time_and_authentication() {
        let key = RetryKey([7; 32]);
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        let token = key.issue(ip, b"original", b"retrycid", 100);
        assert_eq!(
            key.validate(&token, ip, b"retrycid", 110),
            Some(b"original".to_vec())
        );
        assert!(key
            .validate(&token, "192.0.2.11".parse().unwrap(), b"retrycid", 110)
            .is_none());
        assert!(key.validate(&token, ip, b"othercid", 110).is_none());
        assert!(key.validate(&token, ip, b"retrycid", 131).is_none());
        let mut forged = token;
        forged[3] ^= 1;
        assert!(key.validate(&forged, ip, b"retrycid", 110).is_none());
    }

    #[test]
    /** @brief 태그가 원래 목적지 식별자에 묶이는지. 묶이지 않으면 Retry를 지어낼 수 있다. */
    fn retry_packet_integrity_binds_original_destination_cid() {
        let mut packet = build_retry(b"original", b"client", b"server", b"token");
        assert!(verify_integrity(b"original", &packet));
        assert!(!verify_integrity(b"different", &packet));
        packet[8] ^= 1;
        assert!(!verify_integrity(b"original", &packet));
    }

    #[test]
    /**
     * @brief 출발지 연결 식별자가 길이 0인 Initial 을 받아들이는지.
     * @details msquic 을 쓰는 클라이언트가 이렇게 보낸다. 거부하면 리스너가 그 Initial 을
     *          조용히 버려 핸드셰이크가 시간 초과로 끝난다.
     */
    fn initial_header_accepts_zero_length_source_connection_id() {
        let mut packet = vec![0xc0];
        packet.extend_from_slice(&VERSION_1.to_be_bytes());
        packet.push(8);
        packet.extend_from_slice(b"ORIGDCID");
        packet.push(0);
        packet.push(0);
        packet.extend_from_slice(&[0u8; 32]);

        let header = parse_initial_header(&packet).expect("길이 0인 출발지 식별자");
        assert_eq!(header.dcid, b"ORIGDCID");
        assert!(header.scid.is_empty());
        assert!(header.token.is_empty());

        let retry = build_retry(header.dcid, header.scid, b"RETRYCID", b"token");
        assert!(verify_integrity(b"ORIGDCID", &retry));
    }
}
