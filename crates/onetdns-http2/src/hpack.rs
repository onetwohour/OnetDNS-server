/*!
 * @brief HPACK 헤더 압축(RFC 7541).
 *
 * @details 정적 테이블과 동적 테이블을 함께 쓴다. 동적 테이블은 압축 컨텍스트를 연결 내내 공유하므로,
 *          한쪽이 테이블 상태를 잘못 갱신하면 이후 모든 헤더가 어긋난다. 오류는 스트림이
 *          아니라 연결 수준이다.
 */

use std::collections::VecDeque;

use crate::huffman;

/**
 * @brief 디코딩 결과 헤더 목록의 누적 크기 상한.
 * @warning HPACK은 압축 폭탄이 가능하다. 몇 바이트의 지시로 동적 테이블 항목을 반복 참조하면
 *          거대한 헤더 목록이 만들어지므로, 만들어 낸 총량 자체를 제한해야 한다.
 */
const MAX_DECODED_HEADER_LIST: usize = 32 * 1024;

/** @brief RFC 7541 부록 A의 정적 테이블. 인덱스 1부터 시작한다. */
const STATIC: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/**
 * @brief HPACK 가변 길이 정수를 읽는다.
 * @param prefix_bits 첫 바이트에서 값이 차지하는 비트 수.
 * @return (값, 소비한 바이트 수). 시프트 폭을 넘기는 입력은 None이다. 상한이 없으면
 *         연속 바이트로 무한히 이어 붙일 수 있다.
 */
pub fn decode_int(buf: &[u8], prefix_bits: u8) -> Option<(u64, usize)> {
    if !(1..=8).contains(&prefix_bits) {
        return None;
    }
    let mask = (1u16 << prefix_bits) as u64 - 1;
    let first = *buf.first()? as u64;
    let mut value = first & mask;
    if value < mask {
        return Some((value, 1));
    }
    let mut m = 0u32;
    let mut i = 1usize;
    loop {
        let b = *buf.get(i)? as u64;
        i += 1;
        let low = b & 0x7f;
        if m >= 64 || low > (u64::MAX >> m) {
            return None;
        }
        value = value.checked_add(low << m)?;
        m += 7;
        if b & 0x80 == 0 {
            break;
        }
        if m > 63 {
            return None;
        }
    }
    Some((value, i))
}

/** @brief HPACK 가변 길이 정수를 쓴다. first_high는 첫 바이트 상위 비트의 지시자다. */
pub fn encode_int(out: &mut Vec<u8>, value: u64, prefix_bits: u8, first_high: u8) {
    let mask = (1u16 << prefix_bits) as u64 - 1;
    if value < mask {
        out.push(first_high | value as u8);
        return;
    }
    out.push(first_high | mask as u8);
    let mut v = value - mask;
    while v >= 128 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/** @brief 문자열을 읽는다. 최상위 비트가 서 있으면 허프만 인코딩이다. */
fn decode_string(buf: &[u8]) -> Option<(Vec<u8>, usize)> {
    let huff = buf.first()? & 0x80 != 0;
    let (len, n) = decode_int(buf, 7)?;
    let end = n.checked_add(usize::try_from(len).ok()?)?;
    let raw = buf.get(n..end)?;
    let s = if huff {
        huffman::decode(raw)?
    } else {
        raw.to_vec()
    };
    Some((s, end))
}

/** @brief 문자열을 쓴다. 허프만은 결과가 더 짧을 때만 의미가 있다. */
fn encode_string(out: &mut Vec<u8>, s: &[u8], use_huffman: bool) {
    let huff = use_huffman && s.iter().all(|&b| b < 128);
    if huff {
        let enc = huffman::encode(s);
        if enc.len() < s.len() {
            encode_int(out, enc.len() as u64, 7, 0x80);
            out.extend_from_slice(&enc);
            return;
        }
    }
    encode_int(out, s.len() as u64, 7, 0x0);
    out.extend_from_slice(s);
}

/**
 * @brief HPACK 디코더. 연결 내내 동적 테이블 상태를 유지한다.
 * @invariant max_size <= allowed_max_size. 상대가 테이블을 이쪽이 광고한 크기 이상으로
 *            키우지 못하게 막는 한도다.
 */
pub struct Decoder {
    /** @brief 쌓아 둔 헤더들. */
    dynamic: VecDeque<(Vec<u8>, Vec<u8>)>,
    /** @brief 지금 담긴 크기. */
    size: usize,
    /** @brief 지금 허락한 테이블 크기. */
    max_size: usize,
    /** @brief 상대가 알린 최대 테이블 크기. 이보다 크게 요구하면 거부한다. */
    allowed_max_size: usize,
}

/** @brief 동적 테이블 항목의 회계상 크기. +32는 명세가 정한 항목 오버헤드다. */
fn entry_size(n: &[u8], v: &[u8]) -> usize {
    n.len() + v.len() + 32
}

impl Decoder {
    /** @brief 디코더를 만든다. max_size가 상대에게 광고한 테이블 크기다. */
    pub fn new(max_size: usize) -> Self {
        Decoder {
            dynamic: VecDeque::new(),
            size: 0,
            max_size,
            allowed_max_size: max_size,
        }
    }

    /**
     * @brief 인덱스로 헤더를 찾는다. 정적 테이블이 앞, 동적 테이블이 뒤다.
     * @note 인덱스 0은 유효하지 않다. 동적 테이블은 최근 삽입이 낮은 인덱스를 갖는다.
     */
    fn lookup(&self, index: u64) -> Option<(Vec<u8>, Vec<u8>)> {
        if index == 0 {
            return None;
        }
        let i = usize::try_from(index).ok()?;
        if i <= STATIC.len() {
            let (n, v) = STATIC[i - 1];
            Some((n.as_bytes().to_vec(), v.as_bytes().to_vec()))
        } else {
            self.dynamic.get(i - STATIC.len() - 1).cloned()
        }
    }

    /** @brief 동적 테이블 앞에 항목을 넣고, 넘치면 오래된 것부터 퇴거시킨다. */
    fn insert(&mut self, name: Vec<u8>, value: Vec<u8>) {
        let es = entry_size(&name, &value);
        self.dynamic.push_front((name, value));
        self.size += es;
        self.evict();
    }

    /** @brief 테이블 크기가 한도 이하가 될 때까지 오래된 항목을 버린다. */
    fn evict(&mut self) {
        while self.size > self.max_size {
            if let Some((n, v)) = self.dynamic.pop_back() {
                self.size -= entry_size(&n, &v);
            } else {
                break;
            }
        }
    }

    /**
     * @brief 동적 테이블 크기를 바꾼다.
     * @return 이쪽이 광고한 한도를 넘기려 하면 false. 그대로 받아 주면 상대가 이쪽 메모리
     *         사용량을 정하게 된다.
     */
    fn set_max(&mut self, m: usize) -> bool {
        if m > self.allowed_max_size {
            return false;
        }
        self.max_size = m;
        self.evict();
        true
    }

    /**
     * @brief 헤더 블록을 해석한다.
     *
     * @details 만들어 낸 헤더의 누적 크기를 세어 상한에서 멈춘다. 압축 폭탄 방어다.
     * @note 테이블 크기 갱신은 헤더 블록 맨 앞에서만 허용한다. 중간에 끼면 같은 블록을
     *       해석하는 구현마다 테이블 상태가 달라져 이후 헤더가 어긋난다.
     * @return 규칙 위반이면 None. 호출자는 연결 오류로 처리한다.
     */
    pub fn decode(&mut self, mut buf: &[u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut out = Vec::new();
        let mut decoded_size = 0usize;
        let mut size_updates = 0u8;
        let mut first_size_update = None;
        let mut account = |name: &[u8], value: &[u8]| -> Option<()> {
            decoded_size = decoded_size.checked_add(name.len() + value.len() + 32)?;
            (decoded_size <= MAX_DECODED_HEADER_LIST).then_some(())
        };
        while let Some(&first) = buf.first() {
            if first & 0x80 != 0 {
                let (idx, n) = decode_int(buf, 7)?;
                let (name, value) = self.lookup(idx)?;
                account(&name, &value)?;
                out.push((name, value));
                buf = &buf[n..];
            } else if first & 0x40 != 0 {
                let (name, value, consumed) = self.read_literal(buf, 6)?;
                account(&name, &value)?;
                self.insert(name.clone(), value.clone());
                out.push((name, value));
                buf = &buf[consumed..];
            } else if first & 0x20 != 0 {
                let (new_size, n) = decode_int(buf, 5)?;
                let new_size = usize::try_from(new_size).ok()?;
                if !out.is_empty()
                    || size_updates >= 2
                    || first_size_update.is_some_and(|first| new_size < first)
                    || !self.set_max(new_size)
                {
                    return None;
                }
                size_updates += 1;
                first_size_update.get_or_insert(new_size);
                buf = &buf[n..];
            } else {
                let (name, value, consumed) = self.read_literal(buf, 4)?;
                account(&name, &value)?;
                out.push((name, value));
                buf = &buf[consumed..];
            }
        }
        Some(out)
    }

    /** @brief 리터럴 헤더를 읽는다. 이름은 인덱스로 오거나 문자열로 온다. */
    fn read_literal(&self, buf: &[u8], prefix_bits: u8) -> Option<(Vec<u8>, Vec<u8>, usize)> {
        let (name_idx, mut pos) = decode_int(buf, prefix_bits)?;
        let name = if name_idx == 0 {
            let (n, used) = decode_string(&buf[pos..])?;
            pos += used;
            n
        } else {
            let (n, _) = self.lookup(name_idx)?;
            n
        };
        let (value, used) = decode_string(&buf[pos..])?;
        pos += used;
        Some((name, value, pos))
    }
}

/**
 * @brief 응답 헤더를 인코딩한다.
 * @note 동적 테이블을 쓰지 않는다. 인덱스 없는 리터럴만 내보낸다. DoH 응답은 헤더가 몇 개뿐이라
 *       압축 이득이 미미하고, 인코더 쪽 테이블 상태를 가지고 있지 않아도 되는 편이 단순하다.
 */
pub fn encode_response(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(name, value) in headers {
        if let Some(i) = STATIC.iter().position(|&(n, v)| n == name && v == value) {
            encode_int(&mut out, (i + 1) as u64, 7, 0x80);
            continue;
        }

        if let Some(i) = STATIC.iter().position(|&(n, _)| n == name) {
            encode_int(&mut out, (i + 1) as u64, 4, 0x00);
            encode_string(&mut out, value.as_bytes(), true);
        } else {
            out.push(0x00);
            encode_string(&mut out, name.as_bytes(), true);
            encode_string(&mut out, value.as_bytes(), true);
        }
    }
    out
}

#[cfg(test)]
/** @brief 규격 예제와 맞는지, 그리고 상한이 걸리는지. */
mod tests {
    use super::*;

    /** @brief 바이트열을 문자열로. */
    fn s(v: &[u8]) -> String {
        String::from_utf8(v.to_vec()).unwrap()
    }

    #[test]
    /** @brief 수 표기가 규격 예제와 맞는지. */
    fn integer_rfc_examples() {
        let mut o = Vec::new();
        encode_int(&mut o, 10, 5, 0);
        assert_eq!(o, vec![0x0a]);
        assert_eq!(decode_int(&[0x0a], 5).unwrap(), (10, 1));

        let mut o = Vec::new();
        encode_int(&mut o, 1337, 5, 0);
        assert_eq!(o, vec![0x1f, 0x9a, 0x0a]);
        assert_eq!(decode_int(&[0x1f, 0x9a, 0x0a], 5).unwrap(), (1337, 3));
    }

    #[test]
    /** @brief 고정 테이블의 항목을 읽는지. */
    fn decode_indexed_static() {
        let mut d = Decoder::new(4096);
        let hs = d.decode(&[0x82]).unwrap();
        assert_eq!(hs.len(), 1);
        assert_eq!(s(&hs[0].0), ":method");
        assert_eq!(s(&hs[0].1), "GET");
    }

    #[test]
    /** @brief 규격 예제 요청이 그대로 읽히는지. */
    fn rfc_c31_request_with_huffman_and_indexing() {
        let block = [
            0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
            0x90, 0xf4, 0xff,
        ];
        let mut d = Decoder::new(4096);
        let hs = d.decode(&block).unwrap();
        assert_eq!(hs.len(), 4);
        assert_eq!((s(&hs[0].0), s(&hs[0].1)), (":method".into(), "GET".into()));
        assert_eq!(
            (s(&hs[1].0), s(&hs[1].1)),
            (":scheme".into(), "http".into())
        );
        assert_eq!((s(&hs[2].0), s(&hs[2].1)), (":path".into(), "/".into()));
        assert_eq!(
            (s(&hs[3].0), s(&hs[3].1)),
            (":authority".into(), "www.example.com".into())
        );
    }

    #[test]
    /** @brief 적었다 읽으면 같은지. */
    fn encode_then_decode_response() {
        let block = encode_response(&[
            (":status", "200"),
            ("content-type", "application/dns-message"),
            ("content-length", "42"),
        ]);
        let mut d = Decoder::new(4096);
        let hs = d.decode(&block).unwrap();
        assert_eq!(hs.len(), 3);
        assert_eq!(
            (s(&hs[0].0).as_str(), s(&hs[0].1).as_str()),
            (":status", "200")
        );
        assert_eq!(s(&hs[1].0), "content-type");
        assert_eq!(s(&hs[1].1), "application/dns-message");
        assert_eq!(s(&hs[2].1), "42");
    }

    #[test]
    /** @brief 테이블에 쌓이는 항목의 왕복. */
    fn literal_with_incremental_indexing_roundtrips_dynamic() {
        let mut d = Decoder::new(4096);

        let mut block = vec![0x40];
        encode_string(&mut block, b"x-custom", false);
        encode_string(&mut block, b"hello", false);
        let hs = d.decode(&block).unwrap();
        assert_eq!(s(&hs[0].0), "x-custom");
        assert_eq!(s(&hs[0].1), "hello");

        let hs2 = d.decode(&[0xbe]).unwrap();
        assert_eq!(s(&hs2[0].0), "x-custom");
        assert_eq!(s(&hs2[0].1), "hello");
    }

    #[test]
    /** @brief 테이블 크기 변경이 헤더 앞에서만 오는지. 중간에 허용하면 양쪽 테이블이 어긋난다. */
    fn table_size_updates_are_limited_to_the_start_of_a_header_block() {
        let mut after_header = vec![0x82];
        encode_int(&mut after_header, 0, 5, 0x20);
        assert!(Decoder::new(4096).decode(&after_header).is_none());

        let three_updates = [0x20, 0x20, 0x20, 0x82];
        assert!(Decoder::new(4096).decode(&three_updates).is_none());
    }

    #[test]
    /** @brief 읽어 들이는 헤더 크기에 상한이 걸리는지. */
    fn decoded_header_list_is_bounded_at_the_advertised_limit() {
        let block = vec![0x82; 1024];
        assert!(Decoder::new(4096).decode(&block).is_none());
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    /** @brief 담을 수 없는 큰 값을 거부하는지. */
    fn rejects_lengths_indexes_and_table_sizes_wider_than_usize() {
        let wider = u64::from(u32::MAX) + 1;

        let mut string = Vec::new();
        encode_int(&mut string, wider, 7, 0);
        assert!(decode_string(&string).is_none());

        let mut indexed = Vec::new();
        encode_int(&mut indexed, wider + 2, 7, 0x80);
        assert!(Decoder::new(4096).decode(&indexed).is_none());

        let mut table_update = Vec::new();
        encode_int(&mut table_update, wider, 5, 0x20);
        assert!(Decoder::new(4096).decode(&table_update).is_none());
    }
}
