/*!
 * @brief HTTP/2 프레임 헤더와 프로토콜 상수.
 */

/** @brief 클라이언트가 연결 시작에 보내는 고정 서문(RFC 9113). */
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/** @brief 프레임 헤더 길이: 길이 3, 종류 1, 플래그 1, 스트림 4. */
pub const FRAME_HEADER_LEN: usize = 9;

/** @brief 기본 최대 프레임 크기. 이보다 큰 프레임은 협상 없이는 받지 않는다. */
pub const DEFAULT_MAX_FRAME: usize = 16_384;

/** @brief 프레임 종류 코드. */
pub mod frame_type {
    /** @brief 본문 조각. */
    pub const DATA: u8 = 0x0;
    /** @brief 헤더. */
    pub const HEADERS: u8 = 0x1;
    /** @brief 우선순위. */
    pub const PRIORITY: u8 = 0x2;
    /** @brief 이 스트림을 끊는다. */
    pub const RST_STREAM: u8 = 0x3;
    /** @brief 설정 교환. */
    pub const SETTINGS: u8 = 0x4;
    /** @brief 서버 푸시. 이 구현은 푸시를 꺼 두므로 받으면 프로토콜 오류다. */
    pub const PUSH_PROMISE: u8 = 0x5;
    /** @brief 살아 있는지 확인. */
    pub const PING: u8 = 0x6;
    /** @brief 연결을 마무리하겠다는 통지. */
    pub const GOAWAY: u8 = 0x7;
    /** @brief 흐름 제어 윈도우를 늘린다. */
    pub const WINDOW_UPDATE: u8 = 0x8;
    /** @brief 헤더가 이어진다. */
    pub const CONTINUATION: u8 = 0x9;
}

/**
 * @brief 프레임 플래그 비트.
 * @note 같은 비트가 프레임 종류에 따라 다른 뜻이다. 0x1은 DATA/HEADERS에서 END_STREAM,
 *       SETTINGS/PING에서는 ACK다.
 */
pub mod flags {
    /** @brief 이 스트림의 마지막 프레임. */
    pub const END_STREAM: u8 = 0x1;

    /** @brief 받았다는 응답. */
    pub const ACK: u8 = 0x1;
    /** @brief 헤더가 여기서 끝난다. */
    pub const END_HEADERS: u8 = 0x4;
    /** @brief 채우기가 붙어 있다. */
    pub const PADDED: u8 = 0x8;
    /** @brief 우선순위 정보가 붙어 있다. */
    pub const PRIORITY: u8 = 0x20;
}

/** @brief SETTINGS 매개변수 식별자. */
pub mod settings {
    /** @brief 헤더 압축 테이블 크기. */
    pub const HEADER_TABLE_SIZE: u16 = 0x1;
    /** @brief 서버가 밀어 보내는 것을 허용할지. */
    pub const ENABLE_PUSH: u16 = 0x2;
    /** @brief 동시에 열 수 있는 스트림 수. */
    pub const MAX_CONCURRENT_STREAMS: u16 = 0x3;
    /** @brief 처음 흐름 제어 윈도우. */
    pub const INITIAL_WINDOW_SIZE: u16 = 0x4;
    /** @brief 프레임 하나의 크기 상한. */
    pub const MAX_FRAME_SIZE: u16 = 0x5;
    /** @brief 헤더 전체 크기 상한. */
    pub const MAX_HEADER_LIST_SIZE: u16 = 0x6;
}

/** @brief RST_STREAM·GOAWAY에 담기는 오류 코드. */
pub mod error_code {
    /** @brief 오류 없음. */
    pub const NO_ERROR: u32 = 0x0;
    /** @brief 프로토콜을 어겼다. */
    pub const PROTOCOL_ERROR: u32 = 0x1;
    /** @brief 이쪽 문제. */
    pub const INTERNAL_ERROR: u32 = 0x2;
    /** @brief 흐름 제어를 어겼다. */
    pub const FLOW_CONTROL_ERROR: u32 = 0x3;
    /** @brief 프레임 크기가 어긋났다. */
    pub const FRAME_SIZE_ERROR: u32 = 0x6;
    /** @brief 이 스트림을 받지 않는다. */
    pub const REFUSED_STREAM: u32 = 0x7;
    /** @brief 그만둔다. */
    pub const CANCEL: u32 = 0x8;
    /** @brief 헤더 압축 상태가 깨졌다. */
    pub const COMPRESSION_ERROR: u32 = 0x9;
}

/** @brief 9바이트 프레임 헤더. */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /** @brief 페이로드 길이. 와이어에서는 24비트다. */
    pub length: u32,
    /** @brief 이 프레임의 종류. */
    pub frame_type: u8,
    /** @brief 이 프레임에 붙은 표시들. */
    pub flags: u8,

    /** @brief 스트림 번호. 최상위 예약 비트는 항상 지워진다. */
    pub stream_id: u32,
}

impl FrameHeader {
    /** @brief 헤더를 만든다. */
    pub fn new(frame_type: u8, flags: u8, stream_id: u32, length: u32) -> Self {
        FrameHeader {
            length,
            frame_type,
            flags,
            stream_id,
        }
    }

    /**
     * @brief 헤더를 해석한다.
     * @note 스트림 번호의 최상위 예약 비트를 마스크로 지운다. 명세가 무시하라고 정한
     *       비트라, 남겨 두면 같은 스트림이 서로 다른 번호로 보인다.
     */
    pub fn parse(b: &[u8]) -> Option<FrameHeader> {
        if b.len() < FRAME_HEADER_LEN {
            return None;
        }
        Some(FrameHeader {
            length: u32::from_be_bytes([0, b[0], b[1], b[2]]),
            frame_type: b[3],
            flags: b[4],
            stream_id: u32::from_be_bytes([b[5], b[6], b[7], b[8]]) & 0x7fff_ffff,
        })
    }

    /** @brief 헤더를 와이어 바이트로 만든다. 길이는 하위 24비트만 담긴다. */
    pub fn encode(&self) -> [u8; FRAME_HEADER_LEN] {
        let l = self.length.to_be_bytes();
        let s = (self.stream_id & 0x7fff_ffff).to_be_bytes();
        [
            l[1],
            l[2],
            l[3],
            self.frame_type,
            self.flags,
            s[0],
            s[1],
            s[2],
            s[3],
        ]
    }

    /** @brief 플래그 비트가 서 있는지. */
    pub fn has_flag(&self, f: u8) -> bool {
        self.flags & f != 0
    }
}

/** @brief 헤더와 페이로드를 이어 붙여 프레임 하나를 쓴다. */
pub fn write_frame(out: &mut Vec<u8>, frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) {
    let h = FrameHeader::new(frame_type, flags, stream_id, payload.len() as u32);
    out.extend_from_slice(&h.encode());
    out.extend_from_slice(payload);
}

#[cfg(test)]
/** @brief 프레임 헤더의 왕복과, 어긋난 입력에 패닉하지 않는지. */
mod tests {
    use super::*;

    #[test]
    /** @brief 적었다 읽으면 같은지. */
    fn frame_header_roundtrip() {
        let h = FrameHeader::new(frame_type::HEADERS, flags::END_HEADERS, 3, 1000);
        let bytes = h.encode();
        assert_eq!(bytes.len(), 9);
        let back = FrameHeader::parse(&bytes).unwrap();
        assert_eq!(back, h);
        assert_eq!(back.length, 1000);
        assert_eq!(back.frame_type, frame_type::HEADERS);
        assert!(back.has_flag(flags::END_HEADERS));
        assert_eq!(back.stream_id, 3);
    }

    #[test]
    /** @brief 예약 비트를 지우고 읽는지. */
    fn reserved_bit_masked() {
        let mut bytes = FrameHeader::new(frame_type::DATA, 0, 1, 0).encode();
        bytes[5] |= 0x80;
        let h = FrameHeader::parse(&bytes).unwrap();
        assert_eq!(h.stream_id, 1);
    }

    #[test]
    /** @brief 적은 바이트 배치가 규격과 같은지. */
    fn write_frame_layout() {
        let mut out = Vec::new();
        write_frame(&mut out, frame_type::DATA, flags::END_STREAM, 1, b"hello");
        assert_eq!(out.len(), 9 + 5);
        let h = FrameHeader::parse(&out).unwrap();
        assert_eq!(h.length, 5);
        assert!(h.has_flag(flags::END_STREAM));
        assert_eq!(&out[9..], b"hello");
    }

    #[test]
    /** @brief 24비트 길이가 제대로 오가는지. */
    fn large_length_24bit() {
        let h = FrameHeader::new(frame_type::DATA, 0, 1, 0x00FF_FFFF);
        let back = FrameHeader::parse(&h.encode()).unwrap();
        assert_eq!(back.length, 0x00FF_FFFF);
    }

    #[test]
    /** @brief 망가진 입력에 파서가 패닉하지 않는지. */
    fn http2_parsers_no_panic_on_adversarial_input() {
        use crate::hpack::{decode_int, Decoder as HpackDecoder};
        use crate::huffman;
        let mut seed: u32 = 0x2468_ace0;
        let mut rng = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed
        };
        for _ in 0..30000 {
            let len = (rng() % 128) as usize;
            let v: Vec<u8> = (0..len).map(|_| (rng() & 0xff) as u8).collect();
            let _ = FrameHeader::parse(&v);
            let _ = decode_int(&v, ((rng() % 8) + 1) as u8);
            let _ = huffman::decode(&v);
            let mut dec = HpackDecoder::new(4096);
            let _ = dec.decode(&v);
        }
    }
}
