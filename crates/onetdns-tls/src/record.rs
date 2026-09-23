/*!
 * @brief 레코드 계층 프레이밍.
 *
 * @details TLS는 바이트 흐름을 레코드로 나눈다. 각 레코드에 종류와 길이가 붙는다.
 * @warning 길이 상한이 있다. 상한이 없으면 길이 필드 하나로 이쪽 메모리를 잡아 둘 수 있다.
 */

use crate::TlsError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/** @brief 레코드가 전달하는 내용의 종류. */
pub struct ContentType(pub u8);

#[allow(non_upper_case_globals)]
impl ContentType {
    /** @brief 1.3에서는 호환을 위한 더미다. */
    pub const ChangeCipherSpec: ContentType = ContentType(20);
    /** @brief 경고나 오류 통지. */
    pub const Alert: ContentType = ContentType(21);
    /** @brief 핸드셰이크 메시지. */
    pub const Handshake: ContentType = ContentType(22);
    /** @brief 응용 데이터. 1.3에서는 암호화된 모든 것이 이 종류로 위장한다. */
    pub const ApplicationData: ContentType = ContentType(23);
}

/** @brief 평문 조각 크기 상한. */
pub const MAX_FRAGMENT: usize = 1 << 14;
/** @brief 암호문 크기 상한. 태그와 여유 몫이 더해진다. */
pub const MAX_CIPHERTEXT: usize = MAX_FRAGMENT + 256;

/** @brief 레코드에 적는 버전 번호. 1.3도 호환을 위해 이 값을 쓴다. */
pub const LEGACY_VERSION: u16 = 0x0303;

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief 레코드 하나. */
pub struct TlsRecord {
    /** @brief 이 레코드에 담긴 것의 종류. */
    pub content_type: ContentType,
    /** @brief 버전 표기. */
    pub version: u16,
    /** @brief 담긴 바이트. */
    pub fragment: Vec<u8>,
}

impl TlsRecord {
    /** @brief 레코드를 만든다. */
    pub fn new(content_type: ContentType, fragment: Vec<u8>) -> Self {
        Self {
            content_type,
            version: LEGACY_VERSION,
            fragment,
        }
    }

    /** @brief 버퍼에 이어 쓴다. */
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.content_type.0);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&(self.fragment.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.fragment);
    }

    /** @brief 새 버퍼에 쓴다. */
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(5 + self.fragment.len());
        self.encode_into(&mut v);
        v
    }

    /**
     * @brief 바이트열에서 레코드 하나를 읽는다.
     * @return 덜 왔으면 None이다. 오류가 아니라 대기다.
     */
    pub fn parse(buf: &[u8]) -> Result<Option<(TlsRecord, usize)>, TlsError> {
        if buf.len() < 5 {
            return Ok(None);
        }
        let content_type = ContentType(buf[0]);
        let version = u16::from_be_bytes([buf[1], buf[2]]);
        let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        if len > MAX_CIPHERTEXT {
            return Err(TlsError::RecordOverflow);
        }
        if buf.len() < 5 + len {
            return Ok(None);
        }
        Ok(Some((
            TlsRecord {
                content_type,
                version,
                fragment: buf[5..5 + len].to_vec(),
            },
            5 + len,
        )))
    }
}

#[derive(Default)]
/** @brief 흘러 들어오는 바이트를 레코드로 나눠 주는 것. */
pub struct RecordReader {
    /** @brief 아직 온전한 레코드가 되지 못한 바이트. */
    buf: Vec<u8>,
}

impl RecordReader {
    /** @brief 빈 상태. */
    pub fn new() -> Self {
        Self::default()
    }

    /** @brief 받은 바이트를 넣는다. */
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /** @brief 다 온 레코드 하나를 꺼낸다. 없으면 None. */
    pub fn next_record(&mut self) -> Result<Option<TlsRecord>, TlsError> {
        match TlsRecord::parse(&self.buf)? {
            Some((rec, consumed)) => {
                self.buf.drain(..consumed);
                Ok(Some(rec))
            }
            None => Ok(None),
        }
    }
}
