/*!
 * @brief 길이 접두사 있는 값 읽기와 쓰기.
 *
 * @details TLS 메시지는 대부분 1, 2, 3바이트 길이 접두사가 붙은 값의 나열이다.
 * @note 모든 읽기가 경계를 검사한다. 이 파일이 신뢰할 수 없는 바이트가 처음 닿는 곳이다.
 */

use crate::TlsError;

/** @brief 바이트를 앞에서부터 읽는 커서. */
pub struct Reader<'a> {
    /** @brief 읽어 들일 바이트. */
    buf: &'a [u8],
    /** @brief 지금 위치. */
    pos: usize,
}

impl<'a> Reader<'a> {
    /** @brief 바이트열로 커서를 만든다. */
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /** @brief 남은 바이트 수. */
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /** @brief 다 읽었는지. */
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /** @brief 8비트 값. */
    pub fn u8(&mut self) -> Result<u8, TlsError> {
        let b = *self.buf.get(self.pos).ok_or(TlsError::Decode)?;
        self.pos += 1;
        Ok(b)
    }

    /** @brief 16비트 값. */
    pub fn u16(&mut self) -> Result<u16, TlsError> {
        Ok(((self.u8()? as u16) << 8) | self.u8()? as u16)
    }

    /** @brief 24비트 값. 핸드셰이크 메시지 길이가 이 형식이다. */
    pub fn u24(&mut self) -> Result<u32, TlsError> {
        Ok(((self.u8()? as u32) << 16) | ((self.u8()? as u32) << 8) | self.u8()? as u32)
    }

    /** @brief 32비트 값. */
    pub fn u32(&mut self) -> Result<u32, TlsError> {
        Ok(((self.u16()? as u32) << 16) | self.u16()? as u32)
    }

    /** @brief 정해진 길이만큼 가져온다. 모자라면 오류다. */
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], TlsError> {
        let s = self
            .buf
            .get(self.pos..self.pos + n)
            .ok_or(TlsError::Decode)?;
        self.pos += n;
        Ok(s)
    }

    /** @brief 1바이트 길이 접두사가 붙은 값. */
    pub fn vec8(&mut self) -> Result<&'a [u8], TlsError> {
        let n = self.u8()? as usize;
        self.take(n)
    }

    /** @brief 2바이트 길이 접두사가 붙은 값. */
    pub fn vec16(&mut self) -> Result<&'a [u8], TlsError> {
        let n = self.u16()? as usize;
        self.take(n)
    }

    /** @brief 3바이트 길이 접두사가 붙은 값. */
    pub fn vec24(&mut self) -> Result<&'a [u8], TlsError> {
        let n = self.u24()? as usize;
        self.take(n)
    }
}

#[derive(Default)]
/** @brief 바이트를 쌓아 가는 버퍼. */
pub struct Writer {
    /** @brief 적어 넣을 바이트. */
    pub buf: Vec<u8>,
}

impl Writer {
    /** @brief 빈 버퍼. */
    pub fn new() -> Self {
        Self::default()
    }

    /** @brief 8비트 값을 쓴다. */
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /** @brief 16비트 값을 쓴다. */
    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /** @brief 24비트 값을 쓴다. */
    pub fn u24(&mut self, v: u32) {
        self.buf
            .extend_from_slice(&[(v >> 16) as u8, (v >> 8) as u8, v as u8]);
    }

    /** @brief 32비트 값을 쓴다. */
    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /** @brief 바이트를 그대로 쓴다. */
    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    /**
     * @brief 1바이트 길이 접두사로 감싼다.
     * @details 길이 필드를 비워 두고 안을 채운 뒤 길이를 돌아가 채운다. 길이를 미리 계산하지
     *          않아도 되므로 중첩 구조를 쓰기 쉽다.
     */
    pub fn vec8(&mut self, f: impl FnOnce(&mut Writer)) {
        let at = self.buf.len();
        self.buf.push(0);
        f(self);
        let len = (self.buf.len() - at - 1) as u8;
        self.buf[at] = len;
    }

    /** @brief 2바이트 길이 접두사로 감싼다. */
    pub fn vec16(&mut self, f: impl FnOnce(&mut Writer)) {
        let at = self.buf.len();
        self.buf.extend_from_slice(&[0, 0]);
        f(self);
        let len = (self.buf.len() - at - 2) as u16;
        self.buf[at..at + 2].copy_from_slice(&len.to_be_bytes());
    }

    /** @brief 3바이트 길이 접두사로 감싼다. */
    pub fn vec24(&mut self, f: impl FnOnce(&mut Writer)) {
        let at = self.buf.len();
        self.buf.extend_from_slice(&[0, 0, 0]);
        f(self);
        let len = (self.buf.len() - at - 3) as u32;
        self.buf[at..at + 3].copy_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    }
}
