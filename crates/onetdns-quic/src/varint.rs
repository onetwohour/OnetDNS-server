/*!
 * @brief QUIC 가변 길이 정수.
 *
 * @details 첫 두 비트가 길이를 정한다. 1, 2, 4, 8바이트 중 하나이고 나머지 비트가 값이다.
 * @note 같은 값을 여러 길이로 쓸 수 있다. 파싱은 그것을 받아들이지만, 이쪽이 쓸 때는
 *       항상 가장 짧은 형태를 쓴다.
 */

/**
 * @brief 가변 길이 정수를 읽는다.
 * @return 값과 소비한 바이트 수. 바이트가 모자라면 None.
 */
pub fn read(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    let mut val = (first & 0x3f) as u64;
    for i in 1..len {
        val = (val << 8) | *buf.get(i)? as u64;
    }
    Some((val, len))
}

/** @brief 값을 담을 수 있는 가장 짧은 형태로 쓴다. */
pub fn write(out: &mut Vec<u8>, v: u64) {
    if v < (1 << 6) {
        out.push(v as u8);
    } else if v < (1 << 14) {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < (1 << 30) {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

/** @brief 이 값을 쓰는 데 필요한 바이트 수. 길이를 미리 잡을 때 쓴다. */
pub fn len(v: u64) -> usize {
    if v < (1 << 6) {
        1
    } else if v < (1 << 14) {
        2
    } else if v < (1 << 30) {
        4
    } else {
        8
    }
}

#[cfg(test)]
/** @brief 규격 예제 값과 경계에서의 왕복. */
mod tests {
    use super::*;

    #[test]
    /** @brief 규격에 담긴 예제 값들이 그대로 읽히는지. */
    fn rfc9000_examples() {
        let mut o = Vec::new();
        write(&mut o, 151_288_809_941_952_652);
        assert_eq!(o, vec![0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]);
        assert_eq!(read(&o).unwrap(), (151_288_809_941_952_652, 8));

        let mut o = Vec::new();
        write(&mut o, 494_878_333);
        assert_eq!(o, vec![0x9d, 0x7f, 0x3e, 0x7d]);

        let mut o = Vec::new();
        write(&mut o, 15293);
        assert_eq!(o, vec![0x7b, 0xbd]);

        let mut o = Vec::new();
        write(&mut o, 37);
        assert_eq!(o, vec![0x25]);
        assert_eq!(read(&[0x25]).unwrap(), (37, 1));
    }

    #[test]
    /** @brief 각 길이의 경계값이 왕복에서 보존되는지. */
    fn roundtrip_boundaries() {
        for v in [
            0u64,
            63,
            64,
            16383,
            16384,
            (1 << 30) - 1,
            1 << 30,
            (1 << 62) - 1,
        ] {
            let mut o = Vec::new();
            write(&mut o, v);
            assert_eq!(o.len(), len(v));
            assert_eq!(read(&o).unwrap(), (v, len(v)));
        }
    }

    #[test]
    /** @brief 길이 비트를 값에서 제대로 걷어내는지. 남기면 값이 커진다. */
    fn two_byte_decode_value_masks_prefix() {
        assert_eq!(read(&[0x7b, 0xbd]).unwrap(), (15293, 2));
    }
}
