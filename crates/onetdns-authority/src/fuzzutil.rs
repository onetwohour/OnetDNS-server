/*!
 * @brief 크레이트 내부 파서 스윕용 결정적 난수와 변이기.
 *
 * @details 통합 테스트는 크레이트 내부에 닿지 못하므로, DB 백엔드의 와이어 파서 같은
 *          비공개 경로는 여기 도구로 각 모듈이 직접 스윕한다.
 * @note 시드가 같으면 결과도 같다. 패닉을 재현하려면 그 시드만 있으면 된다.
 */

/** @brief SplitMix64 상태. 같은 시드를 넣으면 같은 수열이 나온다. */
pub(crate) struct Rng(u64);

impl Rng {
    /** @brief 시드로 시작한다. */
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed)
    }

    /** @brief 다음 난수. */
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /** @brief 0 이상 n 미만. n이 0이면 0을 준다. 빈 버퍼에서 나머지 연산이 터지지 않게 한다. */
    pub(crate) fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    /** @brief 임의의 한 바이트. */
    pub(crate) fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }

    /** @brief 길이가 max 미만인 임의 바이트열. */
    pub(crate) fn rand_bytes(&mut self, max: usize) -> Vec<u8> {
        let count = self.below(max);
        (0..count).map(|_| self.byte()).collect()
    }
}

/**
 * @brief 정상 입력을 여러 번 변형한다.
 * @details 치환, 비트 뒤집기, 삽입, 삭제, 자르기, 덧붙이기를 섞는다. 자르기가 있어야
 *          길이 필드와 실제 길이가 어긋난 입력이 만들어져 경계 검사를 실제로 건드린다.
 */
pub(crate) fn havoc(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut bytes = seed.to_vec();
    for _ in 0..1 + rng.below(10) {
        if bytes.is_empty() {
            break;
        }
        match rng.below(6) {
            0 => {
                let index = rng.below(bytes.len());
                bytes[index] = rng.byte();
            }
            1 => {
                let index = rng.below(bytes.len());
                bytes[index] ^= 1 << rng.below(8);
            }
            2 => {
                let index = rng.below(bytes.len());
                bytes.insert(index, rng.byte());
            }
            3 => {
                let index = rng.below(bytes.len());
                bytes.remove(index);
            }
            4 => {
                let index = rng.below(bytes.len());
                bytes.truncate(index);
            }
            _ => bytes.push(rng.byte()),
        }
    }
    bytes
}
