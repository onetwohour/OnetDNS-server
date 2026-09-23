/*!
 * @brief 파서 스윕용 결정적 난수와 변이기.
 * @note 시드가 같으면 결과도 같다. 패닉을 재현하려면 그 시드만 있으면 된다.
 */

#![allow(dead_code)]

/** @brief SplitMix64 상태. 같은 시드를 넣으면 같은 수열이 나온다. */
pub struct Rng(u64);

impl Rng {
    /** @brief 시드로 시작한다. */
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    /** @brief 다음 난수. */
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /** @brief 0 이상 n 미만. n이 0이면 0을 준다. */
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    /** @brief 임의의 한 바이트. */
    pub fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }

    /** @brief 길이가 max 미만인 임의 바이트열. */
    pub fn rand_bytes(&mut self, max: usize) -> Vec<u8> {
        let n = self.below(max);
        (0..n).map(|_| self.byte()).collect()
    }
}

/**
 * @brief 정상 입력을 여러 번 변형한다.
 * @details 자르기가 있어야 길이 필드와 실제 길이가 어긋난 입력이 만들어져 경계 검사를
 *          실제로 건드린다.
 */
pub fn havoc(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut b = seed.to_vec();
    for _ in 0..1 + rng.below(10) {
        if b.is_empty() {
            break;
        }
        match rng.below(6) {
            0 => {
                let i = rng.below(b.len());
                b[i] = rng.byte();
            }
            1 => {
                let i = rng.below(b.len());
                b[i] ^= 1 << rng.below(8);
            }
            2 => {
                let i = rng.below(b.len());
                b.insert(i, rng.byte());
            }
            3 => {
                let i = rng.below(b.len());
                b.remove(i);
            }
            4 => {
                let i = rng.below(b.len());
                b.truncate(i);
            }
            _ => b.push(rng.byte()),
        }
    }
    b
}
