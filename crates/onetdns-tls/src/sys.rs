/*!
 * @brief 플랫폼 의존 요소.
 */

pub use onetdns_core::rng::fill_random;

/**
 * @brief 32바이트 난수.
 * @warning 실패하면 패닉한다. 난수 없이 핸드셰이크를 이어 가면 예측 가능한 비밀이 나온다.
 */
pub fn random_32() -> [u8; 32] {
    onetdns_core::rng::random_array::<32>()
}
