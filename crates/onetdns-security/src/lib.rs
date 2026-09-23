/*!
 * @brief 요청 수용 제어: ACL, 속도 제한, DNS 쿠키.
 *
 * @details 셋 다 해석이 시작되기 전에 판정된다. 업스트림으로 나가는 일도, 캐시를 건드리는
 *          일도 없어야 거부 자체가 자원 소모 경로가 되지 않는다.
 */

/** @brief 주소와 식별자로 받아들일지 정하는 것. */
pub mod acl;
/** @brief 키별로 몫을 나눠 주는 것. */
pub mod bucket;
/** @brief 출발지를 속이지 못하게 하는 쿠키. */
pub mod cookie;
/** @brief 클라이언트별 속도 제한. */
pub mod rate;
/** @brief 비밀값을 쓰는 짧은 요약 함수. */
pub mod siphash;
/** @brief 대역 단위 속도 제한. */
pub mod subnet;

pub use acl::IpAcl;
pub use cookie::{CookieCheck, CookieKeeper};
pub use rate::KeyedRateLimiter;
pub use subnet::SubnetRateLimiter;
