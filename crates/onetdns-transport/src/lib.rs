/*!
 * @brief TLS 인증서 재료 준비: PEM 입출력과 자체 서명 생성.
 *
 * @warning 이름과 달리 리스너를 열지 않는다. 실제 전송 처리는 onetdns-bin의 각
 *          핸들러와 onetdns-tls에 있다. 여기는 인증서·키를 다루는 보조 크레이트다.
 */

/** @brief 인증서와 키를 다루는 보조 도구. */
pub mod tls;

pub use tls::{
    generate_self_signed_pem, load_pem, parse_pem, self_signed_material, verify_key_matches_cert,
    TlsError,
};
