/*!
 * @brief 안전 검색 재작성.
 *
 * @details 검색 서비스의 이름을 그 서비스가 제공하는 안전 검색 전용 이름으로 바꾼다.
 *          이 서버가 결과를 거르는 것이 아니라 서비스 쪽 필터를 켜는 것이다.
 */

/** @brief 원래 이름과 안전 검색 전용 이름의 짝. */
pub const SAFE_SEARCH: &[(&str, &str)] = &[
    ("google.com", "forcesafesearch.google.com"),
    ("www.google.com", "forcesafesearch.google.com"),
    ("google.co.kr", "forcesafesearch.google.com"),
    ("www.google.co.kr", "forcesafesearch.google.com"),
    ("bing.com", "strict.bing.com"),
    ("www.bing.com", "strict.bing.com"),
    ("duckduckgo.com", "safe.duckduckgo.com"),
    ("www.duckduckgo.com", "safe.duckduckgo.com"),
    ("youtube.com", "restrict.youtube.com"),
    ("www.youtube.com", "restrict.youtube.com"),
    ("m.youtube.com", "restrict.youtube.com"),
];

/** @brief 이 이름에 대응하는 안전 검색 이름. 대상이 아니면 없다. */
pub fn safe_target(normalized_qname: &str) -> Option<&'static str> {
    SAFE_SEARCH
        .iter()
        .find(|(host, _)| *host == normalized_qname)
        .map(|(_, target)| *target)
}
