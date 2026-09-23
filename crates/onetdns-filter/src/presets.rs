/*!
 * @brief 기본 제공 목록 주소.
 */

/** @brief 안전 브라우징 목록. 악성 도메인을 막는다. */
pub const SAFE_BROWSING_LISTS: &[&str] = &[
    "https://blocklistproject.github.io/Lists/malware.txt",
    "https://blocklistproject.github.io/Lists/phishing.txt",
];

/** @brief 자녀 보호 목록. */
pub const PARENTAL_LISTS: &[&str] = &["https://blocklistproject.github.io/Lists/porn.txt"];
