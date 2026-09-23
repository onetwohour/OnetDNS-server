/*!
 * @brief 광고·추적 차단 엔진.
 *
 * @details 목록을 읽어 도메인 집합을 만들고, 질의마다 정해진 우선순위로 판정한다.
 *          엔진은 전부 원자 교체되므로 질의 경로는 잠금을 잡지 않는다.
 * @note 로드는 느려도 되지만 판정은 빨라야 한다. 그래서 로드 때 자료구조를 최소 형태로
 *       고정해 두고, 판정 경로는 할당도 해시맵 조회도 하지 않는다.
 */

/** @brief 컴파일된 집합을 디스크에 담고 되읽는 캐시. */
mod cache;
/** @brief 도메인 집합의 최소 형태. 역순 도메인 위에 만든 비순환 오토마톤이다. */
mod compact;
/** @brief 로드 중에만 쓰는 도메인 테이블. 고정 전의 임시 구조다. */
mod table;

/** @brief 판정 엔진과 우선순위 사다리. */
pub mod engine;
/** @brief 목록 형식 파서. AdGuard, ABP, hosts, RPZ를 읽는다. */
pub mod loader;
/** @brief 기본으로 제공하는 목록 주소들. */
pub mod presets;
/** @brief 정규식 엔진. */
pub mod regex;
/** @brief 안전 검색 재작성 대상. */
pub mod safesearch;
/** @brief 서비스별 차단 규칙 모음. */
pub mod services;

pub use cache::{
    decode_engine_cache, encode_engine_cache, write_engine_cache, CacheError, CacheWriteError,
    MAX_CACHE_BYTES,
};
pub use engine::{
    normalize_name, normalize_str, BlockEngine, ClientPolicy, DomainSet, EngineParts,
    FilterLoadReport, LocalZoneAction, LocalZoneSet, RewriteSet, RpzIpRule, RpzNameRule,
    SharedFilter, SourceStat, StaticAnswer, StaticZone,
};
pub use loader::{
    build_from_named, build_from_str, load_lists, load_lists_with, load_parts,
    load_parts_with_subscriptions, parse_rpz_text, validate_rule, SubscriptionRules,
    SubscriptionSource,
};
