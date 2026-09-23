/*!
 * @brief 모든 전송이 모이는 질의 핸들러.
 *
 * @details 접근 제어, 속도 제한, 쿠키, 정책, 차단, 안전 검색, 클라이언트 대역 붙이기를
 *          여기서 처리한 뒤 해석 체인으로 내려보낸다. 전송이 무엇이든 여기로 모인다.
 * @warning 차단은 이 위층에서 한다. 그래야 하위 캐시가 클라이언트별 정책을 건너뛰지
 *          못한다.
 * @note 빠른 경로가 둘 더 있다. 캐시가 맞은 UDP 질의를 파싱 없이 내보내는 경로와, 이 서버의
 *       권한 영역의 단순 질의를 조립 없이 내보내는 경로다. 응답을 달라지게 하는 기능이
 *       하나라도 켜지면 두 경로 모두 쓰지 않는다.
 */

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use onetdns_control::{Action, EventDiag, Recorder};
use onetdns_core::{
    AccessControl, AclDecision, ArcSwap, BlockResponse, ClientInfo, FilterEngine, FilterVerdict,
    IpNet, LruMap, MutexExt, RateDecision, RateLimiter, RewriteTarget, Transport,
};
use onetdns_filter::{BlockEngine, SharedFilter};
use onetdns_forward::Forwarder;
use onetdns_proto::{
    DnsClass, Edns, Message, Name as ApName, ProtoError, RData as ApRData, Record as ApRecord,
    RecordType as ApRt, ResponseCode,
};
use onetdns_recurse::Recursor;
use onetdns_runtime::{Handler, RequestCtx, Transport as RtTransport};
use onetdns_security::CookieKeeper;

/** @brief 쿠키 옵션. */
const OPT_COOKIE: u16 = 10;

/**
 * @brief 설정이 너무 작을 때 쓰는 UDP 크기.
 * @details IPv6 최소 MTU에서 헤더를 뺀 값이라 경로 조각화를 피한다.
 */
const DEFAULT_EDNS_PAYLOAD: u16 = 1232;

/**
 * @brief 이 서버가 UDP로 내보내는 응답 크기 상한.
 * @details 상대가 이보다 작게 알리면 절단 사다리가 필요하므로 빠른 경로가 맡지 않는다.
 */
const SERVER_UDP_MAX: u16 = 1232;

/** @brief 옵션이 없는 OPT 레코드의 와이어 길이. 이름 1 + 종류 2 + 종류별 2 + TTL 4 + 길이 2. */
const EMPTY_OPT_WIRE_LEN: usize = 11;
/** @brief 서버 식별 옵션. */
const OPT_NSID: u16 = 3;

/** @brief DDR이 로컬에서 맡는 이름의 소문자 wire 표현. */
const DDR_OWNER_WIRE: &[u8] = b"\x04_dns\x08resolver\x04arpa\x00";

/** @brief 이름이 DDR의 로컬 소유 이름인지. 할당하지 않고 대소문자를 무시하고 비교한다. */
#[cfg_attr(not(unix), allow(dead_code))]
fn ddr_owner(name: &ApName) -> bool {
    name.as_uncompressed_wire()
        .eq_ignore_ascii_case(DDR_OWNER_WIRE)
}

/** @brief 검증에 쓴 키와 그 결과. 응답에도 같은 키로 서명해야 한다. */
type TsigContext = (
    onetdns_dnssec::tsig::TsigKey,
    onetdns_dnssec::tsig::VerifiedTsig,
);

#[derive(Default)]
/** @brief 업스트림 서버가 바뀌었다고 알려 온 영역들. */
pub struct NotifyKick {
    /** @brief 다시 받아 와야 할 영역들. */
    pending: std::sync::Mutex<HashSet<String>>,
    /** @brief 기다리는 쪽을 깨우는 곳. */
    wake: std::sync::Condvar,
}

impl NotifyKick {
    /** @brief 이 영역을 다시 받아 오라고 알린다. */
    pub fn push(&self, origin: String) {
        let inserted = self.pending.lock_recover().insert(origin);
        if inserted {
            self.wake.notify_one();
        }
    }

    /** @brief 알림이 올 때까지 기다렸다 가져간다. */
    pub fn wait_take(&self, timeout: std::time::Duration) -> HashSet<String> {
        let mut pending = self.pending.lock_recover();
        if pending.is_empty() {
            pending = match self.wake.wait_timeout(pending, timeout) {
                Ok((pending, _)) => pending,
                Err(error) => error.into_inner().0,
            };
        }
        std::mem::take(&mut *pending)
    }
}

/** @brief 이보다 큰 질의는 수상하게 본다. 정상 질의가 이만큼 클 일이 없다. */
const MAX_LARGE_QUERY_BYTES: usize = 1024;

#[derive(Clone, Default)]
/** @brief 쿠키를 쓸지, 그리고 없는 질의를 거절할지. */
pub struct CookiePolicy {
    /** @brief 쿠키를 만들고 확인하는 것. 없으면 쿠키를 쓰지 않는다. */
    pub keeper: Option<Arc<CookieKeeper>>,
    /** @brief 쿠키가 없거나 맞지 않으면 거절할지. */
    pub strict: bool,
}

#[derive(Debug, Clone, Copy)]
/** @brief 요일과 시각으로 정한 구간 하나. */
pub struct SchedWindow {
    /** @brief 적용할 요일 비트. */
    pub days: u8,
    /** @brief 시작 시각. 자정부터 흐른 분. */
    pub start_min: u32,
    /** @brief 끝 시각. 자정부터 흐른 분. */
    pub end_min: u32,
}

#[derive(Debug, Default)]
/** @brief 서비스 차단을 멈출 시간대. */
pub struct Schedule {
    /** @brief 서비스 차단을 멈출 구간들. */
    pub windows: Vec<SchedWindow>,
}

impl Schedule {
    /** @brief 지금이 그 시간대인지. 자정을 넘는 구간은 전날 요일로도 본다. */
    pub fn is_active(&self, now: SystemTime) -> bool {
        if self.windows.is_empty() {
            return false;
        }
        let (dow, tod_min) = crate::localtime::local_weekday_minute(now);
        let tod_min = u32::from(tod_min);
        self.windows.iter().any(|w| {
            if w.start_min < w.end_min {
                (w.days & (1 << dow)) != 0 && tod_min >= w.start_min && tod_min < w.end_min
            } else {
                let previous_dow = (dow + 6) % 7;
                ((w.days & (1 << dow)) != 0 && tod_min >= w.start_min)
                    || ((w.days & (1 << previous_dow)) != 0 && tod_min < w.end_min)
            }
        })
    }
}

#[derive(Clone, Default)]
/** @brief 켜고 끌 수 있는 기능들. 설정을 다시 읽으면 한꺼번에 교체한다. */
pub struct NativeFeatures {
    /** @brief IPv6 주소 답을 막는다. */
    pub block_aaaa: bool,
    /** @brief IPv4 답으로 IPv6 답을 지어낼 때 쓸 접두사. */
    pub dns64_prefix: Option<[u8; 16]>,
    /** @brief IPv6 답이 있어도 임의로 만든 답을 함께 준다. */
    pub dns64_synthall: bool,
    /** @brief 밖의 이름이 내부망 주소를 가리키면 막는다. */
    pub rebind_protection: bool,
    /** @brief 위 검사에서 뺄 이름들. */
    pub rebind_allow: Vec<ApName>,
    /** @brief 이 주소들로 답하면 없다고 바꾼다. */
    pub bogus_nxdomain: Vec<IpNet>,
    /** @brief 재귀 답에 이 주소가 있으면 막는다. */
    pub recurse_deny_answers: Vec<IpNet>,
    /** @brief 재귀 답에서 이 주소만 받아들인다. */
    pub recurse_allow_answers: Vec<IpNet>,
    /** @brief 같은 이름의 답 순서를 돌려 가며 낸다. */
    pub rrset_roundrobin: bool,
    /** @brief 돌려 가며 낼 때의 지금 위치. */
    pub rotor: Arc<AtomicUsize>,
    /** @brief 안전 검색이 켜져 있는지. 시간대에 따라 바뀐다. */
    pub safe_search: Arc<AtomicBool>,
    /** @brief 응답에 담을 서버 식별값. */
    pub nsid: Option<Vec<u8>>,
    /** @brief 쿠키 정책. */
    pub cookies: CookiePolicy,
    /** @brief 지표 기록기. */
    pub recorder: Option<Recorder>,
    /** @brief 클라이언트 하드웨어 주소 조회. */
    pub mac_cache: Option<Arc<crate::mac::NeighborCache>>,

    /** @brief 동시에 처리할 질의 수 상한. */
    pub inflight_max: usize,
    /** @brief 지금 처리 중인 질의 수. */
    pub inflight: Arc<AtomicUsize>,

    /** @brief 질의 기록 파일. */
    pub dnstap: Option<Arc<onetdns_control::DnstapWriter>>,

    /** @brief 응답에 알릴 UDP 수신 크기. */
    pub edns_buffer: u16,

    /** @brief 서버 이름을 묻는 질의에 답하지 않는다. */
    pub hide_identity: bool,
    /** @brief 서버 버전을 묻는 질의에 답하지 않는다. */
    pub hide_version: bool,

    /** @brief 서버 이름을 물었을 때 답할 값. */
    pub server_identity: Vec<u8>,
    /** @brief 서버 버전을 물었을 때 답할 값. */
    pub server_version: Vec<u8>,

    /** @brief 모든 종류를 묻는 질의를 받아들일지. 큰 답을 끌어내는 증폭에 쓰인다. */
    pub allow_any: bool,
    /** @brief 꼭 필요한 것만 담아 응답을 줄인다. */
    pub minimal_responses: bool,
    /** @brief 응답 크기를 이 단위로 채운다. 크기로 내용을 짐작하지 못하게 한다. */
    pub padding_block: usize,
    /** @brief 연결을 유지할 시간. 없으면 알리지 않는다. */
    pub tcp_keepalive_100ms: Option<u16>,
    /** @brief 대역 정보를 쓰고 있어 클라이언트에게도 그 사실을 알려야 하는지. */
    pub ecs_in_use: bool,
    /** @brief 지나치게 큰 질의를 버린다. */
    pub harden_large_queries: bool,

    /** @brief 점 없는 이름을 밖에 묻지 않는다. */
    pub domain_needed: bool,

    /** @brief 내부망 주소의 역조회를 밖에 묻지 않는다. */
    pub bogus_priv: bool,

    /** @brief 밖에 새 나가면 안 되는 이름을 막는다. */
    pub empty_zones: bool,

    /** @brief DDR 특수 이름을 일반 해석 체인으로 보내야 하는지. */
    pub ddr_enabled: bool,

    /** @brief 지금 체인 세대의 캐시·재귀 리졸버. */
    pub(crate) lane_runtime: Option<Arc<LaneRuntime>>,
}

impl NativeFeatures {
    /**
     * @brief 질의마다 기록을 남길 곳.
     *
     * @details 기록기가 있어도 볼 곳이 없으면 없는 것으로 답한다. 그 자리에서 만드는 이름과
     *          시계 읽기가 질의마다 드는 비용이라, 만들어서 버릴 것이면 만들지 않아야 한다.
     * @return 볼 곳이 있을 때만 기록기.
     */
    pub fn events(&self) -> Option<&Recorder> {
        self.recorder.as_ref().filter(|r| r.collecting())
    }

    /**
     * @brief 권한 영역 빠른 경로를 막는 기능이 켜져 있는지.
     * @warning 응답을 달라지게 하거나 기록을 남겨야 하는 기능이 하나라도 켜지면 참이다.
     *          lenient 쿠키는 COOKIE 옵션이 붙은 질의만 스캐너가 물리므로 전역 차단하지
     *          않는다. strict는 쿠키 없는 질의도 BADCOOKIE여야 하므로 전역 차단한다.
     */
    fn blocks_authority_wire(&self) -> bool {
        self.dns64_prefix.is_some()
            || self.rrset_roundrobin
            || self.cookies.strict
            || self.dnstap.is_some()
            || self.domain_needed
            || self.bogus_priv
            || self.empty_zones
            || self.block_aaaa
            || self.padding_block > 0
            || self.nsid.is_some()
            || self.rebind_protection
            || !self.bogus_nxdomain.is_empty()
            || !self.recurse_deny_answers.is_empty()
    }
}

/**
 * @brief 기능 세트 전체를 교체하는 슬롯.
 * @details 자주 보는 판정은 원자 값으로 따로 둔다. 질의마다 세트 전체를 복제해 확인하면
 *          그것이 비용이다.
 */
pub struct NativeFeatureSwap {
    /** @brief 지금 기능 세트. */
    swap: ArcSwap<NativeFeatures>,
    /** @brief 권한 영역 빠른 경로가 막혀 있는지. 복제 없이 답하려고 따로 둔다. */
    authority_wire_blocked: AtomicBool,
    /** @brief 큰 질의를 거절하는지. 복제 없이 답하려고 따로 둔다. */
    harden_large_queries: AtomicBool,
    /** @brief 안전 검색 여부. 시간대에 따라 밖에서 바뀐다. */
    safe_search: Arc<AtomicBool>,
    /** @brief 응답 OPT에 알릴 UDP 크기. 복제 없이 답하려고 따로 둔다. */
    edns_buffer: AtomicU16,
    /** @brief 테스트에서 질의당 snapshot 수를 고정한다. 출하 코드에는 없다. */
    #[cfg(test)]
    test_loads: AtomicUsize,
}

impl NativeFeatureSwap {
    /** @brief 값 하나로 만든다. */
    fn from_pointee(value: NativeFeatures) -> Self {
        let authority_wire_blocked = value.blocks_authority_wire();
        let harden_large_queries = value.harden_large_queries;
        let safe_search = value.safe_search.clone();
        let edns_buffer = value.edns_buffer;
        Self {
            swap: ArcSwap::from_pointee(value),
            authority_wire_blocked: AtomicBool::new(authority_wire_blocked),
            harden_large_queries: AtomicBool::new(harden_large_queries),
            safe_search,
            edns_buffer: AtomicU16::new(edns_buffer),
            #[cfg(test)]
            test_loads: AtomicUsize::new(0),
        }
    }

    /** @brief 지금 기능 세트. */
    pub fn load(&self) -> Arc<NativeFeatures> {
        #[cfg(test)]
        self.test_loads.fetch_add(1, Ordering::Relaxed);
        self.swap.load()
    }

    /** @brief 직전 확인 뒤의 테스트용 snapshot 횟수를 돌려주고 0으로 만든다. */
    #[cfg(test)]
    fn take_test_loads(&self) -> usize {
        self.test_loads.swap(0, Ordering::Relaxed)
    }

    /** @brief 기능 세트를 교체하고 요약 판정도 함께 맞춘다. */
    pub fn store(&self, value: Arc<NativeFeatures>) {
        let authority_wire_blocked =
            value.blocks_authority_wire() || !Arc::ptr_eq(&value.safe_search, &self.safe_search);
        let harden_large_queries = value.harden_large_queries;
        self.edns_buffer.store(value.edns_buffer, Ordering::Release);
        if authority_wire_blocked {
            self.authority_wire_blocked.store(true, Ordering::Release);
        }
        if harden_large_queries {
            self.harden_large_queries.store(true, Ordering::Release);
        }
        self.swap.store(value);
        if !authority_wire_blocked {
            self.authority_wire_blocked.store(false, Ordering::Release);
        }
        if !harden_large_queries {
            self.harden_large_queries.store(false, Ordering::Release);
        }
    }

    /** @brief 권한 영역 빠른 경로가 막혀 있는지. */
    fn authority_wire_blocked(&self) -> bool {
        self.authority_wire_blocked.load(Ordering::Acquire)
    }

    /** @brief 큰 질의를 거절하는지. */
    fn harden_large_queries(&self) -> bool {
        self.harden_large_queries.load(Ordering::Acquire)
    }

    /** @brief 안전 검색이 켜져 있는지. */
    fn safe_search_enabled(&self) -> bool {
        self.safe_search.load(Ordering::Acquire)
    }

    /** @brief 응답 OPT에 알릴 UDP 크기. */
    fn edns_buffer(&self) -> u16 {
        self.edns_buffer.load(Ordering::Acquire)
    }
}

/** @brief 처리 중인 질의 수를 세고 끝나면 되돌린다. */
struct InflightGuard(Arc<AtomicUsize>);
impl Drop for InflightGuard {
    /** @brief 처리 중 수를 하나 줄인다. */
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/** @brief 점이 없는 이름인지. */
pub(crate) fn is_single_label(name: &ApName) -> bool {
    name.num_labels() == 1
}

/** @brief 전송 종류를 정책이 쓰는 표현으로. */
pub(crate) fn policy_transport(t: onetdns_core::Transport) -> onetdns_policy::QueryTransport {
    use onetdns_core::Transport as T;
    use onetdns_policy::QueryTransport as Q;
    match t {
        T::Do53Udp => Q::Do53Udp,
        T::Do53Tcp => Q::Do53Tcp,
        T::DoT => Q::Dot,
        T::DoH => Q::Doh,
        T::DoH3 => Q::Doh3,
        T::DoQ => Q::Doq,
        T::DnsCrypt => Q::DnsCrypt,
    }
}

/** @brief 이름을 정책에 넘길 문자열로. 올바른 문자가 아니면 고치지 않고 없음으로 둔다. */
pub(crate) fn normalized_text_name(name: &ApName) -> Option<String> {
    let mut out = String::new();
    for (index, label) in name.labels().iter().enumerate() {
        let label = std::str::from_utf8(label).ok()?;
        if index > 0 {
            out.push('.');
        }
        out.extend(label.chars().map(|c| c.to_ascii_lowercase()));
    }
    Some(out)
}

/** @brief 내부망 주소를 거꾸로 적은 이름인지. */
pub(crate) fn is_private_reverse(name: &ApName) -> bool {
    let labels: Vec<String> = name
        .labels()
        .iter()
        .map(|l| String::from_utf8_lossy(l).to_ascii_lowercase())
        .collect();
    let n = labels.len();
    if n < 3 {
        return false;
    }
    if labels[n - 2] == "in-addr" && labels[n - 1] == "arpa" {
        let octs: Vec<u8> = labels[..n - 2]
            .iter()
            .rev()
            .filter_map(|s| s.parse::<u8>().ok())
            .collect();
        if octs.len() != n - 2 {
            return false;
        }
        return matches!(
            octs.as_slice(),
            [10, ..] | [127, ..] | [192, 168, ..] | [169, 254, ..]
        ) || matches!(octs.as_slice(), [172, b, ..] if (16u8..=31).contains(b));
    }
    if labels[n - 2] == "ip6" && labels[n - 1] == "arpa" {
        let nibs = &labels[..n - 2];
        let hi = nibs.last().map(String::as_str);
        let hi2 = (nibs.len() >= 2).then(|| nibs[nibs.len() - 2].as_str());
        if hi == Some("f") {
            if matches!(hi2, Some("c") | Some("d")) {
                return true;
            }
            if hi2 == Some("e") && nibs.len() >= 3 {
                return matches!(nibs[nibs.len() - 3].as_str(), "8" | "9" | "a" | "b");
            }
        }
        return false;
    }
    false
}

/** @brief 밖에 물으면 안 되는 이름인지. */
pub(crate) fn is_empty_zone(name: &ApName) -> bool {
    if is_private_reverse(name) {
        return true;
    }
    let s = name.to_ascii_lower();
    let s = s.trim_end_matches('.');
    /** @brief 밖에 새 나가면 안 되는 이름들. */
    const ZONES: &[&str] = &[
        "home.arpa",
        "empty.as112.arpa",
        "0.in-addr.arpa",
        "255.in-addr.arpa",
        "2.0.192.in-addr.arpa",
        "100.51.198.in-addr.arpa",
        "113.0.203.in-addr.arpa",
        "64.100.in-addr.arpa",
        "8.e.f.ip6.arpa",
        "9.e.f.ip6.arpa",
        "a.e.f.ip6.arpa",
        "b.e.f.ip6.arpa",
    ];
    ZONES
        .iter()
        .any(|z| s == *z || s.ends_with(&format!(".{z}")))
}

#[derive(Clone)]
/** @brief 누가 무엇을 고칠 수 있는지 정한 규칙 하나. */
pub struct UpdateRule {
    /** @brief 허용인지 거절인지. */
    grant: bool,
    /** @brief 이 키로 서명한 요청에만 걸린다. 없으면 모두. */
    identity: Option<ApName>,
    /** @brief 이 이름 범위에만 걸린다. */
    name: UpdateRuleName,
    /** @brief 이 기록 종류에만 걸린다. 비면 전부. */
    types: Vec<u16>,
}

#[derive(Clone)]
/** @brief 규칙이 걸린 이름의 범위. */
enum UpdateRuleName {
    /** @brief 어느 이름이든. */
    Any,
    /** @brief 이 이름에만. */
    Exact(ApName),
    /** @brief 이 이름과 그 아래 전부. */
    Subtree(ApName),
}

impl UpdateRule {
    /** @brief 규칙 하나를 만든다. 이름이 틀리면 없다. */
    pub fn new(grant: bool, identity: &str, name: &str, types: Vec<u16>) -> Option<Self> {
        let raw_identity = identity.trim();
        if raw_identity != "*" && raw_identity.contains('*') {
            return None;
        }
        let identity = raw_identity.trim_end_matches('.');
        let identity = if identity == "*" {
            None
        } else {
            Some(ApName::from_str(identity).ok()?)
        };
        let raw_name = name.trim();
        let rule_name = raw_name.trim_end_matches('.');
        let name = if rule_name == "*" {
            if raw_name != "*" {
                return None;
            }
            UpdateRuleName::Any
        } else if let Some(suffix) = rule_name.strip_prefix("*.") {
            if suffix.is_empty() || suffix.starts_with('.') || suffix.contains('*') {
                return None;
            }
            UpdateRuleName::Subtree(ApName::from_str(suffix).ok()?)
        } else {
            if rule_name.starts_with('.') || rule_name.contains('*') {
                return None;
            }
            UpdateRuleName::Exact(ApName::from_str(rule_name).ok()?)
        };
        Some(Self {
            grant,
            identity,
            name,
            types,
        })
    }
}

/** @brief 이 이름이 그 접미사로 끝나는지. */
fn name_ends_with(name: &ApName, suffix: &ApName) -> bool {
    name.ends_with_ignore_case(suffix)
}

/** @brief 이 이름이 규칙 범위에 드는지. */
fn update_name_matches(rule_name: &UpdateRuleName, qname: &ApName) -> bool {
    match rule_name {
        UpdateRuleName::Any => true,
        UpdateRuleName::Exact(name) => name.eq_ignore_case(qname),
        UpdateRuleName::Subtree(suffix) => {
            qname.num_labels() > suffix.num_labels() && name_ends_with(qname, suffix)
        }
    }
}

/**
 * @brief 이 업데이트를 허용할지.
 * @warning 규칙이 없으면 거절한다. 기본을 허용으로 두면 규칙을 안 적은 영역이 전부
 *          열린다.
 */
fn update_granted(
    rules: &[UpdateRule],
    identity: Option<&ApName>,
    qname: &ApName,
    rtype: u16,
) -> bool {
    for r in rules {
        let id_ok = match (&r.identity, identity) {
            (None, _) => true,
            (Some(rule), Some(actual)) => rule.eq_ignore_case(actual),
            (Some(_), None) => false,
        };
        let ty_ok = r.types.is_empty() || r.types.contains(&rtype);
        if id_ok && ty_ok && update_name_matches(&r.name, qname) {
            return r.grant;
        }
    }
    false
}

/** @brief 내용이 빈 기록인지. 지우라는 뜻이다. */
fn update_rdata_is_empty(record: &ApRecord) -> bool {
    matches!(&record.rdata, ApRData::Unknown(rtype, bytes) if *rtype == record.rtype.0 && bytes.is_empty())
}

/** @brief 기록 내용을 비교할 키. */
fn update_rdata_key(record: &ApRecord) -> Vec<u8> {
    onetdns_dnssec::canonical_rdata(&record.rdata)
}

/** @brief 밖에서 고치면 안 되는 기록 종류인지. 서명이나 부재 증명을 밖에서 넣게 두면 검증이 깨진다. */
fn prohibited_update_type(rtype: ApRt) -> bool {
    matches!(rtype.0, 0 | 41 | 249..=254)
}

/** @brief WKS RDATA 앞부분의 주소 4바이트와 프로토콜 1바이트. 짧으면 있는 만큼만 쓴다. */
fn wks_endpoint(record: &ApRecord) -> &[u8] {
    match &record.rdata {
        ApRData::Unknown(11, bytes) => &bytes[..bytes.len().min(5)],
        _ => &[],
    }
}

/**
 * @brief 갱신 RR 이 같은 이름·종류의 기존 RR을 대체하는지.
 *
 * @details RFC 2136은 CNAME 과 SOA 를 하나만 둘 수 있는 종류로 보고, WKS 는 주소와
 *          프로토콜이 같으면 같은 위치로 본다. 나머지는 내용이 같을 때만 대체하고 다르면
 *          RRSet 에 덧붙인다.
 * @return 기존 RR을 덮어써야 하면 참.
 */
fn update_replaces(incoming: &ApRecord, existing: &ApRecord) -> bool {
    if incoming.rtype == ApRt::CNAME || incoming.rtype == ApRt::SOA {
        return true;
    }
    if incoming.rtype == ApRt(11) {
        return wks_endpoint(incoming) == wks_endpoint(existing);
    }
    incoming.rdata == existing.rdata
}

/**
 * @brief 갱신이 담은 SOA 가 현재보다 뒤로 가지 않는지.
 *
 * @details RFC 2136은 일련번호를 되돌리는 SOA 교체를 조용히 무시하라고 정하고, 비교를
 *          RFC 1982 모듈로 산술로 고정한다. 같은 값은 되돌리는 것이 아니므로 통과시키고,
 *          그 경우 실제로 바뀐 것이 없어 뒤에서 서버가 하나 올린다.
 * @param current  지금 영역에 있는 기록들.
 * @param incoming 갱신이 담아 온 SOA 기록.
 * @return 교체해도 되면 참. 현재 SOA 가 없거나 SOA 가 아니면 거짓.
 */
fn soa_update_moves_forward(current: &[ApRecord], incoming: &ApRecord) -> bool {
    let Some(now) = current.iter().find_map(|r| match &r.rdata {
        ApRData::Soa(soa) if r.rtype == ApRt::SOA => Some(soa.serial),
        _ => None,
    }) else {
        return false;
    };
    match &incoming.rdata {
        ApRData::Soa(soa) => !crate::serial_gt(now, soa.serial),
        _ => false,
    }
}

/** @brief 기록들 안의 SOA 일련번호. */
fn soa_serial_of(records: &[ApRecord]) -> Option<u32> {
    records.iter().find_map(|r| match &r.rdata {
        ApRData::Soa(soa) if r.rtype == ApRt::SOA => Some(soa.serial),
        _ => None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/**
 * @brief 해석이 실패한 종류.
 * @warning 둘의 구분이 보조 경로로 넘어갈지를 정한다. 전송이 끊긴 것만 다시 물을 값어치가
 *          있고, 나머지는 다시 물어도 같다.
 */
pub enum ResolveFailure {
    /** @brief 닿지 못했다. 다른 경로로 다시 물어볼 값어치가 있다. */
    TransportExhausted,

    /** @brief 다시 물어도 같다. 값은 클라이언트에 알릴 사유 코드. */
    Permanent(Option<u16>),
}

/** @brief 해석 결과. */
pub enum ResolveOutcome {
    /** @brief 답을 얻었다. */
    Response(Message),
    /** @brief 얻지 못했다. */
    Failure(ResolveFailure),
}

/** @brief 해석 체인의 한 슬롯. */
pub trait Resolver: Send + Sync {
    /** @brief 해석한다. 답하지 못하면 없다. */
    fn resolve(&self, request: &Message) -> Option<Message>;

    /** @brief 실패 종류까지 알려 해석한다. 기본은 답하지 못한 것을 되돌릴 수 없는 실패로 본다. */
    fn resolve_outcome(&self, request: &Message) -> ResolveOutcome {
        match self.resolve(request) {
            Some(response) => ResolveOutcome::Response(response),
            None => ResolveOutcome::Failure(ResolveFailure::Permanent(None)),
        }
    }
}

/**
 * @brief 전달 설정으로 아직 만들어지지 않은 전달 리졸버.
 * @details 전달을 쓰지 않는 backend로 시작해도 전달 리졸버 슬롯은 미리 만들어 둔다.
 *          backend를 전달이나 분할로 바꾸면 설정 반영이 이 슬롯을 진짜 리졸버로 바꾼다.
 *          슬롯이 없으면 그 전환을 무중단으로 처리할 수 없다.
 */
pub struct UnbuiltForward;

impl Resolver for UnbuiltForward {
    /** @brief 전달할 곳이 아직 없으므로 답하지 않는다. */
    fn resolve(&self, _request: &Message) -> Option<Message> {
        None
    }
}

#[derive(Clone)]
/**
 * @brief 교체할 수 있는 리졸버 슬롯.
 * @details 설정을 다시 읽었을 때 체인을 전부 다시 만들지 않고 이 슬롯만 바꾼다. 이미 이 슬롯을
 *          잡은 채 처리 중인 질의는 이전 것으로 끝난다.
 */
pub struct ResolverSlot {
    /** @brief 지금 들어 있는 리졸버. */
    inner: Arc<RwLock<Arc<dyn Resolver>>>,
}

impl ResolverSlot {
    /** @brief 리졸버 하나로 만든다. */
    pub fn new(resolver: Arc<dyn Resolver>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(resolver)),
        }
    }

    /** @brief 지금 들어 있는 리졸버. */
    pub fn load(&self) -> Arc<dyn Resolver> {
        self.inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /** @brief 리졸버를 교체한다. 다음 질의부터 새 것으로 간다. */
    pub fn replace(&self, resolver: Arc<dyn Resolver>) {
        *self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = resolver;
    }
}

impl Resolver for ResolverSlot {
    /** @brief 지금 들어 있는 리졸버로 넘긴다. */
    fn resolve(&self, request: &Message) -> Option<Message> {
        self.load().resolve(request)
    }

    /** @brief 지금 들어 있는 리졸버로 넘긴다. */
    fn resolve_outcome(&self, request: &Message) -> ResolveOutcome {
        self.load().resolve_outcome(request)
    }
}

#[derive(Clone)]
/**
 * @brief 특정 클라이언트만 다른 업스트림으로 보내는 경로.
 * @warning 이 경로도 같은 안전·캐시 계층으로 감싼다. 감싸지 않으면 클라이언트를 맞추는
 *          것만으로 정책과 권한 영역을 건너뛴다.
 */
pub struct ClientUpstream {
    /** @brief 이 경로에 드는 주소 대역. */
    pub nets: Vec<IpNet>,
    /** @brief 이 경로에 드는 클라이언트 식별자. */
    pub ids: Vec<String>,
    /** @brief 이 경로가 쓸 해석 체인. */
    pub resolver: Arc<dyn Resolver>,
}

impl ClientUpstream {
    /** @brief 대상 대역과 식별자, 그리고 그 업스트림으로 만든다. */
    pub fn new(nets: Vec<IpNet>, ids: Vec<String>, resolver: Arc<dyn Resolver>) -> Self {
        ClientUpstream {
            nets,
            ids,
            resolver,
        }
    }

    /** @brief 이 경로의 캐시를 남과 구분하는 이름. */
    pub fn namespace_key(&self) -> String {
        let mut nets: Vec<String> = self.nets.iter().map(|n| n.to_string()).collect();
        nets.sort();
        let mut ids = self.ids.clone();
        ids.sort();
        format!("{}|{}", nets.join(","), ids.join(","))
    }

    /** @brief 이 클라이언트가 이 경로에 드는지. */
    fn matches(&self, client: &ClientInfo) -> bool {
        if self.nets.iter().any(|n| n.contains(&client.source_ip)) {
            return true;
        }
        if let Some(id) = &client.client_id {
            if self.ids.iter().any(|x| x == id) {
                return true;
            }
        }
        false
    }
}

/** @brief 검증에 실패한 질의 수. 지표로 내보낸다. */
pub static DNSSEC_BOGUS_TOTAL: AtomicU64 = AtomicU64::new(0);

/** @brief 재귀 오류를 실패 종류로 옮긴다. */
fn recurse_failure(error: onetdns_recurse::RecurseError, qname: &ApName) -> ResolveFailure {
    use onetdns_recurse::RecurseError as E;
    match error {
        E::NoResponse => ResolveFailure::TransportExhausted,
        E::NoRoots | E::NoReachableNs => {
            ResolveFailure::Permanent(Some(onetdns_proto::ede_code::NO_REACHABLE_AUTHORITY))
        }
        E::Bogus => {
            note_dnssec_bogus(qname);
            ResolveFailure::Permanent(Some(onetdns_proto::ede_code::DNSSEC_BOGUS))
        }

        E::TooManyReferrals | E::TooManyCnames | E::TooManyDnames | E::TooManyQueries => {
            ResolveFailure::Permanent(Some(onetdns_proto::ede_code::OTHER))
        }
    }
}

/** @brief 실패 사유를 클라이언트에 알릴 코드와 문구로. */
pub(crate) fn failure_diagnosis(
    failure: &ResolveFailure,
) -> (&'static str, &'static str, Option<u16>) {
    match failure {
        ResolveFailure::TransportExhausted => (
            "RESOLVER_TRANSPORT_EXHAUSTED",
            "transport_exhausted",
            Some(onetdns_proto::ede_code::NETWORK_ERROR),
        ),
        ResolveFailure::Permanent(ede) => ("RESOLVER_PERMANENT_FAILURE", "permanent", *ede),
    }
}

/** @brief 검증 실패를 세고 남긴다. */
fn note_dnssec_bogus(qname: &onetdns_proto::Name) {
    let count = DNSSEC_BOGUS_TOTAL
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    if count.is_power_of_two() {
        onetdns_core::warn!(
            event = "dnssec.validation_bogus",
            qname = %qname,
            count = count,
            "DNSSEC 검증에 실패한 응답을 차단했습니다"
        );
    }
}

/** @brief 체인 맨 안쪽. 전달이거나 재귀다. */
pub enum NativeBackend {
    /** @brief 업스트림 서버로 전달한다. */
    Forward(Forwarder),

    /** @brief 루트부터 직접 따라간다. */
    Recurse {
        /** @brief 재귀 해석을 실행하는 것. */
        recursor: Arc<Recursor>,
        /** @brief 답에 담긴 이름 서버를 거를 규칙. 없으면 거르지 않는다. */
        ns_rpz: Option<Arc<SharedFilter>>,
        /** @brief 차단 답에 담을 수명. */
        block_ttl: Arc<AtomicU32>,
        /** @brief 고정해 둔 주소에 담을 수명. */
        local_ttl: Arc<AtomicU32>,
    },
}

impl Resolver for NativeBackend {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, request: &Message) -> Option<Message> {
        match self.resolve_outcome(request) {
            ResolveOutcome::Response(response) => Some(response),
            ResolveOutcome::Failure(_) => None,
        }
    }

    /**
     * @brief 전달하거나 재귀한다.
     * @warning 전달일 때 업스트림이 설정한 검증 표시를 지운다. 이 서버가 검증하지 않은 것을 검증됐다며
     *          클라이언트에 넘기면 안 된다. 권한 표시도 같이 지운다. 업스트림이 권한이지 이 서버가
     *          아니다. 이 서버의 영역의 답에 그 표시를 설정하는 것은 위쪽 권한 계층이 한다.
     */
    fn resolve_outcome(&self, request: &Message) -> ResolveOutcome {
        match self {
            NativeBackend::Forward(forwarder) => match forwarder.resolve(request) {
                Ok(mut response) => {
                    response.header.authentic_data = false;
                    response.header.authoritative = false;
                    normalize_response_ttls(&mut response);
                    ResolveOutcome::Response(response)
                }
                Err(onetdns_forward::ForwardError::Timeout)
                | Err(onetdns_forward::ForwardError::Io(_))
                | Err(onetdns_forward::ForwardError::BadResponse) => {
                    ResolveOutcome::Failure(ResolveFailure::TransportExhausted)
                }
                Err(onetdns_forward::ForwardError::NoUpstream) => {
                    ResolveOutcome::Failure(ResolveFailure::Permanent(None))
                }
            },
            NativeBackend::Recurse {
                recursor,
                ns_rpz,
                block_ttl,
                local_ttl,
            } => {
                let Some(q) = request.questions.first() else {
                    return ResolveOutcome::Failure(ResolveFailure::Permanent(None));
                };
                let (mut message, ns) = match recursor.resolve_with_ns_cd(
                    &q.name,
                    q.qtype,
                    request.header.checking_disabled,
                ) {
                    Ok(result) => result,
                    Err(error) => {
                        return ResolveOutcome::Failure(recurse_failure(error, &q.name));
                    }
                };

                if let Some(filter) = ns_rpz {
                    if let Some(verdict) = filter.load().rpz_ns_verdict(&ns.names, &ns.ips) {
                        match verdict {
                            FilterVerdict::Allow => {}
                            FilterVerdict::Block(block) => {
                                return ResolveOutcome::Response(block_resp(
                                    request,
                                    &q.name,
                                    q.qtype,
                                    block,
                                    block_ttl.load(Ordering::Acquire),
                                ));
                            }
                            FilterVerdict::Rewrite(target) => {
                                return ResolveOutcome::Response(ns_rpz_rewrite(
                                    request,
                                    &q.name,
                                    q.qtype,
                                    &target,
                                    local_ttl.load(Ordering::Acquire),
                                ));
                            }
                        }
                    }
                }
                message.header.id = request.header.id;
                message.questions = request.questions.clone();
                strip_dnssec_unless_requested(request, &mut message);
                normalize_response_ttls(&mut message);
                ResolveOutcome::Response(message)
            }
        }
    }
}

/**
 * @brief 밖에서 들어온 응답의 수명을 RFC 2181대로 고른다.
 *
 * @details 업스트림이나 재귀가 준 응답이 캐시·wire 고속 경로·클라이언트로 갈라지기 전 위치다.
 *          여기서 한 번 고르면 이후 분기가 모두 같은 값을 쓴다. 나가는 곳에서 하면
 *          미리 만들어 둔 wire 바이트열을 내보내는 경로가 빠진다.
 * @param response 제자리에서 고친다.
 */
fn normalize_response_ttls(response: &mut Message) {
    onetdns_proto::normalize_ttls(&mut response.answers);
    onetdns_proto::normalize_ttls(&mut response.authorities);
    onetdns_proto::normalize_ttls(&mut response.additionals);
}

/** @brief 이름을 감춘 부재 증명의 매개변수. */
const NSEC3PARAM: ApRt = ApRt(51);

/** @brief 이 종류가 DO를 설정한 쪽에만 나가야 하는 것인지. */
fn is_dnssec_only_type(rtype: ApRt) -> bool {
    matches!(rtype, ApRt::RRSIG | ApRt::NSEC | ApRt::NSEC3 | NSEC3PARAM)
}

/**
 * @brief 이 요청이 DNSSEC 레코드를 함께 달라고 했는지.
 *
 * @details DO는 OPT TTL 필드의 상위 비트다. 질의마다 호출되는 함수라 옵션까지 파싱하지
 *          않는다. 파싱하면 그 값을 응답마다 낸다.
 */
pub(crate) fn wants_dnssec(request: &Message) -> bool {
    request
        .additionals
        .iter()
        .any(|record| record.rtype == ApRt::OPT && (record.ttl & 0x0000_8000) != 0)
}

/**
 * @brief DO를 설정하지 않은 질의자에게 나가는 응답에서 DNSSEC 레코드를 걷어낸다.
 *
 * @details 재귀 리졸버는 검증 여부와 무관하게 업스트림에 DO=1로 묻는다. 그래야 DO=1로 묻는
 *          질의자에게 줄 서명을 가지고 있을 수 있기 때문이다. 대신 묻지 않은 쪽에는
 *          보내지 않는다. 응답만 커지고 절단으로 이어진다.
 * @note DNSKEY와 DS는 질의자가 직접 물을 수 있는 종류라 걷어내지 않는다. 답이 곧
 *       그 종류일 때 지우면 물어본 것을 못 주게 된다.
 * @note 걷어낼 것이 하나도 없는 응답이 대부분이다. 먼저 훑어보고 있을 때만 옮긴다.
 *       retain은 지울 것이 없어도 원소를 하나씩 옮겨 쓴다.
 */
pub(crate) fn strip_dnssec_unless_requested(request: &Message, response: &mut Message) {
    let carries_dnssec = |section: &[ApRecord]| {
        section
            .iter()
            .any(|record| is_dnssec_only_type(record.rtype))
    };
    if !carries_dnssec(&response.answers)
        && !carries_dnssec(&response.authorities)
        && !carries_dnssec(&response.additionals)
    {
        return;
    }
    if wants_dnssec(request) {
        return;
    }
    let keep = |record: &ApRecord| !is_dnssec_only_type(record.rtype);
    response.answers.retain(keep);
    response.authorities.retain(keep);
    response.additionals.retain(keep);
}

/** @brief 응답에 담긴 이름 서버가 차단 대상이면 답을 바꾼다. */
fn ns_rpz_rewrite(
    request: &Message,
    qname: &ApName,
    qtype: ApRt,
    target: &RewriteTarget,
    ttl: u32,
) -> Message {
    match target {
        RewriteTarget::Records(rdatas) => {
            let recs: Vec<ApRecord> = rdatas
                .iter()
                .filter(|rd| rd.record_type() == qtype)
                .map(|rd| ApRecord::new(qname.clone(), ttl, rd.clone()))
                .collect();
            records_resp(request, recs)
        }
        RewriteTarget::Cname(t) => {
            let cname = ApRecord::new(qname.clone(), ttl, ApRData::Cname(t.clone()));
            records_resp(request, vec![cname])
        }
    }
}

/** @brief 이 값이 실제로 무언가를 하는지 스스로 답하는 것. */
pub trait GatePresence {
    /** @brief 지금 이 값이 하는 일이 있는지. */
    fn gate_present(&self) -> bool;
}

impl GatePresence for Vec<NativeView> {
    /** @brief 뷰가 하나라도 있는지. */
    fn gate_present(&self) -> bool {
        !self.is_empty()
    }
}

impl GatePresence for onetdns_policy::PolicyEngine {
    /** @brief 규칙이나 플러그인이 하나라도 있는지. */
    fn gate_present(&self) -> bool {
        !self.is_empty()
    }
}

/**
 * @brief 교체할 수 있으면서 비었는지를 값싸게 답하는 것.
 * @details 질의마다 내용을 복제해 비었는지 보면 그것이 비용이다. 비었는지만 원자 값으로
 *          따로 둔다.
 */
pub struct GatedSwap<T> {
    /** @brief 지금 값. */
    swap: ArcSwap<T>,
    /** @brief 지금 값이 하는 일이 있는지. 복제 없이 답하려고 따로 둔다. */
    present: AtomicBool,
}

impl<T: GatePresence> GatedSwap<T> {
    /** @brief 값 하나로 만든다. */
    pub fn from_pointee(value: T) -> Self {
        let present = value.gate_present();
        GatedSwap {
            swap: ArcSwap::from_pointee(value),
            present: AtomicBool::new(present),
        }
    }

    /** @brief 이미 공유된 값으로 만든다. */
    pub fn new(value: Arc<T>) -> Self {
        let present = value.gate_present();
        GatedSwap {
            swap: ArcSwap::new(value),
            present: AtomicBool::new(present),
        }
    }

    /** @brief 지금 값. */
    pub fn load(&self) -> Arc<T> {
        self.swap.load()
    }

    /** @brief 지금 값이 하는 일이 있는지. 복제 없이 답한다. */
    pub fn present(&self) -> bool {
        self.present.load(Ordering::Acquire)
    }

    /** @brief 값을 교체하고 요약 판정도 함께 맞춘다. */
    pub fn store(&self, value: Arc<T>) {
        let present = value.gate_present();
        if present {
            self.present.store(true, Ordering::Release);
            self.swap.store(value);
        } else {
            self.swap.store(value);
            self.present.store(false, Ordering::Release);
        }
    }
}

#[cfg_attr(not(unix), allow(dead_code))]
/** @brief 재귀를 기다리는 동안 스레드를 붙잡지 않는 레인이 쓰는 것들. */
struct ReactorLaneShared {
    /** @brief 레인에 동시에 맡길 수 있는 질의 수. */
    inflight: usize,

    /** @brief 레인이 끝내지 못한 것을 마저 풀 체인. */
    chain: Arc<dyn Resolver>,
}

/** @brief 한 해석 체인 세대에 반드시 함께 속해야 하는 빠른 경로 자원. */
pub(crate) struct LaneRuntime {
    /** @brief wire 항목을 만들 수 있으면 그 수명 정책. */
    factory: Option<crate::wirecache::WireEntryFactory>,
    /** @brief wire 경로와 리액터 레인이 함께 보는 응답 캐시. */
    cache: crate::cache::CacheHandle,
    /** @brief 이 세대의 재귀 리졸버. 전달 전용 세대면 없다. */
    recursor: Option<Arc<Recursor>>,
}

/** @brief 이 서버의 권한 영역의 단순 질의를 조립 없이 내보내는 경로가 쓰는 것들. */
struct AuthorityWirePath {
    /** @brief 서빙할 권한 영역들. */
    store: Arc<ArcSwap<onetdns_authority::ZoneStore>>,
    /** @brief 응답에 재귀 가능 표시를 담을지. */
    recursion_available: bool,
}

/** @brief 질의 하나를 처음부터 끝까지 다루는 것. */
pub struct NativeServer {
    /** @brief 차단 엔진. 한꺼번에 교체한다. */
    pub filter: Arc<SharedFilter>,
    /** @brief 접근 제어. */
    pub acl: Arc<dyn AccessControl>,
    /** @brief 속도 제한들. */
    pub rate_limiters: Vec<Arc<dyn RateLimiter>>,

    /** @brief 해석 체인. */
    pub backend: Arc<dyn Resolver>,

    /** @brief 클라이언트별 업스트림 경로. */
    pub client_upstreams: Vec<ClientUpstream>,

    /** @brief 재귀 대기가 스레드를 붙잡지 않는 레인. 없으면 쓰지 않는다. */
    reactor_lane: Option<ReactorLaneShared>,
    /** @brief 차단 답에 담을 수명. */
    pub block_ttl: Arc<AtomicU32>,
    /** @brief 고정해 둔 주소에 담을 수명. */
    pub local_ttl: Arc<AtomicU32>,
    /** @brief 켜고 끌 수 있는 기능들. */
    pub features: Arc<NativeFeatureSwap>,

    /** @brief 정책 엔진. */
    pub policy: Arc<GatedSwap<onetdns_policy::PolicyEngine>>,

    /** @brief 영역 전송으로 내줄 영역들. 없으면 전송을 하지 않는다. */
    pub xfr_store: Option<Arc<ArcSwap<onetdns_authority::ZoneStore>>>,

    /** @brief 영역 전송·원격 업데이트·서명 설정. 한꺼번에 교체한다. */
    pub authority: Arc<ArcSwap<AuthoritySettings>>,

    /** @brief 이미 본 서명들. 가로챈 요청을 다시 쓰지 못하게 한다. */
    tsig_replay: std::sync::Mutex<LruMap<Vec<u8>, u64>>,

    /** @brief 영역이 고쳐졌을 때 부를 것. */
    pub update_notify: Option<Arc<dyn Fn(&ApName, u32) + Send + Sync>>,

    /** @brief 업스트림 서버가 알려 온 영역들. */
    pub notify_kick: Arc<NotifyKick>,

    /** @brief 영역별 최근 변경 기록. */
    pub journal: Arc<std::sync::Mutex<std::collections::HashMap<Vec<u8>, ZoneJournal>>>,

    /** @brief 클라이언트별로 다르게 답할 뷰들. */
    pub views: Arc<GatedSwap<Vec<NativeView>>>,

    /** @brief 권한 영역 단순 질의의 빠른 경로. 없으면 쓰지 않는다. */
    authority_wire_path: Option<AuthorityWirePath>,

    /** @brief 설정 세대. 이전 세대가 만든 항목이 들어오지 못하게 한다. */
    pub wire_epoch: Arc<AtomicUsize>,

    /** @brief 빠른 경로를 지금 써도 되는지. 설정이 바뀌면 여기만 내린다. */
    pub lane_switch: Arc<LaneSwitch>,
}

#[derive(Clone, Default)]
/**
 * @brief 권한 영역을 다루는 설정 세트.
 *
 * @details 영역 목록이 바뀌면 전송 허용 대역·서명 키·고칠 수 있는 영역·저장 경로가
 *          함께 바뀐다. 하나씩 교체하면 그 사이에 서로 어긋난 상태로 요청을 받는다.
 * @invariant zone_files와 update_zones는 같은 영역 목록에서 나온다.
 */
pub struct AuthoritySettings {
    /** @brief 영역 전송을 허용할 대역. */
    pub xfr_allow: Vec<IpNet>,
    /** @brief 요청 서명에 쓸 공유 키들. */
    pub tsig_keys: Vec<onetdns_dnssec::tsig::TsigKey>,
    /** @brief 영역 전송에 서명을 요구할지. */
    pub xfr_tsig_required: bool,
    /** @brief 원격 업데이트를 허용할 대역. */
    pub update_allow: Vec<IpNet>,
    /** @brief 누가 무엇을 고칠 수 있는지 정한 규칙. */
    pub update_policy: Vec<UpdateRule>,
    /** @brief 원격 업데이트에 서명을 요구할지. */
    pub update_tsig_required: bool,
    /** @brief 영역별 파일 경로. 고친 뒤 저장할 곳이다. */
    pub zone_files: Vec<(ApName, std::path::PathBuf)>,
    /** @brief 원격으로 고칠 수 있는 영역들. */
    pub update_zones: Vec<ApName>,
    /** @brief NOTIFY를 받아들일 보조 영역과 그 주 서버, 기대하는 TSIG 키. */
    pub notify_secondaries: Vec<(ApName, IpAddr, Option<ApName>)>,
    /**
     * @brief 카탈로그를 받아 오는 주 서버와 기대하는 TSIG 키.
     * @details 카탈로그로 찾은 구성원 영역은 실행 중에 늘고 준다. 이 주 서버가 보낸 NOTIFY는
     *          영역 이름을 미리 알지 못해도 받아들이고, 갱신 작업이 모르는 영역은 버린다.
     */
    pub notify_catalog_primaries: Vec<(IpAddr, Option<ApName>)>,
    /** @brief 영역별 서명기. */
    pub zone_signers: Vec<(ApName, crate::ZoneSigningCtx)>,
}

/**
 * @brief 세 빠른 경로의 켜짐 여부를 담는 슬롯.
 *
 * @details 빠른 경로는 전부 순수한 최적화다. 설정이 바뀌어 조건이 깨지면 여기를 내려
 *          일반 경로로 보내면 되고, 조건이 다시 서면 올린다. 소켓과 스레드는 건드리지
 *          않는다.
 * @invariant 내린 상태에서는 조회도 저장도 하지 않는다. 반쪽만 막으면 이전 답이 남는다.
 */
pub struct LaneSwitch {
    /** @brief 캐시 적중 UDP 빠른 경로. */
    wire: AtomicBool,
    /** @brief 권한 영역 단순 질의 빠른 경로. */
    authority: AtomicBool,
    /** @brief 재귀 콜드미스 리액터 레인. */
    reactor: AtomicBool,
}

impl Default for LaneSwitch {
    fn default() -> Self {
        LaneSwitch {
            wire: AtomicBool::new(true),
            authority: AtomicBool::new(true),
            reactor: AtomicBool::new(true),
        }
    }
}

impl LaneSwitch {
    /**
     * @brief 세 경로의 켜짐 여부를 한꺼번에 정한다.
     * @return 하나라도 달라졌으면 참. 달라진 것을 알려야 조용히 느려지지 않는다.
     */
    pub fn set(&self, wire: bool, authority: bool, reactor: bool) -> bool {
        let was_wire = self.wire.swap(wire, Ordering::AcqRel);
        let was_authority = self.authority.swap(authority, Ordering::AcqRel);
        let was_reactor = self.reactor.swap(reactor, Ordering::AcqRel);
        was_wire != wire || was_authority != authority || was_reactor != reactor
    }

    /** @brief 캐시 적중 빠른 경로를 지금 써도 되는지. */
    pub fn wire(&self) -> bool {
        self.wire.load(Ordering::Acquire)
    }

    /** @brief 권한 영역 빠른 경로를 지금 써도 되는지. */
    pub fn authority(&self) -> bool {
        self.authority.load(Ordering::Acquire)
    }

    #[cfg(unix)]
    /** @brief 리액터 레인을 지금 써도 되는지. */
    pub fn reactor(&self) -> bool {
        self.reactor.load(Ordering::Acquire)
    }
}

#[derive(Clone, Default)]
/** @brief 특정 클라이언트에만 다르게 답할 이름들. */
pub struct NativeView {
    /** @brief 이 뷰에 드는 주소 대역. */
    pub nets: Vec<IpNet>,
    /** @brief 이 뷰에 드는 클라이언트 식별자. */
    pub ids: Vec<String>,

    /** @brief 이 뷰에만 답할 IPv4 주소. */
    pub local_a: Vec<(Vec<u8>, Ipv4Addr)>,
    /** @brief 이 뷰에만 답할 IPv6 주소. */
    pub local_aaaa: Vec<(Vec<u8>, Ipv6Addr)>,
}

impl NativeView {
    /** @brief 이 클라이언트가 이 뷰에 드는지. */
    fn matches(&self, client: &ClientInfo) -> bool {
        if self.nets.iter().any(|n| n.contains(&client.source_ip)) {
            return true;
        }
        client
            .client_id
            .as_ref()
            .is_some_and(|id| self.ids.iter().any(|x| x == id))
    }
}

#[derive(Clone)]
/** @brief 영역이 한 판에서 다음 판으로 가며 바뀐 것. */
pub struct ZoneDelta {
    /** @brief 이 변경 전의 시리얼. */
    pub from: u32,
    /** @brief 이 변경 뒤의 시리얼. */
    pub to: u32,

    /** @brief 이 변경에서 지운 기록. */
    pub deleted: Vec<ApRecord>,

    /** @brief 이 변경에서 더한 기록. */
    pub added: Vec<ApRecord>,

    /** @brief 이 변경을 보낼 때의 바이트 수. 전체를 보내는 것보다 커지면 버린다. */
    wire_bytes: usize,
}

#[derive(Default)]
/**
 * @brief 최근 변경 기록. 하위 서버가 바뀐 것만 받아 가게 한다.
 * @note 쌓인 것이 전체를 보내는 것보다 커지면 의미가 없다. 그때는 버리고 전부 보낸다.
 */
pub struct ZoneJournal {
    /** @brief 최근 변경들. 오래된 것부터 밀려난다. */
    pub deltas: std::collections::VecDeque<ZoneDelta>,
}

impl ZoneJournal {
    /** @brief 남겨 둘 변경 기록 수. */
    const MAX: usize = 64;

    /** @brief 이번 변경을 남긴다. */
    pub fn record(&mut self, from: u32, to: u32, old: &[ApRecord], new: &[ApRecord]) {
        let deleted: Vec<ApRecord> = old
            .iter()
            .filter(|r| r.rtype != ApRt::SOA && !new.contains(r))
            .cloned()
            .collect();
        let added: Vec<ApRecord> = new
            .iter()
            .filter(|r| r.rtype != ApRt::SOA && !old.contains(r))
            .cloned()
            .collect();
        if deleted.is_empty() && added.is_empty() {
            if from != to {
                self.deltas.clear();
            }
            return;
        }
        let Some(soa) = new.iter().find(|record| record.rtype == ApRt::SOA) else {
            self.deltas.clear();
            return;
        };
        let soa_bytes = journal_records_wire_bytes(std::slice::from_ref(soa));
        let wire_bytes = journal_records_wire_bytes(&deleted)
            .saturating_add(journal_records_wire_bytes(&added))
            .saturating_add(soa_bytes.saturating_mul(2));
        let axfr_bytes = journal_records_wire_bytes(new).saturating_add(soa_bytes);
        if wire_bytes.saturating_add(soa_bytes.saturating_mul(2)) >= axfr_bytes {
            self.deltas.clear();
            return;
        }
        self.deltas.push_back(ZoneDelta {
            from,
            to,
            deleted,
            added,
            wire_bytes,
        });
        let mut retained_bytes = self
            .deltas
            .iter()
            .fold(0usize, |sum, delta| sum.saturating_add(delta.wire_bytes));
        while self.deltas.len() > Self::MAX
            || retained_bytes.saturating_add(soa_bytes.saturating_mul(2)) >= axfr_bytes
        {
            let Some(removed) = self.deltas.pop_front() else {
                break;
            };
            retained_bytes = retained_bytes.saturating_sub(removed.wire_bytes);
        }
    }

    /** @brief 이 판에서 지금 판까지 이어지는 변경 목록. 끊겼으면 없다. */
    pub fn path_from(&self, client_serial: u32, current: u32) -> Option<Vec<&ZoneDelta>> {
        if client_serial == current {
            return Some(vec![]);
        }
        let mut path = Vec::new();
        let mut cur = client_serial;
        while cur != current {
            let d = self.deltas.iter().find(|d| d.from == cur)?;
            path.push(d);
            cur = d.to;
            if path.len() > Self::MAX {
                return None;
            }
        }
        Some(path)
    }
}

/** @brief 이 기록들을 보낼 때의 바이트 수. */
fn journal_records_wire_bytes(records: &[ApRecord]) -> usize {
    let mut writer = onetdns_proto::Writer::new();
    records.iter().fold(0usize, |sum, record| {
        writer.clear();
        record.encode(&mut writer);
        sum.saturating_add(writer.buf.len())
    })
}

impl NativeServer {
    /** @brief 차단·접근 제어·속도 제한과 해석 체인을 잡은 핸들러를 만든다. */
    pub fn new(
        filter: Arc<SharedFilter>,
        acl: Arc<dyn AccessControl>,
        rate_limiters: Vec<Arc<dyn RateLimiter>>,
        backend: Arc<dyn Resolver>,
        block_ttl: u32,
    ) -> Self {
        NativeServer {
            filter,
            acl,
            rate_limiters,
            backend,
            client_upstreams: Vec::new(),
            reactor_lane: None,
            block_ttl: Arc::new(AtomicU32::new(block_ttl)),
            local_ttl: Arc::new(AtomicU32::new(300)),
            features: Arc::new(NativeFeatureSwap::from_pointee(NativeFeatures::default())),
            policy: Arc::new(GatedSwap::from_pointee(
                onetdns_policy::PolicyEngine::default(),
            )),
            xfr_store: None,
            authority: Arc::new(ArcSwap::from_pointee(AuthoritySettings::default())),
            tsig_replay: std::sync::Mutex::new(LruMap::new(4096)),
            update_notify: None,
            notify_kick: Arc::new(NotifyKick::default()),
            journal: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            views: Arc::new(GatedSwap::from_pointee(Vec::new())),
            authority_wire_path: None,
            wire_epoch: Arc::new(AtomicUsize::new(0)),
            lane_switch: Arc::new(LaneSwitch::default()),
        }
    }

    /** @brief 재귀 대기가 스레드를 붙잡지 않는 레인을 붙인다. */
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn with_reactor_lane(
        self,
        recursor: Arc<Recursor>,
        cache: crate::cache::CacheHandle,
        inflight: usize,
    ) -> Self {
        self.with_reactor_lane_runtime(Some(recursor), cache, inflight)
    }

    /** @brief 재귀 리졸버가 아직 없는 세대도 나중에 레인을 켤 수 있게 슬롯을 붙인다. */
    pub fn with_reactor_lane_runtime(
        mut self,
        recursor: Option<Arc<Recursor>>,
        cache: crate::cache::CacheHandle,
        inflight: usize,
    ) -> Self {
        let mut features = (*self.features.load()).clone();
        let factory = features
            .lane_runtime
            .as_ref()
            .and_then(|runtime| runtime.factory);
        features.lane_runtime = Some(Arc::new(LaneRuntime {
            factory,
            cache,
            recursor,
        }));
        self.features.store(Arc::new(features));
        self.reactor_lane = Some(ReactorLaneShared {
            inflight,
            chain: self.backend.clone(),
        });
        self
    }

    /** @brief 차단과 고정해 둔 주소의 수명 출처를 붙인다. */
    pub fn with_ttl_sources(
        mut self,
        block_ttl: Arc<AtomicU32>,
        local_ttl: Arc<AtomicU32>,
    ) -> Self {
        self.block_ttl = block_ttl;
        self.local_ttl = local_ttl;
        self
    }

    /** @brief 캐시가 맞은 UDP 질의의 빠른 경로를 붙인다. */
    pub fn with_wire_fast_path(
        self,
        fast_path: Option<(
            crate::wirecache::WireEntryFactory,
            crate::cache::CacheHandle,
        )>,
    ) -> Self {
        let mut features = (*self.features.load()).clone();
        let previous = features.lane_runtime.clone();
        features.lane_runtime = match fast_path {
            Some((factory, cache)) => Some(Arc::new(LaneRuntime {
                factory: Some(factory),
                cache,
                recursor: previous.and_then(|runtime| runtime.recursor.clone()),
            })),
            None => previous.map(|runtime| {
                Arc::new(LaneRuntime {
                    factory: None,
                    cache: runtime.cache.clone(),
                    recursor: runtime.recursor.clone(),
                })
            }),
        };
        self.features.store(Arc::new(features));
        self
    }

    /** @brief 체인을 교체한 뒤 빠른 경로도 같은 캐시·재귀 리졸버 세대로 옮긴다. */
    pub fn replace_lane_runtime(
        &self,
        factory: crate::wirecache::WireEntryFactory,
        cache: crate::cache::CacheHandle,
        recursor: Option<Arc<Recursor>>,
        ddr_enabled: bool,
    ) {
        let mut features = (*self.features.load()).clone();
        features.ddr_enabled = ddr_enabled;
        features.lane_runtime = Some(Arc::new(LaneRuntime {
            factory: Some(factory),
            cache,
            recursor,
        }));
        self.features.store(Arc::new(features));
    }

    /** @brief 권한 영역 단순 질의의 빠른 경로를 붙인다. */
    pub fn with_authority_wire_path(
        mut self,
        store: Option<Arc<ArcSwap<onetdns_authority::ZoneStore>>>,
        recursion_available: bool,
    ) -> Self {
        self.authority_wire_path = store.map(|store| AuthorityWirePath {
            store,
            recursion_available,
        });
        self
    }

    /** @brief 클라이언트별로 다르게 답할 뷰를 붙인다. */
    pub fn with_views(mut self, views: Vec<NativeView>) -> Self {
        self.views = Arc::new(GatedSwap::from_pointee(views));
        self
    }

    /** @brief 이 뷰에 이 이름의 답이 있는지. */
    fn view_local_answer(
        &self,
        client: &ClientInfo,
        qname: &ApName,
        qtype: ApRt,
    ) -> Option<Vec<ApRecord>> {
        let views = self.views.load();
        if views.is_empty() {
            return None;
        }
        let mut key = [0u8; 255];
        let key = qname.canonical_key_into(&mut key)?;
        let ttl = self.local_ttl.load(Ordering::Acquire);
        for v in views.iter().filter(|v| v.matches(client)) {
            match qtype {
                ApRt::A => {
                    if let Some((_, ip)) = v.local_a.iter().find(|(n, _)| n.as_slice() == key) {
                        return Some(vec![ApRecord::new(qname.clone(), ttl, ApRData::A(*ip))]);
                    }
                }
                ApRt::AAAA => {
                    if let Some((_, ip)) = v.local_aaaa.iter().find(|(n, _)| n.as_slice() == key) {
                        return Some(vec![ApRecord::new(qname.clone(), ttl, ApRData::Aaaa(*ip))]);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /** @brief 변경 기록 기록을 붙인다. */
    pub fn with_journal(
        mut self,
        journal: Arc<std::sync::Mutex<std::collections::HashMap<Vec<u8>, ZoneJournal>>>,
    ) -> Self {
        self.journal = journal;
        self
    }

    /** @brief 업스트림 서버 알림을 받을 곳을 붙인다. */
    pub fn with_notify_kick(mut self, kick: Arc<NotifyKick>) -> Self {
        self.notify_kick = kick;
        self
    }

    #[cfg(test)]
    /** @brief 변경을 알릴 하위 서버 목록을 붙인다. */
    pub fn with_notify_secondaries(
        mut self,
        secondaries: Vec<(ApName, IpAddr, Option<ApName>)>,
        kick: Arc<NotifyKick>,
    ) -> Self {
        self.edit_authority(|a| a.notify_secondaries = secondaries);
        self.notify_kick = kick;
        self
    }

    /** @brief 기능 세트를 붙인다. */
    pub fn with_features(mut self, features: NativeFeatures) -> Self {
        self.features = Arc::new(NativeFeatureSwap::from_pointee(features));
        self
    }

    /** @brief 클라이언트별 업스트림 경로를 붙인다. */
    pub fn with_client_upstreams(mut self, client_upstreams: Vec<ClientUpstream>) -> Self {
        self.client_upstreams = client_upstreams;
        self
    }

    /**
     * @brief 정책 엔진 슬롯을 붙인다.
     * @details 관리 API의 시뮬레이션과 설명도 같은 슬롯을 읽는다. 따로 가지고 있으면 설정을
     *          바꾼 뒤에도 이전 정책으로 답한다.
     */
    pub fn with_policy(mut self, policy: Arc<GatedSwap<onetdns_policy::PolicyEngine>>) -> Self {
        self.policy = policy;
        self
    }

    /** @brief 권한 영역 설정 세트의 한 부분을 고쳐 넣는다. */
    fn edit_authority(&self, edit: impl FnOnce(&mut AuthoritySettings)) {
        let mut next = (*self.authority.load()).clone();
        edit(&mut next);
        self.authority.store(Arc::new(next));
    }

    /** @brief 권한 영역 설정을 전부 교체한다. */
    pub fn replace_authority(&self, settings: AuthoritySettings) {
        self.authority.store(Arc::new(settings));
    }

    /** @brief 영역 전송을 켠다. */
    pub fn with_xfr(
        mut self,
        store: Arc<ArcSwap<onetdns_authority::ZoneStore>>,
        allow: Vec<IpNet>,
    ) -> Self {
        self.xfr_store = Some(store);
        self.edit_authority(|a| a.xfr_allow = allow);
        self
    }

    #[cfg(test)]
    /** @brief 공유 키 목록을 붙인다. 요구로 두면 서명 없는 요청을 거절한다. */
    pub fn with_tsig(self, keys: Vec<onetdns_dnssec::tsig::TsigKey>, required: bool) -> Self {
        self.edit_authority(|a| {
            a.tsig_keys = keys;
            a.xfr_tsig_required = required;
        });
        self
    }

    #[cfg(test)]
    /** @brief 원격 영역 업데이트를 켠다. */
    pub fn with_ddns(
        self,
        allow: Vec<IpNet>,
        tsig_required: bool,
        zone_files: Vec<(ApName, std::path::PathBuf)>,
        update_zones: Vec<ApName>,
    ) -> Self {
        self.edit_authority(|a| {
            a.update_allow = allow;
            a.update_tsig_required = tsig_required;
            a.zone_files = zone_files;
            a.update_zones = update_zones;
        });
        self
    }

    /** @brief 영역이 고쳐졌을 때 부를 것을 붙인다. */
    pub fn with_update_notify(mut self, notify: Arc<dyn Fn(&ApName, u32) + Send + Sync>) -> Self {
        self.update_notify = Some(notify);
        self
    }

    /** @brief 이 클라이언트에 맞는 체인으로 해석한다. */
    fn resolve_for(&self, request: &Message, client: &ClientInfo) -> ResolveOutcome {
        if let Some(route) = self.client_upstreams.iter().find(|r| r.matches(client)) {
            return route.resolver.resolve_outcome(request);
        }
        self.backend.resolve_outcome(request)
    }

    /** @brief 이 클라이언트에 맞는 체인으로 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve_message_for(&self, request: &Message, client: &ClientInfo) -> Option<Message> {
        match self.resolve_for(request, client) {
            ResolveOutcome::Response(response) => Some(response),
            ResolveOutcome::Failure(_) => None,
        }
    }

    /** @brief 이 클라이언트가 어느 경로로 가는지. 기록에 남긴다. */
    fn resolver_mode(&self, client: &ClientInfo) -> &'static str {
        if self.client_upstreams.iter().any(|r| r.matches(client)) {
            "client_route"
        } else {
            "backend"
        }
    }

    /** @brief 이미 인코딩해 둔 영역 전송 바이트를 그대로 내보낸다. 같은 영역을 매번 다시 짜지 않으려는 것이다. */
    fn handle_cached_axfr_wire(
        &self,
        request: &Message,
        ctx: &RequestCtx,
        out: &mut onetdns_proto::Writer,
        emit: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Option<bool> {
        let authority = self.authority.load();
        if request.header.opcode != 0
            || request.questions.len() != 1
            || !request.authorities.is_empty()
            || request.questions[0].qtype != ApRt(252)
            || request.questions[0].qclass != DnsClass::IN
            || !ctx.transport.supports_xfr()
            || self.rate_limiters.iter().any(|limiter| limiter.is_active())
        {
            return None;
        }
        let features = self.features.load();
        // dnstap은 내보낸 envelope마다 한 건씩 남겨야 하는데 이 경로는 미리 만들어 둔 바이트를
        // 그대로 내보내므로 남길 것을 만들지 못한다. 통계는 성공한 영역 전송을 어느 경로도
        // 남기지 않으므로 여기서 물러설 이유가 없다.
        if features.dnstap.is_some() {
            return None;
        }
        let client = self.identify_with(ctx, &features);
        if self.acl.check(&client) == AclDecision::Deny
            || !authority
                .xfr_allow
                .iter()
                .any(|network| network.contains(&ctx.src.ip()))
        {
            return None;
        }

        let tsig_ctx = if onetdns_dnssec::tsig::contains_tsig(request) {
            match self.check_tsig(request, ctx.raw, authority.xfr_tsig_required, false) {
                Ok(Some(context)) => Some(context),
                Ok(None) | Err(_) => return None,
            }
        } else if authority.xfr_tsig_required {
            return None;
        } else {
            None
        };

        let store = self.xfr_store.as_ref()?.load();
        let question = &request.questions[0];
        let zone = store
            .zones()
            .iter()
            .find(|zone| zone.origin().eq_ignore_case(&question.name))?;
        let templates = zone.axfr_wire_templates().ok()?;
        let question_wire = question.name.as_uncompressed_wire();
        let now = now_unix();
        let mut previous_mac = None;
        for (index, template) in templates.iter().enumerate() {
            out.clear();
            out.push_bytes(template);
            out.buf[0..2].copy_from_slice(&request.header.id.to_be_bytes());
            if request.header.recursion_desired {
                out.buf[2] |= 0x01;
            } else {
                out.buf[2] &= !0x01;
            }
            if index == 0 {
                let name_end = 12 + question_wire.len();
                let target = out.buf.get_mut(12..name_end)?;
                if target.len() != question_wire.len() {
                    return None;
                }
                target.copy_from_slice(question_wire);
            }
            if let Some((key, request_tsig)) = &tsig_ctx {
                let mac = if index == 0 {
                    onetdns_dnssec::tsig::sign_response_wire(out, key, now, request_tsig)
                } else {
                    onetdns_dnssec::tsig::sign_response_wire_subsequent(
                        out,
                        key,
                        now,
                        previous_mac.as_deref().unwrap_or(&[]),
                        request_tsig,
                    )
                }
                .expect("60KiB AXFR wire template에는 TSIG를 추가할 공간이 있습니다");
                previous_mac = Some(mac);
            }
            if !emit(&out.buf) {
                return Some(false);
            }
        }
        Some(true)
    }

    /**
     * @brief 영역 전체 또는 바뀐 부분을 보낸다.
     * @warning 허용한 대역이고 키 검증을 통과해야 한다. 영역 전체는 그 안의 모든 이름을
     *          한꺼번에 내주는 것이다.
     */
    fn handle_axfr(
        &self,
        request: &Message,
        ctx: &RequestCtx,
        qname: &ApName,
        client: &ClientInfo,
        emit: &mut dyn FnMut(Message) -> bool,
    ) -> Option<()> {
        let authority = self.authority.load();
        let qtype = request
            .questions
            .first()
            .map(|q| q.qtype)
            .unwrap_or(ApRt(252));
        let axfr = qtype;
        let is_ixfr = qtype == ApRt(251);

        let store = self.xfr_store.as_ref()?.load();
        if !authority
            .xfr_allow
            .iter()
            .any(|net| net.contains(&ctx.src.ip()))
        {
            onetdns_core::warn!(event = "xfr.refused", peer = %ctx.src.ip(), zone = %qname.to_ascii_lower(), reason = "not_in_xfr_allow", "영역 전송을 허용하지 않은 주소라 거절했습니다");
            self.rec(client, Action::Refused, Some(qname), Some(axfr));
            return emit(error_resp(request, ResponseCode::Refused)).then_some(());
        }

        let tsig_ctx = match self.check_tsig(request, ctx.raw, authority.xfr_tsig_required, false) {
            Ok(t) => t,
            Err(response) => {
                onetdns_core::warn!(event = "xfr.refused", peer = %ctx.src.ip(), zone = %qname.to_ascii_lower(), reason = "tsig", "TSIG 확인에 실패해 영역 전송을 거절했습니다");
                self.rec(client, Action::Refused, Some(qname), Some(axfr));
                return emit(response).then_some(());
            }
        };
        let zone = store
            .zones()
            .iter()
            .find(|z| z.origin().eq_ignore_case(qname));
        let Some(zone) = zone else {
            onetdns_core::warn!(event = "xfr.unknown_zone", peer = %ctx.src.ip(), zone = %qname.to_ascii_lower(), "이 서버가 맡지 않은 영역의 전송 요청이라 거절했습니다");
            return emit(xfr_single_response(
                request,
                ResponseCode(9),
                None,
                false,
                tsig_ctx.as_ref(),
            ))
            .then_some(());
        };

        let client_serial = if is_ixfr {
            match request.authorities.as_slice() {
                [record]
                    if record.name.eq_ignore_case(qname)
                        && record.rtype == ApRt::SOA
                        && record.class == DnsClass::IN =>
                {
                    match &record.rdata {
                        ApRData::Soa(soa) => Some(soa.serial),
                        _ => None,
                    }
                }
                _ => None,
            }
        } else {
            Some(0)
        };
        if client_serial.is_none() {
            return emit(xfr_single_response(
                request,
                ResponseCode::FormErr,
                None,
                false,
                tsig_ctx.as_ref(),
            ))
            .then_some(());
        }

        if !ctx.transport.supports_xfr() {
            if is_ixfr && ctx.transport == RtTransport::Do53Udp {
                let soa = zone.axfr_records_iter().next()?;
                let stale = client_serial != Some(zone.soa().serial);
                let m = xfr_single_response(
                    request,
                    ResponseCode::NoError,
                    Some(soa),
                    stale,
                    tsig_ctx.as_ref(),
                );
                self.rec(client, Action::Resolved, Some(qname), Some(axfr));
                return emit(m).then_some(());
            }
            self.rec(client, Action::Refused, Some(qname), Some(axfr));
            return emit(xfr_single_response(
                request,
                ResponseCode::Refused,
                None,
                false,
                tsig_ctx.as_ref(),
            ))
            .then_some(());
        }

        if is_ixfr {
            let client_serial = client_serial.expect("앞에서 IXFR 일련번호를 확인했습니다");
            let cur_serial = zone.soa().serial;
            if client_serial == cur_serial {
                let soa = zone.axfr_records_iter().next()?;
                self.rec(client, Action::Resolved, Some(qname), Some(axfr));
                return xfr_envelopes_stream(request, std::iter::once(soa), tsig_ctx, emit)
                    .then_some(());
            }
            {
                let jr = self.journal.lock_recover();
                if let Some(path) = jr
                    .get(&apex_key(qname))
                    .and_then(|j| j.path_from(client_serial, cur_serial))
                {
                    let soa_rec = zone.axfr_records_iter().next()?;
                    let mut recs = Vec::new();
                    recs.push(soa_rec.clone());
                    for d in &path {
                        recs.push(soa_with_serial(&soa_rec, d.from));
                        recs.extend(d.deleted.iter().cloned());
                        recs.push(soa_with_serial(&soa_rec, d.to));
                        recs.extend(d.added.iter().cloned());
                    }
                    recs.push(soa_rec);
                    drop(jr);
                    self.rec(client, Action::Resolved, Some(qname), Some(axfr));
                    return xfr_envelopes_stream(request, recs, tsig_ctx, emit).then_some(());
                }
            }
        }

        self.rec(client, Action::Resolved, Some(qname), Some(axfr));
        xfr_envelopes_stream(request, zone.axfr_records_iter(), tsig_ctx, emit).then_some(())
    }

    /**
     * @brief 요청의 서명을 검증한다.
     * @warning 같은 서명을 다시 쓰지 못하게 기억해 둔다. 기억하지 않으면 가로챈 요청을
     *          그대로 다시 보내는 것만으로 통과한다.
     */
    fn check_tsig(
        &self,
        request: &Message,
        raw: Option<&[u8]>,
        required: bool,
        replay_protected: bool,
    ) -> Result<Option<TsigContext>, Message> {
        let authority = self.authority.load();
        // TSIG 오류 응답도 요청이 담은 OPT를 그대로 돌려줘야 한다. 서명 전에 붙어야 MAC이 덮는다.
        let edns_buffer = self.features.load().edns_buffer;
        if onetdns_dnssec::tsig::contains_tsig(request) {
            let Some(key_name) = onetdns_dnssec::tsig::peek_key_name(request) else {
                return Err(edns_error_resp(request, ResponseCode::FormErr, edns_buffer));
            };
            let key = authority
                .tsig_keys
                .iter()
                .find(|key| key.name.eq_ignore_case(&key_name))
                .cloned();
            let Some(key) = key else {
                let request_tsig = match onetdns_dnssec::tsig::request_data(request) {
                    Ok(data) => data,
                    Err(_) => {
                        return Err(edns_error_resp(request, ResponseCode::FormErr, edns_buffer))
                    }
                };
                return Err(unsigned_tsig_error_response(
                    request,
                    &request_tsig,
                    onetdns_dnssec::tsig::UnsignedTsigError::BadKey,
                    edns_buffer,
                ));
            };
            let now = now_unix();
            let verified = match raw {
                Some(wire) => onetdns_dnssec::tsig::verify_wire_detailed(wire, &key, now, None),
                None => return Err(edns_error_resp(request, ResponseCode::FormErr, edns_buffer)),
            };
            match verified {
                Ok(onetdns_dnssec::tsig::WireVerification::Valid { tsig, .. }) => {
                    if replay_protected {
                        let mut replay_key = key.name.to_ascii_lower().into_bytes();
                        replay_key.push(0);
                        replay_key.extend_from_slice(tsig.mac());
                        let mut replay = self.tsig_replay.lock_recover();
                        if replay
                            .peek(&replay_key)
                            .is_some_and(|expires| *expires >= now)
                        {
                            onetdns_core::warn!(event = "authority.tsig_replay_blocked", key = %key.name.to_ascii_lower(), "재사용된 TSIG 요청을 차단했습니다");
                            return Err(signed_tsig_error_response(
                                request,
                                &key,
                                &tsig,
                                ResponseCode(9),
                                edns_buffer,
                            ));
                        }
                        replay.put(replay_key, tsig.valid_until());
                    }
                    Ok(Some((key, tsig)))
                }
                Ok(onetdns_dnssec::tsig::WireVerification::BadTime { tsig, .. }) => Err(
                    signed_badtime_response(request, &key, &tsig, now, edns_buffer),
                ),
                Err(
                    onetdns_dnssec::tsig::TsigError::Missing
                    | onetdns_dnssec::tsig::TsigError::InvalidMessage,
                ) => Err(edns_error_resp(request, ResponseCode::FormErr, edns_buffer)),
                Err(
                    error @ (onetdns_dnssec::tsig::TsigError::BadKey
                    | onetdns_dnssec::tsig::TsigError::BadAlg
                    | onetdns_dnssec::tsig::TsigError::BadSig),
                ) => {
                    let request_tsig = match onetdns_dnssec::tsig::request_data(request) {
                        Ok(data) => data,
                        Err(_) => {
                            return Err(edns_error_resp(
                                request,
                                ResponseCode::FormErr,
                                edns_buffer,
                            ))
                        }
                    };
                    let response_error = if matches!(
                        error,
                        onetdns_dnssec::tsig::TsigError::BadKey
                            | onetdns_dnssec::tsig::TsigError::BadAlg
                    ) {
                        onetdns_dnssec::tsig::UnsignedTsigError::BadKey
                    } else {
                        onetdns_dnssec::tsig::UnsignedTsigError::BadSig
                    };
                    Err(unsigned_tsig_error_response(
                        request,
                        &request_tsig,
                        response_error,
                        edns_buffer,
                    ))
                }
                Err(onetdns_dnssec::tsig::TsigError::BadTime) => {
                    unreachable!("상세 TSIG 검증은 BADTIME 문맥을 보존합니다")
                }
            }
        } else if required {
            Err(error_resp(request, ResponseCode::Refused))
        } else {
            Ok(None)
        }
    }

    /** @brief 서버 이름과 버전을 묻는 질의에 답한다. 감추기로 했으면 답하지 않는다. */
    fn handle_chaos(&self, request: &Message, qname: &ApName) -> Option<Message> {
        let name = qname.to_ascii_lower();
        let f = self.features.load();
        let txt: Option<&[u8]> = match name.as_str() {
            "id.server" | "hostname.bind" => {
                if f.hide_identity {
                    return Some(error_resp(request, ResponseCode::Refused));
                }
                Some(&f.server_identity)
            }
            "version.server" | "version.bind" => {
                if f.hide_version {
                    return Some(error_resp(request, ResponseCode::Refused));
                }
                Some(&f.server_version)
            }
            _ => None,
        };
        let txt = txt?;
        let mut m = base_response(request);
        m.header.authoritative = true;
        m.answers.push(ApRecord {
            name: qname.clone(),
            rtype: ApRt::TXT,
            class: DnsClass(3),
            ttl: 0,
            rdata: ApRData::Txt(vec![txt.to_vec()]),
        });
        Some(m)
    }

    /**
     * @brief 이 이름을 이 서버가 권한으로 맡고 있는지.
     * @details 맡고 있으면 이름이 있는지 없는지를 알므로 표준 알고리즘을 돌릴 수 있다.
     * @param qname 물어본 이름.
     * @return 이 이름을 덮는 영역이 실려 있으면 참.
     */
    fn serves_zone_for(&self, qname: &ApName) -> bool {
        self.authority_wire_path
            .as_ref()
            .is_some_and(|path| path.store.load().zone_for(qname).is_some())
    }

    /** @brief 업스트림 서버가 바뀌었다는 알림을 받는다. 이 서버가 아는 업스트림에서 온 것만 받아들인다. */
    fn handle_notify(&self, request: &Message, ctx: &RequestCtx) -> Option<Message> {
        let authority = self.authority.load();
        if request.header.response {
            return None;
        }
        let mut m = base_response(request);
        m.header.opcode = 4;
        m.header.authoritative = true;
        m.header.recursion_available = false;
        m.additionals.clear();
        // RFC 6891은 여기에도 적용된다. TSIG 서명 앞에 붙여야 서명이 이 OPT까지 덮는다.
        if request.opt().is_some() {
            m = finalize(
                m,
                Some(base_edns(request, self.features.load().edns_buffer)),
            );
        }
        let Some(q) = request.questions.first().filter(|q| {
            request.questions.len() == 1 && q.qtype == ApRt::SOA && q.qclass == DnsClass::IN
        }) else {
            m.header.rcode = ResponseCode::FormErr.0;
            return Some(m);
        };
        let known = authority
            .notify_secondaries
            .iter()
            .find(|(o, p, _)| o.eq_ignore_case(&q.name) && *p == ctx.src.ip())
            .map(|(origin, _, key)| (origin, key))
            .or_else(|| {
                authority
                    .notify_catalog_primaries
                    .iter()
                    .find(|(primary, _)| *primary == ctx.src.ip())
                    .map(|(_, key)| (&q.name, key))
            });
        match known {
            Some((origin, expected_key)) => {
                let tsig_ctx =
                    match self.check_tsig(request, ctx.raw, expected_key.is_some(), false) {
                        Ok(context) => context,
                        Err(response) => return Some(response),
                    };
                if let (Some(expected), Some((actual, verified))) =
                    (expected_key.as_ref(), tsig_ctx.as_ref())
                {
                    if !actual.name.eq_ignore_case(expected) {
                        return Some(signed_tsig_error_response(
                            request,
                            actual,
                            verified,
                            ResponseCode(9),
                            self.features.load().edns_buffer,
                        ));
                    }
                }
                self.notify_kick.push(origin.to_ascii_lower());
                onetdns_core::info!(event = "authority.notify_received", zone = %origin.to_ascii_lower(), src = %ctx.src, "DNS NOTIFY를 받아 보조 영역 갱신을 예약했습니다");
                if let Some((key, verified)) = tsig_ctx.as_ref() {
                    if onetdns_dnssec::tsig::sign_response_message(
                        &mut m,
                        key,
                        now_unix(),
                        verified,
                    )
                    .is_err()
                    {
                        return Some(edns_error_resp(
                            request,
                            ResponseCode::ServFail,
                            self.features.load().edns_buffer,
                        ));
                    }
                }
            }
            None => {
                onetdns_core::warn!(event = "authority.notify_unknown_master", zone = %q.name.to_ascii_lower(), src = %ctx.src, "알 수 없는 주 서버의 DNS NOTIFY를 무시했습니다");
                return None;
            }
        }
        Some(m)
    }

    /**
     * @brief 원격에서 영역을 고친다.
     * @warning 허용 대역, 키, 그리고 규칙을 모두 통과해야 한다. 선행 조건이 붙었으면
     *          그것부터 확인하고, 하나라도 어긋나면 아무것도 고치지 않는다.
     */
    fn handle_update(
        &self,
        request: &Message,
        ctx: &RequestCtx,
        client: &ClientInfo,
    ) -> Option<Message> {
        let authority = self.authority.load();
        let reply = |rcode: u16| {
            let mut m = base_response(request);
            m.header.opcode = 5;
            m.header.rcode = rcode;
            m.additionals.clear();
            Some(m)
        };

        // RFC 2136은 영역부 개수와 ZTYPE 만 형식 오류로 본다. ZCLASS 가 맞지 않는
        // 것은 요청이 깨진 것이 아니라 이 서버가 맡지 않은 영역이라는 뜻이라 아래에서 NOTAUTH
        // 로 답한다.
        if request.questions.len() != 1 || request.questions[0].qtype != ApRt::SOA {
            return reply(ResponseCode::FormErr.0);
        }

        if !authority
            .update_allow
            .iter()
            .any(|net| net.contains(&ctx.src.ip()))
        {
            self.rec(client, Action::Refused, None, None);
            return reply(ResponseCode::Refused.0);
        }

        let tsig_ctx = match self.check_tsig(request, ctx.raw, authority.update_tsig_required, true)
        {
            Ok(t) => t,
            Err(response) => {
                self.rec(client, Action::Refused, None, None);
                return Some(response);
            }
        };
        let reply = |rcode: u16| {
            let mut m = base_response(request);
            m.header.opcode = 5;
            m.header.rcode = rcode;
            m.additionals.clear();
            if let Some((key, request_tsig)) = &tsig_ctx {
                onetdns_dnssec::tsig::sign_response_message(&mut m, key, now_unix(), request_tsig)
                    .expect("최소 UPDATE 응답은 TSIG 서명 전에 항상 인코딩 가능");
            }
            Some(m)
        };

        let zq = request.questions.first();
        let Some(zq) = zq.filter(|q| q.qtype == ApRt::SOA) else {
            return reply(ResponseCode::FormErr.0);
        };
        let Some(store_swap) = self.xfr_store.as_ref() else {
            return reply(9);
        };
        if zq.qclass != DnsClass::IN {
            return reply(9);
        }
        if !authority
            .update_zones
            .iter()
            .any(|origin| origin.eq_ignore_case(&zq.name))
        {
            return reply(9);
        }

        let mut journals = self.journal.lock_recover();
        let store = store_swap.load();
        let Some(zone) = store
            .zones()
            .iter()
            .find(|z| z.origin().eq_ignore_case(&zq.name))
        else {
            return reply(9);
        };

        let mut recs = zone.axfr_records();
        recs.pop();
        let old_recs = recs.clone();
        let old_serial = zone.soa().serial;

        let mut present_names = std::collections::HashSet::new();
        let mut present_sets: std::collections::HashMap<(Vec<u8>, u16), Vec<Vec<u8>>> =
            std::collections::HashMap::new();
        for record in &recs {
            let name = record.name.canonical_key();
            present_names.insert(name.clone());
            present_sets
                .entry((name, record.rtype.0))
                .or_default()
                .push(update_rdata_key(record));
        }
        for values in present_sets.values_mut() {
            values.sort_unstable();
            values.dedup();
        }
        let mut prerequisite_classes = std::collections::HashMap::new();
        let mut required_sets: std::collections::HashMap<(Vec<u8>, u16), Vec<Vec<u8>>> =
            std::collections::HashMap::new();

        for p in &request.answers {
            // RFC 2136 의사코드는 TTL 을 영역 범위보다 먼저 본다. 둘 다 어긋난 요청에
            // 어느 오류를 낼지가 여기서 갈린다.
            if p.ttl != 0 {
                return reply(ResponseCode::FormErr.0);
            }
            if !zone.contains(&p.name) {
                return reply(10);
            }
            if prohibited_update_type(p.rtype) {
                return reply(ResponseCode::FormErr.0);
            }
            if matches!(p.class.0, 254 | 255) && !update_rdata_is_empty(p) {
                return reply(ResponseCode::FormErr.0);
            }
            if p.class == DnsClass::IN && (p.rtype == ApRt(255) || p.rdata.record_type() != p.rtype)
            {
                return reply(ResponseCode::FormErr.0);
            }
            let name = p.name.canonical_key();
            let key = (name.clone(), p.rtype.0);
            if prerequisite_classes
                .insert(key.clone(), p.class.0)
                .is_some_and(|class| class != p.class.0)
            {
                return reply(ResponseCode::FormErr.0);
            }
            let exists_name = present_names.contains(&name);
            let exists_type = present_sets.contains_key(&key);
            match p.class.0 {
                255 if p.rtype == ApRt(255) => {
                    if !exists_name {
                        return reply(ResponseCode::NXDomain.0);
                    }
                }
                255 => {
                    if !exists_type {
                        return reply(8);
                    }
                }
                254 if p.rtype == ApRt(255) => {
                    if exists_name {
                        return reply(6);
                    }
                }
                254 => {
                    if exists_type {
                        return reply(7);
                    }
                }
                1 => {
                    required_sets
                        .entry(key)
                        .or_default()
                        .push(update_rdata_key(p));
                }
                _ => return reply(ResponseCode::FormErr.0),
            }
        }
        for (key, required) in &mut required_sets {
            required.sort_unstable();
            required.dedup();
            if present_sets.get(key) != Some(required) {
                return reply(8);
            }
        }

        let apex = zone.origin().clone();

        for u in &request.authorities {
            if !zone.contains(&u.name) {
                return reply(10);
            }
            if prohibited_update_type(u.rtype) {
                return reply(ResponseCode::FormErr.0);
            }
            match u.class.0 {
                1 if u.rtype != ApRt(255)
                    && !update_rdata_is_empty(u)
                    && u.rdata.record_type() == u.rtype => {}
                255 if u.ttl == 0 && update_rdata_is_empty(u) => {}
                254 if u.ttl == 0
                    && u.rtype != ApRt(255)
                    && !update_rdata_is_empty(u)
                    && u.rdata.record_type() == u.rtype => {}
                _ => return reply(ResponseCode::FormErr.0),
            }
        }

        if !authority.update_policy.is_empty() {
            let identity = tsig_ctx.as_ref().map(|(k, _)| &k.name);
            for u in &request.authorities {
                if u.rtype == ApRt::SOA {
                    continue;
                }
                if !update_granted(&authority.update_policy, identity, &u.name, u.rtype.0) {
                    self.rec(client, Action::Refused, Some(&u.name), Some(u.rtype));
                    return reply(ResponseCode::Refused.0);
                }
            }
        }

        for u in &request.authorities {
            match u.class.0 {
                1 => {
                    // CNAME 은 다른 데이터와 공존하지 못한다. 어느 방향이든 이 갱신 RR
                    // 하나만 건너뛴다. 메시지 전체를 실패로 돌리면 함께 온 멀쩡한 갱신까지
                    // 잃고, RFC 2136은 남은 RR 을 마저 처리한 뒤 NOERROR 를 낸다.
                    let conflicting_cname = if u.rtype == ApRt::CNAME {
                        recs.iter()
                            .any(|r| r.name.eq_ignore_case(&u.name) && r.rtype != ApRt::CNAME)
                    } else {
                        recs.iter()
                            .any(|r| r.name.eq_ignore_case(&u.name) && r.rtype == ApRt::CNAME)
                    };
                    if conflicting_cname {
                        continue;
                    }
                    if u.rtype == ApRt::SOA && !soa_update_moves_forward(&recs, u) {
                        continue;
                    }
                    if let Some(ex) = recs.iter_mut().find(|r| {
                        r.name.eq_ignore_case(&u.name)
                            && r.rtype == u.rtype
                            && update_replaces(u, r)
                    }) {
                        *ex = u.clone();
                    } else {
                        recs.push(u.clone());
                    }
                }
                255 if u.rtype == ApRt(255) => {
                    recs.retain(|r| {
                        !r.name.eq_ignore_case(&u.name)
                            || (r.name.eq_ignore_case(&apex)
                                && (r.rtype == ApRt::SOA || r.rtype == ApRt::NS))
                    });
                }
                255 => {
                    if u.name.eq_ignore_case(&apex) && (u.rtype == ApRt::SOA || u.rtype == ApRt::NS)
                    {
                        continue;
                    }
                    recs.retain(|r| !(r.name.eq_ignore_case(&u.name) && r.rtype == u.rtype));
                }
                254 => {
                    if u.rtype == ApRt::SOA {
                        continue;
                    }
                    // 정점의 마지막 NS 를 지우면 영역에 권한 서버가 없어지므로 RFC 2136
                    // 3.4.2.4 가 이 RR 만 건너뛰라고 한다. 정점이 아닌 NS 는 위임이라
                    // 마지막 하나를 지우는 것이 위임을 걷는 정상 동작이다.
                    if u.rtype == ApRt::NS
                        && u.name.eq_ignore_case(&apex)
                        && !recs.iter().any(|r| {
                            r.name.eq_ignore_case(&apex)
                                && r.rtype == ApRt::NS
                                && r.rdata != u.rdata
                        })
                    {
                        continue;
                    }
                    recs.retain(|r| {
                        !(r.name.eq_ignore_case(&u.name)
                            && r.rtype == u.rtype
                            && r.rdata == u.rdata)
                    });
                }
                _ => return reply(ResponseCode::FormErr.0),
            }
        }

        if recs == old_recs {
            self.rec(client, Action::Resolved, Some(&zq.name), Some(ApRt::SOA));
            return reply(ResponseCode::NoError.0);
        }

        // RFC 2136은 갱신이 일련번호를 스스로 바꾸지 않았을 때만 서버가 올리라고 한다.
        // 갱신이 지정한 값 위에 하나를 더 얹으면 요청자가 적어 준 값이 영역에 남지 않는다.
        if soa_serial_of(&recs) == Some(old_serial) {
            if let Some(soa_rec) = recs.iter_mut().find(|r| r.rtype == ApRt::SOA) {
                if let ApRData::Soa(s) = &mut soa_rec.rdata {
                    s.serial = s.serial.wrapping_add(1);
                }
            }
        }

        if let Some((_, ctx)) = authority
            .zone_signers
            .iter()
            .find(|(o, _)| o.eq_ignore_case(&apex))
        {
            recs = ctx.sign(&recs);
        }
        let new_zone = match onetdns_authority::Zone::from_records(recs) {
            Ok(z) => z,
            Err(error) => {
                onetdns_core::error!(event = "authority.ddns_zone_invalid", zone = %apex.to_ascii_lower(), %error, "동적 DNS 갱신을 적용하면 영역이 어긋나 변경을 버렸습니다");
                return reply(ResponseCode::ServFail.0);
            }
        };

        if let Some((_, path)) = authority
            .zone_files
            .iter()
            .find(|(o, _)| o.eq_ignore_case(&apex))
        {
            if let Err(error) = crate::atomic_write(path, new_zone.to_master_file().as_bytes()) {
                onetdns_core::error!(event = "authority.ddns_save_failed", zone = %apex.to_ascii_lower(), path = %path.display(), %error,
                    "동적 DNS 갱신을 저장하지 못해 변경을 되돌렸습니다");
                return reply(ResponseCode::ServFail.0);
            }
        }

        let mut new_recs = new_zone.axfr_records();
        new_recs.pop();
        let new_serial = new_zone.soa().serial;
        store_swap.update(|current| {
            let mut next = onetdns_authority::ZoneStore::new();
            for zone in current.zones() {
                if !zone.origin().eq_ignore_case(&apex) {
                    next.add(zone.clone());
                }
            }
            next.add(new_zone);
            next
        });
        journals
            .entry(apex.canonical_key())
            .or_default()
            .record(old_serial, new_serial, &old_recs, &new_recs);
        drop(journals);
        if let Some(notify) = &self.update_notify {
            notify(&apex, new_serial);
        }
        onetdns_core::info!(event = "authority.ddns_applied", zone = %apex.to_ascii_lower(), src = %ctx.src, "동적 DNS 갱신을 적용하고 일련번호를 올렸습니다");

        self.rec(client, Action::Resolved, Some(&zq.name), Some(ApRt::SOA));
        reply(ResponseCode::NoError.0)
    }
}

impl Handler for NativeServer {
    /** @brief 질의 하나를 처리한다. */
    fn handle(&self, request: &Message, ctx: &RequestCtx) -> Option<Message> {
        let timer = onetdns_control::RequestTimer::start();
        let ordinary_query = request.header.opcode == 0
            && request
                .questions
                .first()
                .is_none_or(|question| question.qtype != ApRt(251) && question.qtype != ApRt(252));
        let query_tsig = if ordinary_query && onetdns_dnssec::tsig::contains_tsig(request) {
            match self.check_tsig(request, ctx.raw, false, false) {
                Ok(context) => context,
                Err(response) => return Some(response),
            }
        } else {
            None
        };
        let mut resp = self.handle_inner(request, ctx)?;
        let features = self.features.load();
        if let Err(error) = postprocess(&features, &mut resp, request, ctx) {
            onetdns_core::error!(event = "dns.response_postprocess_failed", %error,
                "응답의 EDNS 후처리에 실패해 SERVFAIL로 교체합니다");
            resp = error_resp(request, ResponseCode::ServFail);
        }
        if let Some((key, request_tsig)) = query_tsig {
            resp.additionals.retain(|record| record.rtype != ApRt(250));
            if onetdns_dnssec::tsig::sign_response_message(
                &mut resp,
                &key,
                now_unix(),
                &request_tsig,
            )
            .is_err()
            {
                resp = error_resp(request, ResponseCode::ServFail);
                onetdns_dnssec::tsig::sign_response_message(
                    &mut resp,
                    &key,
                    now_unix(),
                    &request_tsig,
                )
                .expect("최소 SERVFAIL은 TSIG 서명 전에 항상 인코딩 가능");
            }
        }
        if features.events().is_some() {
            let client = self.identify(ctx);
            self.rec_latency(
                &features,
                &client,
                request.questions.first().map(|q| &q.name),
                timer.elapsed_us(),
            );
        }

        if let Some(dt) = &features.dnstap {
            let proto = dnstap_proto(ctx.transport);
            if let Ok(wire) = resp.try_encode() {
                dt.log_client_response(ctx.src, proto, SystemTime::now(), &wire);
            }
        }
        Some(resp)
    }

    /** @brief 파싱하기 전에 빠른 경로로 답할 수 있는지 본다. 못 하면 보통 경로로 보낸다. */
    fn handle_udp_wire(
        &self,
        packet: &[u8],
        ctx: &RequestCtx,
        out: &mut onetdns_proto::Writer,
        now: std::time::Instant,
    ) -> onetdns_runtime::WireDisposition {
        let authority = self.authority_wire_dispatch(packet, ctx, out);
        if authority != onetdns_runtime::WireDisposition::Fallback {
            return authority;
        }
        self.wire_dispatch(packet, ctx, out, now, false)
    }

    /** @brief 파싱하기 전에 권한 영역 빠른 경로로 답할 수 있는지 본다. */
    fn handle_tcp_wire(
        &self,
        packet: &[u8],
        ctx: &RequestCtx,
        out: &mut onetdns_proto::Writer,
        _now: std::time::Instant,
    ) -> onetdns_runtime::WireDisposition {
        self.authority_wire_dispatch(packet, ctx, out)
    }

    /** @brief 이미 인코딩해 둔 응답을 그대로 내보낸다. */
    fn handle_preencoded_stream(
        &self,
        request: &Message,
        ctx: &RequestCtx,
        out: &mut onetdns_proto::Writer,
        emit: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Option<bool> {
        self.handle_cached_axfr_wire(request, ctx, out, emit)
    }

    #[cfg(unix)]
    /** @brief 레인이 이미 캐시에 넣은 답을 빠른 경로로 내보낸다. */
    fn handle_udp_wire_hit(
        &self,
        packet: &[u8],
        ctx: &RequestCtx,
        out: &mut onetdns_proto::Writer,
        now: std::time::Instant,
    ) -> onetdns_runtime::WireDisposition {
        self.wire_dispatch(packet, ctx, out, now, true)
    }
    #[cfg(unix)]
    /** @brief 레인이 붙어 있는지. */
    fn reactor_active(&self) -> bool {
        self.reactor_lane.is_some()
            && (self.lane_switch.reactor()
                || LANE.with(|slot| {
                    slot.borrow()
                        .as_ref()
                        .is_some_and(|state| !state.clients.is_empty())
                }))
    }

    #[cfg(unix)]
    /** @brief 레인에 더 맡길 슬롯이 있는지. */
    fn reactor_has_capacity(&self) -> bool {
        let Some(lane) = &self.reactor_lane else {
            return false;
        };
        LANE.with(|slot| {
            slot.borrow()
                .as_ref()
                .is_none_or(|st| st.reactor.live() < lane.inflight)
        })
    }

    #[cfg(unix)]
    /** @brief 다음 데드라인까지 기다릴 밀리초. */
    fn reactor_deadline_ms(&self, now: std::time::Instant) -> i32 {
        LANE.with(|slot| {
            slot.borrow()
                .as_ref()
                .and_then(|st| st.reactor.next_deadline_in(now))
                .map(|d| (d.as_millis() as i32).clamp(1, 50))
                .unwrap_or(50)
        })
    }

    #[cfg(unix)]
    /** @brief 레인이 지켜보는 소켓들을 모은다. */
    fn reactor_collect(&self, fds: &mut Vec<libc::pollfd>, map: &mut Vec<usize>) {
        LANE.with(|slot| {
            if let Some(st) = slot.borrow().as_ref() {
                st.reactor.collect_pollfds(fds, map);
            }
        })
    }

    #[cfg(unix)]
    /**
     * @brief 이 질의를 레인에 맡긴다.
     * @warning 응답을 달라지게 하는 기능이 켜져 있으면 맡기지 않는다. 레인은 그 처리를
     *          하지 않으므로 맡기면 그 기능이 없는 것처럼 답이 나간다.
     */
    fn reactor_submit(
        &self,
        packet: &[u8],
        ctx: &RequestCtx,
        out: &mut onetdns_proto::Writer,
        now: std::time::Instant,
    ) -> onetdns_runtime::ReactorDisposition {
        use onetdns_recurse::reactor::SubmitOutcome;
        use onetdns_runtime::ReactorDisposition as R;
        let Some(lane) = &self.reactor_lane else {
            return R::Fallback;
        };
        if !self.lane_switch.reactor() {
            return R::Fallback;
        }
        let f = self.features.load();
        let Some(runtime) = f
            .lane_runtime
            .as_ref()
            .filter(|runtime| runtime.recursor.is_some())
            .cloned()
        else {
            return R::Fallback;
        };
        if f.dns64_prefix.is_some()
            || f.rrset_roundrobin
            || f.cookies.strict
            || f.dnstap.is_some()
            || f.domain_needed
            || f.bogus_priv
            || f.empty_zones
            || f.block_aaaa
            || f.padding_block > 0
            || self.views.present()
            || self.policy.present()
            || f.safe_search.load(Ordering::Relaxed)
            || f.rebind_protection
            || !f.bogus_nxdomain.is_empty()
            || !f.recurse_deny_answers.is_empty()
        {
            return R::Fallback;
        }
        if f.harden_large_queries && packet.len() > MAX_LARGE_QUERY_BYTES {
            return R::Fallback;
        }
        let Ok(request) = Message::parse(packet) else {
            return R::Fallback;
        };
        if request.header.opcode != 0 || request.questions.len() != 1 {
            return R::Fallback;
        }
        // lenient는 쿠키 없는 질의만 이 레인에 맡긴다. COOKIE 질의는 정상 경로가 서버
        // 쿠키를 발급·검증해야 하므로, 여기서 답하면 보안 기능이 없는 것처럼 보인다.
        if f.cookies.keeper.is_some() && read_cookie(&request).is_some() {
            return R::Fallback;
        }
        // 이 레인은 handle_inner 를 거치지 않으므로 거기 있는 EDNS 버전 협상도 돌지 않는다.
        // 모르는 버전에는 RFC 6891이 BADVERS 를 요구하는데, 여기서 맡으면 답까지
        // 담아 보내 이 서버가 그 버전을 구현한다고 알리게 된다.
        if request
            .opt()
            .and_then(Edns::from_record)
            .is_some_and(|edns| edns.version != 0)
        {
            return R::Fallback;
        }
        if onetdns_dnssec::tsig::peek_key_name(&request).is_some() {
            return R::Fallback;
        }
        if f.ddr_enabled && ddr_owner(&request.questions[0].name) {
            return R::Fallback;
        }
        let qtype = request.questions[0].qtype;
        if qtype == ApRt(251) || qtype == ApRt(252) {
            return R::Fallback;
        }
        let client = self.identify_with(ctx, &f);
        if self.acl.check(&client) == AclDecision::Deny {
            return R::Fallback;
        }
        let filter = self.filter.load();

        if filter.has_rpz_ns() || filter.has_rpz_ip() {
            return R::Fallback;
        }
        if !filter.is_trivially_allow() {
            if filter.client_safe_search(&client).unwrap_or(false) {
                return R::Fallback;
            }
            if !matches!(
                filter.verdict(&request.questions[0].name, qtype, &client),
                FilterVerdict::Allow
            ) {
                return R::Fallback;
            }
        }

        if let Some(mut resp) = runtime
            .cache
            .lane_response(&request)
            .or_else(|| runtime.cache.lane_failure(&request))
        {
            if !filter.is_trivially_allow()
                && Self::cname_uncloak(&filter, &resp.answers, &client).is_some()
            {
                return R::Fallback;
            }
            reactor_response_edns(&f, &mut resp, &request);
            if postprocess(&f, &mut resp, &request, ctx).is_err() {
                return R::Fallback;
            }
            onetdns_runtime::encode_limited(&request, &resp, out);
            if out.buf.is_empty() {
                return R::Fallback;
            }

            for limiter in &self.rate_limiters {
                if limiter.check(&client) == RateDecision::Throttle {
                    out.clear();
                    return R::Fallback;
                }
            }

            if let Some(recorder) = f.events() {
                recorder.record_cache(true);
                onetdns_forward::note_response_source("캐시");
                let timer = onetdns_control::RequestTimer::start();
                let qname = &request.questions[0].name;
                self.rec_final_answer(&f, &client, qname, qtype, &resp);
                self.rec_latency(&f, &client, Some(qname), timer.elapsed_us());
            }
            return R::Respond;
        }

        for limiter in &self.rate_limiters {
            if limiter.check(&client) == RateDecision::Throttle {
                return R::Fallback;
            }
        }
        let qname = request.questions[0].name.clone();
        LANE.with(|slot| {
            let mut st = slot.borrow_mut();
            if st.as_ref().is_some_and(|state| {
                !Arc::ptr_eq(&state.runtime, &runtime) && !state.clients.is_empty()
            }) {
                return R::Fallback;
            }
            if st
                .as_ref()
                .is_some_and(|state| !Arc::ptr_eq(&state.runtime, &runtime))
            {
                *st = None;
            }
            let st = st.get_or_insert_with(|| LaneState::new(lane.chain.clone(), runtime.clone()));
            let token = st.next;
            match st.reactor.submit(
                runtime
                    .recursor
                    .as_ref()
                    .expect("재귀 리졸버가 있는 세대만 위에서 통과했습니다"),
                qname,
                qtype,
                token,
                now,
                request.header.checking_disabled,
            ) {
                SubmitOutcome::Accepted | SubmitOutcome::Merged => {
                    st.next = st.next.wrapping_add(1);
                    if let Some(recorder) = f.events() {
                        recorder.record_cache(false);
                    }
                    st.clients.insert(
                        token,
                        LaneClient {
                            src: ctx.src,
                            raw: packet.to_vec(),
                            request,
                            client,
                            submitted: now,
                        },
                    );
                    R::Submitted
                }
                SubmitOutcome::Rejected | SubmitOutcome::Failed => R::Fallback,
            }
        })
    }

    #[cfg(unix)]
    /** @brief 준비된 소켓을 읽어 레인을 진행한다. */
    fn reactor_pump(
        &self,
        fds: &[libc::pollfd],
        base: usize,
        map: &[usize],
        now: std::time::Instant,
        out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
    ) {
        let Some(_lane) = &self.reactor_lane else {
            return;
        };
        LANE.with(|slot| {
            let mut st = slot.borrow_mut();
            let Some(st) = st.as_mut() else { return };
            let mut comps = Vec::new();
            st.reactor.pump(
                st.runtime
                    .recursor
                    .as_ref()
                    .expect("진행 중인 레인 세대에는 재귀 리졸버가 있습니다"),
                fds,
                base,
                map,
                now,
                &mut comps,
            );
            self.lane_drain_fallback(st, out);
            self.lane_finish(st, comps, out);
        })
    }

    #[cfg(unix)]
    /** @brief 데드라인이 지난 것을 처리한다. */
    fn reactor_tick(
        &self,
        now: std::time::Instant,
        out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
    ) {
        let Some(_lane) = &self.reactor_lane else {
            return;
        };
        LANE.with(|slot| {
            let mut st = slot.borrow_mut();
            let Some(st) = st.as_mut() else { return };
            let mut comps = Vec::new();
            st.reactor.on_tick(
                st.runtime
                    .recursor
                    .as_ref()
                    .expect("진행 중인 레인 세대에는 재귀 리졸버가 있습니다"),
                now,
                &mut comps,
            );
            self.lane_drain_fallback(st, out);
            self.lane_finish(st, comps, out);
        })
    }

    /** @brief 응답이 여럿인 질의를 처리한다. */
    fn handle_multi(&self, request: &Message, ctx: &RequestCtx) -> Option<Vec<Message>> {
        let mut responses = Vec::new();
        self.emit_responses(request, ctx, &mut |message| {
            responses.push(message);
            true
        })?;
        Some(responses)
    }

    /**
     * @brief 파싱하지 못한 질의에 FORMERR로 답한다.
     *
     * @details 버리면 클라이언트는 데드라인을 다 기다린 뒤 재시도한다. 응답은 머리말뿐이라
     *          질의보다 크지 않으므로 증폭이 되지 않는다. 파싱 전이라 일반 경로를 지나오지
     *          못했으므로 접근 제어와 속도 제한을 여기서 본다.
     */
    fn handle_unparsable(&self, packet: &[u8], ctx: &RequestCtx) -> Option<Message> {
        if !self.client_allowed(ctx) {
            return None;
        }
        let flags = u16::from_be_bytes([packet[2], packet[3]]);
        let mut response = Message::default();
        response.header.id = u16::from_be_bytes([packet[0], packet[1]]);
        response.header.response = true;
        response.header.opcode = ((flags >> 11) & 0xF) as u8;
        response.header.recursion_desired = flags & 0x0100 != 0;
        response.header.recursion_available = true;
        response.header.rcode = ResponseCode::FormErr.0;
        onetdns_core::debug!(
            event = "dns.unparsable_query",
            client = %ctx.src.ip(),
            bytes = packet.len(),
            "질의를 읽지 못해 FORMERR로 답했습니다"
        );
        Some(response)
    }

    /** @brief 스트림 전송의 질의를 처리한다. */
    fn handle_stream(
        &self,
        request: &Message,
        ctx: &RequestCtx,
        emit: &mut dyn FnMut(&Message) -> bool,
    ) -> bool {
        self.emit_responses(request, ctx, &mut |message| emit(&message))
            .is_some()
    }
}

#[cfg(unix)]
/** @brief 이 스레드의 레인 상태. */
struct LaneState {
    /** @brief 이 상태 기계가 시작할 때 잡은 캐시·재귀 리졸버 세대. */
    runtime: Arc<LaneRuntime>,
    /** @brief 재귀를 돌리는 상태 기계. */
    reactor: onetdns_recurse::reactor::Reactor,
    /** @brief 답을 기다리는 클라이언트들. */
    clients: std::collections::HashMap<u64, LaneClient>,
    /** @brief 다음에 줄 질의 번호. */
    next: u64,

    /** @brief 레인이 끝내지 못한 것을 마저 푸는 곳. */
    fallback: LaneFallback,
}

#[cfg(unix)]
/** @brief 레인이 끝내지 못한 것을 보통 체인으로 마저 푸는 곳. 안 그러면 그 질의만 답을 못 받는다. */
struct LaneFallback {
    /** @brief 마저 풀 일을 맡기는 곳. */
    jobs: std::sync::mpsc::Sender<(u64, Message, ClientInfo)>,
    /**
     * @brief 마저 푼 결과들.
     * @details 실패도 종류를 담아 돌려준다. 없음으로 접으면 영구 실패까지 전송 실패로 보여
     *          클라이언트가 잘못된 사유를 받는다.
     */
    done: LaneFallbackResults,
}

#[cfg(unix)]
/** @brief 대체 처리가 끝낸 질의 번호와 그 결과. */
type LaneFallbackResults = Arc<std::sync::Mutex<Vec<(u64, Result<Message, ResolveFailure>)>>>;

#[cfg(unix)]
impl LaneFallback {
    /** @brief 체인을 잡고 워커를 시작한다. */
    fn new(chain: Arc<dyn Resolver>) -> Self {
        let (jobs, rx) = std::sync::mpsc::channel::<(u64, Message, ClientInfo)>();
        let done: LaneFallbackResults = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = done.clone();

        if let Err(error) = std::thread::Builder::new()
            .name("onetdns-lane-fallback".into())
            .spawn(move || {
                while let Ok((token, request, client)) = rx.recv() {
                    let answer = onetdns_core::isolation::catch_request(|| {
                        chain_resolve(&chain, &request, &client)
                    })
                    .unwrap_or(Err(ResolveFailure::Permanent(None)));
                    sink.lock_recover().push((token, answer));
                }
            })
        {
            onetdns_core::error!(event = "reactor.fallback_worker_start_failed", %error, "리액터의 대체 처리 스레드를 시작하지 못했습니다. 레인이 풀지 못한 질의는 수신 루프에서 바로 처리됩니다");
            return Self {
                jobs,
                done: Arc::new(std::sync::Mutex::new(Vec::new())),
            };
        }
        Self { jobs, done }
    }

    /** @brief 마저 푼 것들을 가져간다. */
    fn take_done(&self) -> Vec<(u64, Result<Message, ResolveFailure>)> {
        let mut slot = self.done.lock_recover();
        if slot.is_empty() {
            return Vec::new();
        }
        std::mem::take(&mut slot)
    }
}

#[cfg(unix)]
/** @brief 체인으로 해석한다. */
fn chain_resolve(
    chain: &Arc<dyn Resolver>,
    request: &Message,
    _client: &ClientInfo,
) -> Result<Message, ResolveFailure> {
    match chain.resolve_outcome(request) {
        ResolveOutcome::Response(response) => Ok(response),
        ResolveOutcome::Failure(failure) => Err(failure),
    }
}

#[cfg(unix)]
/** @brief 레인에 맡긴 질의 하나와 그것을 보낸 클라이언트. */
struct LaneClient {
    /** @brief 이 질의를 보낸 곳. */
    src: std::net::SocketAddr,

    /** @brief 받은 그대로의 바이트. */
    raw: Vec<u8>,
    /** @brief 읽어 낸 질의. */
    request: Message,
    /** @brief 알아본 클라이언트. */
    client: ClientInfo,

    /** @brief 레인에 맡긴 시각. */
    submitted: std::time::Instant,
}

#[cfg(unix)]
impl LaneState {
    /** @brief 이 스레드의 레인을 연다. 마저 풀 곳도 함께 만든다. */
    fn new(chain: Arc<dyn Resolver>, runtime: Arc<LaneRuntime>) -> Self {
        Self {
            runtime,
            reactor: onetdns_recurse::reactor::Reactor::new(
                onetdns_recurse::reactor::ReactorConfig::default(),
            ),
            clients: std::collections::HashMap::new(),
            next: 0,
            fallback: LaneFallback::new(chain),
        }
    }
}

#[cfg(unix)]
thread_local! {
    /** @brief 이 스레드의 레인. 스레드마다 따로 둔다. */
    static LANE: std::cell::RefCell<Option<LaneState>> = const { std::cell::RefCell::new(None) };
}

impl NativeServer {
    /**
     * @brief 이 클라이언트에게 답해도 되는지.
     *
     * @details 질의를 해석하기 전에 답을 내보내는 경로들이 쓴다. 파이프라인을 타지 않는
     *          응답도 접근 제어와 속도 제한 뒤에 있어야 한다. 그렇지 않으면 그 경로만
     *          누구에게나 열린 증폭기가 된다.
     */
    pub fn client_allowed(&self, ctx: &RequestCtx) -> bool {
        let features = self.features.load();
        let client = self.identify_with(ctx, &features);
        if self.acl.check(&client) == AclDecision::Deny {
            return false;
        }
        !self
            .rate_limiters
            .iter()
            .any(|limiter| limiter.check(&client) == RateDecision::Throttle)
    }

    /** @brief 내보낸 응답을 빠른 경로가 다시 쓸 수 있게 담아 둔다. 담을 수 없는 응답이면 담지 않는다. */
    fn store_wire_response(
        &self,
        runtime: &LaneRuntime,
        key: &[u8],
        response_wire: &[u8],
        filter_tag: usize,
        answers_summary: String,
        now: std::time::Instant,
    ) {
        let Some(factory) = runtime.factory.as_ref() else {
            return;
        };
        let Some(candidate) = runtime.cache.wire_candidate(key, now) else {
            return;
        };
        let entry = if candidate.has_fixed_local_ttl() {
            factory.prepare_fixed(response_wire, filter_tag, answers_summary, now)
        } else {
            factory.prepare(
                response_wire,
                filter_tag,
                answers_summary,
                now,
                candidate.lifetime_secs(),
            )
        };
        let Some(entry) = entry else {
            return;
        };
        runtime.cache.promote_wire(key, &candidate, entry);
    }

    /**
     * @brief 이 서버의 권한 영역의 단순 질의를 조립 없이 내보낸다.
     * @warning 조금이라도 응답이 달라질 여지가 있으면 보통 경로로 보낸다. 위임, 서명 요구,
     *          부가 옵션, 기록을 남겨야 하는 기능이 모두 그렇다.
     */
    fn authority_wire_dispatch(
        &self,
        packet: &[u8],
        ctx: &RequestCtx,
        out: &mut onetdns_proto::Writer,
    ) -> onetdns_runtime::WireDisposition {
        use onetdns_runtime::WireDisposition as Wire;

        let Some(path) = &self.authority_wire_path else {
            return Wire::Fallback;
        };
        if !self.lane_switch.authority() {
            return Wire::Fallback;
        }

        if self.features.authority_wire_blocked()
            || self.views.present()
            || self.policy.present()
            || self.features.safe_search_enabled()
            || (self.features.harden_large_queries() && packet.len() > MAX_LARGE_QUERY_BYTES)
        {
            return Wire::Fallback;
        }
        let Some(scanned) = crate::wirecache::scan_query(packet) else {
            return Wire::Fallback;
        };
        let ddr_features = if scanned.canonical_qname() == DDR_OWNER_WIRE {
            let features = self.features.load();
            if features.ddr_enabled {
                return Wire::Fallback;
            }
            Some(features)
        } else {
            None
        };
        if !matches!(scanned.qtype, 1 | 28) {
            return Wire::Fallback;
        }
        // 질의 뒤에 아무것도 없거나, 옵션 없는 OPT 하나만 붙은 것만 맡는다. 옵션이 있거나
        // DO가 켜져 있으면 응답에 담을 것이 생기고, 알린 크기가 이 서버의 상한보다 작으면 절단
        // 사다리가 필요하므로 전부 구조적 경로로 보낸다.
        let bare_len = 12 + scanned.qname.len() + 4;
        let edns = match &scanned.edns {
            None => {
                if packet.len() != bare_len {
                    return Wire::Fallback;
                }
                None
            }
            Some(edns) => {
                if edns.dnssec_ok
                    || edns.has_options
                    || edns.udp_payload < SERVER_UDP_MAX
                    || packet.len() != bare_len + EMPTY_OPT_WIRE_LEN
                {
                    return Wire::Fallback;
                }
                Some(advertised_udp_payload(self.features.edns_buffer()))
            }
        };
        if self.filter.wire_blocked() {
            return Wire::Fallback;
        }
        // DDR 이름이면 위에서 이미 잡은 같은 세대를 재사용한다. 보통 이름은 모든 조기
        // fallback을 지난 뒤에만 snapshot을 잡아, 맡지 않을 질의에 새 lock 비용을 붙이지 않는다.
        let features = ddr_features.unwrap_or_else(|| self.features.load());
        let acl_trivially_allows = self.acl.is_trivially_allow();
        let rate_limiters_active = self.rate_limiters.iter().any(|limiter| limiter.is_active());
        let client = (!acl_trivially_allows || rate_limiters_active)
            .then(|| self.identify_with(ctx, &features));
        if !acl_trivially_allows
            && self
                .acl
                .check(client.as_ref().expect("non-trivial ACL needs client"))
                == AclDecision::Deny
        {
            return Wire::Fallback;
        }
        let id = u16::from_be_bytes(scanned.id);
        let recursion_desired = packet[2] & 0x01 != 0;
        let request_flags = (u16::from(recursion_desired) << 8)
            | (u16::from(path.recursion_available) << 7)
            | u16::from(packet[3] & 0x10);
        out.clear();
        let simple = onetdns_authority::SimpleRequest {
            original_qname: scanned.qname,
            qtype: ApRt(scanned.qtype),
            id,
            request_flags,
            edns,
        };
        if !path
            .store
            .load()
            .write_simple_response(scanned.canonical_qname(), &simple, out)
        {
            return Wire::Fallback;
        }
        // EDNS 를 쓰지 않은 UDP 질의의 상한은 RFC 1035 의 512바이트다. 이 경로에는
        // 절단 사다리가 없으므로 넘으면 구조적 경로로 전환한다. TCP 에는 이 상한이 없다.
        if edns.is_none()
            && ctx.transport == RtTransport::Do53Udp
            && out.buf.len() > onetdns_runtime::NON_EDNS_UDP_MAX
        {
            out.clear();
            return Wire::Fallback;
        }
        for limiter in self
            .rate_limiters
            .iter()
            .filter(|limiter| limiter.is_active())
        {
            // 위에서 꺼져 있다고 본 뒤 제한기가 켜졌으면 클라이언트를 만들지 않았다. 제한을
            // 건너뛰지 않고 보통 경로로 전환한다. 고속 경로는 언제 일반 경로로 넘겨도 정답이다.
            let Some(client) = client.as_ref() else {
                out.clear();
                return Wire::Fallback;
            };
            if limiter.check(client) == RateDecision::Throttle {
                out.clear();
                return Wire::Fallback;
            }
        }
        self.record_authority_wire(&features, ctx, &scanned, client, out);
        Wire::Respond
    }

    /**
     * @brief 무할당 경로로 답한 질의를 지표에 남긴다.
     *
     * @details 이 경로가 기록하지 못하던 시절에는 기록기가 있다는 것만으로 경로를 닫았다.
     *          컨트롤 플레인을 수신 주소 없이도 만들어 두게 된 뒤로는 그 조건이 언제나 참이라 경로가
     *          전부 죽는다. 응답 코드는 방금 쓴 와이어의 헤더에서 그대로 읽어 구조적
     *          경로와 같은 값을 남긴다.
     * @param features 접근 제어·DDR 판정과 함께 잡은 질의 세대 snapshot.
     * @param client 접근 제어나 제한기 때문에 이미 만들어 둔 것이 있으면 다시 만들지 않는다.
     */
    fn record_authority_wire(
        &self,
        features: &NativeFeatures,
        ctx: &RequestCtx,
        scanned: &crate::wirecache::ScannedQuery<'_>,
        client: Option<ClientInfo>,
        out: &onetdns_proto::Writer,
    ) {
        let Some(recorder) = features.events() else {
            return;
        };
        let Some(flags) = out.buf.get(3) else {
            return;
        };
        let rcode = ResponseCode(u16::from(flags & 0x0f));
        let client = match client {
            Some(client) => client,
            None => self.identify_with(ctx, features),
        };
        let qname = ApName::from_uncompressed_wire(scanned.qname);
        let (log, stat) = self.filter.load().client_log_stat(&client);
        self.rec_rc_diag_with(
            recorder,
            &client,
            Action::Resolved,
            qname.as_ref(),
            Some(ApRt(scanned.qtype)),
            rcode,
            "",
            "",
            "",
            log,
            stat,
            None,
        );
    }

    /**
     * @brief 캐시가 맞은 UDP 질의를 파싱 없이 내보낸다.
     * @warning 맞았더라도 접근 제어·속도 제한·차단은 지금 세대로 다시 본다. 통과하지 못하면
     *          보통 경로로 보낸다.
     */
    fn wire_dispatch(
        &self,
        packet: &[u8],
        ctx: &RequestCtx,
        out: &mut onetdns_proto::Writer,
        now: std::time::Instant,
        hit_only: bool,
    ) -> onetdns_runtime::WireDisposition {
        use onetdns_runtime::WireDisposition as Wire;
        if !self.lane_switch.wire() {
            return Wire::Fallback;
        }
        let f = self.features.load();
        let Some(runtime) = f
            .lane_runtime
            .as_ref()
            .filter(|runtime| runtime.factory.is_some())
        else {
            return Wire::Fallback;
        };

        if f.dns64_prefix.is_some()
            || f.rrset_roundrobin
            || f.cookies.strict
            || f.dnstap.is_some()
            || f.domain_needed
            || f.bogus_priv
            || f.empty_zones
            || f.block_aaaa
            || f.padding_block > 0
            || self.views.present()
            || self.policy.present()
        {
            return Wire::Fallback;
        }

        if f.safe_search.load(Ordering::Relaxed) {
            return Wire::Fallback;
        }
        if f.harden_large_queries && packet.len() > MAX_LARGE_QUERY_BYTES {
            return Wire::Fallback;
        }
        let Some(scanned) = crate::wirecache::scan_query(packet) else {
            return Wire::Fallback;
        };

        let filter = self.filter.load();
        let filter_tag = (Arc::as_ptr(&filter) as usize).rotate_left(17)
            ^ self.wire_epoch.load(Ordering::Acquire);

        let trivial = filter.is_trivially_allow();

        if let Some((entry, elapsed_secs)) = runtime.cache.wire_get(scanned.key(), filter_tag, now)
        {
            let events = f.events();
            let timer = events.is_some().then(onetdns_control::RequestTimer::start);
            let client = self.identify_with(ctx, &f);
            if self.acl.check(&client) == AclDecision::Deny {
                return Wire::Fallback;
            }

            let qname = if !trivial || events.is_some() {
                match ApName::from_uncompressed_wire(scanned.qname) {
                    Some(name) => Some(name),
                    None => return Wire::Fallback,
                }
            } else {
                None
            };
            if !trivial {
                if filter.client_safe_search(&client).unwrap_or(false) {
                    return Wire::Fallback;
                }

                if let Some(name) = &qname {
                    match filter.verdict(name, ApRt(scanned.qtype), &client) {
                        FilterVerdict::Allow => {}
                        _ => return Wire::Fallback,
                    }
                }
            }

            for limiter in &self.rate_limiters {
                if limiter.check(&client) == RateDecision::Throttle {
                    return Wire::Fallback;
                }
            }
            entry.emit_at_age(&scanned, elapsed_secs, out);
            if let Some(recorder) = events {
                let (log, stat) = filter.client_log_stat(&client);
                recorder.record_cache(true);
                self.rec_rc_diag_with(
                    recorder,
                    &client,
                    Action::Resolved,
                    qname.as_ref(),
                    Some(ApRt(scanned.qtype)),
                    ResponseCode::NoError,
                    entry.answers_summary(),
                    "캐시",
                    "",
                    log,
                    stat,
                    None,
                );
                if let Some(timer) = timer {
                    recorder.record_latency_for(timer.elapsed_us(), stat, qname.as_ref());
                }
            }
            return Wire::Respond;
        }

        if hit_only {
            return Wire::Fallback;
        }

        let client = self.identify_with(ctx, &f);

        let storable = trivial || {
            if filter.has_client_specific_rules() {
                return Wire::Fallback;
            }
            if filter.client_safe_search(&client).unwrap_or(false) {
                return Wire::Fallback;
            }
            let Some(qname) = ApName::from_uncompressed_wire(scanned.qname) else {
                return Wire::Fallback;
            };
            matches!(
                filter.verdict(&qname, ApRt(scanned.qtype), &client),
                FilterVerdict::Allow
            )
        };
        if !storable {
            return Wire::Fallback;
        }
        let Ok(request) = Message::parse(packet) else {
            return Wire::Fallback;
        };
        let Some(response) = self.handle(&request, ctx) else {
            return Wire::Drop;
        };
        onetdns_runtime::encode_limited(&request, &response, out);
        if out.buf.is_empty() {
            return Wire::Fallback;
        }

        let summary = if f.events().is_some() {
            answers_summary(&response.answers)
        } else {
            String::new()
        };
        self.store_wire_response(runtime, scanned.key(), &out.buf, filter_tag, summary, now);
        Wire::Respond
    }

    #[cfg(unix)]
    /** @brief 마저 푼 것들을 거둬 내보낸다. */
    fn lane_drain_fallback(
        &self,
        st: &mut LaneState,
        out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
    ) {
        use onetdns_recurse::reactor::Completion;
        let finished = st.fallback.take_done();
        if finished.is_empty() {
            return;
        }
        let mut comps = Vec::with_capacity(finished.len());
        let mut failures = Vec::new();
        for (token, answer) in finished {
            match answer {
                Ok(response) => comps.push(Completion::Answer(token, response)),
                Err(failure) => failures.push((token, failure)),
            }
        }
        self.lane_finish(st, comps, out);
        for (token, failure) in failures {
            if let Some(cl) = st.clients.remove(&token) {
                self.lane_fail(cl, &failure, out);
            }
        }
    }

    #[cfg(unix)]
    /**
     * @brief 레인이나 대체 처리가 풀지 못한 질의에 실패 응답을 보낸다.
     * @param failure 실패 종류. 클라이언트에 붙일 확장 오류 코드가 여기서 정해진다.
     */
    fn lane_fail(
        &self,
        cl: LaneClient,
        failure: &ResolveFailure,
        out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
    ) {
        let f = self.features.load();
        let qname = cl.request.questions.first().map(|q| &q.name);
        let (reason, class, ede) = failure_diagnosis(failure);
        let detail = format!(
            "DNS 질의를 처리했지만 응답을 만들지 못했습니다. 처리 방식={}, 질의 클래스={class}",
            self.resolver_mode(&cl.client)
        );
        let timer = onetdns_control::RequestTimer::start_at(cl.submitted);
        self.rec_failure(
            &cl.client,
            qname,
            cl.request.questions.first().map(|q| q.qtype),
            reason,
            "resolver",
            &detail,
        );
        self.rec_latency(&f, &cl.client, qname, timer.elapsed_us());
        let mut resp = error_resp(&cl.request, ResponseCode::ServFail);
        if let Some(code) = ede {
            let edns = with_ede(None, &cl.request, f.edns_buffer, code, ede_text(code));
            resp = finalize(resp, edns);
        }
        let ctx = RequestCtx::new(cl.src, onetdns_runtime::Transport::Do53Udp);
        reactor_response_edns(&f, &mut resp, &cl.request);
        let _ = postprocess(&f, &mut resp, &cl.request, &ctx);
        let mut w = onetdns_proto::Writer::with_limit(1232);
        onetdns_runtime::encode_limited(&cl.request, &resp, &mut w);
        if !w.buf.is_empty() {
            out.push((cl.src, w.buf));
        }
    }

    #[cfg(unix)]
    /** @brief 레인이 끝낸 질의의 응답을 마무리한다. */
    fn lane_finish(
        &self,
        st: &mut LaneState,
        comps: Vec<onetdns_recurse::reactor::Completion>,
        out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
    ) {
        use onetdns_recurse::reactor::Completion;
        if comps.is_empty() {
            return;
        }
        let f = self.features.load();
        let runtime = st.runtime.clone();
        let filter = self.filter.load();
        let filter_tag = (Arc::as_ptr(&filter) as usize).rotate_left(17)
            ^ self.wire_epoch.load(Ordering::Acquire);
        let mut w = onetdns_proto::Writer::with_limit(1232);
        for comp in comps {
            let (token, lane_answer) = match comp {
                Completion::Answer(token, resp) => (token, Some(resp)),
                Completion::Retry(token) => (token, None),
                Completion::Fail(token, error) => {
                    let Some(cl) = st.clients.remove(&token) else {
                        continue;
                    };
                    runtime.cache.lane_remember_failure(&cl.request);
                    let failure = match cl.request.questions.first() {
                        Some(question) => recurse_failure(error, &question.name),
                        None => ResolveFailure::Permanent(None),
                    };
                    self.lane_fail(cl, &failure, out);
                    continue;
                }
            };
            let Some(cl) = st.clients.remove(&token) else {
                continue;
            };
            let req = &cl.request;

            let timer = onetdns_control::RequestTimer::start_at(cl.submitted);
            let mut resp = match lane_answer {
                Some(mut resp) => {
                    onetdns_forward::clear_response_source();
                    // 레인은 체인을 거치지 않으므로 여기서 걷어낸다. 캐시
                    // 키에 DO가 들어 있어 두 모양이 섞이지는 않는다.
                    strip_dnssec_unless_requested(req, &mut resp);
                    resp
                }
                None => {
                    match st
                        .fallback
                        .jobs
                        .send((token, req.clone(), cl.client.clone()))
                    {
                        Ok(()) => {
                            st.clients.insert(token, cl);
                            continue;
                        }

                        Err(_) => {
                            reactor_fallback_unavailable();
                            onetdns_forward::clear_response_source();
                            match self.resolve_for(req, &cl.client) {
                                ResolveOutcome::Response(response) => response,
                                ResolveOutcome::Failure(failure) => {
                                    self.lane_fail(cl, &failure, out);
                                    continue;
                                }
                            }
                        }
                    }
                }
            };
            resp.header.id = req.header.id;
            resp.header.response = true;
            resp.header.opcode = req.header.opcode;
            resp.header.recursion_desired = req.header.recursion_desired;
            resp.header.recursion_available = true;
            resp.header.checking_disabled = req.header.checking_disabled;
            resp.questions = req.questions.clone();
            let ctx = RequestCtx::new(cl.src, onetdns_runtime::Transport::Do53Udp);
            reactor_response_edns(&f, &mut resp, req);
            if let Err(error) = postprocess(&f, &mut resp, req, &ctx) {
                onetdns_core::error!(event = "dns.response_postprocess_failed", %error,
                    "응답의 EDNS 후처리에 실패해 SERVFAIL로 교체합니다");
                resp = error_resp(req, ResponseCode::ServFail);
            }
            runtime.cache.store(req, &resp);

            let uncloaked = (!filter.is_trivially_allow())
                .then(|| Self::cname_uncloak(&filter, &resp.answers, &cl.client))
                .flatten();
            let blocked = uncloaked.is_some();
            if let Some(br) = uncloaked {
                let q = &req.questions[0];
                resp = block_resp(
                    req,
                    &q.name,
                    q.qtype,
                    br,
                    self.block_ttl.load(Ordering::Acquire),
                );
                self.rec_rc(
                    &cl.client,
                    Action::Blocked,
                    Some(&q.name),
                    Some(q.qtype),
                    ResponseCode(resp.header.rcode),
                );
            } else {
                self.rec_final_answer(
                    &f,
                    &cl.client,
                    &req.questions[0].name,
                    req.questions[0].qtype,
                    &resp,
                );
            }
            self.rec_latency(
                &f,
                &cl.client,
                Some(&req.questions[0].name),
                timer.elapsed_us(),
            );
            w.clear();
            onetdns_runtime::encode_limited(req, &resp, &mut w);
            if w.buf.is_empty() {
                continue;
            }

            if let (Some(fast_path), Some(scanned)) = (
                (!blocked && self.lane_switch.wire())
                    .then_some(runtime.as_ref())
                    .filter(|runtime| runtime.factory.is_some()),
                crate::wirecache::scan_query(&cl.raw),
            ) {
                let storable = filter.is_trivially_allow()
                    || (!filter.has_client_specific_rules()
                        && !filter.client_safe_search(&cl.client).unwrap_or(false)
                        && matches!(
                            filter.verdict(
                                &req.questions[0].name,
                                req.questions[0].qtype,
                                &cl.client
                            ),
                            FilterVerdict::Allow
                        ));
                if storable {
                    self.store_wire_response(
                        fast_path,
                        scanned.key(),
                        &w.buf,
                        filter_tag,
                        String::new(),
                        std::time::Instant::now(),
                    );
                }
            }
            out.push((cl.src, w.buf.clone()));
        }
    }

    /** @brief 만든 응답들을 실제로 내보낸다. */
    fn emit_responses(
        &self,
        request: &Message,
        ctx: &RequestCtx,
        emit: &mut dyn FnMut(Message) -> bool,
    ) -> Option<()> {
        let is_xfr = request.header.opcode == 0
            && request.questions.len() == 1
            && request
                .questions
                .first()
                .is_some_and(|q| q.qtype == ApRt(252) || q.qtype == ApRt(251));
        if !is_xfr {
            return emit(self.handle(request, ctx)?).then_some(());
        }
        if request.questions[0].qclass != DnsClass::IN {
            return emit(edns_error_resp(
                request,
                ResponseCode::FormErr,
                self.features.load().edns_buffer,
            ))
            .then_some(());
        }

        let _timer = onetdns_control::RequestTimer::start();
        let client = self.identify(ctx);
        let features = self.features.load();
        if self.acl.check(&client) == AclDecision::Deny {
            self.rec(&client, Action::Denied, None, None);
            let edns = with_ede(
                None,
                request,
                features.edns_buffer,
                onetdns_proto::ede_code::PROHIBITED,
                "access denied by ACL",
            );
            return emit(finalize(error_resp(request, ResponseCode::Refused), edns)).then_some(());
        }
        for rl in &self.rate_limiters {
            if rl.check(&client) == RateDecision::Throttle {
                self.rec_rc(
                    &client,
                    Action::Throttled,
                    request.questions.first().map(|question| &question.name),
                    request.questions.first().map(|question| question.qtype),
                    ResponseCode::ServFail,
                );
                let edns = with_ede(
                    None,
                    request,
                    features.edns_buffer,
                    onetdns_proto::ede_code::PROHIBITED,
                    "query rate limit exceeded",
                );
                return emit(finalize(error_resp(request, ResponseCode::ServFail), edns))
                    .then_some(());
            }
        }
        let qname = request.questions.first()?.name.clone();
        let dnstap = features.dnstap.as_ref();
        let proto = dnstap_proto(ctx.transport);
        self.handle_axfr(request, ctx, &qname, &client, &mut |message| {
            if let Some(dt) = dnstap {
                if let Ok(wire) = message.try_encode() {
                    dt.log_client_response(ctx.src, proto, SystemTime::now(), &wire);
                }
            }
            emit(message)
        })
    }

    /** @brief 이 요청을 보낸 클라이언트를 알아본다. */
    fn identify(&self, ctx: &RequestCtx) -> ClientInfo {
        self.identify_with(ctx, &self.features.load())
    }

    /** @brief 켜진 기능에 맞춰 클라이언트를 알아본다. */
    fn identify_with(&self, ctx: &RequestCtx, f: &NativeFeatures) -> ClientInfo {
        let transport = core_transport(ctx.transport);
        let mut client = ClientInfo {
            source_ip: canonical_source_ip(ctx.src.ip()),

            client_id: if ctx.authenticated {
                ctx.auth_identity.clone().or_else(|| ctx.client_id.clone())
            } else {
                None
            },
            transport,

            authenticated: ctx.authenticated,
        };
        if client.client_id.is_none() {
            if let Some(mc) = &f.mac_cache {
                client.client_id = mc.lookup(client.source_ip);
            }
        }
        client
    }

    /**
     * @brief 질의 하나를 실제로 처리한다.
     * @details 접근 제어, 속도 제한, 쿠키, 정책, 차단을 차례로 보고 통과한 것만 해석 체인으로
     *          내려보낸다. 돌아온 답에는 응답 쪽 검사와 다듬기를 건다.
     */
    fn handle_inner(&self, request: &Message, ctx: &RequestCtx) -> Option<Message> {
        let f = self.features.load();
        let policy = self.policy.load();
        let block_ttl = self.block_ttl.load(Ordering::Acquire);

        if request.header.response {
            return None;
        }

        if request.header.opcode == 4 || request.header.opcode == 5 {
            // UPDATE 는 ZCLASS 가 달라도 형식 오류가 아니다. RFC 2136은 그것을
            // 이 서버가 맡지 않은 영역으로 보고 NOTAUTH 로 답하게 하므로 handle_update 로 넘긴다.
            let valid_zone_question = request.questions.len() == 1
                && request.questions[0].qtype == ApRt::SOA
                && (request.header.opcode == 5 || request.questions[0].qclass == DnsClass::IN);
            if !valid_zone_question {
                return Some(edns_error_resp(
                    request,
                    ResponseCode::FormErr,
                    f.edns_buffer,
                ));
            }
        }

        let client = self.identify(ctx);

        if request.header.opcode == 4 || request.header.opcode == 5 {
            if self.acl.check(&client) == AclDecision::Deny {
                self.rec(&client, Action::Denied, None, None);
                let edns = with_ede(
                    None,
                    request,
                    f.edns_buffer,
                    onetdns_proto::ede_code::PROHIBITED,
                    "access denied by ACL",
                );
                return Some(finalize(error_resp(request, ResponseCode::Refused), edns));
            }
            for limiter in &self.rate_limiters {
                if limiter.check(&client) == RateDecision::Throttle {
                    self.rec_rc(
                        &client,
                        Action::Throttled,
                        request.questions.first().map(|question| &question.name),
                        request.questions.first().map(|question| question.qtype),
                        ResponseCode::ServFail,
                    );
                    let edns = with_ede(
                        None,
                        request,
                        f.edns_buffer,
                        onetdns_proto::ede_code::PROHIBITED,
                        "query rate limit exceeded",
                    );
                    return Some(finalize(error_resp(request, ResponseCode::ServFail), edns));
                }
            }
        }

        if request.header.opcode == 5 {
            return self.handle_update(request, ctx, &client);
        }

        if request.header.opcode == 4 {
            return self.handle_notify(request, ctx);
        }
        if request.header.opcode != 0 {
            return Some(edns_error_resp(
                request,
                ResponseCode::NotImp,
                f.edns_buffer,
            ));
        }
        if request.questions.len() != 1 {
            // RFC 9619는 opcode 0인 DNS 메시지가 QDCOUNT를 1보다 크게 담을 수 없다고 정한다.
            // 응답도 opcode 0이므로 그대로 돌려주면 이 서버의 답이 같은 규칙을 어긴다. 질문부를 비운다.
            let mut response = edns_error_resp(request, ResponseCode::FormErr, f.edns_buffer);
            response.questions.clear();
            return Some(response);
        }

        if self.acl.check(&client) == AclDecision::Deny {
            self.rec(&client, Action::Denied, None, None);

            let edns = with_ede(
                None,
                request,
                f.edns_buffer,
                onetdns_proto::ede_code::PROHIBITED,
                "access denied by ACL",
            );
            return Some(finalize(error_resp(request, ResponseCode::Refused), edns));
        }

        let mut resp_edns: Option<Edns> = None;
        if let Some(request_edns) = request.opt().and_then(Edns::from_record) {
            if request_edns.version != 0 {
                let mut response_edns = base_edns(request, f.edns_buffer);
                response_edns.extended_rcode = (ResponseCode::BadVers.0 >> 4) as u8;
                return Some(finalize(
                    error_resp(request, ResponseCode::BadVers),
                    Some(response_edns),
                ));
            }

            // RFC 6891: 요청에 OPT가 있으면 응답에도 반드시 넣는다. 빼면 상대는 이 서버가 EDNS를
            // 모르는 것으로 보고 512바이트로 전환하고, 쿠키·NSID·패딩·EDE를 담을 슬롯도 없다.
            // 이미 읽어 둔 요청 EDNS를 그대로 고쳐 쓴다. base_edns를 부르면 같은 OPT를 한 번
            // 더 파싱하며 곧 버릴 옵션들을 항목마다 복제한다.
            let mut response_edns = request_edns;
            response_edns.udp_payload = advertised_udp_payload(f.edns_buffer);
            response_edns.extended_rcode = 0;
            response_edns.version = 0;
            response_edns.options.clear();
            resp_edns = Some(response_edns);
        }
        if let Some(keeper) = &f.cookies.keeper {
            match read_cookie(request) {
                Some(bytes) => match keeper.parse_and_validate(&bytes, client.source_ip) {
                    Some(check) => {
                        resp_edns = Some(cookie_edns(
                            request,
                            keeper.response_cookie(&check.client, client.source_ip),
                            f.edns_buffer,
                        ));
                        if f.cookies.strict
                            && client.transport == Transport::Do53Udp
                            && !check.valid
                        {
                            return Some(finalize(
                                error_resp(request, ResponseCode::BadCookie),
                                resp_edns,
                            ));
                        }
                    }
                    // COOKIE는 OPT 안에만 있으므로 이 요청에는 반드시 OPT가 있었다. 위에서
                    // 만든 응답 OPT를 그대로 담아야 RFC 6891을 지킨다. 빼면 상대는
                    // 이 서버가 EDNS를 모르는 것으로 보고 512바이트로 전환한다.
                    None => {
                        return Some(finalize(
                            error_resp(request, ResponseCode::FormErr),
                            resp_edns,
                        ))
                    }
                },
                None if f.cookies.strict && client.transport == Transport::Do53Udp => {
                    return Some(finalize(
                        error_resp(request, ResponseCode::BadCookie),
                        Some(base_edns(request, f.edns_buffer)),
                    ));
                }
                None => {}
            }
        }

        let nsid_requested = request
            .opt()
            .and_then(Edns::from_record)
            .is_some_and(|edns| edns.options.iter().any(|(code, _)| *code == OPT_NSID));
        if nsid_requested {
            if let Some(nsid) = &f.nsid {
                let buf = f.edns_buffer;
                resp_edns
                    .get_or_insert_with(|| base_edns(request, buf))
                    .options
                    .push((OPT_NSID, nsid.clone()));
            }
        }

        for rl in &self.rate_limiters {
            if rl.check(&client) == RateDecision::Throttle {
                self.rec_rc(
                    &client,
                    Action::Throttled,
                    request.questions.first().map(|question| &question.name),
                    request.questions.first().map(|question| question.qtype),
                    ResponseCode::ServFail,
                );
                let edns = with_ede(
                    resp_edns,
                    request,
                    f.edns_buffer,
                    onetdns_proto::ede_code::PROHIBITED,
                    "query rate limit exceeded",
                );
                return Some(finalize(error_resp(request, ResponseCode::ServFail), edns));
            }
        }

        let q = request.questions.first()?;
        let qname = q.name.clone();
        let qtype = q.qtype;

        if f.harden_large_queries && ctx.raw.is_some_and(|raw| raw.len() > MAX_LARGE_QUERY_BYTES) {
            self.rec(&client, Action::Denied, Some(&qname), Some(qtype));
            return None;
        }

        if qtype == ApRt(252) || qtype == ApRt(251) {
            let mut first = None;
            let _ = self.handle_axfr(request, ctx, &qname, &client, &mut |message| {
                first = Some(message);
                false
            });
            return first;
        }

        if q.qclass.0 == 3 && qtype == ApRt::TXT {
            if let Some(resp) = self.handle_chaos(request, &qname) {
                self.rec(&client, Action::Resolved, Some(&qname), Some(qtype));
                return Some(finalize(resp, resp_edns));
            }
        }

        if q.qclass != DnsClass::IN {
            self.rec(&client, Action::Refused, Some(&qname), Some(qtype));
            return Some(finalize(
                error_resp(request, ResponseCode::Refused),
                resp_edns,
            ));
        }

        // RFC 8482는 ANY를 온전히 답하지 않는 방법을 셋만 열거하고, 그 밖에는 표준 알고리즘을
        // 따르라고 정한다. 거절은 그 셋에 없으므로 4.2의 합성 HINFO로 답한다.
        // DO를 설정한 질의자에게는 관례대로 답한다. 4.2가 서명된 영역이면 RRSIG를 함께 요구하는데
        // 합성한 레코드에는 붙일 서명이 없다. 관례적 응답은 그 자체로 표준 알고리즘이다.
        let minimal_any = qtype == ApRt::ANY && !f.allow_any && !wants_dnssec(request);
        // 이 서버가 맡은 영역 밖이면 이름이 있는지 알 수 없으므로 여기서 바로 합성한다. 안이면
        // 표준 알고리즘을 먼저 돌린 뒤 답 구간만 바꾼다. 없는 이름에 NOERROR를 주면 존재를
        // 알리는 셈이고 부정 캐시도 서지 않는다.
        if minimal_any && !self.serves_zone_for(&qname) {
            self.rec(&client, Action::Resolved, Some(&qname), Some(qtype));
            return Some(finalize(
                records_resp(request, vec![rfc8482_hinfo(&qname)]),
                resp_edns,
            ));
        }

        if let Some(recs) = self.view_local_answer(&client, &qname, qtype) {
            self.rec(&client, Action::Resolved, Some(&qname), Some(qtype));
            return Some(finalize(records_resp(request, recs), resp_edns));
        }

        if f.block_aaaa && qtype == ApRt::AAAA {
            self.rec_rc(
                &client,
                Action::Blocked,
                Some(&qname),
                Some(qtype),
                ResponseCode::NoError,
            );
            let edns = with_ede(
                resp_edns,
                request,
                f.edns_buffer,
                onetdns_proto::ede_code::FILTERED,
                "IPv6 disabled",
            );
            return Some(finalize(
                policy_negative_resp(request, &qname, ResponseCode::NoError, block_ttl),
                edns,
            ));
        }

        let mut policy_allow = false;
        if !policy.is_empty() {
            if let Some(qn) = normalized_text_name(&qname) {
                let now = SystemTime::now();
                let pin = onetdns_policy::PolicyInput {
                    client: client.source_ip,
                    qname: &qn,
                    qtype: qtype.0,
                    unix_time: crate::localtime::unix_seconds(now),
                    local_minute_of_week: crate::localtime::local_minute_of_week(now),
                    transport: policy_transport(client.transport),
                    client_id: client.client_id.as_deref(),
                    authenticated: client.authenticated,
                };
                match policy.evaluate(&pin) {
                    onetdns_policy::Action::Continue => {}
                    onetdns_policy::Action::Allow => policy_allow = true,
                    onetdns_policy::Action::Block => {
                        self.rec_rc(
                            &client,
                            Action::Blocked,
                            Some(&qname),
                            Some(qtype),
                            ResponseCode::NXDomain,
                        );
                        let edns = with_ede(
                            resp_edns,
                            request,
                            f.edns_buffer,
                            onetdns_proto::ede_code::BLOCKED,
                            "blocked by policy",
                        );
                        return Some(finalize(
                            policy_negative_resp(
                                request,
                                &qname,
                                ResponseCode::NXDomain,
                                block_ttl,
                            ),
                            edns,
                        ));
                    }
                    onetdns_policy::Action::Refuse => {
                        self.rec(&client, Action::Refused, Some(&qname), Some(qtype));
                        let edns = with_ede(
                            resp_edns,
                            request,
                            f.edns_buffer,
                            onetdns_proto::ede_code::PROHIBITED,
                            "refused by policy",
                        );
                        return Some(finalize(error_resp(request, ResponseCode::Refused), edns));
                    }
                    onetdns_policy::Action::Rewrite(ip) => {
                        let response = self.rewrite_resp(
                            request,
                            &qname,
                            qtype,
                            RewriteTarget::ip(ip.into()),
                            &client,
                        );
                        self.rec_rewrite_response(&client, &qname, qtype, &response, "policy");
                        return Some(finalize(response, resp_edns));
                    }
                }
            }
        }

        let filter = self.filter.load();
        if !policy_allow {
            match filter.verdict(&qname, qtype, &client) {
                FilterVerdict::Allow => {}
                FilterVerdict::Block(br) => {
                    let rule = self.filter_rule_label(&qname, qtype, &client);
                    self.rec_rc_diag(
                        &client,
                        Action::Blocked,
                        Some(&qname),
                        Some(qtype),
                        block_rcode(&br, qtype),
                        "",
                        "",
                        rule.as_match(),
                    );

                    let edns = with_ede(
                        resp_edns,
                        request,
                        f.edns_buffer,
                        onetdns_proto::ede_code::BLOCKED,
                        "blocked by filter",
                    );
                    return Some(finalize(
                        block_resp(request, &qname, qtype, br, block_ttl),
                        edns,
                    ));
                }
                FilterVerdict::Rewrite(target) => {
                    let rule = self.filter_rule_label(&qname, qtype, &client);
                    let response = self.rewrite_resp(request, &qname, qtype, target, &client);
                    self.rec_rewrite_response(&client, &qname, qtype, &response, rule.as_match());
                    return Some(finalize(response, resp_edns));
                }
            }
        }

        let _permit = if f.inflight_max > 0 {
            let n = f.inflight.fetch_add(1, Ordering::Relaxed);
            if n >= f.inflight_max {
                f.inflight.fetch_sub(1, Ordering::Relaxed);
                self.rec_overloaded(&client, &qname, qtype);
                return Some(finalize(
                    error_resp(request, ResponseCode::ServFail),
                    resp_edns,
                ));
            }
            Some(InflightGuard(f.inflight.clone()))
        } else {
            None
        };

        let ss = filter
            .client_safe_search(&client)
            .unwrap_or_else(|| f.safe_search.load(Ordering::Relaxed));
        let mut resolve_name = qname.clone();
        let mut safe_cname: Option<ApRecord> = None;
        if ss {
            if let Some(target) = normalized_text_name(&qname)
                .as_deref()
                .and_then(onetdns_filter::safesearch::safe_target)
            {
                if let Ok(tn) = ApName::from_str(target) {
                    safe_cname = Some(ApRecord::new(
                        qname.clone(),
                        self.local_ttl.load(Ordering::Acquire),
                        ApRData::Cname(tn.clone()),
                    ));
                    resolve_name = tn;
                }
            }
        }

        let resolve_req_storage;
        let resolve_req = if resolve_name == qname && request.additionals.is_empty() {
            request
        } else {
            let mut rewritten = request.clone();
            if let Some(question) = rewritten.questions.first_mut() {
                question.name = resolve_name.clone();
                question.qtype = qtype;
            }
            strip_client_hop_edns(&mut rewritten);
            resolve_req_storage = rewritten;
            &resolve_req_storage
        };

        onetdns_forward::clear_response_source();
        let mut resp = match self.resolve_for(resolve_req, &client) {
            ResolveOutcome::Response(response) => response,
            ResolveOutcome::Failure(failure) => {
                let (reason, class, ede) = failure_diagnosis(&failure);
                let detail = format!(
                    "DNS 질의를 처리했지만 응답을 만들지 못했습니다. 처리 방식={}, 질의 클래스={class}",
                    self.resolver_mode(&client)
                );
                self.rec_failure(
                    &client,
                    Some(&qname),
                    Some(qtype),
                    reason,
                    "resolver",
                    &detail,
                );

                let resp_edns = match ede {
                    Some(code) => with_ede(resp_edns, request, f.edns_buffer, code, ede_text(code)),
                    None => resp_edns,
                };
                return Some(finalize(
                    error_resp(request, ResponseCode::ServFail),
                    resp_edns,
                ));
            }
        };

        normalize_recursive_response(&mut resp, request);

        // 표준 알고리즘이 낸 응답에서 답 구간만 합성 HINFO로 바꾼다. 없는 이름의 NXDOMAIN,
        // 자료가 없는 이름의 NODATA, 권한 표시는 그대로 둔다. RFC 8482는 QNAME에 CNAME이
        // 있으면 합성하지 말라고 하므로 그때도 그대로 둔다.
        if minimal_any
            && resp.header.rcode == ResponseCode::NoError.0
            && !resp.answers.is_empty()
            && !resp
                .answers
                .iter()
                .any(|record| record.rtype == ApRt::CNAME && record.name.eq_ignore_case(&qname))
        {
            resp.answers = vec![rfc8482_hinfo(&qname)];
        }

        if let Some(prefix) = f.dns64_prefix {
            let has_aaaa = resp
                .answers
                .iter()
                .any(|record| matches!(&record.rdata, ApRData::Aaaa(_)));
            if qtype == ApRt::AAAA
                && resp.header.rcode != ResponseCode::NXDomain.0
                && (!has_aaaa || f.dns64_synthall)
            {
                let negative_ttl = dns64_negative_ttl(&resp);
                let mut a_request = (*resolve_req).clone();
                if let Some(question) = a_request.questions.first_mut() {
                    question.qtype = ApRt::A;
                }
                if let Some(mut a_response) = self.resolve_message_for(&a_request, &client) {
                    normalize_recursive_response(&mut a_response, &a_request);
                    if a_response.header.rcode == ResponseCode::NoError.0 {
                        let synthesized =
                            synthesize_dns64(&a_response.answers, &prefix, negative_ttl);
                        if !synthesized.is_empty() {
                            let mut merged = Vec::new();

                            for record in resp.answers.iter().chain(a_response.answers.iter()) {
                                if matches!(&record.rdata, ApRData::Cname(_) | ApRData::Dname(_))
                                    && !merged.iter().any(|existing: &ApRecord| {
                                        existing.name.eq_ignore_case(&record.name)
                                            && existing.rtype == record.rtype
                                            && existing.rdata == record.rdata
                                    })
                                {
                                    merged.push(record.clone());
                                }
                            }
                            if f.dns64_synthall {
                                for record in &resp.answers {
                                    if matches!(&record.rdata, ApRData::Aaaa(_)) {
                                        merged.push(record.clone());
                                    }
                                }
                            }
                            merged.extend(synthesized);
                            resp.answers = merged;

                            resp.authorities.clear();
                            resp.header.rcode = ResponseCode::NoError.0;
                            clear_dnssec_assertion(&mut resp);
                        }
                    }
                }
            }
        }

        // 근거 없이 비어 온 NOERROR도 그대로 전달한다. RFC 2308이 모든 구간이 빈 것을
        // NODATA의 한 모양으로 열거해 두었고, SOA가 없을 때 규격이 정한 처분은 거절이 아니라
        // 캐시 금지다. 특히 RFC 4074는 IPv6 주소가 없는 이름의 AAAA에 SERVFAIL을 주면
        // 질의자가 A로 다시 묻지 못하고 되풀이한다고 고정한다. 담지 않는 것은 캐시 계층이 한다.
        if resp.header.rcode == ResponseCode::NoError.0
            && !response_has_requested_answer(resolve_req, &resp)
            && !has_negative_soa(&resp)
            && !is_delegation_referral(&resp)
            && !has_alias_answer(&resp)
        {
            onetdns_core::debug!(
                event = "dns.unproven_nodata",
                qname = %qname.to_ascii_lower(),
                qtype = qtype.0,
                "부정 응답 SOA 없이 비어 온 NOERROR를 그대로 전달합니다. 캐시에는 담지 않습니다"
            );
        }

        if resp.header.rcode == ResponseCode::ServFail.0 {
            let detail = format!(
                "DNS 처리 경로에서 서버 오류 응답을 반환했습니다. 처리 방식={}",
                self.resolver_mode(&client)
            );
            self.rec_failure(
                &client,
                Some(&qname),
                Some(qtype),
                "UPSTREAM_SERVFAIL",
                "upstream",
                &detail,
            );
            return Some(finalize(resp, resp_edns));
        }
        if resp.header.rcode == ResponseCode::Refused.0 {
            self.rec(&client, Action::Refused, Some(&qname), Some(qtype));
            return Some(finalize(resp, resp_edns));
        }

        if f.rebind_protection {
            let exempt = f.rebind_allow.iter().any(|s| name_ends_with(&qname, s));
            if !exempt {
                let before = resp.answers.len();
                let removed = strip_private_records(&mut resp);
                if removed {
                    clear_dnssec_assertion(&mut resp);
                }
                if resp.answers.len() != before
                    && !response_has_requested_answer(resolve_req, &resp)
                {
                    self.rec(&client, Action::Blocked, Some(&qname), Some(qtype));
                    let edns = with_ede(
                        resp_edns,
                        request,
                        f.edns_buffer,
                        onetdns_proto::ede_code::FILTERED,
                        "private answer blocked by rebind protection",
                    );
                    return Some(finalize(
                        policy_negative_resp(request, &qname, ResponseCode::NXDomain, block_ttl),
                        edns,
                    ));
                }
            }
        }

        if !f.bogus_nxdomain.is_empty()
            && resp
                .answers
                .iter()
                .any(|r| rdata_in_nets(&r.rdata, &f.bogus_nxdomain))
        {
            self.rec(&client, Action::Blocked, Some(&qname), Some(qtype));
            return Some(finalize(
                policy_negative_resp(request, &qname, ResponseCode::NXDomain, block_ttl),
                resp_edns,
            ));
        }

        let denied_answer = resp.answers.iter().any(|record| {
            rdata_ip(&record.rdata).is_some_and(|ip| {
                f.recurse_deny_answers.iter().any(|net| net.contains(&ip))
                    && !f.recurse_allow_answers.iter().any(|net| net.contains(&ip))
            })
        });
        if denied_answer {
            self.rec(&client, Action::Blocked, Some(&qname), Some(qtype));
            let edns = with_ede(
                resp_edns,
                request,
                f.edns_buffer,
                onetdns_proto::ede_code::FILTERED,
                "answer address denied",
            );
            return Some(finalize(
                policy_negative_resp(request, &qname, ResponseCode::NXDomain, block_ttl),
                edns,
            ));
        }

        if f.rrset_roundrobin && resp.answers.len() > 1 {
            let n = f.rotor.fetch_add(1, Ordering::Relaxed) % resp.answers.len();
            resp.answers.rotate_left(n);
        }

        if let Some(cname) = safe_cname {
            resp.answers.insert(0, cname);
            clear_dnssec_assertion(&mut resp);
        }

        if let Some(br) = Self::cname_uncloak(&filter, &resp.answers, &client) {
            self.rec_rc(
                &client,
                Action::Blocked,
                Some(&qname),
                Some(qtype),
                block_rcode(&br, qtype),
            );
            return Some(finalize(
                block_resp(request, &qname, qtype, br, block_ttl),
                resp_edns,
            ));
        }

        if let Some(v) = Self::rpz_ip_check(&filter, &resp.answers) {
            match v {
                FilterVerdict::Allow => {}
                FilterVerdict::Block(br) => {
                    self.rec_rc(
                        &client,
                        Action::Blocked,
                        Some(&qname),
                        Some(qtype),
                        block_rcode(&br, qtype),
                    );

                    let edns = with_ede(
                        resp_edns,
                        request,
                        f.edns_buffer,
                        onetdns_proto::ede_code::BLOCKED,
                        "blocked by filter",
                    );
                    return Some(finalize(
                        block_resp(request, &qname, qtype, br, block_ttl),
                        edns,
                    ));
                }
                FilterVerdict::Rewrite(t) => {
                    let response = self.rewrite_resp(request, &qname, qtype, t, &client);
                    self.rec_rewrite_response(&client, &qname, qtype, &response, "rpz-ip");
                    return Some(finalize(response, resp_edns));
                }
            }
        }

        if let Some((code, text)) = resp.opt().and_then(Edns::from_record).and_then(|e| e.ede()) {
            resp.additionals
                .retain(|r| r.rtype != onetdns_proto::RecordType::OPT);
            resp_edns = with_ede(resp_edns, request, f.edns_buffer, code, &text);
        }

        // 후처리 뒤에도 같은 판단이다. 이 서버의 필터가 답을 걷어내 비게 된 경우는 걷어내는 곳에서
        // 각자 자기 응답을 만들어 돌려주므로 여기까지 오지 않는다.
        if resp.header.rcode == ResponseCode::NoError.0
            && !response_has_requested_answer(request, &resp)
            && !has_negative_soa(&resp)
            && !is_delegation_referral(&resp)
            && !has_alias_answer(&resp)
        {
            onetdns_core::debug!(
                event = "dns.unproven_nodata_after_postprocess",
                qname = %qname.to_ascii_lower(),
                qtype = qtype.0,
                "후처리 뒤에도 근거 없이 비어 있어 그대로 전달합니다"
            );
        }

        if policy.has_response_hook() {
            if let Some(qn) = normalized_text_name(&qname) {
                let mut addrs: Vec<IpAddr> = Vec::new();
                for record in &resp.answers {
                    if let Some(ip) = rdata_ip(&record.rdata) {
                        addrs.push(ip);
                        if addrs.len() >= 16 {
                            break;
                        }
                    }
                }
                let rin = onetdns_policy::ResponseInput {
                    qname: &qn,
                    qtype: qtype.0,
                    rcode: resp.header.rcode,
                    addrs: &addrs,
                };
                match policy.evaluate_response(&rin) {
                    onetdns_policy::ResponseVerdict::Pass => {}
                    onetdns_policy::ResponseVerdict::Block => {
                        self.rec_rc(
                            &client,
                            Action::Blocked,
                            Some(&qname),
                            Some(qtype),
                            ResponseCode::NXDomain,
                        );
                        let edns = with_ede(
                            resp_edns,
                            request,
                            f.edns_buffer,
                            onetdns_proto::ede_code::FILTERED,
                            "blocked by response policy",
                        );
                        return Some(finalize(
                            policy_negative_resp(
                                request,
                                &qname,
                                ResponseCode::NXDomain,
                                block_ttl,
                            ),
                            edns,
                        ));
                    }
                    onetdns_policy::ResponseVerdict::Refuse => {
                        self.rec(&client, Action::Refused, Some(&qname), Some(qtype));
                        let edns = with_ede(
                            resp_edns,
                            request,
                            f.edns_buffer,
                            onetdns_proto::ede_code::PROHIBITED,
                            "refused by response policy",
                        );
                        return Some(finalize(error_resp(request, ResponseCode::Refused), edns));
                    }
                }
            }
        }

        self.rec_final_answer(&f, &client, &qname, qtype, &resp);
        normalize_recursive_response(&mut resp, request);
        Some(finalize(resp, resp_edns))
    }
}

/** @brief 질의 기록에 남길 걸린 규칙과 그 규칙이 들어 있던 목록. */
#[derive(Default, Clone, Copy)]
struct RuleMatch<'a> {
    /** @brief 걸린 규칙. */
    rule: &'a str,
    /** @brief 그 규칙이 들어 있던 목록. 목록에 속하지 않으면 비어 있다. */
    list: &'a str,
}

impl<'a> From<&'a str> for RuleMatch<'a> {
    /** @brief 목록 없이 규칙 이름만 남긴다. */
    fn from(rule: &'a str) -> Self {
        RuleMatch { rule, list: "" }
    }
}

/** @brief 필터 판정을 설명하는 규칙과 목록. 기록할 때까지 들고 있는 값이다. */
struct FilterRuleLabel {
    /** @brief 걸린 규칙. 규칙 원문이 없으면 판정 단계 이름이다. */
    rule: String,
    /** @brief 그 규칙이 들어 있던 목록. */
    list: String,
}

impl FilterRuleLabel {
    /** @brief 기록에 넘길 형태로 빌려 준다. */
    fn as_match(&self) -> RuleMatch<'_> {
        RuleMatch {
            rule: &self.rule,
            list: &self.list,
        }
    }
}

impl NativeServer {
    /** @brief 답을 바꾼 것을 기록에 남긴다. */
    fn rec_rewrite_response<'r>(
        &self,
        client: &ClientInfo,
        name: &ApName,
        qtype: ApRt,
        response: &Message,
        rule: impl Into<RuleMatch<'r>>,
    ) {
        let rcode = ResponseCode(response.header.rcode);
        if rcode == ResponseCode::ServFail {
            self.rec_failure(
                client,
                Some(name),
                Some(qtype),
                "REWRITE_TARGET_RESOLUTION_FAILED",
                "rewrite",
                "rewrite 대상의 후속 해석이 유효한 응답을 만들지 못했습니다",
            );
        } else if rcode == ResponseCode::Refused {
            self.rec_rc(client, Action::Refused, Some(name), Some(qtype), rcode);
        } else {
            let answers = answers_summary(&response.answers);
            self.rec_rc_diag(
                client,
                Action::Rewritten,
                Some(name),
                Some(qtype),
                rcode,
                &answers,
                "",
                rule,
            );
        }
    }

    /** @brief 어느 규칙이 걸렸는지와 그 규칙이 들어 있던 목록. */
    fn filter_rule_label(
        &self,
        name: &ApName,
        qtype: ApRt,
        client: &ClientInfo,
    ) -> FilterRuleLabel {
        let exp = self.filter.load().explain(name, qtype, client);
        FilterRuleLabel {
            rule: exp
                .matched
                .unwrap_or_else(|| exp.stage.as_str().to_string()),
            list: exp.source.unwrap_or_default(),
        }
    }

    /** @brief 실패를 기록에 남긴다. */
    #[allow(clippy::too_many_arguments)]
    fn rec_failure(
        &self,
        client: &ClientInfo,
        name: Option<&ApName>,
        qtype: Option<ApRt>,
        reason: &'static str,
        stage: &'static str,
        detail: &str,
    ) {
        resolution_failed(reason, stage, name);
        let features = self.features.load();
        if let Some(r) = features.events() {
            let (log, stat) = self.filter.load().client_log_stat(client);
            r.record_detailed(
                client.transport,
                Action::ServFail,
                client.source_ip,
                name,
                qtype,
                log,
                stat,
                EventDiag {
                    rcode: "SERVFAIL",
                    reason,
                    stage,
                    detail,
                    ..Default::default()
                },
            );
        }
    }

    /** @brief 최종 답을 기록에 남긴다. */
    fn rec_final_answer(
        &self,
        f: &NativeFeatures,
        client: &ClientInfo,
        qname: &ApName,
        qtype: ApRt,
        resp: &Message,
    ) {
        let source = onetdns_forward::take_response_source().unwrap_or_default();
        let Some(recorder) = f.events() else {
            return;
        };
        if resp.header.rcode == ResponseCode::ServFail.0 {
            let detail = format!(
                "DNS 처리 경로에서 서버 오류 응답을 반환했습니다. 처리 방식={}",
                self.resolver_mode(client)
            );
            self.rec_failure(
                client,
                Some(qname),
                Some(qtype),
                "UPSTREAM_SERVFAIL",
                "upstream",
                &detail,
            );
            return;
        }
        let action = if resp.header.rcode == ResponseCode::Refused.0 {
            Action::Refused
        } else if resp.header.rcode != ResponseCode::NoError.0
            && resp.header.rcode != ResponseCode::NXDomain.0
        {
            Action::ServFail
        } else {
            Action::Resolved
        };
        // 요약은 질의 기록에만 담긴다. 꺼져 있으면 만들자마자 버려지므로 만들지 않는다.
        let answers = if recorder.querylog_enabled() {
            answers_summary(&resp.answers)
        } else {
            String::new()
        };
        // 여기서 확인한 레코더를 그대로 넘겨 같은 질의 세대의 snapshot을 다시 잡지 않는다.
        let (log, stat) = self.filter.load().client_log_stat(client);
        self.rec_rc_diag_with(
            recorder,
            client,
            action,
            Some(qname),
            Some(qtype),
            ResponseCode(resp.header.rcode),
            &answers,
            &source,
            "",
            log,
            stat,
            None,
        );
    }

    /** @brief 처리에 걸린 시간을 남긴다. */
    fn rec_latency(
        &self,
        f: &NativeFeatures,
        client: &ClientInfo,
        qname: Option<&ApName>,
        elapsed_us: u64,
    ) {
        if let Some(r) = f.events() {
            let (_, stat) = self.filter.load().client_log_stat(client);
            r.record_latency_for(elapsed_us, stat, qname);
        }
    }

    /** @brief 질의 하나를 기록에 남긴다. */
    fn rec(&self, client: &ClientInfo, action: Action, name: Option<&ApName>, qtype: Option<ApRt>) {
        note_rejection(action, client);
        let features = self.features.load();
        if let Some(r) = features.events() {
            let (log, stat) = self.filter.load().client_log_stat(client);
            r.record(
                client.transport,
                action,
                client.source_ip,
                name,
                qtype,
                log,
                stat,
            );
        }
    }

    /** @brief 응답 코드와 함께 남긴다. */
    fn rec_rc(
        &self,
        client: &ClientInfo,
        action: Action,
        name: Option<&ApName>,
        qtype: Option<ApRt>,
        rcode: ResponseCode,
    ) {
        self.rec_rc_diag(client, action, name, qtype, rcode, "", "", "");
    }

    #[allow(clippy::too_many_arguments)]
    /** @brief 응답 코드와 사유를 함께 남긴다. */
    fn rec_rc_diag<'r>(
        &self,
        client: &ClientInfo,
        action: Action,
        name: Option<&ApName>,
        qtype: Option<ApRt>,
        rcode: ResponseCode,
        answers: &str,
        upstream: &str,
        rule: impl Into<RuleMatch<'r>>,
    ) {
        note_rejection(action, client);
        let features = self.features.load();
        if let Some(recorder) = features.events() {
            let (log, stat) = self.filter.load().client_log_stat(client);
            self.rec_rc_diag_with(
                recorder, client, action, name, qtype, rcode, answers, upstream, rule, log, stat,
                None,
            );
        }
    }

    /**
     * @brief 동시 처리 한도에 걸려 거절한 질의를 남긴다.
     * @details 속도 제한과 같은 Throttled 로 세지만 까닭은 다르다. 운영자는 까닭을 보고
     *          클라이언트를 볼지 서버 용량을 볼지 정한다.
     */
    fn rec_overloaded(&self, client: &ClientInfo, name: &ApName, qtype: ApRt) {
        note_rejection(Action::Throttled, client);
        let features = self.features.load();
        if let Some(recorder) = features.events() {
            let (log, stat) = self.filter.load().client_log_stat(client);
            self.rec_rc_diag_with(
                recorder,
                client,
                Action::Throttled,
                Some(name),
                Some(qtype),
                ResponseCode::ServFail,
                "",
                "",
                "",
                log,
                stat,
                Some("MAX_INFLIGHT"),
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    /**
     * @brief 응답 코드와 사유, 답 요약을 함께 남긴다.
     * @param reason 동작만으로 까닭이 정해지지 않을 때 넘기는 까닭. 없으면 동작에서 고른다.
     */
    fn rec_rc_diag_with<'r>(
        &self,
        recorder: &Recorder,
        client: &ClientInfo,
        action: Action,
        name: Option<&ApName>,
        qtype: Option<ApRt>,
        rcode: ResponseCode,
        answers: &str,
        upstream: &str,
        rule: impl Into<RuleMatch<'r>>,
        log: bool,
        stat: bool,
        reason: Option<&'static str>,
    ) {
        let reason = reason.unwrap_or(match action {
            Action::ServFail => "UNSPECIFIED_SERVFAIL",
            Action::Refused | Action::Denied => "POLICY_REFUSED",
            Action::Blocked => "FILTER_BLOCKED",
            Action::Throttled => "RATE_LIMITED",
            _ => "",
        });
        let rcode_name = rcode_str(rcode);
        let rule = rule.into();
        recorder.record_detailed(
            client.transport,
            action,
            client.source_ip,
            name,
            qtype,
            log,
            stat,
            EventDiag {
                rcode: &rcode_name,
                reason,
                answers,
                upstream,
                rule: rule.rule,
                list: rule.list,
                ..Default::default()
            },
        );
    }

    /** @brief 별칭 체인에 차단 대상이 숨어 있는지 본다. 끝만 보면 별칭 뒤에 숨겨 지나갈 수 있다. */
    fn cname_uncloak(
        engine: &BlockEngine,
        answers: &[ApRecord],
        client: &ClientInfo,
    ) -> Option<BlockResponse> {
        for rec in answers {
            if let ApRData::Cname(cn) = &rec.rdata {
                if let FilterVerdict::Block(br) = engine.verdict(cn, ApRt::CNAME, client) {
                    return Some(br);
                }
            }
        }
        None
    }

    /** @brief 답에 담긴 주소가 차단 대상인지 본다. */
    fn rpz_ip_check(engine: &BlockEngine, answers: &[ApRecord]) -> Option<FilterVerdict> {
        if !engine.has_rpz_ip() {
            return None;
        }
        for rec in answers {
            let ip = match &rec.rdata {
                ApRData::A(a) => IpAddr::V4(*a),
                ApRData::Aaaa(a) => IpAddr::V6(*a),
                _ => continue,
            };
            if let Some(v) = engine.rpz_ip_verdict(ip) {
                return Some(v.clone());
            }
        }
        None
    }

    /** @brief 차단·재작성 판정대로 응답을 바꾼다. */
    fn rewrite_resp(
        &self,
        request: &Message,
        qname: &ApName,
        qtype: ApRt,
        target: RewriteTarget,
        client: &ClientInfo,
    ) -> Message {
        let ttl = self.local_ttl.load(Ordering::Acquire);
        match target {
            RewriteTarget::Records(rdatas) => {
                let recs: Vec<ApRecord> = rdatas
                    .into_iter()
                    .filter(|rd| rd.record_type() == qtype)
                    .map(|rd| ApRecord::new(qname.clone(), ttl, rd))
                    .collect();
                records_resp(request, recs)
            }
            RewriteTarget::Cname(target_name) => {
                let cname = ApRecord::new(qname.clone(), ttl, ApRData::Cname(target_name.clone()));
                let mut recs = vec![cname];
                if qtype != ApRt::CNAME {
                    let mut sub = request.clone();
                    if let Some(question) = sub.questions.first_mut() {
                        question.name = target_name.clone();
                        question.qtype = qtype;
                    }
                    let Some(ans) = self.resolve_message_for(&sub, client) else {
                        return error_resp(request, ResponseCode::ServFail);
                    };
                    if ans.header.rcode != ResponseCode::NoError.0
                        || !response_has_requested_answer(&sub, &ans)
                    {
                        return error_resp(request, ResponseCode::ServFail);
                    }
                    recs.extend(ans.answers);
                }
                records_resp(request, recs)
            }
        }
    }
}

/** @brief 출발지 주소를 한 형태로 맞춘다. IPv4를 담은 IPv6 표기를 펴지 않으면 같은 주소가 제한을 두 번 받는다. */
fn canonical_source_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/** @brief 전송 종류를 공통 표현으로. */
fn core_transport(t: RtTransport) -> Transport {
    match t {
        RtTransport::Do53Udp => Transport::Do53Udp,
        RtTransport::Do53Tcp => Transport::Do53Tcp,
        RtTransport::DoT => Transport::DoT,
        RtTransport::DoH => Transport::DoH,
        RtTransport::DoH3 => Transport::DoH3,
        RtTransport::DoQ => Transport::DoQ,
        RtTransport::DnsCrypt => Transport::DnsCrypt,
    }
}

/** @brief 전송 종류를 기록 형식의 표현으로. */
fn dnstap_proto(t: RtTransport) -> onetdns_control::DnstapProtocol {
    match t {
        RtTransport::Do53Udp => onetdns_control::DnstapProtocol::Udp,
        RtTransport::Do53Tcp => onetdns_control::DnstapProtocol::Tcp,
        RtTransport::DoT => onetdns_control::DnstapProtocol::Dot,
        RtTransport::DoH | RtTransport::DoH3 => onetdns_control::DnstapProtocol::Doh,
        RtTransport::DoQ => onetdns_control::DnstapProtocol::Doq,
        RtTransport::DnsCrypt => onetdns_control::DnstapProtocol::DnscryptUdp,
    }
}

/** @brief 요청에 담긴 쿠키. */
fn read_cookie(request: &Message) -> Option<Vec<u8>> {
    let opt = request.opt()?;
    let edns = Edns::from_record(opt)?;
    edns.options
        .iter()
        .find(|(c, _)| *c == OPT_COOKIE)
        .map(|(_, b)| b.clone())
}

/**
 * @brief 클라이언트와 이 서버의 사이에서만 뜻이 있는 옵션을 뗀다.
 * @warning 떼지 않고 업스트림으로 넘기면 그 옵션이 업스트림에 이 서버의 클라이언트 정보를 흘리거나,
 *          응답 캐시 키를 쓸데없이 구분한다.
 */
fn strip_client_hop_edns(request: &mut Message) {
    request
        .additionals
        .retain(|record| record.rtype != ApRt(250));
    for record in &mut request.additionals {
        if record.rtype != ApRt::OPT {
            continue;
        }
        let Some(mut edns) = Edns::from_record(record) else {
            continue;
        };
        edns.options.retain(|(code, _)| {
            !matches!(
                *code,
                OPT_COOKIE
                    | OPT_NSID
                    | onetdns_proto::EDNS_TCP_KEEPALIVE
                    | onetdns_proto::EDNS_PADDING
            )
        });
        *record = edns
            .try_to_record()
            .expect("EDNS 옵션을 제거한 레코드는 원본보다 커질 수 없음");
    }
}

/**
 * @brief 응답 OPT에 알릴 UDP 크기.
 * @details 설정이 512보다 작으면 기본값으로 올린다. 빠른 경로와 구조적 경로가 같은 값을
 *          알려야 한다. 어긋나면 같은 질의에 경로마다 다른 바이트가 나간다.
 */
fn advertised_udp_payload(configured: u16) -> u16 {
    if configured < 512 {
        DEFAULT_EDNS_PAYLOAD
    } else {
        configured
    }
}

/** @brief 응답에 담을 기본 옵션. */
fn base_edns(request: &Message, udp_payload: u16) -> Edns {
    let payload = advertised_udp_payload(udp_payload);
    let mut edns = request
        .opt()
        .and_then(Edns::from_record)
        .unwrap_or_default();
    edns.udp_payload = payload;
    edns.extended_rcode = 0;
    edns.version = 0;
    edns.options.clear();
    edns
}

/** @brief 쿠키를 담은 응답 옵션. */
fn cookie_edns(request: &Message, cookie: Vec<u8>, udp_payload: u16) -> Edns {
    let mut edns = base_edns(request, udp_payload);
    edns.options.push((OPT_COOKIE, cookie));
    edns
}

/** @brief 검증됐다는 표시를 지운다. 이 서버가 검증하지 않은 것을 검증됐다고 하면 안 된다. */
fn clear_dnssec_assertion(message: &mut Message) {
    message.header.authentic_data = false;
    let is_proof =
        |record: &ApRecord| matches!(record.rtype, ApRt::RRSIG | ApRt::NSEC | ApRt::NSEC3);
    message.answers.retain(|record| !is_proof(record));
    message.authorities.retain(|record| !is_proof(record));
    message.additionals.retain(|record| !is_proof(record));
}

#[cfg(unix)]
/**
 * @brief 리액터의 대체 처리 경로가 막혔음을 알린다.
 * @details 이 경로가 막히면 리액터가 풀지 못한 질의를 그 자리에서 동기로 풀어, 수신
 *          루프가 그동안 멈춘다. 질의마다 호출되는 경로라 2의 거듭제곱 번째만 남긴다.
 */
fn reactor_fallback_unavailable() {
    /** @brief 누적 횟수. */
    static COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        onetdns_core::warn!(event = "reactor.fallback_unavailable", count = count, "리액터의 대체 처리 경로가 닫혀 질의를 수신 루프에서 바로 풀었습니다. 그동안 다른 질의가 밀립니다");
    }
}

/**
 * @brief 클라이언트를 막아 답하지 않았음을 알린다.
 * @details 접근 제한과 속도 제한 판정은 통계 기록기에만 남았다. 기록기를 끈 배포에서는
 *          "왜 아무것도 안 되는지"를 알 방법이 없다. 판정마다 호출되는 경로라 종류별로
 *          2의 거듭제곱 번째만 남긴다.
 */
fn note_rejection(action: Action, client: &ClientInfo) {
    /** @brief 접근 제한에 막힌 누적 수. */
    static DENIED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    /** @brief 속도 제한에 막힌 누적 수. */
    static THROTTLED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let (counter, denied) = match action {
        Action::Denied => (&DENIED, true),
        Action::Throttled => (&THROTTLED, false),
        _ => return,
    };
    let count = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    if !count.is_power_of_two() {
        return;
    }
    if denied {
        onetdns_core::warn!(event = "dns.client_rejected", reason = "acl", client = %client.source_ip, count = count, "접근을 허용하지 않은 주소의 질의를 막았습니다");
    } else {
        onetdns_core::warn!(event = "dns.client_rejected", reason = "rate_limit", client = %client.source_ip, count = count, "속도 제한에 걸린 질의를 막았습니다");
    }
}

/**
 * @brief 질의를 풀지 못해 SERVFAIL로 답했음을 알린다.
 * @details 통계 기록기를 끈 배포에서는 이 기록이 해석 실패를 알 수 있는 유일한 경로다.
 *          질의마다 호출되는 경로라 2의 거듭제곱 번째만 남긴다.
 */
fn resolution_failed(reason: &'static str, stage: &'static str, name: Option<&ApName>) {
    /** @brief 누적 실패 수. */
    static COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    if !count.is_power_of_two() {
        return;
    }
    let qname = name.map(|n| n.to_ascii_lower()).unwrap_or_default();
    onetdns_core::warn!(event = "dns.resolution_failed", reason = reason, stage = stage, qname = %qname, count = count, "질의를 풀지 못해 SERVFAIL로 답했습니다");
}

/**
 * @brief 클라이언트가 보낸 ECS 옵션을 응답에 그대로 돌려줄 형태로 만든다.
 *
 * @details RFC 7871은 FAMILY, SOURCE PREFIX-LENGTH, ADDRESS 를 질의의 것과 같게
 *          하라고 한다. SCOPE 는 0 으로 둔다. 이 서버는 설정된 고정 대역으로 업스트림에 묻기
 *          때문에 어느 클라이언트에게나 같은 답이 나가고, 0 이 아닌 값을 적으면 하류가
 *          그 대역 전용 답으로 잘못 담는다.
 * @param raw 질의에 실려 온 옵션 바이트.
 * @return 그대로 돌려줄 바이트. 앞 4바이트가 없거나 주소가 SOURCE 를 덮지 못하면 없음.
 */
fn echoed_client_subnet(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() < 4 {
        return None;
    }
    let source = raw[2];
    if usize::from(source).div_ceil(8) != raw.len() - 4 {
        return None;
    }
    let mut echo = raw.to_vec();
    echo[3] = 0;
    Some(echo)
}

/** @brief 내보내기 전에 응답을 다듬는다. */
fn postprocess(
    f: &NativeFeatures,
    msg: &mut Message,
    request: &Message,
    ctx: &RequestCtx,
) -> Result<(), ProtoError> {
    if f.minimal_responses && msg.header.rcode == ResponseCode::NoError.0 && !msg.answers.is_empty()
    {
        msg.authorities.clear();
        msg.additionals
            .retain(|r| r.rtype == onetdns_proto::RecordType::OPT);
    }
    if let Some(to) = f.tcp_keepalive_100ms {
        let tcp = matches!(ctx.transport, RtTransport::Do53Tcp | RtTransport::DoT);
        let asked = request
            .opt()
            .and_then(Edns::from_record)
            .map(|e| e.has_option(onetdns_proto::EDNS_TCP_KEEPALIVE))
            .unwrap_or(false);
        if tcp && asked {
            msg.set_tcp_keepalive(to)?;
        }
    }

    // RFC 7871: 대역 정보를 쓰는 서버는 클라이언트가 그 옵션을 보냈을 때만, 그러나
    // 보냈으면 반드시 응답에도 담아야 한다. 하류가 전달 리졸버면 이 값으로 자기 캐시의
    // 범위를 정하므로, 없으면 대역별 답을 모두에게 주는 캐시가 된다.
    if f.ecs_in_use {
        if let Some(echo) = request
            .opt()
            .and_then(Edns::from_record)
            .and_then(|e| e.client_subnet().map(<[u8]>::to_vec))
            .and_then(|raw| echoed_client_subnet(&raw))
        {
            msg.set_client_subnet(echo)?;
        }
    }

    if f.padding_block > 0 && request.requested_padding() {
        msg.pad_to(f.padding_block)?;
    }
    Ok(())
}

/**
 * @brief 리액터 경로 응답의 OPT를 이 서버의 값으로 바꾼다.
 *
 * @details 동기 경로에서는 finalize가 하는 일이다. 이 경로는 그것을 거치지 않아, 두지 않으면
 *          재귀가 업스트림 권한 서버에서 담아 온 OPT가 그대로 나간다. 이 서버가 광고한 적 없는
 *          버퍼 크기와 남의 DO 비트다. RFC 6891은 요청에 OPT가 있을 때만 응답에 넣게
 *          하고, RFC 3225는 DO를 질의에서 복사하게 한다. base_edns가 그 둘을 지킨다.
 * @note 리액터 경로가 unix 에만 있으므로 이 함수도 그렇다. 붙이지 않으면 다른 platform 에서
 *       호출하는 곳이 없어 죽은 코드가 된다.
 */
#[cfg(unix)]
fn reactor_response_edns(f: &NativeFeatures, msg: &mut Message, request: &Message) {
    // 이 서버가 붙인 확장 오류는 살린다. 재귀는 bogus 판정의 사유를 이 옵션으로 담아 오고,
    // 동기 경로도 같은 사유를 담아 내보내므로 여기서 지우면 두 경로의 답이 갈린다.
    let carried: Vec<(u16, Vec<u8>)> = msg
        .opt()
        .and_then(Edns::from_record)
        .map(|edns| {
            edns.options
                .into_iter()
                .filter(|(code, _)| *code == onetdns_proto::EDE_OPTION)
                .collect()
        })
        .unwrap_or_default();
    msg.additionals
        .retain(|r| r.rtype != onetdns_proto::RecordType::OPT);
    if request.opt().is_none() {
        return;
    }
    let mut edns = base_edns(request, f.edns_buffer);
    edns.options = carried;
    if let Ok(record) = edns.try_to_record() {
        msg.additionals.push(record);
    }
}

/** @brief 옵션을 붙여 응답을 마무리한다. */
fn finalize(mut msg: Message, edns: Option<Edns>) -> Message {
    // 요청에 OPT가 없으면 응답에도 없어야 한다. RFC 6891이 그렇게 정한다. 업스트림이나
    // 재귀가 담아 온 OPT를 그대로 흘리면 이 서버가 광고한 적 없는 버퍼 크기와 남의 DO 비트가
    // 클라이언트에 나간다.
    msg.additionals
        .retain(|r| r.rtype != onetdns_proto::RecordType::OPT);
    if let Some(e) = edns {
        msg.additionals.push(
            e.try_to_record()
                .expect("내부에서 제한한 응답 EDNS는 인코딩 가능"),
        );
    }
    msg
}

/** @brief 사유 코드의 문구. */
pub(crate) fn ede_text(code: u16) -> &'static str {
    use onetdns_proto::ede_code as ec;
    match code {
        ec::OTHER => "recursion limit exceeded",
        ec::DNSSEC_BOGUS => "DNSSEC validation failed",
        ec::NO_REACHABLE_AUTHORITY => "no reachable authority",
        ec::NETWORK_ERROR => "network error",
        _ => "",
    }
}

/** @brief 응답에 사유를 붙인다. */
fn with_ede(
    edns: Option<Edns>,
    request: &Message,
    buf: u16,
    code: u16,
    text: &str,
) -> Option<Edns> {
    let mut e = match edns {
        Some(e) => e,
        None if request.opt().is_some() => base_edns(request, buf),
        None => return None,
    };
    e.push_ede(code, text);
    Some(e)
}

/** @brief 기록에 담긴 주소. */
fn rdata_ip(rd: &ApRData) -> Option<IpAddr> {
    match rd {
        ApRData::A(a) => Some(IpAddr::V4(*a)),
        ApRData::Aaaa(a) => Some(IpAddr::V6(*a)),
        _ => None,
    }
}

/** @brief 기록의 주소가 이 대역들에 드는지. */
fn rdata_in_nets(rd: &ApRData, nets: &[IpNet]) -> bool {
    rdata_ip(rd).is_some_and(|ip| nets.iter().any(|n| n.contains(&ip)))
}

/** @brief 지어낼 답에 쓸 부정 수명. */
fn dns64_negative_ttl(response: &Message) -> Option<u32> {
    response.authorities.iter().find_map(|record| {
        if let ApRData::Soa(soa) = &record.rdata {
            Some(record.ttl.min(soa.minimum))
        } else {
            None
        }
    })
}

/** @brief IPv4 주소로 IPv6 주소를 임의로 만든다. IPv6만 되는 망에서 IPv4만 있는 곳에 닿게 하려는 것이다. */
fn synthesize_dns64(
    answers: &[ApRecord],
    prefix: &[u8; 16],
    ttl_cap: Option<u32>,
) -> Vec<ApRecord> {
    answers
        .iter()
        .filter_map(|record| {
            if let ApRData::A(address) = &record.rdata {
                let mut v6 = *prefix;
                v6[12..16].copy_from_slice(&address.octets());
                let ttl = ttl_cap.map_or(record.ttl, |cap| record.ttl.min(cap));
                Some(ApRecord::new(
                    record.name.clone(),
                    ttl,
                    ApRData::Aaaa(Ipv6Addr::from(v6)),
                ))
            } else {
                None
            }
        })
        .collect()
}

/** @brief 기록에 내부망 주소가 담겼는지. */
fn is_private_rdata(rd: &ApRData) -> bool {
    match rd {
        ApRData::A(address) => is_private_v4(*address),
        ApRData::Aaaa(address) => is_private_v6(*address),
        ApRData::Svcb { params, .. } | ApRData::Https { params, .. } => {
            params.iter().any(|(key, value)| match *key {
                4 => {
                    value.len() % 4 != 0
                        || value.chunks_exact(4).any(|bytes| {
                            is_private_v4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
                        })
                }
                6 => {
                    value.len() % 16 != 0
                        || value.chunks_exact(16).any(|bytes| {
                            let mut octets = [0u8; 16];
                            octets.copy_from_slice(bytes);
                            is_private_v6(Ipv6Addr::from(octets))
                        })
                }
                _ => false,
            })
        }
        _ => false,
    }
}

/**
 * @brief 답에서 내부망 주소를 뺀다.
 * @warning 밖의 이름이 이 서버의 내부 주소를 가리키면 브라우저가 그 이름의 권한으로 내부망에
 *          접근한다. 그것을 막는 것이다.
 */
fn strip_private_records(message: &mut Message) -> bool {
    let before = message.answers.len() + message.authorities.len() + message.additionals.len();
    message
        .answers
        .retain(|record| !is_private_rdata(&record.rdata));
    message
        .authorities
        .retain(|record| !is_private_rdata(&record.rdata));
    message
        .additionals
        .retain(|record| !is_private_rdata(&record.rdata));
    before != message.answers.len() + message.authorities.len() + message.additionals.len()
}

/** @brief 밖에 있을 수 없는 IPv4 주소인지. */
fn is_private_v4(ip: Ipv4Addr) -> bool {
    let value = u32::from(ip);
    let in_net = |network: [u8; 4], prefix: u8| {
        let mask = u32::MAX << (32 - prefix);
        value & mask == u32::from(Ipv4Addr::from(network)) & mask
    };
    in_net([0, 0, 0, 0], 8)
        || in_net([10, 0, 0, 0], 8)
        || in_net([100, 64, 0, 0], 10)
        || in_net([127, 0, 0, 0], 8)
        || in_net([169, 254, 0, 0], 16)
        || in_net([172, 16, 0, 0], 12)
        || in_net([192, 0, 0, 0], 24)
        || in_net([192, 0, 2, 0], 24)
        || in_net([192, 88, 99, 0], 24)
        || in_net([192, 168, 0, 0], 16)
        || in_net([198, 18, 0, 0], 15)
        || in_net([198, 51, 100, 0], 24)
        || in_net([203, 0, 113, 0], 24)
        || in_net([224, 0, 0, 0], 4)
        || in_net([240, 0, 0, 0], 4)
}

/** @brief 밖에 있을 수 없는 IPv6 주소인지. */
fn is_private_v6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_private_v4(mapped);
    }
    let octets = ip.octets();
    let seg0 = ip.segments()[0];
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (seg0 & 0xfe00) == 0xfc00
        || (seg0 & 0xffc0) == 0xfe80
        || octets[..4] == [0x20, 0x01, 0x0d, 0xb8]
        || octets[..8] == [0x01, 0x00, 0, 0, 0, 0, 0, 0]
        || octets[..4] == [0x20, 0x01, 0x00, 0x02]
}

/** @brief 재귀로 받은 응답을 클라이언트에 낼 형태로 맞춘다. */
fn normalize_recursive_response(response: &mut Message, request: &Message) {
    response.header.id = request.header.id;
    response.header.response = true;
    response.header.opcode = request.header.opcode;
    response.header.recursion_desired = request.header.recursion_desired;
    response.header.recursion_available = true;
    response.header.checking_disabled = request.header.checking_disabled;
    let same_questions = response.questions.len() == request.questions.len()
        && response
            .questions
            .iter()
            .zip(&request.questions)
            .all(|(response, request)| {
                response.name == request.name
                    && response.qtype == request.qtype
                    && response.qclass == request.qclass
            });
    if !same_questions {
        response.questions.clone_from(&request.questions);
    }
}

/** @brief 없다는 것을 뒷받침하는 권한 기록이 실렸는지. */
fn has_negative_soa(response: &Message) -> bool {
    response
        .authorities
        .iter()
        .any(|record| record.rtype == ApRt::SOA)
}

/** @brief 답에 별칭이 실렸는지. */
fn has_alias_answer(response: &Message) -> bool {
    response
        .answers
        .iter()
        .any(|record| matches!(&record.rdata, ApRData::Cname(_) | ApRData::Dname(_)))
}

/** @brief 다른 서버로 가라는 응답인지. */
fn is_delegation_referral(response: &Message) -> bool {
    !response.header.authoritative
        && response.answers.is_empty()
        && response
            .authorities
            .iter()
            .any(|record| record.rtype == ApRt::NS)
}

/** @brief 기록에 남길 답 요약. */
fn answers_summary(answers: &[ApRecord]) -> String {
    /** @brief 요약에 담을 항목 수. */
    const MAX: usize = 5;
    let mut parts: Vec<String> = answers
        .iter()
        .take(MAX)
        .map(|record| {
            let value = rdata_brief(&record.rdata);
            if value.is_empty() {
                record.rtype.name().to_string()
            } else {
                format!("{} {value}", record.rtype.name())
            }
        })
        .collect();
    if answers.len() > MAX {
        parts.push(format!("외 {}개", answers.len() - MAX));
    }
    parts.join(" · ")
}

/** @brief 기록 하나를 짧은 문자열로. */
pub(crate) fn rdata_brief(rdata: &ApRData) -> String {
    match rdata {
        ApRData::A(ip) => ip.to_string(),
        ApRData::Aaaa(ip) => ip.to_string(),
        ApRData::Cname(n) | ApRData::Ns(n) | ApRData::Ptr(n) | ApRData::Dname(n) => {
            n.to_ascii_lower()
        }
        ApRData::Mx {
            preference,
            exchange,
        } => format!("{preference} {}", exchange.to_ascii_lower()),
        ApRData::Txt(parts) => {
            let text = parts
                .first()
                .map(|p| String::from_utf8_lossy(p).to_string())
                .unwrap_or_default();
            if text.chars().count() > 60 {
                let head: String = text.chars().take(60).collect();
                format!("{head}…")
            } else {
                text
            }
        }
        ApRData::Soa(s) => s.mname.to_ascii_lower(),
        ApRData::Srv {
            priority,
            weight,
            port,
            target,
        } => format!("{priority} {weight} {port} {}", target.to_ascii_lower()),
        _ => String::new(),
    }
}

/** @brief 질문한 것이 실제로 답에 들어 있는지. 별칭을 따라가며 본다. */
fn response_has_requested_answer(request: &Message, response: &Message) -> bool {
    let Some(question) = request.questions.first() else {
        return !response.answers.is_empty();
    };
    if question.qtype == ApRt::ANY {
        return !response.answers.is_empty();
    }

    let mut current = question.name.clone();
    let mut seen = HashSet::<Vec<u8>>::new();
    for _ in 0..16 {
        if response
            .answers
            .iter()
            .any(|record| record.name.eq_ignore_case(&current) && record.rtype == question.qtype)
        {
            return true;
        }
        if !seen.insert(current.canonical_key()) {
            return false;
        }
        let target = response
            .answers
            .iter()
            .find_map(|record| {
                if record.name.eq_ignore_case(&current) {
                    if let ApRData::Cname(target) = &record.rdata {
                        return Some(target.clone());
                    }
                }
                None
            })
            .or_else(|| dname_answer_target(&current, &response.answers));
        let Some(target) = target else {
            return false;
        };
        current = target;
    }
    false
}

/** @brief 통째 옮김 기록이 가리키는 이름. */
fn dname_answer_target(current: &ApName, answers: &[ApRecord]) -> Option<ApName> {
    let record = answers
        .iter()
        .filter(|record| {
            matches!(&record.rdata, ApRData::Dname(_))
                && current.num_labels() > record.name.num_labels()
                && current
                    .suffix(record.name.num_labels())
                    .eq_ignore_case(&record.name)
        })
        .max_by_key(|record| record.name.num_labels())?;
    let ApRData::Dname(target_suffix) = &record.rdata else {
        return None;
    };
    let prefix_len = current.num_labels() - record.name.num_labels();
    let mut labels: Vec<Vec<u8>> = current
        .labels()
        .take(prefix_len)
        .map(<[u8]>::to_vec)
        .collect();
    labels.extend(target_suffix.labels().map(<[u8]>::to_vec));
    ApName::from_labels(labels).ok()
}

/** @brief 이 요청에 대한 빈 응답 뼈대. */
fn base_response(request: &Message) -> Message {
    let mut m = Message::default();
    m.header.id = request.header.id;
    m.header.response = true;
    m.header.opcode = request.header.opcode;
    m.header.recursion_desired = request.header.recursion_desired;
    m.header.recursion_available = true;
    m.questions = request.questions.clone();
    m
}

/** @brief 현재 Unix 초. */
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/** @brief 영역 꼭대기 이름을 가리키는 키. */
fn apex_key(name: &ApName) -> Vec<u8> {
    name.canonical_key()
}

/** @brief 시리얼만 바꾼 권한 기록. */
fn soa_with_serial(soa: &ApRecord, serial: u32) -> ApRecord {
    let mut r = soa.clone();
    if let ApRData::Soa(s) = &mut r.rdata {
        s.serial = serial;
    }
    r
}

/** @brief 이 코드의 오류 응답. */
fn error_resp(request: &Message, code: ResponseCode) -> Message {
    let mut m = base_response(request);
    m.header.rcode = code.0;
    m
}

/**
 * @brief 요청이 담은 OPT를 그대로 돌려주는 오류 응답.
 *
 * @details RFC 6891은 요청에 OPT가 있으면 응답에도 넣게 한다. 빼면 상대는 이 서버가
 *          EDNS를 모르는 것으로 보고 512바이트로 전환하므로, 형식 오류 하나가 그 뒤 모든
 *          질의의 버퍼 크기를 깎는다. 요청에 OPT가 없으면 응답에도 넣지 않는다.
 * @param udp_payload 이 서버가 광고할 버퍼 크기.
 */
fn edns_error_resp(request: &Message, code: ResponseCode, udp_payload: u16) -> Message {
    let edns = request.opt().map(|_| base_edns(request, udp_payload));
    finalize(error_resp(request, code), edns)
}

/** @brief 서명 없이 내보내는 오류 응답. 키를 모르는 상대에게는 서명할 수 없다. */
fn unsigned_tsig_error_response(
    request: &Message,
    request_tsig: &onetdns_dnssec::tsig::TsigRecordData,
    error: onetdns_dnssec::tsig::UnsignedTsigError,
    udp_payload: u16,
) -> Message {
    let mut response = edns_error_resp(request, ResponseCode(9), udp_payload);
    onetdns_dnssec::tsig::append_unsigned_error(&mut response, request_tsig, error);
    if response.try_encode().is_err() {
        response.questions.clear();
        response.additionals.clear();
        onetdns_dnssec::tsig::append_unsigned_error(&mut response, request_tsig, error);
    }
    response
}

/** @brief 시각이 어긋났다는 오류에 서명해 답한다. 상대가 시각을 맞출 수 있게 이 서버의 시각을 담는다. */
fn signed_badtime_response(
    request: &Message,
    key: &onetdns_dnssec::tsig::TsigKey,
    request_tsig: &onetdns_dnssec::tsig::VerifiedTsig,
    server_now: u64,
    udp_payload: u16,
) -> Message {
    let mut response = edns_error_resp(request, ResponseCode(9), udp_payload);
    if onetdns_dnssec::tsig::sign_badtime_response(&mut response, key, request_tsig, server_now)
        .is_err()
    {
        response.questions.clear();
        response.additionals.clear();
        onetdns_dnssec::tsig::sign_badtime_response(&mut response, key, request_tsig, server_now)
            .expect("최소 BADTIME 응답은 TSIG 서명 전에 항상 인코딩 가능");
    }
    response
}

/** @brief 오류 응답에 서명해 답한다. */
fn signed_tsig_error_response(
    request: &Message,
    key: &onetdns_dnssec::tsig::TsigKey,
    request_tsig: &onetdns_dnssec::tsig::VerifiedTsig,
    code: ResponseCode,
    udp_payload: u16,
) -> Message {
    let mut response = edns_error_resp(request, code, udp_payload);
    if onetdns_dnssec::tsig::sign_response_message(&mut response, key, now_unix(), request_tsig)
        .is_err()
    {
        response.questions.clear();
        response.additionals.clear();
        onetdns_dnssec::tsig::sign_response_message(&mut response, key, now_unix(), request_tsig)
            .expect("최소 TSIG 오류 응답은 서명 전에 항상 인코딩 가능");
    }
    response
}

/** @brief 이 기록들을 답으로 담은 응답. */
/**
 * @brief ANY를 온전히 답하지 않을 때 대신 내보내는 합성 HINFO.
 *
 * @details RFC 8482가 정한 모양이다. CPU 필드에 RFC8482, OS 필드에 빈 문자열을 넣는다.
 *          질의자는 이것을 보고 이 응답이 온전한 ANY가 아님을 안다. 절단 비트는 설정하지
 *          않는다. 잘린 것이 아니라 이것이 답이기 때문이다.
 * @note HINFO(13)는 이 서버의 codec이 구조로 다루지 않는 종류라 wire 바이트로 만든다. 두
 *       character-string이 길이 프리픽스를 달고 이어지는 형식이다.
 */
fn rfc8482_hinfo(qname: &ApName) -> ApRecord {
    /** @brief 합성 HINFO의 수명. 질의자가 오래 붙들 이유가 없는 값이다. */
    const TTL: u32 = 3600;
    let mut wire = Vec::with_capacity(9);
    wire.push(b"RFC8482".len() as u8);
    wire.extend_from_slice(b"RFC8482");
    wire.push(0);
    ApRecord {
        name: qname.clone(),
        rtype: ApRt(13),
        class: DnsClass::IN,
        ttl: TTL,
        rdata: ApRData::Unknown(13, wire),
    }
}

fn records_resp(request: &Message, answers: Vec<ApRecord>) -> Message {
    let mut m = base_response(request);
    m.header.rcode = ResponseCode::NoError.0;
    m.answers = answers;
    m
}

/**
 * @brief 밖에 물어보면 안 되는 이름에 돌려줄 부정 응답.
 * @details 로컬에서 아무도 답하지 못했을 때만 쓰인다. 정책이 막았을 때와 같은 모양이다.
 */
pub(crate) fn local_only_negative_response(request: &Message, qname: &ApName, ttl: u32) -> Message {
    policy_negative_resp(request, qname, ResponseCode::NXDomain, ttl)
}

/** @brief 정책이 막았을 때의 응답. */
fn policy_negative_resp(
    request: &Message,
    qname: &ApName,
    code: ResponseCode,
    ttl: u32,
) -> Message {
    let mut response = error_resp(request, code);
    let mname = ApName::from_str("blocked.invalid").unwrap_or_else(|_| ApName::root());
    let rname = ApName::from_str("hostmaster.blocked.invalid").unwrap_or_else(|_| ApName::root());
    response.authorities.push(ApRecord::new(
        qname.clone(),
        ttl,
        ApRData::soa(onetdns_proto::Soa {
            mname,
            rname,
            serial: 1,
            refresh: ttl,
            retry: ttl,
            expire: ttl.saturating_mul(24).max(ttl),
            minimum: ttl,
        }),
    ));
    response
}

/** @brief 영역 전송 한 청크에 담을 크기. */
const XFR_CHUNK_BUDGET: usize = onetdns_authority::XFR_CHUNK_BUDGET;

/** @brief 한 청크로 끝나는 영역 전송 응답. */
fn xfr_single_response(
    request: &Message,
    rcode: ResponseCode,
    answer: Option<ApRecord>,
    truncated: bool,
    tsig_ctx: Option<&TsigContext>,
) -> Message {
    let mut response = base_response(request);
    response.additionals.clear();
    response.header.authoritative = true;
    response.header.rcode = rcode.0;
    response.header.truncated = truncated;
    response.answers.extend(answer);
    if let Some((key, request_tsig)) = tsig_ctx {
        onetdns_dnssec::tsig::sign_response_message(&mut response, key, now_unix(), request_tsig)
            .expect("크기가 제한된 단일 XFR 응답은 TSIG 서명 전에 인코딩 가능");
    }
    response
}

/** @brief 영역을 여러 청크로 나눠 보낸다. */
fn xfr_envelopes_stream<I>(
    request: &Message,
    records: I,
    tsig_ctx: Option<TsigContext>,
    emit: &mut dyn FnMut(Message) -> bool,
) -> bool
where
    I: IntoIterator<Item = ApRecord>,
{
    let mut chunk = Vec::new();
    let mut size = 0usize;
    let mut index = 0usize;
    let mut prev_mac = None;

    let mut estimate_writer = onetdns_proto::Writer::new();
    for r in records {
        estimate_writer.clear();
        r.encode(&mut estimate_writer);
        let est = estimate_writer.buf.len();
        if size + est > XFR_CHUNK_BUDGET && !chunk.is_empty() {
            let message = xfr_envelope(
                request,
                std::mem::take(&mut chunk),
                index,
                &tsig_ctx,
                &mut prev_mac,
            );
            if !emit(message) {
                return false;
            }
            index += 1;
            size = 0;
        }
        size += est;
        chunk.push(r);
    }
    emit(xfr_envelope(
        request,
        chunk,
        index,
        &tsig_ctx,
        &mut prev_mac,
    ))
}

/** @brief 영역 전송 청크 하나. */
fn xfr_envelope(
    request: &Message,
    answers: Vec<ApRecord>,
    index: usize,
    tsig_ctx: &Option<TsigContext>,
    prev_mac: &mut Option<Vec<u8>>,
) -> Message {
    let mut message = base_response(request);
    message.additionals.clear();
    message.header.authoritative = true;
    if index > 0 {
        message.questions.clear();
    }
    message.answers = answers;
    if let Some((key, request_tsig)) = tsig_ctx {
        let mac = if index == 0 {
            onetdns_dnssec::tsig::sign_response_message(&mut message, key, now_unix(), request_tsig)
        } else {
            onetdns_dnssec::tsig::sign_response_subsequent(
                &mut message,
                key,
                now_unix(),
                prev_mac.as_deref().unwrap_or(&[]),
                request_tsig,
            )
        }
        .expect("16KiB로 제한한 XFR 엔벨로프는 TSIG 서명 전에 인코딩 가능");
        *prev_mac = Some(mac);
    }
    message
}

/**
 * @brief 응답 코드의 이름.
 * @note 아는 코드는 정적 문자열을 그대로 빌려 준다. 질의마다 실행되는 경로라 이름 하나를
 *       힙에 옮겨 담지 않는다.
 */
pub(crate) fn rcode_str(code: ResponseCode) -> std::borrow::Cow<'static, str> {
    let name = match code.0 {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        16 => "BADVERS_OR_BADSIG",
        17 => "BADKEY",
        18 => "BADTIME",
        19 => "BADMODE",
        20 => "BADNAME",
        21 => "BADALG",
        22 => "BADTRUNC",
        23 => "BADCOOKIE",
        _ => return std::borrow::Cow::Owned(format!("UNKNOWN({})", code.0)),
    };
    std::borrow::Cow::Borrowed(name)
}

/** @brief 차단 방식과 질의 종류에 맞는 응답 코드. */
pub(crate) fn block_rcode(br: &BlockResponse, qtype: ApRt) -> ResponseCode {
    match br {
        BlockResponse::NxDomain => ResponseCode::NXDomain,
        BlockResponse::Refused => ResponseCode::Refused,
        BlockResponse::NoData | BlockResponse::ZeroIp => ResponseCode::NoError,
        BlockResponse::Custom { v4, v6 } => {
            let has = match qtype {
                ApRt::A => v4.is_some(),
                ApRt::AAAA => v6.is_some(),
                _ => false,
            };
            if has {
                ResponseCode::NoError
            } else {
                ResponseCode::NXDomain
            }
        }
    }
}

/** @brief 차단 응답을 만든다. */
fn block_resp(
    request: &Message,
    qname: &ApName,
    qtype: ApRt,
    br: BlockResponse,
    block_ttl: u32,
) -> Message {
    match br {
        BlockResponse::NxDomain => {
            policy_negative_resp(request, qname, ResponseCode::NXDomain, block_ttl)
        }
        BlockResponse::Refused => error_resp(request, ResponseCode::Refused),
        BlockResponse::NoData => {
            policy_negative_resp(request, qname, ResponseCode::NoError, block_ttl)
        }
        BlockResponse::ZeroIp => {
            let recs = custom_ip_records(
                qname,
                qtype,
                Some(Ipv4Addr::UNSPECIFIED),
                Some(Ipv6Addr::UNSPECIFIED),
                block_ttl,
            );
            records_resp(request, recs)
        }
        BlockResponse::Custom { v4, v6 } => {
            let recs = custom_ip_records(qname, qtype, v4, v6, block_ttl);
            if recs.is_empty() {
                policy_negative_resp(request, qname, ResponseCode::NXDomain, block_ttl)
            } else {
                records_resp(request, recs)
            }
        }
    }
}

/** @brief 지정한 주소를 답으로 담은 기록들. */
fn custom_ip_records(
    qname: &ApName,
    qtype: ApRt,
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
    block_ttl: u32,
) -> Vec<ApRecord> {
    match qtype {
        ApRt::A => v4
            .map(|a| vec![ApRecord::new(qname.clone(), block_ttl, ApRData::A(a))])
            .unwrap_or_default(),
        ApRt::AAAA => v6
            .map(|a| vec![ApRecord::new(qname.clone(), block_ttl, ApRData::Aaaa(a))])
            .unwrap_or_default(),
        _ => vec![],
    }
}

#[cfg(test)]
/** @brief 두 빠른 경로가 보통 경로와 같은 답을 내는지, 그리고 각 관문이 실제로 막는지. */
mod tests {
    use super::*;
    use onetdns_proto::RecordType;
    use onetdns_security::IpAcl;
    use std::net::{SocketAddr, UdpSocket};
    use std::time::{Duration, Instant};

    #[test]
    /** @brief 비었는지 판정이 값과 함께 교체되는지. */
    fn gated_swap_tracks_emptiness() {
        let views: GatedSwap<Vec<NativeView>> = GatedSwap::from_pointee(Vec::new());
        assert!(!views.present(), "빈 값은 present=false");

        views.store(Arc::new(vec![NativeView::default()]));
        assert!(views.present(), "채워지면 present=true");
        assert_eq!(views.load().len(), 1);

        views.store(Arc::new(Vec::new()));
        assert!(!views.present(), "다시 비우면 present=false");

        let seeded = GatedSwap::from_pointee(vec![NativeView::default()]);
        assert!(seeded.present(), "비어 있지 않게 생성하면 처음부터 true");

        let policy = GatedSwap::from_pointee(onetdns_policy::PolicyEngine::default());
        assert!(!policy.present(), "기본 정책 엔진은 비어 있다");
    }

    /** @brief 언제나 실패하는 테스트용 체인. */
    struct FailBackend;
    impl Resolver for FailBackend {
        /** @brief 언제나 답하지 않는다. */
        fn resolve(&self, _req: &Message) -> Option<Message> {
            None
        }
    }

    #[test]
    /** @brief 다른 서버로 가라는 응답이 그대로 클라이언트에 가는지. */
    fn native_server_passes_authority_referral_to_client() {
        let root_text = "$TTL 3600\n. IN SOA ns.root. host.root. 1 3600 900 604800 3600\n. IN NS ns.root.\nns.root. IN A 127.0.1.1\ntest. IN NS ns.test.\nns.test. IN A 127.0.2.1\n";
        let zone = onetdns_authority::parse_zone(root_text, ".").unwrap();
        let mut zs = onetdns_authority::ZoneStore::new();
        zs.add(zone);
        let store = Arc::new(ArcSwap::new(Arc::new(zs)));
        let authority = Arc::new(crate::layers::AuthorityLayer::new(
            Arc::new(FailBackend) as Arc<dyn Resolver>,
            store,
        ));
        let srv = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::build_from_str(
                "",
                "",
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            authority,
            60,
        );
        let resp = srv.handle(&q("a00.z0007.test"), &ctx()).expect("응답");
        assert_eq!(
            resp.header.rcode,
            ResponseCode::NoError.0,
            "위임 아래 이름은 SERVFAIL이 아니라 권한 리퍼럴이어야 함"
        );
        assert!(resp
            .authorities
            .iter()
            .any(|a| matches!(&a.rdata, ApRData::Ns(t) if t.eq_ignore_case(&ApName::from_str("ns.test").unwrap()))));
    }

    #[test]
    /** @brief 표기가 다른 같은 주소를 하나로 보는지. 안 그러면 제한을 두 배로 받는다. */
    fn ipv4_mapped_v6_canonicalizes_to_v4() {
        let mapped: IpAddr = "::ffff:1.2.3.4".parse().unwrap();
        assert_eq!(
            canonical_source_ip(mapped),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );

        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(canonical_source_ip(v6), v6);

        let v4: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(canonical_source_ip(v4), v4);
    }

    #[test]
    /** @brief 차단 방식에 맞는 응답 코드가 나가는지. */
    fn block_rcode_reflects_actual_response() {
        assert_eq!(
            block_rcode(&BlockResponse::Refused, ApRt::A),
            ResponseCode::Refused
        );
        assert_eq!(
            block_rcode(&BlockResponse::NoData, ApRt::A),
            ResponseCode::NoError
        );
        assert_eq!(
            block_rcode(&BlockResponse::ZeroIp, ApRt::A),
            ResponseCode::NoError
        );
        assert_eq!(
            block_rcode(&BlockResponse::NxDomain, ApRt::A),
            ResponseCode::NXDomain
        );

        let custom = BlockResponse::Custom {
            v4: Some(Ipv4Addr::new(10, 0, 0, 1)),
            v6: None,
        };
        assert_eq!(block_rcode(&custom, ApRt::A), ResponseCode::NoError);
        assert_eq!(block_rcode(&custom, ApRt::AAAA), ResponseCode::NXDomain);
        assert_eq!(block_rcode(&custom, ApRt::MX), ResponseCode::NXDomain);
    }

    #[test]
    /** @brief 차단 수명을 0으로 두면 그대로 0으로 나가는지. */
    fn zero_block_ttl_is_preserved_in_synthesized_responses() {
        let request = Message::query(1, ApName::from_str("blocked.example").unwrap(), ApRt::A);
        let qname = request.questions[0].name.clone();

        let address = block_resp(&request, &qname, ApRt::A, BlockResponse::ZeroIp, 0);
        assert_eq!(address.answers[0].ttl, 0);

        let negative = policy_negative_resp(&request, &qname, ResponseCode::NXDomain, 0);
        assert_eq!(negative.authorities[0].ttl, 0);

        let missing_family = block_resp(
            &request,
            &qname,
            ApRt::AAAA,
            BlockResponse::Custom {
                v4: Some(Ipv4Addr::new(192, 0, 2, 1)),
                v6: None,
            },
            0,
        );
        assert_eq!(missing_family.header.rcode, ResponseCode::NXDomain.0);
        assert_eq!(negative_soa_ttl(&missing_family), 0);
    }

    #[test]
    /** @brief 응답 코드 이름. */
    fn rcode_str_labels() {
        assert_eq!(rcode_str(ResponseCode::NoError), "NOERROR");
        assert_eq!(rcode_str(ResponseCode::ServFail), "SERVFAIL");
        assert_eq!(rcode_str(ResponseCode::NXDomain), "NXDOMAIN");
        assert_eq!(rcode_str(ResponseCode::Refused), "REFUSED");
        assert_eq!(rcode_str(ResponseCode(9)), "NOTAUTH");
        assert_eq!(rcode_str(ResponseCode(4095)), "UNKNOWN(4095)");
    }

    /** @brief 고정 응답을 내는 테스트용 업스트림. */
    fn mock_upstream() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                if let Ok(req) = Message::parse(&buf[..n]) {
                    let mut m = base_response(&req);
                    m.header.rcode = ResponseCode::NoError.0;
                    if let Some(q) = req.questions.first() {
                        m.answers.push(ApRecord::new(
                            q.name.clone(),
                            60,
                            ApRData::A(Ipv4Addr::new(7, 7, 7, 7)),
                        ));
                    }
                    let _ = sock.send_to(&m.try_encode().unwrap(), from);
                }
            }
        });
        addr
    }

    /** @brief 자기가 권한이라고 표시해 보내는 테스트용 업스트림. */
    fn mock_upstream_authoritative() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                if let Ok(req) = Message::parse(&buf[..n]) {
                    let mut response = base_response(&req);
                    response.header.authoritative = true;
                    response.header.authentic_data = true;
                    if let Some(q) = req.questions.first() {
                        response.answers.push(ApRecord::new(
                            q.name.clone(),
                            60,
                            ApRData::A(Ipv4Addr::new(7, 7, 7, 7)),
                        ));
                    }
                    let _ = sock.send_to(&response.try_encode().unwrap(), from);
                }
            }
        });
        addr
    }

    /** @brief 검증됐다고 표시해 보내는 테스트용 업스트림. */
    fn mock_upstream_with_untrusted_ad() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            if let Ok((n, from)) = sock.recv_from(&mut buf) {
                let req = Message::parse(&buf[..n]).unwrap();
                let q = req.questions.first().unwrap();
                let mut response = base_response(&req);
                response.header.authentic_data = true;
                response.answers.push(ApRecord::new(
                    q.name.clone(),
                    60,
                    ApRData::A(Ipv4Addr::new(7, 7, 7, 7)),
                ));
                response.answers.push(ApRecord::new(
                    q.name.clone(),
                    60,
                    ApRData::Unknown(RecordType::RRSIG.0, vec![0; 32]),
                ));
                let _ = sock.send_to(&response.try_encode().unwrap(), from);
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        addr
    }

    #[test]
    /** @brief 업스트림이 설정한 검증 표시를 지우는지. 그대로 넘기면 검증하지 않은 것을 검증됐다고 하는 셈이다. */
    fn forward_backend_never_reasserts_unvalidated_ad() {
        let backend = NativeBackend::Forward(Forwarder::new(
            vec![mock_upstream_with_untrusted_ad()],
            Duration::from_secs(2),
        ));
        let response = backend
            .resolve(&q("signed.example"))
            .expect("업스트림 응답");
        assert!(!response.header.authentic_data, "로컬 검증 전에는 AD=0");
        assert!(
            response
                .answers
                .iter()
                .any(|record| record.rtype == RecordType::RRSIG),
            "클라이언트 자체 검증용 DNSSEC 레코드는 보존"
        );
    }

    /** @brief 차단 목록을 걸어 만든 테스트용 핸들러. */
    fn server(block_list: &str) -> NativeServer {
        server_with_chain(block_list, |base| base)
    }

    /**
     * @brief 기본 백엔드를 계층으로 감싼 테스트용 서버.
     * @details 밖에 물어보면 안 되는 이름을 끊는 일은 업스트림 질의 바로 앞 계층이 한다.
     *          그 계층을 빼고 테스트하면 실제 조립과 다른 것을 재게 된다.
     */
    fn server_with_chain(
        block_list: &str,
        wrap: impl FnOnce(Arc<dyn Resolver>) -> Arc<dyn Resolver>,
    ) -> NativeServer {
        let engine = onetdns_filter::build_from_str(block_list, "", BlockResponse::NxDomain);
        let base: Arc<dyn Resolver> = Arc::new(NativeBackend::Forward(Forwarder::new(
            vec![mock_upstream()],
            Duration::from_secs(2),
        )));
        NativeServer::new(
            shared_filter(ArcSwap::from_pointee(engine)),
            Arc::new(IpAcl::allow_all()),
            vec![],
            wrap(base),
            60,
        )
    }

    /** @brief 밖에 물어보면 안 되는 이름을 끊는 계층을 씌운 테스트용 서버. */
    fn server_local_only(domain_needed: bool, bogus_priv: bool, empty_zones: bool) -> NativeServer {
        let names = Arc::new(crate::layers::LocalOnlyNames::new(
            domain_needed,
            bogus_priv,
            empty_zones,
        ));
        let ttl = Arc::new(std::sync::atomic::AtomicU32::new(60));
        server_with_chain("", move |base| {
            Arc::new(crate::layers::LocalOnlyLayer::new(base, names, ttl))
        })
    }

    /** @brief 한 이름에만 답하는 테스트용 로컬 소스. 권한 영역 슬롯을 대신한다. */
    struct StaticAnswer {
        /** @brief 답할 이름. */
        name: ApName,
    }

    impl Resolver for StaticAnswer {
        /** @brief 이 이름이면 답하고, 아니면 없음. */
        fn resolve(&self, request: &Message) -> Option<Message> {
            let question = request.questions.first()?;
            if !question.name.eq_ignore_case(&self.name) {
                return None;
            }
            let mut response = Message::default();
            response.header.id = request.header.id;
            response.header.response = true;
            response.questions = request.questions.clone();
            response.answers.push(ApRecord::new(
                question.name.clone(),
                60,
                ApRData::A(std::net::Ipv4Addr::new(192, 168, 1, 50)),
            ));
            Some(response)
        }
    }

    /** @brief 로컬 원천을 먼저 보고 없으면 안으로 넘기는 테스트용 계층. */
    struct StaticFirst {
        /** @brief 로컬 원천. */
        local: Arc<dyn Resolver>,
        /** @brief 다음 계층. */
        inner: Arc<dyn Resolver>,
    }

    impl Resolver for StaticFirst {
        /** @brief 해석한다. */
        fn resolve(&self, request: &Message) -> Option<Message> {
            match self.resolve_outcome(request) {
                ResolveOutcome::Response(response) => Some(response),
                ResolveOutcome::Failure(_) => None,
            }
        }

        /** @brief 로컬이 답하면 그 답, 아니면 안쪽 결과. */
        fn resolve_outcome(&self, request: &Message) -> ResolveOutcome {
            match self.local.resolve(request) {
                Some(response) => ResolveOutcome::Response(response),
                None => self.inner.resolve_outcome(request),
            }
        }
    }

    /** @brief 테스트 중에 기능 세트를 바꾼다. */
    fn update_features(server: &NativeServer, update: impl FnOnce(&mut NativeFeatures)) {
        let mut features = (*server.features.load()).clone();
        update(&mut features);
        server.features.store(Arc::new(features));
    }

    /** @brief 테스트용 차단 엔진 슬롯. */
    fn shared_filter(filter: ArcSwap<BlockEngine>) -> Arc<SharedFilter> {
        Arc::new(SharedFilter::new(filter.load()))
    }

    #[test]
    /** @brief 권한 영역 빠른 경로를 막는 기능이 켜지면 판정도 함께 바뀌는지. */
    fn native_feature_swap_tracks_authority_wire_gates() {
        let features = NativeFeatures::default();
        let safe_search = features.safe_search.clone();
        let swap = NativeFeatureSwap::from_pointee(features);
        assert!(!swap.authority_wire_blocked());
        assert!(!swap.harden_large_queries());
        assert!(!swap.safe_search_enabled());

        let mut next = (*swap.load()).clone();
        next.block_aaaa = true;
        swap.store(Arc::new(next));
        assert!(swap.authority_wire_blocked());

        let mut next = (*swap.load()).clone();
        next.block_aaaa = false;
        next.harden_large_queries = true;
        swap.store(Arc::new(next));
        assert!(!swap.authority_wire_blocked());
        assert!(swap.harden_large_queries());

        let mut next = (*swap.load()).clone();
        next.cookies = CookiePolicy {
            keeper: Some(Arc::new(CookieKeeper::from_secret(&[1; 16]))),
            strict: false,
        };
        swap.store(Arc::new(next));
        assert!(
            !swap.authority_wire_blocked(),
            "lenient는 COOKIE 옵션이 붙은 질의만 구조적 경로로 보내야 합니다"
        );

        let mut next = (*swap.load()).clone();
        next.cookies.strict = true;
        swap.store(Arc::new(next));
        assert!(
            swap.authority_wire_blocked(),
            "strict는 쿠키 없는 질의도 BADCOOKIE로 보내야 합니다"
        );

        safe_search.store(true, Ordering::Release);
        assert!(swap.safe_search_enabled());

        let mut replacement = (*swap.load()).clone();
        replacement.harden_large_queries = false;
        replacement.safe_search = Arc::new(AtomicBool::new(false));
        swap.store(Arc::new(replacement));
        assert!(
            swap.authority_wire_blocked(),
            "추적되지 않는 safe-search 포인터 교체는 fail-closed"
        );
    }

    #[test]
    #[ignore = "microbenchmark: run with --release -- --ignored --nocapture"]
    /** @brief 같은 질의에서 기능 snapshot을 두 번 잡는 비용과 한 번 재사용하는 비용. */
    fn bench_native_feature_snapshot_reuse() {
        use std::hint::black_box;

        const ITERS: u64 = 4_000_000;
        const ROUNDS: usize = 6;

        fn once(swap: &ArcSwap<NativeFeatures>, iters: u64) -> f64 {
            let mut sink = 0usize;
            let started = Instant::now();
            for _ in 0..iters {
                let features = black_box(swap.load());
                sink ^= black_box(features.edns_buffer as usize);
                sink ^= black_box(features.events().is_some() as usize);
            }
            black_box(sink);
            started.elapsed().as_nanos() as f64 / iters as f64
        }

        fn twice(swap: &ArcSwap<NativeFeatures>, iters: u64) -> f64 {
            let mut sink = 0usize;
            let started = Instant::now();
            for _ in 0..iters {
                let identify = black_box(swap.load());
                sink ^= black_box(identify.edns_buffer as usize);
                let record = black_box(swap.load());
                sink ^= black_box(record.events().is_some() as usize);
            }
            black_box(sink);
            started.elapsed().as_nanos() as f64 / iters as f64
        }

        let swap = ArcSwap::from_pointee(NativeFeatures::default());
        black_box(once(&swap, 100_000));
        black_box(twice(&swap, 100_000));
        let mut one = Vec::with_capacity(ROUNDS);
        let mut two = Vec::with_capacity(ROUNDS);
        for round in 0..ROUNDS {
            if round % 2 == 0 {
                one.push(once(&swap, ITERS));
                two.push(twice(&swap, ITERS));
            } else {
                two.push(twice(&swap, ITERS));
                one.push(once(&swap, ITERS));
            }
        }
        let range = |values: &[f64]| {
            values
                .iter()
                .fold((f64::INFINITY, 0.0f64), |(low, high), value| {
                    (low.min(*value), high.max(*value))
                })
        };
        let (one_low, one_high) = range(&one);
        let (two_low, two_high) = range(&two);
        let ratios: Vec<_> = two.iter().zip(&one).map(|(old, new)| old / new).collect();
        let (ratio_low, ratio_high) = range(&ratios);
        println!(
            "feature snapshot: twice={two_low:.2}..{two_high:.2} ns/query \
             once={one_low:.2}..{one_high:.2} ns/query ratio={ratio_low:.2}..{ratio_high:.2}x"
        );
    }

    #[test]
    /**
     * @brief 읽지 못한 질의를 버리지 않고 FORMERR로 답하는지, 그리고 그 답이 접근 제어와
     *        속도 제한을 지나는지.
     * @details 버리면 클라이언트에게는 무응답이라 데드라인을 다 기다린 뒤 재시도한다. 다만
     *          파싱 전이라 일반 경로의 두 관문을 지나오지 못했으므로 여기서 다시 봐야
     *          한다. 안 보면 거부한 클라이언트에게도 서버가 있다고 알리게 된다.
     */
    fn an_unparsable_query_is_answered_with_formerr_behind_the_usual_gates() {
        // 질문 하나를 적어 놓고 둘이라고 말하는 헤더. 파서가 거부한다.
        let mut packet = vec![0u8; 12];
        packet[0..2].copy_from_slice(&0xbeefu16.to_be_bytes());
        packet[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
        packet[4..6].copy_from_slice(&2u16.to_be_bytes());
        packet.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0, 1, 0, 1]);
        assert!(
            Message::parse(&packet).is_err(),
            "대조군이 무효입니다. 이 패킷은 파싱되면 안 됩니다"
        );

        let allowed = server_with_chain("", |base| base);
        let response = allowed
            .handle_unparsable(&packet, &ctx())
            .expect("읽지 못한 질의를 버렸습니다");
        assert_eq!(response.header.rcode, ResponseCode::FormErr.0);
        assert_eq!(response.header.id, 0xbeef);
        assert!(response.header.response);
        assert!(response.header.recursion_desired);
        assert!(response.questions.is_empty());

        let denied = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::build_from_str(
                "",
                "",
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::new(vec![], vec![], false)),
            vec![],
            Arc::new(NativeBackend::Forward(Forwarder::new(
                vec![mock_upstream()],
                Duration::from_secs(2),
            ))),
            60,
        );
        assert!(
            denied.handle_unparsable(&packet, &ctx()).is_none(),
            "거부한 클라이언트에게 서버가 있다고 알렸습니다"
        );
    }

    #[test]
    /**
     * @brief 리액터 경로가 업스트림의 OPT를 그대로 흘리지 않는지.
     * @details 재귀는 업스트림 권한 서버의 OPT를 응답에 담아 온다. 이 경로는 finalize를 거치지
     *          않으므로 여기서 걷지 않으면 이 서버가 광고한 적 없는 버퍼 크기와 남의 DO 비트가
     *          나간다. RFC 6891은 요청에 OPT가 있을 때만 응답에 넣게 하고, RFC 3225는
     *          DO를 질의에서 복사하게 한다.
     */
    #[cfg(unix)]
    fn the_reactor_path_never_forwards_an_upstream_opt() {
        let features = NativeFeatures {
            edns_buffer: 1232,
            ..NativeFeatures::default()
        };
        // 업스트림이 자기 값으로 광고한 OPT. 이 서버의 값(1232)과 다르고 DO도 서 있다.
        let upstream_opt = Edns {
            udp_payload: 4096,
            dnssec_ok: true,
            ..Edns::default()
        }
        .try_to_record()
        .expect("업스트림 OPT");

        let bare = Message::query(1, ApName::from_str("a.test").unwrap(), ApRt::A);
        let mut response = Message::default();
        response.additionals.push(upstream_opt.clone());
        reactor_response_edns(&features, &mut response, &bare);
        assert!(
            response.opt().is_none(),
            "OPT 없는 질의에 업스트림 OPT를 담아 보냈습니다"
        );

        for asked_do in [false, true] {
            let mut request = Message::query(2, ApName::from_str("b.test").unwrap(), ApRt::A);
            request.additionals.push(
                Edns {
                    udp_payload: 512,
                    dnssec_ok: asked_do,
                    ..Edns::default()
                }
                .try_to_record()
                .expect("질의 OPT"),
            );
            let mut response = Message::default();
            response.additionals.push(upstream_opt.clone());
            reactor_response_edns(&features, &mut response, &request);
            let answered = response
                .opt()
                .and_then(Edns::from_record)
                .expect("OPT 있는 질의에 OPT를 주지 않았습니다");
            assert_eq!(
                answered.udp_payload, 1232,
                "업스트림이 광고한 크기가 나갔습니다"
            );
            assert_eq!(
                answered.dnssec_ok, asked_do,
                "DO를 질의에서 복사하지 않았습니다"
            );
            assert_eq!(answered.version, 0);
        }
    }

    #[test]
    /**
     * @brief 전달 백엔드가 업스트림의 권한 표시를 그대로 돌려주지 않는지.
     * @details 업스트림이 권한이지 이 서버가 아니다. 그대로 돌려주면 이 서버가 맡지 않은 이름에 권한이라고
     *          알리는 것이고, 캐시 히트에서는 그 표시가 사라져 같은 서버의 두 경로가 서로
     *          다른 답을 낸다. 이 서버의 영역의 답에 이 표시를 설정하는 것은 위쪽 권한 계층이 한다.
     */
    fn the_forward_backend_does_not_echo_the_upstream_authoritative_bit() {
        let backend = NativeBackend::Forward(Forwarder::new(
            vec![mock_upstream_authoritative()],
            Duration::from_secs(2),
        ));
        let request = Message::query(7, ApName::from_str("www.mock.test").unwrap(), ApRt::A);
        let outcome = backend.resolve_outcome(&request);
        let ResolveOutcome::Response(response) = outcome else {
            panic!("업스트림이 답하지 않았습니다");
        };
        assert!(
            !response.header.authoritative,
            "업스트림의 권한 표시를 그대로 되울렸습니다"
        );
        assert!(!response.header.authentic_data);
    }

    /** @brief 테스트용 요청 맥락. */
    fn ctx<'a>() -> RequestCtx<'a> {
        RequestCtx {
            src: "127.0.0.1:5555".parse().unwrap(),
            transport: RtTransport::Do53Udp,
            raw: None,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        }
    }

    /** @brief 테스트용 질의. */
    fn q(name: &str) -> Message {
        Message::query(0x1234, ApName::from_str(name).unwrap(), RecordType::A)
    }

    /** @brief 응답에 담긴 부정 수명. */
    fn negative_soa_ttl(message: &Message) -> u32 {
        message
            .authorities
            .iter()
            .find(|record| record.rtype == RecordType::SOA)
            .expect("합성 부정 응답 SOA")
            .ttl
    }

    #[test]
    /** @brief 이 서버와 클라이언트 사이에서만 뜻이 있는 옵션만 떼는지. 더 떼면 응답이 달라진다. */
    fn client_hop_edns_is_stripped_before_resolver_and_semantic_options_remain() {
        /** @brief 쿠키를 담은 테스트용 질의. */
        fn request(cookie: u8) -> Message {
            let mut request = q("edns-hop.example");
            let mut edns = Edns {
                udp_payload: 1232,
                dnssec_ok: true,
                ..Default::default()
            };
            edns.options.push((OPT_COOKIE, vec![cookie; 8]));
            edns.options.push((OPT_NSID, Vec::new()));
            edns.options
                .push((onetdns_proto::EDNS_TCP_KEEPALIVE, vec![0, 10]));
            edns.options
                .push((onetdns_proto::EDNS_PADDING, vec![0; 32]));
            edns.options.push((8, vec![0, 1, 24, 0, 192, 0, 2]));
            request.additionals.push(edns.try_to_record().unwrap());
            request.additionals.push(ApRecord {
                name: ApName::from_str("client-key").unwrap(),
                rtype: ApRt(250),
                class: DnsClass(255),
                ttl: 0,
                rdata: ApRData::Unknown(250, vec![1, 2, 3]),
            });
            request
        }

        let mut first = request(1);
        let mut second = request(2);
        strip_client_hop_edns(&mut first);
        strip_client_hop_edns(&mut second);

        assert_eq!(
            first.try_encode().unwrap(),
            second.try_encode().unwrap(),
            "client cookie must not split cache keys"
        );
        let edns = first.opt().and_then(Edns::from_record).unwrap();
        assert!(edns.dnssec_ok, "DO is resolver-semantic");
        assert_eq!(edns.udp_payload, 1232);
        assert_eq!(edns.options, vec![(8, vec![0, 1, 24, 0, 192, 0, 2])]);
        assert!(first
            .additionals
            .iter()
            .all(|record| record.rtype != ApRt(250)));
    }

    #[test]
    /** @brief lenient 쿠키가 무쿠키 wire 질의는 늦추지 않고 쿠키 클라이언트에는 발급하는지. */
    fn lenient_cookie_keeps_plain_wire_and_handles_cookie_requests_structurally() {
        use onetdns_runtime::WireDisposition;

        let server = shaped_server(true);
        update_features(&server, |features| {
            features.cookies = CookiePolicy {
                keeper: Some(Arc::new(CookieKeeper::from_secret(&[2; 16]))),
                strict: false,
            };
        });

        let plain = q("cookie-wire.example");
        let mut output = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.handle_udp_wire(
                &plain.try_encode().unwrap(),
                &ctx(),
                &mut output,
                Instant::now()
            ),
            WireDisposition::Respond,
            "쿠키를 보내지 않은 질의는 기존 wire 레인을 유지합니다"
        );

        let client_cookie = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut cookie_request = q("cookie-wire.example");
        let mut edns = Edns::default();
        edns.options.push((OPT_COOKIE, client_cookie.to_vec()));
        cookie_request
            .additionals
            .push(edns.try_to_record().unwrap());
        output.clear();
        assert_eq!(
            server.handle_udp_wire(
                &cookie_request.try_encode().unwrap(),
                &ctx(),
                &mut output,
                Instant::now()
            ),
            WireDisposition::Fallback,
            "COOKIE 옵션은 서버 쿠키를 만들 수 있는 구조적 경로가 맡습니다"
        );

        let response = server
            .handle(&cookie_request, &ctx())
            .expect("lenient 쿠키 응답");
        let returned = read_cookie(&response).expect("응답 COOKIE 옵션");
        assert_eq!(returned.len(), 24, "client 8 + RFC 9018 server 16");
        assert_eq!(&returned[..8], &client_cookie);

        update_features(&server, |features| features.cookies.strict = true);
        output.clear();
        assert_eq!(
            server.handle_udp_wire(
                &plain.try_encode().unwrap(),
                &ctx(),
                &mut output,
                Instant::now()
            ),
            WireDisposition::Fallback,
            "strict에서는 무쿠키 질의도 BADCOOKIE 처리가 필요합니다"
        );
        let strict = server
            .handle(&plain, &ctx())
            .expect("strict BADCOOKIE 응답");
        assert_eq!(strict.header.rcode, ResponseCode::BadCookie.0);
    }

    #[test]
    /**
     * @brief 오류 응답도 요청이 담은 OPT를 그대로 돌려주는지.
     * @details RFC 6891이 요청에 OPT가 있으면 응답에도 넣게 한다. 빼면 상대는 이 서버가
     *          EDNS를 모르는 것으로 보고 512바이트로 전환하므로, 형식 오류 한 번이 그 뒤
     *          모든 질의의 버퍼 크기를 깎는다.
     */
    fn protocol_error_responses_echo_the_request_opt() {
        let server = shaped_server(true);

        let with_edns = |mut request: Message| {
            let mut edns = Edns::default();
            edns.udp_payload = 1232;
            request.additionals.push(edns.try_to_record().unwrap());
            request
        };

        let mut not_implemented = with_edns(q("opcode.example"));
        not_implemented.header.opcode = 2;
        let mut zero_questions = with_edns(q("qdcount.example"));
        zero_questions.questions.clear();
        let mut bad_update = with_edns(q("update.example"));
        bad_update.header.opcode = 5;
        let mut bad_notify = with_edns(q("notify.example"));
        bad_notify.header.opcode = 4;

        for (label, request, rcode) in [
            ("opcode 2", not_implemented, ResponseCode::NotImp.0),
            ("QDCOUNT 0", zero_questions, ResponseCode::FormErr.0),
            ("UPDATE zone question", bad_update, ResponseCode::FormErr.0),
            ("NOTIFY zone question", bad_notify, ResponseCode::FormErr.0),
        ] {
            let response = server.handle(&request, &ctx()).expect("오류 응답");
            assert_eq!(response.header.rcode, rcode, "{label}");
            assert!(
                response.opt().is_some(),
                "{label}: 요청 OPT를 그대로 돌려줘야 합니다"
            );
        }

        let mut plain = q("opcode.example");
        plain.header.opcode = 2;
        let response = server.handle(&plain, &ctx()).expect("EDNS 없는 오류 응답");
        assert!(
            response.opt().is_none(),
            "요청에 OPT가 없으면 응답에도 넣지 않습니다"
        );

        // TSIG 오류 응답도 같은 규칙을 따르고, OPT가 TSIG 앞에 와야 서명이 그것을 덮는다.
        let key = onetdns_dnssec::tsig::TsigKey::new(
            ApName::from_str("probe-key").unwrap(),
            vec![7u8; 32],
        )
        .expect("테스트용 TSIG 키");
        let mut signed = with_edns(q("tsig.example"));
        onetdns_dnssec::tsig::sign_message(&mut signed, &key, 1_700_000_000, None)
            .expect("요청 서명");
        let request_tsig = onetdns_dnssec::tsig::request_data(&signed).expect("요청 TSIG");
        let unsigned_error = unsigned_tsig_error_response(
            &signed,
            &request_tsig,
            onetdns_dnssec::tsig::UnsignedTsigError::BadKey,
            1232,
        );
        assert!(
            unsigned_error.opt().is_some(),
            "TSIG BADKEY 응답도 요청 OPT를 그대로 돌려줘야 합니다"
        );
        let types: Vec<u16> = unsigned_error
            .additionals
            .iter()
            .map(|record| record.rtype.0)
            .collect();
        assert_eq!(types, vec![41, 250], "OPT가 TSIG보다 앞이어야 합니다");
    }

    #[test]
    /**
     * @brief 형식이 틀린 COOKIE를 FORMERR로 거절하되 응답 OPT는 유지하는지.
     * @details RFC 7873이 길이 8도 16에서 40도 아닌 옵션을 FORMERR로 정하고,
     *          RFC 6891이 요청에 OPT가 있으면 응답에도 넣게 한다. OPT를 빼면 상대는
     *          이 서버가 EDNS를 모르는 것으로 보고 512바이트 평문으로 전환한다.
     */
    fn malformed_cookie_is_formerr_that_still_carries_opt() {
        let server = shaped_server(true);
        update_features(&server, |features| {
            features.cookies = CookiePolicy {
                keeper: Some(Arc::new(CookieKeeper::from_secret(&[3; 16]))),
                strict: false,
            };
        });

        for length in [1usize, 7, 9, 15, 41, 64] {
            let mut request = q("bad-cookie.example");
            let mut edns = Edns::default();
            edns.udp_payload = 1232;
            edns.options.push((OPT_COOKIE, vec![0x5a; length]));
            request.additionals.push(edns.try_to_record().unwrap());

            let response = server
                .handle(&request, &ctx())
                .expect("규격에 어긋난 COOKIE 응답");
            assert_eq!(
                response.header.rcode,
                ResponseCode::FormErr.0,
                "COOKIE 길이 {length}"
            );
            assert!(
                response.opt().is_some(),
                "COOKIE 길이 {length}: 요청 OPT를 그대로 돌려줘야 합니다"
            );
            assert!(
                read_cookie(&response).is_none(),
                "COOKIE 길이 {length}: 규격에 어긋난 요청에는 서버 쿠키를 주지 않습니다"
            );
        }

        let mut valid = q("bad-cookie.example");
        let mut edns = Edns::default();
        edns.udp_payload = 1232;
        edns.options.push((OPT_COOKIE, vec![0x5a; 8]));
        valid.additionals.push(edns.try_to_record().unwrap());
        let response = server.handle(&valid, &ctx()).expect("정상 COOKIE 응답");
        assert_ne!(
            response.header.rcode,
            ResponseCode::FormErr.0,
            "8바이트 클라이언트 쿠키는 규격에 맞습니다"
        );
    }

    /** @brief 정해진 응답 코드를 내는 테스트용 체인. */
    struct FixedRcode(u16);

    impl Resolver for FixedRcode {
        /** @brief 미리 정해 둔 응답을 돌려준다. */
        fn resolve(&self, request: &Message) -> Option<Message> {
            let mut response = base_response(request);
            response.header.rcode = self.0;
            Some(response)
        }
    }

    /** @brief 정해진 답을 내는 테스트용 체인. */
    struct FixedAnswer;

    impl Resolver for FixedAnswer {
        /** @brief 미리 정해 둔 응답을 돌려준다. */
        fn resolve(&self, request: &Message) -> Option<Message> {
            let mut response = base_response(request);
            let name = request.questions.first().unwrap().name.clone();
            response.answers.push(ApRecord::new(
                name,
                300,
                ApRData::A(Ipv4Addr::new(1, 2, 3, 4)),
            ));
            Some(response)
        }
    }

    /** @brief 정해진 답과 그것을 담을 캐시. */
    fn fixed_answer_cache() -> (Arc<dyn Resolver>, crate::cache::CacheHandle) {
        let layer =
            crate::cache::CacheLayer::new(Arc::new(FixedAnswer), 64, 1, 0, 86_400, 0, 86_400);
        let handle = layer.handle();
        (Arc::new(layer), handle)
    }

    #[test]
    /** @brief 빠른 경로가 질의 번호를 고쳐 내보내고, 세대가 다르면 쓰지 않는지. */
    fn wire_lane_hits_patch_id_and_respect_filter_generation() {
        use onetdns_runtime::WireDisposition;

        let engine =
            onetdns_filter::build_from_str("||blocked.example^", "", BlockResponse::NxDomain);
        let (backend, cache) = fixed_answer_cache();
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(engine)),
            Arc::new(IpAcl::allow_all()),
            vec![],
            backend,
            60,
        )
        .with_wire_fast_path(Some((
            crate::wirecache::WireEntryFactory::new(0, 86_400),
            cache,
        )));

        let first_wire = Message::query(0x0101, ApName::from_str("ok.example").unwrap(), ApRt::A)
            .try_encode()
            .unwrap();
        let mut out = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.handle_udp_wire(&first_wire, &ctx(), &mut out, std::time::Instant::now()),
            WireDisposition::Respond
        );
        let first = Message::parse(&out.buf).expect("미스 경로 응답");
        assert_eq!(first.header.id, 0x0101);
        assert_eq!(first.answers.len(), 1);

        let second_wire = Message::query(0x0202, ApName::from_str("OK.EXAMPLE").unwrap(), ApRt::A)
            .try_encode()
            .unwrap();
        let mut out2 = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.handle_udp_wire(&second_wire, &ctx(), &mut out2, std::time::Instant::now()),
            WireDisposition::Respond
        );
        let second = Message::parse(&out2.buf).expect("히트 경로 응답");
        assert_eq!(second.header.id, 0x0202);
        assert_eq!(second.answers[0].rdata, first.answers[0].rdata);
        assert_eq!(
            second.questions[0].name.to_ascii_lower(),
            "ok.example",
            "질의 이름은 요청 케이스 구간으로 패치"
        );

        let blocked_wire = Message::query(
            0x0303,
            ApName::from_str("blocked.example").unwrap(),
            ApRt::A,
        )
        .try_encode()
        .unwrap();
        let mut out3 = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.handle_udp_wire(&blocked_wire, &ctx(), &mut out3, std::time::Instant::now()),
            WireDisposition::Fallback
        );

        server.filter.store(Arc::new(onetdns_filter::build_from_str(
            "||other.example^",
            "",
            BlockResponse::NxDomain,
        )));
        let third_wire = Message::query(0x0404, ApName::from_str("ok.example").unwrap(), ApRt::A)
            .try_encode()
            .unwrap();
        let mut out4 = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.handle_udp_wire(&third_wire, &ctx(), &mut out4, std::time::Instant::now()),
            WireDisposition::Respond
        );
        assert_eq!(Message::parse(&out4.buf).unwrap().header.id, 0x0404);

        update_features(&server, |features| features.block_aaaa = true);
        let mut out5 = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.handle_udp_wire(&third_wire, &ctx(), &mut out5, std::time::Instant::now()),
            WireDisposition::Fallback
        );
    }

    #[test]
    /** @brief 인라인 키보다 긴 정상 질의가 거부되지 않고 구조화 경로에서 답을 받는지. */
    fn wire_lane_long_key_falls_back_to_structured_response() {
        use onetdns_runtime::WireDisposition;

        let server = shaped_server(true);
        let name = ApName::from_str(&"a".repeat(55)).expect("정상 55바이트 라벨");
        let request = Message::query(0x5151, name.clone(), ApRt::A);
        let packet = request.try_encode().expect("정상 DNS 질의");
        let mut output = onetdns_proto::Writer::with_limit(1232);

        assert_eq!(
            server.handle_udp_wire(&packet, &ctx(), &mut output, Instant::now()),
            WireDisposition::Fallback,
            "긴 키는 할당 없는 wire 레인 대신 구조화 경로가 맡습니다"
        );
        let response = server.handle(&request, &ctx()).expect("구조화 응답");
        assert_eq!(response.header.id, 0x5151);
        assert!(response
            .answers
            .iter()
            .any(|record| record.name.eq_ignore_case(&name) && record.rtype == ApRt::A));
    }

    /** @brief 모양을 정해 둔 답을 내는 테스트용 체인. */
    struct ShapedAnswer;

    impl Resolver for ShapedAnswer {
        /** @brief 미리 정해 둔 응답을 돌려준다. */
        fn resolve(&self, request: &Message) -> Option<Message> {
            let q = request.questions.first()?;
            let mut response = base_response(request);
            match q.name.to_ascii_lower().as_str() {
                "nodata.example" => response.authorities.push(ApRecord::new(
                    ApName::from_str("example.").unwrap(),
                    60,
                    ApRData::soa(onetdns_proto::Soa {
                        mname: ApName::from_str("ns.example.").unwrap(),
                        rname: ApName::from_str("hostmaster.example.").unwrap(),
                        serial: 1,
                        refresh: 3600,
                        retry: 600,
                        expire: 86_400,
                        minimum: 60,
                    }),
                )),
                "multi.example" => {
                    for last in [10u8, 11, 12] {
                        response.answers.push(ApRecord::new(
                            q.name.clone(),
                            60,
                            ApRData::A(Ipv4Addr::new(192, 0, 2, last)),
                        ));
                    }
                }
                "alias.example" => {
                    let target = ApName::from_str("target.example.").unwrap();
                    response.answers.push(ApRecord::new(
                        q.name.clone(),
                        60,
                        ApRData::Cname(target.clone()),
                    ));
                    response.answers.push(ApRecord::new(
                        target,
                        60,
                        ApRData::A(Ipv4Addr::new(192, 0, 2, 20)),
                    ));
                }
                _ => response.answers.push(ApRecord::new(
                    q.name.clone(),
                    60,
                    ApRData::A(Ipv4Addr::new(192, 0, 2, 1)),
                )),
            }
            Some(response)
        }
    }

    /** @brief 빠른 경로를 켜거나 끈 테스트용 핸들러. */
    fn shaped_server(with_wire: bool) -> NativeServer {
        let layer =
            crate::cache::CacheLayer::new(Arc::new(ShapedAnswer), 64, 1, 0, 86_400, 0, 86_400);
        let cache = layer.handle();
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            Arc::new(layer),
            60,
        );
        if with_wire {
            server.with_wire_fast_path(Some((
                crate::wirecache::WireEntryFactory::new(0, 86_400),
                cache,
            )))
        } else {
            server
        }
    }

    #[test]
    #[ignore = "microbenchmark: run with --release -- --ignored --nocapture"]
    /** @brief 고정해 둔 주소를 캐시 밖에서 답할 때와 담아 둔 바이트로 답할 때의 비용. */
    fn bench_split_local_outside_cache_vs_cached_wire_hit() {
        /** @brief 테스트용 핸들러. */
        fn local_server(mode: u8) -> NativeServer {
            let ttl = Arc::new(AtomicU32::new(300));
            let addresses = Arc::new(
                crate::layers::LocalAddressTable::new(
                    &[("router.lan".to_string(), Ipv4Addr::new(192, 168, 0, 1))],
                    &[],
                    ttl,
                )
                .unwrap(),
            );
            let empty_filter = || {
                shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                    BlockResponse::NxDomain,
                )))
            };

            if mode < 2 {
                let cache = crate::cache::CacheLayer::new(
                    Arc::new(FixedAnswer),
                    64,
                    1,
                    0,
                    86_400,
                    0,
                    86_400,
                );
                let handle = cache.handle();
                let wire_cache = (mode == 1).then(|| {
                    let slot = Arc::new(std::sync::OnceLock::new());
                    let _ = slot.set(handle.clone());
                    slot
                });
                let local =
                    crate::layers::LocalAddressLayer::new(Arc::new(cache), addresses, wire_cache);
                NativeServer::new(
                    empty_filter(),
                    Arc::new(IpAcl::allow_all()),
                    vec![],
                    Arc::new(local),
                    60,
                )
                .with_wire_fast_path(Some((
                    crate::wirecache::WireEntryFactory::new(0, 86_400),
                    handle,
                )))
            } else {
                let local =
                    crate::layers::LocalAddressLayer::new(Arc::new(FixedAnswer), addresses, None);
                let cache =
                    crate::cache::CacheLayer::new(Arc::new(local), 64, 1, 0, 86_400, 0, 86_400);
                let handle = cache.handle();
                NativeServer::new(
                    empty_filter(),
                    Arc::new(IpAcl::allow_all()),
                    vec![],
                    Arc::new(cache),
                    60,
                )
                .with_wire_fast_path(Some((
                    crate::wirecache::WireEntryFactory::new(0, 86_400),
                    handle,
                )))
            }
        }

        /** @brief 반복 횟수. */
        const ITERS: u32 = 1_000_000;
        let packet = Message::query(
            0x1234,
            ApName::from_str("router.lan").unwrap(),
            RecordType::A,
        )
        .try_encode()
        .unwrap();
        for (label, server) in [
            ("outside-cache", local_server(0)),
            ("fixed-local-wire", local_server(1)),
            ("cached-wire", local_server(2)),
        ] {
            let mut output = onetdns_proto::Writer::with_limit(1232);
            assert_eq!(
                server.handle_udp_wire(&packet, &ctx(), &mut output, Instant::now()),
                onetdns_runtime::WireDisposition::Respond
            );
            let started = Instant::now();
            for _ in 0..ITERS {
                assert_eq!(
                    server.handle_udp_wire(
                        std::hint::black_box(&packet),
                        &ctx(),
                        &mut output,
                        Instant::now(),
                    ),
                    onetdns_runtime::WireDisposition::Respond
                );
                std::hint::black_box(&output.buf);
            }
            println!(
                "{label}: {:.2} ns/query",
                started.elapsed().as_nanos() as f64 / f64::from(ITERS)
            );
        }
    }

    #[test]
    /** @brief 설정을 다시 읽은 뒤 이전 수명으로 만든 항목이 들어오지 못하는지. */
    fn split_local_fixed_wire_rejects_late_old_ttl_generation() {
        let ttl = Arc::new(AtomicU32::new(17));
        let addresses = Arc::new(
            crate::layers::LocalAddressTable::new(
                &[("router.lan".to_string(), Ipv4Addr::new(192, 168, 0, 1))],
                &[],
                ttl.clone(),
            )
            .unwrap(),
        );
        let cache =
            crate::cache::CacheLayer::new(Arc::new(FixedAnswer), 64, 1, 0, 86_400, 0, 86_400);
        let handle = cache.handle();
        let wire_cache = Arc::new(std::sync::OnceLock::new());
        let _ = wire_cache.set(handle.clone());
        let local =
            crate::layers::LocalAddressLayer::new(Arc::new(cache), addresses, Some(wire_cache));
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            Arc::new(local),
            60,
        )
        .with_ttl_sources(Arc::new(AtomicU32::new(60)), ttl.clone())
        .with_wire_fast_path(Some((
            crate::wirecache::WireEntryFactory::new(0, 86_400),
            handle.clone(),
        )));

        let request = Message::query(
            0x1234,
            ApName::from_str("router.lan").unwrap(),
            RecordType::A,
        );
        let packet = request.try_encode().unwrap();
        let now = Instant::now();
        let mut output = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.handle_udp_wire(&packet, &ctx(), &mut output, now),
            onetdns_runtime::WireDisposition::Respond
        );
        assert_eq!(Message::parse(&output.buf).unwrap().answers[0].ttl, 17);
        let old_wire = handle.wire_entry_for(&request).expect("고정 로컬 wire");

        assert_eq!(
            server.handle_udp_wire(
                &packet,
                &ctx(),
                &mut output,
                now + Duration::from_secs(3_600),
            ),
            onetdns_runtime::WireDisposition::Respond
        );
        assert_eq!(
            Message::parse(&output.buf).unwrap().answers[0].ttl,
            17,
            "로컬 설정 TTL은 캐시 나이만큼 감소하지 않음"
        );

        ttl.store(0, Ordering::Release);
        server.wire_epoch.fetch_add(1, Ordering::AcqRel);
        assert!(handle.install_local_wire_for_test(&request, old_wire.clone()));
        assert_eq!(
            server.handle_udp_wire(
                &packet,
                &ctx(),
                &mut output,
                now + Duration::from_secs(7_200),
            ),
            onetdns_runtime::WireDisposition::Respond
        );
        assert_eq!(
            Message::parse(&output.buf).unwrap().answers[0].ttl,
            0,
            "늦게 삽입된 이전 세대 wire가 TTL 0 핫 변경을 가리면 안 됨"
        );
        let zero_wire = handle.wire_entry_for(&request).expect("TTL 0 고정 wire");
        assert!(!crate::wirecache::WireEntry::ptr_eq(&old_wire, &zero_wire));

        assert_eq!(
            server.handle_udp_wire(
                &packet,
                &ctx(),
                &mut output,
                now + Duration::from_secs(86_400),
            ),
            onetdns_runtime::WireDisposition::Respond
        );
        assert_eq!(Message::parse(&output.buf).unwrap().answers[0].ttl, 0);
        let zero_hit = handle.wire_entry_for(&request).expect("TTL 0 wire hit");
        assert!(crate::wirecache::WireEntry::ptr_eq(&zero_wire, &zero_hit));

        ttl.store(u32::MAX, Ordering::Release);
        server.wire_epoch.fetch_add(1, Ordering::AcqRel);
        assert_eq!(
            server.handle_udp_wire(
                &packet,
                &ctx(),
                &mut output,
                now + Duration::from_secs(172_800),
            ),
            onetdns_runtime::WireDisposition::Respond
        );
        assert_eq!(
            Message::parse(&output.buf).unwrap().answers[0].ttl,
            u32::MAX
        );

        let txt = Message::query(
            0x2345,
            ApName::from_str("router.lan").unwrap(),
            RecordType::TXT,
        );
        let txt_packet = txt.try_encode().unwrap();
        assert_eq!(
            server.handle_udp_wire(
                &txt_packet,
                &ctx(),
                &mut output,
                now + Duration::from_secs(172_801),
            ),
            onetdns_runtime::WireDisposition::Respond
        );
        assert!(Message::parse(&output.buf).unwrap().answers.is_empty());
        assert!(
            handle.wire_entry_for(&txt).is_some(),
            "빈 로컬 NODATA도 업스트림으로 떨어뜨리지 않고 wire 재사용"
        );
    }

    #[test]
    /** @brief 바깥 계층의 답을 고정해 둔 주소의 답으로 오해하지 않는지. 오해하면 수명이 늙지 않는다. */
    fn outer_override_is_not_mislabeled_as_local_wire() {
        let ttl = Arc::new(AtomicU32::new(17));
        let addresses = Arc::new(
            crate::layers::LocalAddressTable::new(
                &[("router.lan".to_string(), Ipv4Addr::new(192, 168, 0, 1))],
                &[],
                ttl,
            )
            .unwrap(),
        );
        let cache =
            crate::cache::CacheLayer::new(Arc::new(FixedAnswer), 64, 1, 0, 86_400, 0, 86_400);
        let handle = cache.handle();
        let wire_cache = Arc::new(std::sync::OnceLock::new());
        let _ = wire_cache.set(handle.clone());
        let local =
            crate::layers::LocalAddressLayer::new(Arc::new(cache), addresses, Some(wire_cache));
        let stub = crate::layers::StubLayer::new(
            Arc::new(local),
            vec![(
                "router.lan".to_string(),
                Arc::new(FixedAnswer) as Arc<dyn Resolver>,
            )],
        )
        .unwrap();
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            Arc::new(stub),
            60,
        )
        .with_wire_fast_path(Some((
            crate::wirecache::WireEntryFactory::new(0, 86_400),
            handle.clone(),
        )));

        let request = Message::query(
            0x3456,
            ApName::from_str("router.lan").unwrap(),
            RecordType::A,
        );
        let packet = request.try_encode().unwrap();
        let mut output = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.handle_udp_wire(&packet, &ctx(), &mut output, Instant::now()),
            onetdns_runtime::WireDisposition::Respond
        );
        let response = Message::parse(&output.buf).unwrap();
        assert_eq!(response.answers[0].ttl, 300, "바깥 Stub 응답이 우선");
        assert!(
            handle.wire_entry_for(&request).is_none(),
            "실제 로컬 합성 계층을 지나지 않은 응답은 고정 TTL로 저장하지 않음"
        );
    }

    #[test]
    /** @brief 단순 질의는 조립 없이 나가고, 기능이 하나라도 켜지면 보통 경로로 전환하는지. */
    fn authoritative_wire_exact_address_is_direct_and_optional_features_fall_back() {
        let zone_text = "$ORIGIN fast.test.\n$TTL 300\n@ IN SOA ns admin 1 300 60 3600 60\n@ IN NS ns\nns IN A 192.0.2.53\nwww IN A 192.0.2.9\n*.wild IN A 192.0.2.99\n";
        let mut zones = onetdns_authority::ZoneStore::new();
        zones.add(onetdns_authority::parse_zone(zone_text, "fast.test").unwrap());
        let store = Arc::new(ArcSwap::new(Arc::new(zones)));
        let authority = Arc::new(crate::layers::AuthorityLayer::new(
            Arc::new(FixedAnswer),
            store.clone(),
        ));
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            authority,
            60,
        )
        .with_authority_wire_path(Some(store), true);
        let mut request = Message::query(
            0x4567,
            ApName::from_str("WWW.fast.test").unwrap(),
            RecordType::A,
        );
        request.header.checking_disabled = true;
        let packet = request.try_encode().unwrap();
        let mut output = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.handle_udp_wire(&packet, &ctx(), &mut output, Instant::now()),
            onetdns_runtime::WireDisposition::Respond
        );
        let response = Message::parse(&output.buf).unwrap();
        assert_eq!(response.header.id, 0x4567);
        assert!(response.header.authoritative);
        assert!(response.header.recursion_available);
        assert!(response.header.checking_disabled);
        assert!(matches!(
            response.answers.as_slice(),
            [ApRecord {
                rdata: ApRData::A(address),
                ..
            }] if *address == Ipv4Addr::new(192, 0, 2, 9)
        ));
        let direct_wire = output.buf.clone();
        let tcp_context = RequestCtx {
            transport: RtTransport::Do53Tcp,
            ..ctx()
        };
        output.clear();
        assert_eq!(
            server.handle_tcp_wire(&packet, &tcp_context, &mut output, Instant::now()),
            onetdns_runtime::WireDisposition::Respond
        );
        assert_eq!(output.buf, direct_wire, "TCP와 UDP direct wire가 동일함");
        let structured = server.handle(&request, &ctx()).unwrap();
        let mut structured_wire = onetdns_proto::Writer::with_limit(1232);
        onetdns_runtime::encode_limited(&request, &structured, &mut structured_wire);
        assert_eq!(direct_wire, structured_wire.buf);

        let missing = Message::query(
            0x5678,
            ApName::from_str("missing.fast.test").unwrap(),
            RecordType::A,
        );
        let missing_packet = missing.try_encode().unwrap();
        output.clear();
        assert_eq!(
            server.handle_udp_wire(&missing_packet, &ctx(), &mut output, Instant::now()),
            onetdns_runtime::WireDisposition::Respond
        );
        let negative = Message::parse(&output.buf).unwrap();
        assert_eq!(negative.header.rcode, ResponseCode::NXDomain.0);
        assert!(negative.header.authoritative);
        assert!(negative.answers.is_empty());
        assert!(matches!(
            negative.authorities.as_slice(),
            [ApRecord {
                rdata: ApRData::Soa(_),
                ..
            }]
        ));

        let wildcard = Message::query(
            0x6789,
            ApName::from_str("hit.wild.fast.test").unwrap(),
            RecordType::A,
        );
        let wildcard_packet = wildcard.try_encode().unwrap();
        output.clear();
        assert_eq!(
            server.handle_udp_wire(&wildcard_packet, &ctx(), &mut output, Instant::now()),
            onetdns_runtime::WireDisposition::Respond
        );
        let wildcard_response = Message::parse(&output.buf).unwrap();
        assert!(matches!(
            wildcard_response.answers.as_slice(),
            [ApRecord {
                rdata: ApRData::A(address),
                ..
            }] if *address == Ipv4Addr::new(192, 0, 2, 99)
        ));

        // 옵션 없는 OPT 하나만 붙은 질의는 빠른 경로가 맡되, 나가는 바이트는 구조적 경로와
        // 한 바이트도 다르면 안 된다. 실제 클라이언트는 거의 전부 이 모양으로 물어본다.
        let mut with_edns = request.clone();
        with_edns
            .additionals
            .push(Edns::default().try_to_record().unwrap());
        let packet = with_edns.try_encode().unwrap();
        output.clear();
        assert_eq!(
            server.handle_udp_wire(&packet, &ctx(), &mut output, Instant::now()),
            onetdns_runtime::WireDisposition::Respond,
            "옵션 없는 EDNS 질의는 빠른 경로가 맡아야 합니다"
        );
        let edns_wire = output.buf.clone();
        let structured = server.handle(&with_edns, &ctx()).unwrap();
        let mut structured_wire = onetdns_proto::Writer::with_limit(1232);
        onetdns_runtime::encode_limited(&with_edns, &structured, &mut structured_wire);
        assert_eq!(
            edns_wire, structured_wire.buf,
            "EDNS 질의의 빠른 경로 응답이 구조적 경로와 다릅니다"
        );
        let edns_response = Message::parse(&edns_wire).unwrap();
        let opt = edns_response.opt().expect("응답에 OPT가 없습니다");
        let echoed = Edns::from_record(opt).expect("응답 OPT를 읽지 못했습니다");
        assert_eq!(echoed.version, 0);
        assert!(
            !echoed.dnssec_ok,
            "요청이 DO를 안 켰으면 응답도 꺼야 합니다"
        );
        assert!(echoed.options.is_empty());

        // 응답에 담을 것이 생기거나 절단 사다리가 필요한 모양은 전부 물러선다.
        let mut with_do = request.clone();
        let mut do_edns = Edns::default();
        do_edns.dnssec_ok = true;
        with_do.additionals.push(do_edns.try_to_record().unwrap());
        output.clear();
        assert_eq!(
            server.handle_udp_wire(
                &with_do.try_encode().unwrap(),
                &ctx(),
                &mut output,
                Instant::now()
            ),
            onetdns_runtime::WireDisposition::Fallback,
            "DO를 켠 질의는 구조적 경로가 맡아야 합니다"
        );
        assert!(output.buf.is_empty());

        let mut with_option = request.clone();
        let mut padded = Edns::default();
        padded
            .options
            .push((onetdns_proto::EDNS_PADDING, vec![0; 4]));
        with_option
            .additionals
            .push(padded.try_to_record().unwrap());
        output.clear();
        assert_eq!(
            server.handle_udp_wire(
                &with_option.try_encode().unwrap(),
                &ctx(),
                &mut output,
                Instant::now()
            ),
            onetdns_runtime::WireDisposition::Fallback,
            "옵션이 붙은 질의는 구조적 경로가 맡아야 합니다"
        );
        assert!(output.buf.is_empty());

        let mut small_buffer = request;
        let mut tiny = Edns::default();
        tiny.udp_payload = 512;
        small_buffer.additionals.push(tiny.try_to_record().unwrap());
        output.clear();
        assert_eq!(
            server.handle_udp_wire(
                &small_buffer.try_encode().unwrap(),
                &ctx(),
                &mut output,
                Instant::now()
            ),
            onetdns_runtime::WireDisposition::Fallback,
            "이 서버의 상한보다 작게 알린 질의는 절단 사다리가 필요합니다"
        );
        assert!(output.buf.is_empty());
    }

    #[test]
    /** @brief DDR이 켜져도 권한 고속 경로는 특수 이름 하나만 양보하고 나머지는 유지하는지. */
    fn ddr_only_preempts_its_owner_in_the_authority_wire_lane() {
        let zone_text = "$ORIGIN resolver.arpa.\n$TTL 300\n@ IN SOA ns admin 1 300 60 3600 60\n@ IN NS ns\nns IN A 192.0.2.53\n_dns IN A 192.0.2.9\nwww IN A 192.0.2.10\n";
        let mut zones = onetdns_authority::ZoneStore::new();
        zones.add(onetdns_authority::parse_zone(zone_text, "resolver.arpa").unwrap());
        let store = Arc::new(ArcSwap::new(Arc::new(zones)));
        let authority = Arc::new(crate::layers::AuthorityLayer::new(
            Arc::new(FixedAnswer),
            store.clone(),
        ));
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            authority,
            60,
        )
        .with_features(NativeFeatures {
            ddr_enabled: true,
            ..NativeFeatures::default()
        })
        .with_authority_wire_path(Some(store), true);

        let special = Message::query(
            1,
            ApName::from_str("_DNS.Resolver.ARPA").unwrap(),
            RecordType::A,
        )
        .try_encode()
        .unwrap();
        let mut output = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.handle_udp_wire(&special, &ctx(), &mut output, Instant::now()),
            onetdns_runtime::WireDisposition::Fallback,
            "DDR 계층이 NODATA로 닫아야 할 이름을 권한 A 레코드가 가로채면 안 됩니다"
        );

        let ordinary = Message::query(
            2,
            ApName::from_str("www.resolver.arpa").unwrap(),
            RecordType::A,
        )
        .try_encode()
        .unwrap();
        assert_eq!(
            server.handle_udp_wire(&ordinary, &ctx(), &mut output, Instant::now()),
            onetdns_runtime::WireDisposition::Respond,
            "DDR 때문에 관계없는 권한 이름까지 느린 경로로 보내면 안 됩니다"
        );
    }

    #[test]
    /** @brief 밖을 가리키는 별칭을 오류로 바꾸지 않는지. */
    fn authoritative_external_alias_is_not_replaced_with_servfail() {
        let zone_text = "$ORIGIN alias.test.\n$TTL 300\n@ IN SOA ns admin 1 300 60 3600 60\n@ IN NS ns\nns IN A 192.0.2.53\nalias IN CNAME outside.example.\nold IN DNAME target.example.\n";
        let mut zones = onetdns_authority::ZoneStore::new();
        zones.add(onetdns_authority::parse_zone(zone_text, "alias.test").unwrap());
        let store = Arc::new(ArcSwap::new(Arc::new(zones)));
        let authority = Arc::new(crate::layers::AuthorityLayer::new(
            Arc::new(FixedAnswer),
            store,
        ));
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            authority,
            60,
        );

        let cname = server
            .handle(
                &Message::query(
                    1,
                    ApName::from_str("alias.alias.test").unwrap(),
                    RecordType::A,
                ),
                &ctx(),
            )
            .unwrap();
        assert_eq!(cname.header.rcode, ResponseCode::NoError.0);
        assert!(cname.header.authoritative);
        assert!(matches!(
            cname.answers.as_slice(),
            [ApRecord {
                rdata: ApRData::Cname(target),
                ..
            }] if target.eq_ignore_case(&ApName::from_str("outside.example").unwrap())
        ));

        let dname = server
            .handle(
                &Message::query(
                    2,
                    ApName::from_str("host.old.alias.test").unwrap(),
                    RecordType::A,
                ),
                &ctx(),
            )
            .unwrap();
        assert_eq!(dname.header.rcode, ResponseCode::NoError.0);
        assert!(dname.header.authoritative);
        assert!(dname
            .answers
            .iter()
            .any(|record| matches!(record.rdata, ApRData::Dname(_))));
        assert!(dname
            .answers
            .iter()
            .any(|record| matches!(record.rdata, ApRData::Cname(_))));
    }

    #[test]
    #[ignore = "microbenchmark: run with --release -- --ignored --nocapture"]
    /** @brief 권한 영역 빠른 경로와 보통 경로의 비용. */
    fn bench_authoritative_exact_wire_vs_structured_path() {
        /** @brief 테스트용 권한 핸들러. */
        fn authority_server(
            store: Arc<ArcSwap<onetdns_authority::ZoneStore>>,
            direct: bool,
        ) -> NativeServer {
            let authority = Arc::new(crate::layers::AuthorityLayer::new(
                Arc::new(FixedAnswer),
                store.clone(),
            ));
            let server = NativeServer::new(
                shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                    BlockResponse::NxDomain,
                ))),
                Arc::new(IpAcl::allow_all()),
                vec![],
                authority,
                60,
            );
            if direct {
                server.with_authority_wire_path(Some(store), true)
            } else {
                server
            }
        }

        /** @brief 질의 하나를 처리해 바이트를 받는다. */
        fn serve(
            server: &NativeServer,
            packet: &[u8],
            context: &RequestCtx<'_>,
            output: &mut onetdns_proto::Writer,
            now: Instant,
        ) {
            if server.handle_udp_wire(packet, context, output, now)
                == onetdns_runtime::WireDisposition::Fallback
            {
                let request = Message::parse(packet).unwrap();
                let response = server.handle(&request, context).unwrap();
                onetdns_runtime::encode_limited(&request, &response, output);
            }
        }

        let store = big_zone_store(100_000);
        let structured = authority_server(store.clone(), false);
        let direct = authority_server(store, true);
        let request = Message::query(
            0x1234,
            ApName::from_str("host-99999-with-a-rather-long-owner-label.big.test").unwrap(),
            RecordType::A,
        );
        let packet = request.try_encode().unwrap();
        let context = ctx();
        let now = Instant::now();
        let mut structured_out = onetdns_proto::Writer::with_limit(1232);
        let mut direct_out = onetdns_proto::Writer::with_limit(1232);
        serve(&structured, &packet, &context, &mut structured_out, now);
        serve(&direct, &packet, &context, &mut direct_out, now);
        assert_eq!(direct_out.buf, structured_out.buf);

        for _ in 0..10_000 {
            serve(&structured, &packet, &context, &mut structured_out, now);
            serve(&direct, &packet, &context, &mut direct_out, now);
        }
        /** @brief 반복 횟수. */
        const ITERATIONS: usize = 500_000;
        let measure = |server: &NativeServer, packet: &[u8], output: &mut onetdns_proto::Writer| {
            let started = Instant::now();
            for _ in 0..ITERATIONS {
                serve(server, std::hint::black_box(packet), &context, output, now);
                std::hint::black_box(&output.buf);
            }
            started.elapsed().as_nanos() as f64 / ITERATIONS as f64
        };
        let direct_1 = measure(&direct, &packet, &mut direct_out);
        let structured_1 = measure(&structured, &packet, &mut structured_out);
        let structured_2 = measure(&structured, &packet, &mut structured_out);
        let direct_2 = measure(&direct, &packet, &mut direct_out);
        println!(
            "authority exact end-to-end: structured={structured_1:.1}/{structured_2:.1}ns direct={direct_1:.1}/{direct_2:.1}ns"
        );

        let missing = Message::query(
            0x2345,
            ApName::from_str("deep.missing.big.test").unwrap(),
            RecordType::A,
        );
        let missing_packet = missing.try_encode().unwrap();
        serve(
            &structured,
            &missing_packet,
            &context,
            &mut structured_out,
            now,
        );
        serve(&direct, &missing_packet, &context, &mut direct_out, now);
        let structured_negative = Message::parse(&structured_out.buf).unwrap();
        let direct_negative = Message::parse(&direct_out.buf).unwrap();
        assert_eq!(
            direct_negative.header.rcode,
            structured_negative.header.rcode
        );
        assert_eq!(direct_negative.authorities.len(), 1);
        assert_eq!(
            direct_negative.authorities[0].rdata,
            structured_negative.authorities[0].rdata
        );
        let direct_1 = measure(&direct, &missing_packet, &mut direct_out);
        let structured_1 = measure(&structured, &missing_packet, &mut structured_out);
        let structured_2 = measure(&structured, &missing_packet, &mut structured_out);
        let direct_2 = measure(&direct, &missing_packet, &mut direct_out);
        println!(
            "authority nxdomain end-to-end: structured={structured_1:.1}/{structured_2:.1}ns direct={direct_1:.1}/{direct_2:.1}ns"
        );
    }

    #[test]
    /** @brief 빠른 경로의 답이 보통 경로와 바이트까지 같은지. 다르면 캐시가 맞았는지에 따라 답이 갈린다. */
    fn wire_fast_path_answers_match_the_normal_path() {
        use onetdns_runtime::WireDisposition;

        let mut compared = 0usize;
        for name in [
            "ok.example",
            "multi.example",
            "alias.example",
            "nodata.example",
        ] {
            let wire_server = shaped_server(true);
            let plain_server = shaped_server(false);
            let request = Message::query(0x51, ApName::from_str(name).unwrap(), ApRt::A);
            let packet = request.try_encode().unwrap();

            let mut warm = onetdns_proto::Writer::with_limit(1232);
            assert_eq!(
                wire_server.handle_udp_wire(&packet, &ctx(), &mut warm, std::time::Instant::now()),
                WireDisposition::Respond,
                "{name}: 미스도 응답해야 한다"
            );
            plain_server
                .handle(&request, &ctx())
                .expect("일반 경로 미스");

            let mut hit = onetdns_proto::Writer::with_limit(1232);
            let disposition =
                wire_server.handle_udp_wire(&packet, &ctx(), &mut hit, std::time::Instant::now());
            let plain = plain_server
                .handle(&request, &ctx())
                .expect("일반 경로 히트");
            if disposition != WireDisposition::Respond {
                continue;
            }
            let fast = Message::parse(&hit.buf).expect("wire 히트 응답");
            compared += 1;

            assert_eq!(
                fast.header.rcode, plain.header.rcode,
                "{name}: rcode 불일치"
            );
            assert_eq!(fast.header.id, request.header.id, "{name}: 요청 ID 에코");
            assert_eq!(
                (
                    fast.header.authentic_data,
                    fast.header.authoritative,
                    fast.header.truncated,
                    fast.header.recursion_available,
                ),
                (
                    plain.header.authentic_data,
                    plain.header.authoritative,
                    plain.header.truncated,
                    plain.header.recursion_available,
                ),
                "{name}: 헤더 비트 불일치"
            );
            assert_eq!(
                record_keys(&fast.answers),
                record_keys(&plain.answers),
                "{name}: 답변 구획 불일치"
            );
            assert_eq!(
                record_keys(&fast.authorities),
                record_keys(&plain.authorities),
                "{name}: 권한 구획 불일치"
            );
            assert_eq!(
                record_keys(&fast.additionals),
                record_keys(&plain.additionals),
                "{name}: 부가 구획 불일치"
            );
        }

        assert_eq!(compared, 4, "wire 고속 경로로 실제 대조한 형태 수");
    }

    #[test]
    /** @brief 아무것도 막지 않는 설정에서 빠른 경로를 쓰는지. */
    fn wire_lane_trivial_filter_serves_hit_via_fast_path() {
        use onetdns_runtime::WireDisposition;

        let engine = onetdns_filter::build_from_str("", "", BlockResponse::NxDomain);
        assert!(engine.is_trivially_allow(), "빈 필터는 자명-허용");
        let (backend, cache) = fixed_answer_cache();
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(engine)),
            Arc::new(IpAcl::allow_all()),
            vec![],
            backend,
            60,
        )
        .with_wire_fast_path(Some((
            crate::wirecache::WireEntryFactory::new(0, 86_400),
            cache,
        )));

        let miss = Message::query(0x0111, ApName::from_str("ok.example").unwrap(), ApRt::A)
            .try_encode()
            .unwrap();
        let mut out = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.handle_udp_wire(&miss, &ctx(), &mut out, std::time::Instant::now()),
            WireDisposition::Respond
        );
        let first = Message::parse(&out.buf).expect("미스 응답");
        assert_eq!(first.answers.len(), 1);

        let hit = Message::query(0x0222, ApName::from_str("OK.EXAMPLE").unwrap(), ApRt::A)
            .try_encode()
            .unwrap();
        let mut out2 = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.handle_udp_wire(&hit, &ctx(), &mut out2, std::time::Instant::now()),
            WireDisposition::Respond
        );
        let second = Message::parse(&out2.buf).expect("히트 응답");
        assert_eq!(second.header.id, 0x0222);
        assert_eq!(second.answers[0].rdata, first.answers[0].rdata);
        assert_eq!(second.questions[0].name.to_ascii_lower(), "ok.example");
    }

    #[test]
    /** @brief 빠른 경로가 응답 캐시 하나만 쓰는지. 둘로 나누면 같은 답을 두 번 담는다. */
    fn wire_fast_path_uses_the_response_cache_as_its_only_index() {
        use onetdns_runtime::WireDisposition;

        let engine = onetdns_filter::build_from_str("", "", BlockResponse::NxDomain);
        let cache_layer =
            crate::cache::CacheLayer::new(Arc::new(FixedAnswer), 64, 1, 0, 86_400, 0, 86_400);
        let response_cache = cache_layer.handle();
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(engine)),
            Arc::new(IpAcl::allow_all()),
            vec![],
            Arc::new(cache_layer),
            60,
        )
        .with_wire_fast_path(Some((
            crate::wirecache::WireEntryFactory::new(0, 86_400),
            response_cache.clone(),
        )));

        let request = Message::query(0x1111, ApName::from_str("shared.example").unwrap(), ApRt::A);
        let request_wire = request.try_encode().unwrap();
        let scanned = crate::wirecache::scan_query(&request_wire).unwrap();
        let mut out = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.handle_udp_wire(&request_wire, &ctx(), &mut out, std::time::Instant::now()),
            WireDisposition::Respond
        );

        let filter = server.filter.load();
        let filter_tag = (Arc::as_ptr(&filter) as usize).rotate_left(17)
            ^ server.wire_epoch.load(Ordering::Acquire);
        let (wire_entry, _) = response_cache
            .wire_get(scanned.key(), filter_tag, std::time::Instant::now())
            .expect("응답 LRU의 wire 항목");
        let response_entry = response_cache
            .wire_entry_for(&request)
            .expect("구조화 LRU가 wire 표현으로 승격되어야 합니다");
        assert!(
            crate::wirecache::WireEntry::ptr_eq(&wire_entry, &response_entry),
            "UDP fast path와 일반 응답 경로가 같은 단일 할당 payload를 사용해야 합니다"
        );

        let parsed = response_cache
            .lane_response(&request)
            .expect("UDP 이외 경로는 공유 wire를 필요할 때 파싱합니다");
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(
            parsed.answers[0].rdata,
            Message::parse(&out.buf).unwrap().answers[0].rdata
        );
    }

    #[test]
    /** @brief 체인을 바꾸면 새 질의는 새 캐시를 보고, 진행 중 스냅숏은 이전 세대를 안전하게 유지하는지. */
    fn lane_runtime_replacement_is_generation_atomic() {
        let old_layer =
            crate::cache::CacheLayer::new(Arc::new(FixedAnswer), 16, 1, 0, 86_400, 0, 86_400);
        let old_cache = old_layer.handle();
        let new_layer = crate::cache::CacheLayer::new(Arc::new(FixedAnswer), 32, 1, 0, 300, 0, 300);
        let new_cache = new_layer.handle();
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            Arc::new(old_layer),
            60,
        )
        .with_wire_fast_path(Some((
            crate::wirecache::WireEntryFactory::new(0, 86_400),
            old_cache.clone(),
        )));

        let old_snapshot = server
            .features
            .load()
            .lane_runtime
            .clone()
            .expect("시작 세대");
        assert!(old_snapshot.cache.ptr_eq(&old_cache));

        server.replace_lane_runtime(
            crate::wirecache::WireEntryFactory::new(0, 300),
            new_cache.clone(),
            None,
            true,
        );
        let new_snapshot = server
            .features
            .load()
            .lane_runtime
            .clone()
            .expect("교체 세대");
        assert!(!Arc::ptr_eq(&old_snapshot, &new_snapshot));
        assert!(old_snapshot.cache.ptr_eq(&old_cache));
        assert!(new_snapshot.cache.ptr_eq(&new_cache));
        assert!(!new_snapshot.cache.ptr_eq(&old_cache));
        assert!(server.features.load().ddr_enabled);
    }

    #[test]
    /** @brief 체인 교체 뒤 wire 경로도 새 캐시와 새 TTL 상한을 즉시 쓰는지. */
    fn lane_runtime_replacement_applies_the_new_ttl_policy() {
        use onetdns_runtime::WireDisposition;

        let old_layer = crate::cache::CacheLayer::new(Arc::new(FixedAnswer), 16, 1, 0, 7, 0, 7);
        let old_cache = old_layer.handle();
        let slot = Arc::new(ResolverSlot::new(Arc::new(old_layer)));
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            slot.clone(),
            60,
        )
        .with_wire_fast_path(Some((
            crate::wirecache::WireEntryFactory::new(0, 7),
            old_cache,
        )));
        let packet = Message::query(1, ApName::from_str("ttl-swap.example").unwrap(), ApRt::A)
            .try_encode()
            .unwrap();
        let mut output = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.handle_udp_wire(&packet, &ctx(), &mut output, Instant::now()),
            WireDisposition::Respond
        );
        assert_eq!(Message::parse(&output.buf).unwrap().answers[0].ttl, 7);

        let new_layer = crate::cache::CacheLayer::new(Arc::new(FixedAnswer), 16, 1, 0, 31, 0, 31);
        let new_cache = new_layer.handle();
        slot.replace(Arc::new(new_layer));
        server.wire_epoch.fetch_add(1, Ordering::AcqRel);
        server.replace_lane_runtime(
            crate::wirecache::WireEntryFactory::new(0, 31),
            new_cache,
            None,
            false,
        );

        output.clear();
        assert_eq!(
            server.handle_udp_wire(&packet, &ctx(), &mut output, Instant::now()),
            WireDisposition::Respond
        );
        assert_eq!(
            Message::parse(&output.buf).unwrap().answers[0].ttl,
            31,
            "이전 wire factory나 이전 응답 캐시가 남으면 7이 나옵니다"
        );
    }

    #[test]
    /** @brief 빠른 경로에서 일반 경로로 넘어가도 제한을 두 번 세지 않는지. */
    fn wire_lane_hit_charges_rate_limit_once_across_fallback() {
        use onetdns_runtime::WireDisposition;

        /** @brief 호출 수를 세는 테스트용 제한기. */
        struct CountingLimiter(AtomicUsize);
        impl RateLimiter for CountingLimiter {
            /** @brief 세고 통과시킨다. */
            fn check(&self, _client: &ClientInfo) -> RateDecision {
                self.0.fetch_add(1, Ordering::Relaxed);
                RateDecision::Permit
            }
        }

        let limiter = Arc::new(CountingLimiter(AtomicUsize::new(0)));

        let engine =
            onetdns_filter::build_from_str("", "", BlockResponse::NxDomain).with_clients(vec![
                onetdns_filter::ClientPolicy::with_options(
                    vec!["10.0.0.0/8".parse().unwrap()],
                    vec![],
                    vec![],
                    &[],
                    &[],
                    false,
                    Some(true),
                ),
            ]);
        let (backend, cache) = fixed_answer_cache();
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(engine)),
            Arc::new(IpAcl::allow_all()),
            vec![limiter.clone()],
            backend,
            60,
        )
        .with_wire_fast_path(Some((
            crate::wirecache::WireEntryFactory::new(0, 86_400),
            cache,
        )));

        let miss = Message::query(0x1, ApName::from_str("ok.example").unwrap(), ApRt::A)
            .try_encode()
            .unwrap();
        let mut out = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.handle_udp_wire(&miss, &ctx(), &mut out, std::time::Instant::now()),
            WireDisposition::Respond
        );

        limiter.0.store(0, Ordering::Relaxed);

        let hit = Message::query(0x2, ApName::from_str("ok.example").unwrap(), ApRt::A)
            .try_encode()
            .unwrap();
        let mut out2 = onetdns_proto::Writer::with_limit(1232);
        let ss_ctx = RequestCtx {
            src: "10.0.0.1:5555".parse().unwrap(),
            transport: RtTransport::Do53Udp,
            raw: None,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };
        assert_eq!(
            server.handle_udp_wire(&hit, &ss_ctx, &mut out2, std::time::Instant::now()),
            WireDisposition::Fallback
        );
        assert_eq!(
            limiter.0.load(Ordering::Relaxed),
            0,
            "폴백하는 히트는 wire 경로에서 rate limit 토큰을 소비하지 않아야 한다"
        );
    }

    #[test]
    /** @brief 교체해도 이미 잡고 처리 중인 것이 깨지지 않는지. */
    fn resolver_slot_replaces_new_requests_without_invalidating_old_handles() {
        let slot = ResolverSlot::new(Arc::new(FixedRcode(ResponseCode::ServFail.0)));
        let previous = slot.load();
        slot.replace(Arc::new(FixedRcode(ResponseCode::NoError.0)));

        assert_eq!(
            previous.resolve(&q("old.example")).unwrap().header.rcode,
            ResponseCode::ServFail.0
        );
        assert_eq!(
            slot.resolve(&q("new.example")).unwrap().header.rcode,
            ResponseCode::NoError.0
        );
    }

    /** @brief 빈 응답을 내는 테스트용 업스트림. */
    fn mock_empty_upstream() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                if let Ok(req) = Message::parse(&buf[..n]) {
                    let mut response = base_response(&req);
                    response.header.rcode = ResponseCode::NoError.0;
                    let _ = sock.send_to(&response.try_encode().unwrap(), from);
                }
            }
        });
        addr
    }

    /**
     * @brief 별칭 하나만 담아 보내는 테스트용 업스트림. 부정 응답 SOA는 담지 않는다.
     *
     * @details 이름이 CNAME으로 이어지고 그 끝에 요청한 종류가 없을 때(IPv6 주소가 없는
     *          이름의 AAAA가 대표적이다) 실제 업스트림이 내는 모양이다. 공개 리졸버 여럿이
     *          이때 SOA를 담지 않는다.
     */
    fn mock_alias_only_upstream() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                if let Ok(req) = Message::parse(&buf[..n]) {
                    let mut response = base_response(&req);
                    response.header.rcode = ResponseCode::NoError.0;
                    if let Some(question) = req.questions.first() {
                        response.answers.push(ApRecord::new(
                            question.name.clone(),
                            60,
                            ApRData::Cname(ApName::from_str("target.example.").unwrap()),
                        ));
                    }
                    let _ = sock.send_to(&response.try_encode().unwrap(), from);
                }
            }
        });
        addr
    }

    /** @brief 내부망 주소를 답하는 테스트용 업스트림. */
    fn mock_private_upstream() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                if let Ok(req) = Message::parse(&buf[..n]) {
                    let mut response = base_response(&req);
                    response.header.rcode = ResponseCode::NoError.0;
                    if let Some(question) = req.questions.first() {
                        response.answers.push(ApRecord::new(
                            question.name.clone(),
                            60,
                            ApRData::A(Ipv4Addr::new(10, 0, 0, 7)),
                        ));
                    }
                    let _ = sock.send_to(&response.try_encode().unwrap(), from);
                }
            }
        });
        addr
    }

    /** @brief 이 업스트림을 쓰는 테스트용 핸들러. */
    fn server_with_upstream(upstream: SocketAddr) -> NativeServer {
        NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            Arc::new(NativeBackend::Forward(Forwarder::new(
                vec![upstream],
                Duration::from_secs(2),
            ))),
            60,
        )
    }

    /** @brief 사유 코드를 담아 보내는 테스트용 업스트림. */
    fn mock_upstream_ede() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                if let Ok(req) = Message::parse(&buf[..n]) {
                    let mut m = base_response(&req);
                    m.header.rcode = ResponseCode::NoError.0;
                    if let Some(qq) = req.questions.first() {
                        m.answers.push(ApRecord::new(
                            qq.name.clone(),
                            60,
                            ApRData::A(Ipv4Addr::new(7, 7, 7, 7)),
                        ));
                    }
                    let mut e = onetdns_proto::Edns::default();
                    e.push_ede(onetdns_proto::ede_code::STALE_ANSWER, "stale");
                    m.additionals.push(e.try_to_record().unwrap());
                    let _ = sock.send_to(&m.try_encode().unwrap(), from);
                }
            }
        });
        addr
    }

    #[test]
    /** @brief 답한 주소가 바이트로 오갔다 와도 그대로인지. */
    fn resolved_address_survives_client_wire_roundtrip() {
        let srv = server("");
        let mut request = q("wire.example.");
        request.header.checking_disabled = true;
        let response = srv.handle(&request, &ctx()).expect("응답");
        let parsed =
            Message::parse(&response.try_encode().unwrap()).expect("클라이언트 wire parse");

        assert_eq!(parsed.header.id, request.header.id);
        assert!(parsed.header.response);
        assert!(parsed.header.recursion_available);
        assert!(parsed.header.recursion_desired);
        assert!(parsed.header.checking_disabled);
        assert_eq!(parsed.questions.len(), 1);
        assert!(parsed.questions[0]
            .name
            .eq_ignore_case(&request.questions[0].name));
        assert_eq!(parsed.questions[0].qtype, request.questions[0].qtype);
        assert_eq!(parsed.questions[0].qclass, request.questions[0].qclass);
        assert!(parsed
            .answers
            .iter()
            .any(|record| { record.rdata == ApRData::A(Ipv4Addr::new(7, 7, 7, 7)) }));
    }

    #[test]
    /**
     * @brief 별칭만 실려 온 응답을 실패로 바꾸지 않는지.
     *
     * @details 이름이 CNAME으로 이어지고 그 끝에 요청한 종류가 없으면 업스트림은 CNAME 하나에
     *          NOERROR로 답한다. 부정 응답 SOA를 함께 담지 않는 업스트림이 흔하다. 그것을
     *          실패로 바꾸면 CNAME 뒤에 선 이름의 AAAA가 전부 실패한다. 실제로
     *          emergency.zeta-ai.io의 AAAA가 그렇게 막혔다.
     * @warning 별칭이 없는 빈 NOERROR는 그대로 막아야 한다. 그것은 근거도 답도 없는 응답이다.
     */
    fn an_alias_only_answer_is_not_turned_into_a_failure() {
        let srv = server_with_upstream(mock_alias_only_upstream());
        let response = srv.handle(&q("alias.example."), &ctx()).expect("응답");
        assert_eq!(
            response.header.rcode,
            ResponseCode::NoError.0,
            "별칭만 온 응답을 실패로 바꿨습니다"
        );
        assert!(
            response
                .answers
                .iter()
                .any(|record| matches!(&record.rdata, ApRData::Cname(_))),
            "별칭을 그대로 전달해야 합니다"
        );
    }

    #[test]
    /**
     * @brief 근거 없이 비어 온 응답을 규격대로 그대로 전달하는지.
     *
     * @details RFC 2308이 모든 구간이 빈 것을 NODATA의 한 모양으로 열거해 두었다.
     *          SOA가 없을 때 규격이 정한 처분은 거절이 아니라 캐시 금지이고, 담지 않는 것은
     *          캐시 계층이 따로 한다(unproven_empty_noerror_is_not_cached).
     * @warning 한때 이것을 SERVFAIL로 바꿨다. RFC 4074가 바로 그 동작을 지목한다. IPv6
     *          주소가 없는 이름의 AAAA에 SERVFAIL을 주면 질의자가 A로 다시 묻지 못하고
     *          되풀이한다. 실제로 CNAME 뒤에 선 이름의 AAAA가 전부 막혔다.
     */
    fn unproven_empty_noerror_is_passed_through_not_failed() {
        let srv = server_with_upstream(mock_empty_upstream());
        let response = srv.handle(&q("empty.example."), &ctx()).expect("응답");
        assert_eq!(
            response.header.rcode,
            ResponseCode::NoError.0,
            "규격이 인정한 NODATA를 실패로 바꿨습니다"
        );
        assert!(
            response.answers.is_empty(),
            "없는 레코드를 지어내면 안 됩니다"
        );
    }

    #[test]
    /** @brief 내부망 주소를 걷어 낸 뒤 빈 성공 응답이 남지 않는지. 남으면 없다는 뜻이 된다. */
    fn rebind_filter_never_leaves_empty_success() {
        let srv = server_with_upstream(mock_private_upstream()).with_features(NativeFeatures {
            rebind_protection: true,
            ..NativeFeatures::default()
        });
        let mut request = q("private.example.");
        request
            .additionals
            .push(onetdns_proto::Edns::default().try_to_record().unwrap());
        let response = srv.handle(&request, &ctx()).expect("응답");
        assert_eq!(response.header.rcode, ResponseCode::NXDomain.0);
        assert!(response.answers.is_empty());
        assert_eq!(negative_soa_ttl(&response), 60);
        let ede = response
            .opt()
            .and_then(onetdns_proto::Edns::from_record)
            .and_then(|edns| edns.ede());
        assert!(ede.is_some(), "필터 이유를 EDE로 전달");
    }

    #[test]
    /**
     * @brief ECS 옵션을 요청한 클라이언트에게만 그대로 돌려주는지.
     *
     * @details RFC 7871은 두 방향을 함께 규정한다. 대역 정보를 쓰는 서버는 질의에
     *          그 옵션이 없었으면 응답에 넣어서는 안 되고, 있었으면 반드시 넣어야 한다.
     *          하류가 전달 리졸버면 이 값으로 자기 캐시의 범위를 정하므로, 빠뜨리면 대역별
     *          답을 모두에게 주는 캐시가 된다.
     * @note SCOPE 는 0 이다. 이 서버는 설정된 고정 대역으로 업스트림에 물으므로 어느 클라이언트에게나
     *       같은 답이 나가고, 0 이 아닌 값을 적으면 하류가 그 대역 전용 답으로 잘못 담는다.
     */
    fn client_subnet_is_echoed_only_when_the_query_carried_one() {
        let with_ecs = |raw: Option<Vec<u8>>| {
            let mut request = q("a.example.");
            let mut edns = onetdns_proto::Edns::default();
            if let Some(raw) = raw {
                edns.set_client_subnet(raw);
            }
            request.additionals.push(edns.try_to_record().unwrap());
            request
        };
        let echoed = |response: &Message| {
            response
                .opt()
                .and_then(onetdns_proto::Edns::from_record)
                .and_then(|edns| edns.client_subnet().map(<[u8]>::to_vec))
        };
        let using = |on: bool| {
            server("").with_features(NativeFeatures {
                ecs_in_use: on,
                ..NativeFeatures::default()
            })
        };

        // FAMILY 1, SOURCE 24, SCOPE 0, 192.0.2.0
        let asked = vec![0, 1, 24, 0, 192, 0, 2];
        let response = using(true)
            .handle(&with_ecs(Some(asked.clone())), &ctx())
            .unwrap();
        assert_eq!(
            echoed(&response),
            Some(asked.clone()),
            "FAMILY, SOURCE, ADDRESS 는 질의의 것과 같고 SCOPE 는 0 입니다"
        );

        // 클라이언트가 SCOPE 를 잘못 적어 보내도 이 서버의 응답의 SCOPE 는 0 이다.
        let bad_scope = vec![0, 1, 24, 24, 192, 0, 2];
        let response = using(true)
            .handle(&with_ecs(Some(bad_scope)), &ctx())
            .unwrap();
        assert_eq!(echoed(&response), Some(asked.clone()));

        let response = using(true).handle(&with_ecs(None), &ctx()).unwrap();
        assert_eq!(
            echoed(&response),
            None,
            "요청하지 않은 클라이언트에게는 넣지 않습니다"
        );

        let response = using(false).handle(&with_ecs(Some(asked)), &ctx()).unwrap();
        assert_eq!(
            echoed(&response),
            None,
            "대역 정보를 쓰지 않으면 그대로 돌려줄 것도 없습니다"
        );

        // SOURCE 24 인데 주소가 두 옥텟뿐이라 형식이 깨졌다. 그대로 돌려주면 어긋난 옵션을
        // 하류로 퍼뜨리게 되므로 넣지 않는다.
        let short = vec![0, 1, 24, 0, 192, 0];
        let response = using(true).handle(&with_ecs(Some(short)), &ctx()).unwrap();
        assert_eq!(
            echoed(&response),
            None,
            "형식이 깨진 옵션은 그대로 돌려주지 않습니다"
        );
    }

    #[test]
    /** @brief 업스트림이 보낸 사유가 그대로 전해지는지. */
    fn ede_passthrough_from_upstream() {
        let srv = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            Arc::new(NativeBackend::Forward(Forwarder::new(
                vec![mock_upstream_ede()],
                Duration::from_secs(2),
            ))),
            60,
        );

        let mut req = q("a.example.");
        req.additionals
            .push(onetdns_proto::Edns::default().try_to_record().unwrap());
        let resp = srv.handle(&req, &ctx()).unwrap();
        let opt = resp.opt().expect("EDNS 클라엔 OPT");
        let (code, _) = onetdns_proto::Edns::from_record(opt)
            .unwrap()
            .ede()
            .expect("EDE 전달");
        assert_eq!(code, onetdns_proto::ede_code::STALE_ANSWER);

        let resp2 = srv.handle(&q("b.example."), &ctx()).unwrap();
        assert!(resp2.opt().is_none(), "비EDNS 클라엔 OPT 강제 안 함");
    }

    #[test]
    /** @brief 실패에 사유가 담기는지. */
    fn resolver_failure_carries_diagnostic_ede() {
        /** @brief 정해진 실패를 내는 테스트용 체인. */
        struct FailBackend(ResolveFailure);
        impl Resolver for FailBackend {
            /** @brief 언제나 답하지 않는다. */
            fn resolve(&self, _req: &Message) -> Option<Message> {
                None
            }
            /** @brief 정해진 실패를 알린다. */
            fn resolve_outcome(&self, _req: &Message) -> ResolveOutcome {
                ResolveOutcome::Failure(match self.0 {
                    ResolveFailure::TransportExhausted => ResolveFailure::TransportExhausted,
                    ResolveFailure::Permanent(code) => ResolveFailure::Permanent(code),
                })
            }
        }

        let srv = |failure: ResolveFailure| {
            NativeServer::new(
                shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                    BlockResponse::NxDomain,
                ))),
                Arc::new(IpAcl::allow_all()),
                vec![],
                Arc::new(FailBackend(failure)),
                60,
            )
        };
        let ede_of = |resp: &Message| -> Option<u16> {
            resp.opt()
                .and_then(onetdns_proto::Edns::from_record)
                .and_then(|e| e.ede())
                .map(|(code, _)| code)
        };

        let s = srv(ResolveFailure::Permanent(Some(
            onetdns_proto::ede_code::NO_REACHABLE_AUTHORITY,
        )));
        let mut req = q("fail.example.");
        req.additionals
            .push(onetdns_proto::Edns::default().try_to_record().unwrap());
        let resp = s.handle(&req, &ctx()).unwrap();
        assert_eq!(resp.header.rcode, ResponseCode::ServFail.0);
        assert_eq!(
            ede_of(&resp),
            Some(onetdns_proto::ede_code::NO_REACHABLE_AUTHORITY)
        );

        let s = srv(ResolveFailure::Permanent(Some(
            onetdns_proto::ede_code::DNSSEC_BOGUS,
        )));
        let resp = s.handle(&req, &ctx()).unwrap();
        assert_eq!(ede_of(&resp), Some(onetdns_proto::ede_code::DNSSEC_BOGUS));

        let s = srv(ResolveFailure::TransportExhausted);
        let resp = s.handle(&req, &ctx()).unwrap();
        assert_eq!(ede_of(&resp), Some(onetdns_proto::ede_code::NETWORK_ERROR));

        let s = srv(ResolveFailure::Permanent(Some(
            onetdns_proto::ede_code::OTHER,
        )));
        let resp = s.handle(&req, &ctx()).unwrap();
        let ede = resp
            .opt()
            .and_then(onetdns_proto::Edns::from_record)
            .and_then(|e| e.ede());
        assert_eq!(ede.as_ref().map(|(code, _)| *code), Some(0));
        assert_eq!(
            ede.map(|(_, text)| text),
            Some("recursion limit exceeded".to_string())
        );

        let s = srv(ResolveFailure::Permanent(None));
        let resp = s.handle(&q("fail.example."), &ctx()).unwrap();
        assert_eq!(resp.header.rcode, ResponseCode::ServFail.0);
        assert!(resp.opt().is_none());
    }

    #[test]
    /** @brief 접근 제어에 막혔음을 사유로 알리는지. */
    fn acl_denied_query_carries_prohibited_ede() {
        let srv = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::new(vec![], vec![], false)),
            vec![],
            Arc::new(FixedRcode(ResponseCode::NoError.0)),
            60,
        );
        let ede_of = |resp: &Message| -> Option<u16> {
            resp.opt()
                .and_then(onetdns_proto::Edns::from_record)
                .and_then(|e| e.ede())
                .map(|(code, _)| code)
        };

        let mut req = q("denied.example.");
        req.additionals
            .push(onetdns_proto::Edns::default().try_to_record().unwrap());
        let resp = srv.handle(&req, &ctx()).unwrap();
        assert_eq!(resp.header.rcode, ResponseCode::Refused.0);
        assert_eq!(ede_of(&resp), Some(onetdns_proto::ede_code::PROHIBITED));

        let resp2 = srv.handle(&q("denied.example."), &ctx()).unwrap();
        assert_eq!(resp2.header.rcode, ResponseCode::Refused.0);
        assert!(resp2.opt().is_none());
    }

    #[test]
    #[ignore = "마이크로벤치: cargo test -p onetdns --release -- --ignored --nocapture"]
    /** @brief 답 요약을 만드는 비용. */
    fn bench_answers_summary_cost() {
        use std::time::Instant;
        let name = ApName::from_str("www.example.com").unwrap();
        let ip = |b: u8| ApRData::A(Ipv4Addr::new(93, 184, 216, b));
        let answers = vec![
            ApRecord::new(name.clone(), 300, ip(34)),
            ApRecord::new(name.clone(), 300, ip(35)),
        ];
        for _ in 0..50_000 {
            let _ = answers_summary(&answers);
        }
        let iters = 1_000_000u128;
        let mut sink = 0usize;
        let t = Instant::now();
        for _ in 0..iters {
            sink = sink.wrapping_add(answers_summary(&answers).len());
        }
        let ns = t.elapsed().as_nanos() as f64 / iters as f64;
        println!(
            "answers_summary(2xA): {ns:.1} ns/call saved per store when no recorder (sink={sink})"
        );
    }

    #[test]
    /** @brief 차단됐음을 사유로 알리는지. */
    fn ede_on_filter_block() {
        let srv = server("||blocked.test^\n");

        let mut req = q("blocked.test.");
        req.additionals
            .push(onetdns_proto::Edns::default().try_to_record().unwrap());
        let resp = srv.handle(&req, &ctx()).unwrap();
        assert_eq!(resp.header.rcode, ResponseCode::NXDomain.0);
        let opt = resp.opt().expect("EDNS 클라엔 OPT 에코");
        let (code, text) = onetdns_proto::Edns::from_record(opt)
            .unwrap()
            .ede()
            .expect("EDE");
        assert_eq!(code, onetdns_proto::ede_code::BLOCKED);
        assert_eq!(text, "blocked by filter");

        let resp2 = srv.handle(&q("blocked.test."), &ctx()).unwrap();
        assert_eq!(resp2.header.rcode, ResponseCode::NXDomain.0);
        assert!(resp2.opt().is_none(), "비EDNS 클라엔 OPT 강제 안 함");
    }

    #[test]
    /** @brief 답에 담긴 주소가 차단 대상이면 막는지. */
    fn rpz_ip_blocks_resolved_answer() {
        let mut parts = onetdns_filter::EngineParts::default();
        parts.rpz_ip.push(onetdns_filter::RpzIpRule::new(
            "7.7.7.7/32".parse().unwrap(),
            FilterVerdict::Block(BlockResponse::NxDomain),
        ));
        let engine = onetdns_filter::BlockEngine::new(parts, BlockResponse::NxDomain);
        let srv = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(engine)),
            Arc::new(IpAcl::allow_all()),
            vec![],
            Arc::new(NativeBackend::Forward(Forwarder::new(
                vec![mock_upstream()],
                Duration::from_secs(2),
            ))),
            60,
        );
        let resp = srv.handle(&q("anything.example."), &ctx()).unwrap();
        assert_eq!(
            resp.header.rcode,
            ResponseCode::NXDomain.0,
            "응답 IP가 rpz-ip 트리거에 걸려 NXDOMAIN"
        );

        let resp2 = server("").handle(&q("anything.example."), &ctx()).unwrap();
        assert_eq!(resp2.header.rcode, ResponseCode::NoError.0);
        assert!(resp2
            .answers
            .iter()
            .any(|r| r.rdata == ApRData::A(Ipv4Addr::new(7, 7, 7, 7))));
    }

    #[test]
    /** @brief 서명한 영역 전송이 오가고, 요구 설정이 서명 없는 것을 막는지. */
    fn axfr_tsig_signed_roundtrip_and_required_mode() {
        use onetdns_dnssec::tsig;
        let zone_text = "$ORIGIN example.com.\n$TTL 300\n@ IN SOA ns1 admin 1 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.1\n";
        let zone = onetdns_authority::parse_zone(zone_text, "example.com").unwrap();
        let mut zs = onetdns_authority::ZoneStore::new();
        zs.add(zone);
        let store = Arc::new(ArcSwap::new(Arc::new(zs)));
        let key = tsig::TsigKey::new(
            ApName::from_str("xfer-key").unwrap(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();
        let srv = server("")
            .with_xfr(store, vec!["127.0.0.0/8".parse().unwrap()])
            .with_tsig(vec![key.clone()], true);
        let tcp = RequestCtx {
            src: "127.0.0.1:5555".parse().unwrap(),
            transport: RtTransport::Do53Tcp,
            raw: None,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };

        let unsigned = Message::query(7, ApName::from_str("example.com").unwrap(), ApRt(252));
        let resp = srv.handle(&unsigned, &tcp).unwrap();
        assert_eq!(resp.header.rcode, ResponseCode::Refused.0, "비서명 거부");

        let mut signed = Message::query(8, ApName::from_str("example.com").unwrap(), ApRt(252));
        let req_mac = tsig::sign_message(&mut signed, &key, now_unix(), None).unwrap();
        let signed_wire = signed.try_encode().unwrap();
        let tcp_raw = RequestCtx {
            src: "127.0.0.1:5555".parse().unwrap(),
            transport: RtTransport::Do53Tcp,
            raw: Some(signed_wire.as_slice()),
            client_id: None,

            authenticated: false,
            auth_identity: None,
        };
        let resp = srv.handle(&signed, &tcp_raw).unwrap();
        assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
        assert!(
            resp.answers.iter().any(|r| r.rtype == RecordType::SOA),
            "SOA 포함"
        );
        tsig::verify_message(&resp, &key, now_unix(), Some(&req_mac)).expect("응답 TSIG 검증");

        let mut ordinary = q("ordinary.example");
        let ordinary_mac = tsig::sign_message(&mut ordinary, &key, now_unix(), None).unwrap();
        let ordinary_wire = ordinary.try_encode().unwrap();
        let ordinary_ctx = RequestCtx {
            raw: Some(&ordinary_wire),
            ..tcp_raw
        };
        let ordinary_resp = srv.handle(&ordinary, &ordinary_ctx).unwrap();
        tsig::verify_message(&ordinary_resp, &key, now_unix(), Some(&ordinary_mac))
            .expect("일반 DNS 응답도 요청 TSIG에 연쇄 서명");

        let bad = tsig::TsigKey::new(key.name.clone(), b"wrong-wrong-wrong!".to_vec()).unwrap();
        let mut forged = Message::query(9, ApName::from_str("example.com").unwrap(), ApRt(252));
        tsig::sign_message(&mut forged, &bad, now_unix(), None).unwrap();
        let forged_wire = forged.try_encode().unwrap();
        let forged_ctx = RequestCtx {
            raw: Some(&forged_wire),
            ..tcp.clone()
        };
        let resp = srv.handle(&forged, &forged_ctx).unwrap();
        assert_eq!(resp.header.rcode, 9, "BADSIG → NOTAUTH");
        assert_eq!(
            resp.additionals.last().map(|record| record.rtype),
            Some(ApRt(250)),
            "BADSIG 응답은 빈 MAC의 TSIG 오류 레코드를 포함해야 합니다"
        );
        let error = tsig::response_data(&resp).expect("BADSIG TSIG");
        assert_eq!(error.error(), tsig::TSIG_ERROR_BADSIG);
        assert!(error.mac().is_empty(), "BADSIG 오류는 서명하면 안 됩니다");
        assert!(error.other().is_empty());

        let unknown = tsig::TsigKey::new(
            ApName::from_str("unknown-key").unwrap(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();
        let mut unknown_request =
            Message::query(10, ApName::from_str("example.com").unwrap(), ApRt(252));
        tsig::sign_message(&mut unknown_request, &unknown, now_unix(), None).unwrap();
        let unknown_wire = unknown_request.try_encode().unwrap();
        let unknown_ctx = RequestCtx {
            raw: Some(&unknown_wire),
            ..tcp.clone()
        };
        let resp = srv.handle(&unknown_request, &unknown_ctx).unwrap();
        assert_eq!(resp.header.rcode, 9, "BADKEY → NOTAUTH");
        assert_eq!(
            resp.additionals.last().map(|record| record.rtype),
            Some(ApRt(250)),
            "BADKEY 응답은 빈 MAC의 TSIG 오류 레코드를 포함해야 합니다"
        );
        let error = tsig::response_data(&resp).expect("BADKEY TSIG");
        assert_eq!(error.error(), tsig::TSIG_ERROR_BADKEY);
        assert_eq!(error.key_name(), &unknown.name);
        assert!(error.mac().is_empty(), "BADKEY 오류는 서명하면 안 됩니다");
        assert!(error.other().is_empty());

        let mut unsupported =
            Message::query(11, ApName::from_str("example.com").unwrap(), ApRt(252));
        tsig::sign_message(&mut unsupported, &key, now_unix(), None).unwrap();
        let raw = match &mut unsupported.additionals.last_mut().unwrap().rdata {
            ApRData::Unknown(250, raw) => raw,
            _ => panic!("TSIG RDATA가 아닙니다"),
        };
        let algorithm = raw
            .windows(b"hmac-sha256".len())
            .position(|window| window == b"hmac-sha256")
            .expect("알고리즘 이름");
        raw[algorithm..algorithm + b"hmac-sha512".len()].copy_from_slice(b"hmac-sha512");
        let unsupported_wire = unsupported.try_encode().unwrap();
        let unsupported_ctx = RequestCtx {
            raw: Some(&unsupported_wire),
            ..tcp.clone()
        };
        let resp = srv.handle(&unsupported, &unsupported_ctx).unwrap();
        let error = tsig::response_data(&resp).expect("unsupported algorithm BADKEY TSIG");
        assert_eq!(error.error(), tsig::TSIG_ERROR_BADKEY);
        assert_eq!(error.algorithm().to_ascii_lower(), "hmac-sha512");
        assert!(error.mac().is_empty());

        let client_time = now_unix().saturating_sub(301);
        let mut expired = Message::query(12, ApName::from_str("example.com").unwrap(), ApRt(252));
        let expired_mac = tsig::sign_message(&mut expired, &key, client_time, None).unwrap();
        let expired_wire = expired.try_encode().unwrap();
        let expired_ctx = RequestCtx {
            raw: Some(&expired_wire),
            ..tcp.clone()
        };
        let resp = srv.handle(&expired, &expired_ctx).unwrap();
        assert_eq!(resp.header.rcode, 9, "BADTIME → NOTAUTH");
        assert_eq!(
            resp.additionals.last().map(|record| record.rtype),
            Some(ApRt(250)),
            "BADTIME 응답은 서명된 TSIG 오류 레코드를 포함해야 합니다"
        );
        let error = tsig::response_data(&resp).expect("BADTIME TSIG");
        assert_eq!(error.error(), tsig::TSIG_ERROR_BADTIME);
        assert_eq!(error.time_signed(), client_time);
        assert_eq!(error.fudge(), 300);
        assert_eq!(error.other().len(), 6);
        assert_eq!(error.mac().len(), 32, "BADTIME 오류는 서명해야 합니다");
        let server_time = error
            .other()
            .iter()
            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
        assert!(now_unix().abs_diff(server_time) <= 1);
        tsig::verify_message(&resp, &key, client_time, Some(&expired_mac))
            .expect("BADTIME 응답 MAC 검증");

        let stale_bad =
            tsig::TsigKey::new(key.name.clone(), b"wrong-wrong-wrong!".to_vec()).unwrap();
        let mut stale_forged =
            Message::query(13, ApName::from_str("example.com").unwrap(), ApRt(252));
        tsig::sign_message(&mut stale_forged, &stale_bad, client_time, None).unwrap();
        let stale_forged_wire = stale_forged.try_encode().unwrap();
        let stale_forged_ctx = RequestCtx {
            raw: Some(&stale_forged_wire),
            ..tcp.clone()
        };
        let resp = srv.handle(&stale_forged, &stale_forged_ctx).unwrap();
        let error = tsig::response_data(&resp).expect("stale BADSIG TSIG");
        assert_eq!(
            error.error(),
            tsig::TSIG_ERROR_BADSIG,
            "시간보다 MAC을 먼저 검증해야 합니다"
        );
        assert!(error.mac().is_empty());

        let mut unsigned_ixfr =
            Message::query(14, ApName::from_str("example.com").unwrap(), ApRt(251));
        unsigned_ixfr.authorities.push(ApRecord {
            name: ApName::from_str("example.com").unwrap(),
            rtype: ApRt::SOA,
            class: DnsClass::IN,
            ttl: 300,
            rdata: ApRData::soa(onetdns_proto::Soa {
                mname: ApName::from_str("ns1.example.com").unwrap(),
                rname: ApName::from_str("admin.example.com").unwrap(),
                serial: 1,
                refresh: 300,
                retry: 60,
                expire: 86400,
                minimum: 60,
            }),
        });
        let udp = RequestCtx {
            transport: RtTransport::Do53Udp,
            ..tcp
        };
        let resp = srv.handle(&unsigned_ixfr, &udp).unwrap();
        assert_eq!(
            resp.header.rcode,
            ResponseCode::Refused.0,
            "UDP IXFR도 필수 TSIG를 우회할 수 없습니다"
        );
    }

    #[test]
    /** @brief 서명이 망가진 요청이 서명 없는 전송으로 넘어가지 않는지. 넘어가면 검증을 우회한다. */
    fn malformed_tsig_layout_cannot_fall_back_to_unsigned_axfr() {
        use onetdns_dnssec::tsig;
        let zone_text = "$ORIGIN example.com.\n$TTL 300\n@ IN SOA ns1 admin 1 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.1\n";
        let zone = onetdns_authority::parse_zone(zone_text, "example.com").unwrap();
        let mut zones = onetdns_authority::ZoneStore::new();
        zones.add(zone);
        let store = Arc::new(ArcSwap::new(Arc::new(zones)));
        let key = tsig::TsigKey::new(
            ApName::from_str("xfer-key").unwrap(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();
        let srv = server("")
            .with_xfr(store, vec!["127.0.0.0/8".parse().unwrap()])
            .with_tsig(vec![key.clone()], false);

        let mut request = Message::query(8, ApName::from_str("example.com").unwrap(), ApRt(252));
        tsig::sign_message(&mut request, &key, now_unix(), None).unwrap();
        request.additionals.push(ApRecord {
            name: ApName::from_str("padding.example.com").unwrap(),
            rtype: ApRt(65_000),
            class: DnsClass::IN,
            ttl: 0,
            rdata: ApRData::Unknown(65_000, Vec::new()),
        });
        let raw = request.try_encode().unwrap();
        let tcp = RequestCtx {
            src: "127.0.0.1:5555".parse().unwrap(),
            transport: RtTransport::Do53Tcp,
            raw: Some(&raw),
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };

        let response = srv.handle(&request, &tcp).unwrap();
        assert_eq!(
            response.header.rcode,
            ResponseCode::FormErr.0,
            "마지막 RR이 아닌 TSIG는 unsigned AXFR로 강등하지 않습니다"
        );
    }

    /** @brief 큰 테스트용 영역. */
    fn big_zone_store(n: usize) -> Arc<ArcSwap<onetdns_authority::ZoneStore>> {
        let mut zone_text = String::from(
            "$ORIGIN big.test.\n$TTL 300\n@ IN SOA ns1 admin 1 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.1\n",
        );
        for i in 0..n {
            zone_text.push_str(&format!(
                "host-{i:05}-with-a-rather-long-owner-label IN A 10.{}.{}.{}\n",
                (i >> 16) & 0xff,
                (i >> 8) & 0xff,
                i & 0xff
            ));
        }
        let zone = onetdns_authority::parse_zone(&zone_text, "big.test").unwrap();
        let mut zs = onetdns_authority::ZoneStore::new();
        zs.add(zone);
        Arc::new(ArcSwap::new(Arc::new(zs)))
    }

    /** @brief 언제나 통과시키는 테스트용 제한기. */
    struct ActivePermitLimiter;

    impl RateLimiter for ActivePermitLimiter {
        /** @brief 통과시킨다. */
        fn check(&self, _client: &ClientInfo) -> RateDecision {
            RateDecision::Permit
        }
    }

    /**
     * @brief 첫 판정 뒤에 켜지는 테스트용 제한기.
     * @details DynamicRateLimiter::replace가 질의 처리 도중에 제한기를 거는 것을 결정적으로
     *          흉내 낸다. 실제로는 컨트롤 플레인 스레드가 그 사이에 끼어든다.
     */
    struct LateActivatingLimiter {
        /** @brief is_active를 몇 번 물었는지. */
        asked: std::sync::atomic::AtomicUsize,
    }

    impl RateLimiter for LateActivatingLimiter {
        /** @brief 통과시킨다. */
        fn check(&self, _client: &ClientInfo) -> RateDecision {
            RateDecision::Permit
        }

        /** @brief 처음 물을 때만 꺼져 있다고 답한다. */
        fn is_active(&self) -> bool {
            self.asked.fetch_add(1, Ordering::Relaxed) != 0
        }
    }

    #[test]
    /** @brief 판정 사이에 제한기가 켜져도 고속 경로가 답으로 수렴하는지. */
    fn authority_wire_survives_limiter_activating_mid_dispatch() {
        let zone_text = "$ORIGIN fast.test.\n$TTL 300\n@ IN SOA ns admin 1 300 60 3600 60\n@ IN NS ns\nns IN A 192.0.2.53\nwww IN A 192.0.2.9\n";
        let mut zones = onetdns_authority::ZoneStore::new();
        zones.add(onetdns_authority::parse_zone(zone_text, "fast.test").unwrap());
        let store = Arc::new(ArcSwap::new(Arc::new(zones)));
        let authority = Arc::new(crate::layers::AuthorityLayer::new(
            Arc::new(FixedAnswer),
            store.clone(),
        ));
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![Arc::new(LateActivatingLimiter {
                asked: std::sync::atomic::AtomicUsize::new(0),
            })],
            authority,
            60,
        )
        .with_authority_wire_path(Some(store), true);
        let request = Message::query(
            0x4567,
            ApName::from_str("www.fast.test").unwrap(),
            RecordType::A,
        );
        let packet = request.try_encode().unwrap();
        let mut output = onetdns_proto::Writer::with_limit(1232);
        // 제한기가 꺼져 있다고 본 뒤 켜졌으므로 클라이언트를 만들지 않았다. 여기서 죽지 않고
        // 보통 경로로 전환해야 한다. 고속 경로는 언제 일반 경로로 넘겨도 정답이다.
        assert_eq!(
            server.handle_udp_wire(&packet, &ctx(), &mut output, Instant::now()),
            onetdns_runtime::WireDisposition::Fallback
        );
        assert!(
            output.buf.is_empty(),
            "물러설 때 절반 쓴 응답을 남기면 안 됩니다"
        );
    }

    #[test]
    /**
     * @brief EDNS 없는 UDP 질의에 512바이트를 넘는 답을 무할당 경로가 그대로 내보내지
     *        않는지. TCP 에는 그 상한이 없으므로 거기서는 그대로 답해야 한다.
     * @details 이 경로에는 절단 사다리가 없다. 물러서지 않으면 RFC 1035가 정한
     *          크기를 넘는 데이터그램이 나가고, 클라이언트는 TC 도 못 보므로 TCP 로 다시
     *          묻지도 않는다.
     */
    fn the_allocation_free_path_declines_a_non_edns_udp_answer_over_512_bytes() {
        let mut zone_text = String::from(
            "$ORIGIN wide.test.\n$TTL 300\n@ IN SOA ns admin 1 300 60 3600 60\n@ IN NS ns\nns IN A 192.0.2.53\n",
        );
        for index in 1..=60 {
            zone_text.push_str(&format!("many IN A 198.51.100.{index}\n"));
        }
        let mut zones = onetdns_authority::ZoneStore::new();
        zones.add(onetdns_authority::parse_zone(&zone_text, "wide.test").unwrap());
        let store = Arc::new(ArcSwap::new(Arc::new(zones)));
        let authority = Arc::new(crate::layers::AuthorityLayer::new(
            Arc::new(FixedAnswer),
            store.clone(),
        ));
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            authority,
            60,
        )
        .with_authority_wire_path(Some(store), true);

        let request = Message::query(
            0x5150,
            ApName::from_str("many.wide.test").unwrap(),
            RecordType::A,
        );
        let packet = request.try_encode().unwrap();

        let mut output = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.handle_udp_wire(&packet, &ctx(), &mut output, Instant::now()),
            onetdns_runtime::WireDisposition::Fallback,
            "512바이트를 넘는 답을 EDNS 없는 UDP 로 그대로 내보냈습니다"
        );
        assert!(output.buf.is_empty(), "물러설 때 절반 쓴 응답을 남겼습니다");

        let tcp = RequestCtx {
            src: "127.0.0.1:5555".parse().unwrap(),
            transport: RtTransport::Do53Tcp,
            raw: None,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };
        let mut tcp_output = onetdns_proto::Writer::with_limit(65535);
        assert_eq!(
            server.handle_tcp_wire(&packet, &tcp, &mut tcp_output, Instant::now()),
            onetdns_runtime::WireDisposition::Respond,
            "TCP 에는 512바이트 상한이 없습니다"
        );
        assert!(tcp_output.buf.len() > 512);
    }

    #[test]
    /**
     * @brief 이 서버가 맡은 영역의 ANY가 표준 알고리즘을 먼저 따르는지.
     * @details RFC 8482는 최소 응답을 답 구간에만 허용하고 "Except as described below
     *          in this section, the DNS responder MUST follow the standard algorithms"
     *          라고 규정한다. 해석하기 전에 합성하면 없는 이름이 NOERROR가 되어 존재를
     *          알리고 부정 캐시도 서지 않으며, 권한 표시도 서지 않는다. 4.2는 QNAME에
     *          CNAME이 있으면 합성하지 말라고 하므로 그것도 함께 본다.
     */
    fn minimal_any_follows_the_standard_algorithm_inside_our_own_zones() {
        let zone_text = concat!(
            "$ORIGIN any.test.\n$TTL 300\n",
            "@ IN SOA ns admin 1 300 60 3600 60\n",
            "@ IN NS ns\n",
            "ns IN A 192.0.2.53\n",
            "host IN A 192.0.2.9\n",
            "host IN TXT \"two rrsets\"\n",
            "alias IN CNAME host\n",
        );
        let mut zones = onetdns_authority::ZoneStore::new();
        zones.add(onetdns_authority::parse_zone(zone_text, "any.test").unwrap());
        let store = Arc::new(ArcSwap::new(Arc::new(zones)));
        let authority = Arc::new(crate::layers::AuthorityLayer::new(
            Arc::new(FixedAnswer),
            store.clone(),
        ));
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            authority,
            60,
        )
        .with_authority_wire_path(Some(store), true);

        let ask = |name: &str| -> Message {
            let request = Message::query(0x7788, ApName::from_str(name).unwrap(), ApRt::ANY);
            server.handle(&request, &ctx()).expect("응답")
        };

        let existing = ask("host.any.test");
        assert_eq!(existing.header.rcode, ResponseCode::NoError.0);
        assert!(
            existing.header.authoritative,
            "권한 표시를 설정하지 않았습니다"
        );
        assert_eq!(existing.answers.len(), 1);
        assert_eq!(existing.answers[0].rtype, ApRt(13), "합성 HINFO여야 합니다");

        let missing = ask("nosuch.any.test");
        assert_eq!(
            missing.header.rcode,
            ResponseCode::NXDomain.0,
            "없는 이름에 NOERROR를 주면 있다고 알리는 것입니다"
        );
        assert!(missing.answers.is_empty());
        assert!(missing.header.authoritative);

        let aliased = ask("alias.any.test");
        assert!(
            aliased
                .answers
                .iter()
                .any(|record| record.rtype == ApRt::CNAME),
            "QNAME에 CNAME이 있으면 합성하지 않습니다"
        );
    }

    #[test]
    /** @brief 큰 영역이 여러 청크로 나뉘어 가는지. */
    fn axfr_large_zone_streams_multiple_envelopes() {
        let store = big_zone_store(2000);
        let mut srv = server("").with_xfr(store, vec!["127.0.0.0/8".parse().unwrap()]);
        let tcp = RequestCtx {
            src: "127.0.0.1:5555".parse().unwrap(),
            transport: RtTransport::Do53Tcp,
            raw: None,
            client_id: None,

            authenticated: false,
            auth_identity: None,
        };
        let axfr = Message::query(7, ApName::from_str("BiG.test").unwrap(), ApRt(252));
        let msgs = srv.handle_multi(&axfr, &tcp).expect("AXFR 응답");
        assert!(msgs.len() > 1, "다중 envelope이어야: {}", msgs.len());

        let mut all: Vec<ApRecord> = Vec::new();
        for (i, m) in msgs.iter().enumerate() {
            let wire = m.try_encode().unwrap();
            assert!(
                wire.len() <= 0xffff,
                "각 envelope은 64KB 이하: {}",
                wire.len()
            );
            assert!(m.header.authoritative);
            if i == 0 {
                assert_eq!(m.questions.len(), 1, "첫 envelope에만 질문");
            } else {
                assert!(m.questions.is_empty(), "후속 envelope은 질문 생략");
            }
            all.extend(m.answers.iter().cloned());
        }

        assert_eq!(all.first().unwrap().rtype, RecordType::SOA);
        assert_eq!(all.last().unwrap().rtype, RecordType::SOA);
        assert_eq!(all.len(), 2000 + 2 + 2);
        let rebuilt = onetdns_authority::Zone::from_records(all).expect("재조립 영역 구성");
        assert_eq!(rebuilt.soa().serial, 1);

        let mut streamed = 0usize;
        let completed = srv.handle_stream(&axfr, &tcp, &mut |_| {
            streamed += 1;
            false
        });
        assert!(!completed, "전송 중단을 즉시 전파");
        assert_eq!(streamed, 1, "나머지 AXFR envelope을 미리 생성하지 않음");

        let first = srv.handle(&axfr, &tcp).unwrap();
        assert_eq!(first.answers.first().unwrap().rtype, RecordType::SOA);

        let mut cached_writer = onetdns_proto::Writer::new();
        let mut cached_wires = Vec::new();
        assert_eq!(
            srv.handle_preencoded_stream(&axfr, &tcp, &mut cached_writer, &mut |wire| {
                cached_wires.push(wire.to_vec());
                true
            }),
            Some(true)
        );
        assert!(cached_wires.len() > 1);
        let mut cached_records = 0usize;
        for (index, wire) in cached_wires.iter().enumerate() {
            let message = Message::parse(wire).expect("cached AXFR wire parse");
            assert_eq!(message.header.id, axfr.header.id);
            assert!(message.header.authoritative);
            assert_eq!(message.questions.len(), usize::from(index == 0));
            if index == 0 {
                assert_eq!(
                    message.questions[0].name.as_uncompressed_wire(),
                    axfr.questions[0].name.as_uncompressed_wire(),
                    "cached AXFR preserves question case"
                );
            }
            cached_records += message.answers.len();
        }
        assert_eq!(cached_records, 2000 + 2 + 2);
        let first_cached = cached_wires.clone();
        cached_wires.clear();
        assert_eq!(
            srv.handle_preencoded_stream(&axfr, &tcp, &mut cached_writer, &mut |wire| {
                cached_wires.push(wire.to_vec());
                true
            }),
            Some(true)
        );
        assert_eq!(cached_wires, first_cached, "lazy AXFR wire cache is reused");

        // 성공한 영역 전송은 어느 경로도 통계에 남기지 않는다. 기록기가 있다는 이유로 이
        // 경로가 포기하면 영역을 전부 다시 만들기만 하고 남는 기록은 그대로 없다.
        {
            let (recorder, _stats) = onetdns_control::channel(
                8,
                8,
                60,
                onetdns_control::RecorderOpts::default(),
                onetdns_control::PersistOpts::default(),
            );
            let mut features = (*srv.features.load()).clone();
            features.recorder = Some(recorder);
            srv.features.store(Arc::new(features));
            cached_wires.clear();
            assert_eq!(
                srv.handle_preencoded_stream(&axfr, &tcp, &mut cached_writer, &mut |wire| {
                    cached_wires.push(wire.to_vec());
                    true
                }),
                Some(true),
                "기록기가 있다고 미리 만들어 둔 영역 전송 경로가 전부 죽었습니다"
            );
            assert_eq!(
                cached_wires, first_cached,
                "기록기가 응답 바이트를 바꿨습니다"
            );
        }

        srv.rate_limiters.push(Arc::new(ActivePermitLimiter));
        assert_eq!(
            srv.handle_preencoded_stream(&axfr, &tcp, &mut cached_writer, &mut |_| true),
            None,
            "an active limiter keeps AXFR on the policy-aware Message path"
        );

        let doq = RequestCtx {
            transport: RtTransport::DoQ,
            ..tcp
        };
        let refused = srv.handle(&axfr, &doq).unwrap();
        assert_eq!(refused.header.rcode, ResponseCode::Refused.0);
    }

    #[test]
    /** @brief 여러 청크의 서명이 체인으로 이어져 검증되는지. */
    fn axfr_multi_envelope_tsig_chain_verifies() {
        use onetdns_dnssec::tsig;
        let store = big_zone_store(2000);
        let key = tsig::TsigKey::new(
            ApName::from_str("xfer-key").unwrap(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();
        let srv = server("")
            .with_xfr(store, vec!["127.0.0.0/8".parse().unwrap()])
            .with_tsig(vec![key.clone()], true);

        let mut signed = Message::query(8, ApName::from_str("big.test").unwrap(), ApRt(252));
        let req_mac = tsig::sign_message(&mut signed, &key, now_unix(), None).unwrap();
        let wire = signed.try_encode().unwrap();
        let tcp_raw = RequestCtx {
            src: "127.0.0.1:5555".parse().unwrap(),
            transport: RtTransport::Do53Tcp,
            raw: Some(wire.as_slice()),
            client_id: None,

            authenticated: false,
            auth_identity: None,
        };
        let msgs = srv.handle_multi(&signed, &tcp_raw).expect("AXFR 응답");
        assert!(msgs.len() > 1, "다중 envelope: {}", msgs.len());

        let mut prev = req_mac.clone();
        for (i, m) in msgs.iter().enumerate() {
            let w = m.try_encode().unwrap();
            let res = if i == 0 {
                tsig::verify_wire(&w, &key, now_unix(), Some(&prev))
            } else {
                tsig::verify_wire_subsequent(&w, &key, now_unix(), &prev)
            };
            let (_, mac) = res.unwrap_or_else(|e| {
                panic!("{i}번째 전송 메시지의 TSIG 검증에 실패했습니다: {e:?}")
            });
            prev = mac;
        }

        let mut writer = onetdns_proto::Writer::new();
        let mut wires = Vec::new();
        assert_eq!(
            srv.handle_preencoded_stream(&signed, &tcp_raw, &mut writer, &mut |wire| {
                wires.push(wire.to_vec());
                true
            }),
            Some(true),
            "TSIG AXFR도 캐시된 wire template을 사용합니다"
        );
        assert_eq!(wires.len(), msgs.len());
        let mut prev = req_mac;
        for (index, wire) in wires.iter().enumerate() {
            let (stripped, mac) = if index == 0 {
                tsig::verify_wire(wire, &key, now_unix(), Some(&prev))
            } else {
                tsig::verify_wire_subsequent(wire, &key, now_unix(), &prev)
            }
            .unwrap_or_else(|error| panic!("{index}번째 fast TSIG envelope: {error:?}"));
            let message = Message::parse(&stripped).unwrap();
            assert_eq!(message.questions.len(), usize::from(index == 0));
            prev = mac;
        }
    }

    #[test]
    /** @brief 원격 업데이트가 반영되고 시리얼이 오르는지. */
    fn ddns_update_applies_and_bumps_serial() {
        let zone_text = "$ORIGIN example.com.\n$TTL 300\n@ IN SOA ns1 admin 1 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.1\n";
        let zone = onetdns_authority::parse_zone(zone_text, "example.com").unwrap();
        let mut zs = onetdns_authority::ZoneStore::new();
        zs.add(zone);
        let store = Arc::new(ArcSwap::new(Arc::new(zs)));
        let srv = server("")
            .with_xfr(store.clone(), vec!["127.0.0.0/8".parse().unwrap()])
            .with_ddns(
                vec!["127.0.0.0/8".parse().unwrap()],
                false,
                vec![],
                vec![ApName::from_str("example.com").unwrap()],
            );
        let tcp = RequestCtx {
            src: "127.0.0.1:5555".parse().unwrap(),
            transport: RtTransport::Do53Tcp,
            raw: None,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };

        let mut up = Message::default();
        up.header.id = 0x77;
        up.header.opcode = 5;
        up.questions = vec![onetdns_proto::Question {
            name: ApName::from_str("example.com").unwrap(),
            qtype: ApRt::SOA,
            qclass: DnsClass::IN,
        }];

        up.answers.push(ApRecord {
            name: ApName::from_str("ns1.example.com").unwrap(),
            rtype: ApRt::A,
            class: DnsClass(255),
            ttl: 0,
            rdata: ApRData::Unknown(ApRt::A.0, vec![]),
        });

        up.authorities.push(ApRecord::new(
            ApName::from_str("www.example.com").unwrap(),
            120,
            ApRData::A(Ipv4Addr::new(10, 0, 0, 9)),
        ));
        let resp = srv.handle(&up, &tcp).unwrap();
        assert_eq!(resp.header.rcode, ResponseCode::NoError.0, "UPDATE 성공");

        let z = store.load();
        let zone = z.zones().first().unwrap().clone();
        assert_eq!(zone.soa().serial, 2, "serial+1");
        let q = zone.query(&ApName::from_str("www.example.com").unwrap(), ApRt::A);
        assert!(q
            .answers
            .iter()
            .any(|r| r.rdata == ApRData::A(Ipv4Addr::new(10, 0, 0, 9))));

        let other = RequestCtx {
            src: "192.168.1.9:5555".parse().unwrap(),
            transport: RtTransport::Do53Tcp,
            raw: None,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };
        let resp = srv.handle(&up, &other).unwrap();
        assert_eq!(resp.header.rcode, ResponseCode::Refused.0, "ACL 밖 거부");

        let mut bad = up.clone();
        bad.answers[0].name = ApName::from_str("nope.example.com").unwrap();
        let resp = srv.handle(&bad, &tcp).unwrap();
        assert_eq!(resp.header.rcode, 8, "전제 실패 NXRRSET");
    }

    #[test]
    /** @brief 선행 조건과 기록 모양을 확인하는지. 어긋난 것이 통과하면 영역이 깨진다. */
    fn ddns_enforces_prerequisite_sets_and_update_record_shape() {
        let zone_text = "$ORIGIN example.com.\n$TTL 300\n@ IN SOA ns1 admin 10 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.1\nmulti IN A 10.0.0.2\nmulti IN A 10.0.0.3\n";
        let zone = onetdns_authority::parse_zone(zone_text, "example.com").unwrap();
        let mut zs = onetdns_authority::ZoneStore::new();
        zs.add(zone);
        let store = Arc::new(ArcSwap::new(Arc::new(zs)));
        let srv = server("")
            .with_xfr(store.clone(), vec!["127.0.0.0/8".parse().unwrap()])
            .with_ddns(
                vec!["127.0.0.0/8".parse().unwrap()],
                false,
                vec![],
                vec![ApName::from_str("example.com").unwrap()],
            );
        let tcp = RequestCtx {
            src: "127.0.0.1:5555".parse().unwrap(),
            transport: RtTransport::Do53Tcp,
            raw: None,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };
        let mut update = Message::default();
        update.header.opcode = 5;
        update.questions.push(onetdns_proto::Question {
            name: ApName::from_str("example.com").unwrap(),
            qtype: ApRt::SOA,
            qclass: DnsClass::IN,
        });
        update.answers.push(ApRecord::new(
            ApName::from_str("multi.example.com").unwrap(),
            0,
            ApRData::A(Ipv4Addr::new(10, 0, 0, 2)),
        ));
        assert_eq!(
            srv.handle(&update, &tcp).unwrap().header.rcode,
            8,
            "부분집합은 value-dependent prerequisite를 만족하지 않음"
        );

        update.answers.push(ApRecord::new(
            ApName::from_str("multi.example.com").unwrap(),
            0,
            ApRData::A(Ipv4Addr::new(10, 0, 0, 3)),
        ));
        assert_eq!(
            srv.handle(&update, &tcp).unwrap().header.rcode,
            ResponseCode::NoError.0
        );
        assert_eq!(store.load().zones()[0].soa().serial, 10, "무변경 UPDATE");

        update.answers[0].name = ApName::from_str("outside.test").unwrap();
        assert_eq!(srv.handle(&update, &tcp).unwrap().header.rcode, 10);

        update.answers.clear();
        update.authorities.push(ApRecord {
            name: ApName::from_str("multi.example.com").unwrap(),
            rtype: ApRt::A,
            class: DnsClass(255),
            ttl: 1,
            rdata: ApRData::Unknown(ApRt::A.0, vec![]),
        });
        assert_eq!(
            srv.handle(&update, &tcp).unwrap().header.rcode,
            ResponseCode::FormErr.0,
            "CLASS=ANY 삭제는 TTL=0이어야 함"
        );
        assert_eq!(store.load().zones()[0].soa().serial, 10);

        update.authorities[0].ttl = 0;
        update.authorities[0].rtype = ApRt(252);
        update.authorities[0].rdata = ApRData::Unknown(252, vec![]);
        assert_eq!(
            srv.handle(&update, &tcp).unwrap().header.rcode,
            ResponseCode::FormErr.0,
            "QTYPE/meta-type은 UPDATE 레코드로 사용할 수 없습니다"
        );

        let secondary = server("")
            .with_xfr(store, vec!["127.0.0.0/8".parse().unwrap()])
            .with_ddns(
                vec!["127.0.0.0/8".parse().unwrap()],
                false,
                vec![],
                vec![ApName::from_str("primary-only.test").unwrap()],
            );
        update.answers.clear();
        update.authorities.clear();
        assert_eq!(
            secondary.handle(&update, &tcp).unwrap().header.rcode,
            9,
            "secondary 복제 zone은 로컬 DDNS 수정 불가"
        );
    }

    /** @brief DDNS 갱신 판정에 쓸 영역과 서버를 새로 만든다. */
    #[allow(clippy::type_complexity)]
    fn ddns_fixture() -> (Arc<ArcSwap<onetdns_authority::ZoneStore>>, NativeServer) {
        let zone_text = "$ORIGIN skip.test.\n$TTL 300\n@ IN SOA ns admin 10 300 60 86400 60\n@ IN NS ns\nns IN A 10.0.0.1\nmulti IN A 10.0.0.2\nsub IN NS ns.sub\nns.sub IN A 10.0.0.5\n";
        let mut zs = onetdns_authority::ZoneStore::new();
        zs.add(onetdns_authority::parse_zone(zone_text, "skip.test").unwrap());
        let store = Arc::new(ArcSwap::new(Arc::new(zs)));
        let srv = server("")
            .with_xfr(store.clone(), vec!["127.0.0.0/8".parse().unwrap()])
            .with_ddns(
                vec!["127.0.0.0/8".parse().unwrap()],
                false,
                vec![],
                vec![ApName::from_str("skip.test").unwrap()],
            );
        (store, srv)
    }

    /** @brief 갱신부에 기록들을 담은 UPDATE 한 통. */
    fn ddns_update(records: Vec<ApRecord>) -> Message {
        let mut m = Message::default();
        m.header.opcode = 5;
        m.questions.push(onetdns_proto::Question {
            name: ApName::from_str("skip.test").unwrap(),
            qtype: ApRt::SOA,
            qclass: DnsClass::IN,
        });
        m.authorities = records;
        m
    }

    /** @brief 이 이름에 이 종류가 몇 개나 있는지. */
    fn ddns_count(
        store: &Arc<ArcSwap<onetdns_authority::ZoneStore>>,
        name: &str,
        rtype: ApRt,
    ) -> usize {
        store.load().zones()[0]
            .query(&ApName::from_str(name).unwrap(), rtype)
            .answers
            .iter()
            .filter(|r| r.rtype == rtype)
            .count()
    }

    #[test]
    /**
     * @brief 어긋나는 갱신 RR 하나만 건너뛰고 나머지는 그대로 적용하는지.
     *
     * @details RFC 2136은 CNAME 이 다른 데이터와 공존하게 되는 추가와 정점의
     *          마지막 NS 삭제를 그 RR 만 건너뛰고 남은 것을 마저 처리한 뒤 NOERROR 로
     *          답하라고 정한다. 예전에는 일단 적용해 보고 영역 검증이 거부하면 SERVFAIL 을
     *          냈는데, 그러면 같은 메시지에 실려 온 멀쩡한 갱신까지 함께 사라진다.
     * @note 위임의 마지막 NS 는 지울 수 있어야 한다. 정점과 같은 규칙을 걸면 한번 만든
     *       위임을 영영 걷지 못한다.
     */
    fn ddns_skips_only_the_conflicting_record() {
        let tcp = RequestCtx {
            src: "127.0.0.1:5555".parse().unwrap(),
            transport: RtTransport::Do53Tcp,
            raw: None,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };

        let (store, srv) = ddns_fixture();
        let resp = srv
            .handle(
                &ddns_update(vec![
                    ApRecord::new(
                        ApName::from_str("multi.skip.test").unwrap(),
                        60,
                        ApRData::Cname(ApName::from_str("t.skip.test").unwrap()),
                    ),
                    ApRecord::new(
                        ApName::from_str("fresh.skip.test").unwrap(),
                        60,
                        ApRData::A(Ipv4Addr::new(10, 0, 0, 9)),
                    ),
                ]),
                &tcp,
            )
            .unwrap();
        assert_eq!(
            resp.header.rcode,
            ResponseCode::NoError.0,
            "공존할 수 없는 CNAME 하나 때문에 메시지 전체를 실패시키지 않습니다"
        );
        assert_eq!(
            ddns_count(&store, "multi.skip.test", ApRt::CNAME),
            0,
            "다른 데이터가 있는 이름에는 CNAME 을 넣지 않습니다"
        );
        assert_eq!(ddns_count(&store, "multi.skip.test", ApRt::A), 1);
        assert_eq!(
            ddns_count(&store, "fresh.skip.test", ApRt::A),
            1,
            "같은 메시지의 멀쩡한 갱신은 그대로 적용합니다"
        );

        let (store, srv) = ddns_fixture();
        let cname = ApRecord::new(
            ApName::from_str("c1.skip.test").unwrap(),
            60,
            ApRData::Cname(ApName::from_str("t1.skip.test").unwrap()),
        );
        assert_eq!(
            srv.handle(&ddns_update(vec![cname]), &tcp)
                .unwrap()
                .header
                .rcode,
            ResponseCode::NoError.0
        );
        let resp = srv
            .handle(
                &ddns_update(vec![
                    ApRecord::new(
                        ApName::from_str("c1.skip.test").unwrap(),
                        60,
                        ApRData::A(Ipv4Addr::new(10, 0, 0, 8)),
                    ),
                    ApRecord::new(
                        ApName::from_str("c1.skip.test").unwrap(),
                        60,
                        ApRData::Cname(ApName::from_str("t2.skip.test").unwrap()),
                    ),
                ]),
                &tcp,
            )
            .unwrap();
        assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
        assert_eq!(
            ddns_count(&store, "c1.skip.test", ApRt::A),
            0,
            "CNAME 이 있는 이름에는 다른 종류를 넣지 않습니다"
        );
        let cnames = store.load().zones()[0]
            .query(&ApName::from_str("c1.skip.test").unwrap(), ApRt::CNAME)
            .answers
            .iter()
            .filter_map(|r| match &r.rdata {
                ApRData::Cname(target) => Some(target.to_ascii_lower()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            cnames,
            vec!["t2.skip.test".to_string()],
            "CNAME 은 하나만 둘 수 있어 새 값이 이전 값을 대체합니다"
        );

        let (store, srv) = ddns_fixture();
        let drop_ns = |owner: &str, target: &str| ApRecord {
            name: ApName::from_str(owner).unwrap(),
            rtype: ApRt::NS,
            class: DnsClass(254),
            ttl: 0,
            rdata: ApRData::Ns(ApName::from_str(target).unwrap()),
        };
        assert_eq!(
            srv.handle(
                &ddns_update(vec![drop_ns("skip.test", "ns.skip.test")]),
                &tcp
            )
            .unwrap()
            .header
            .rcode,
            ResponseCode::NoError.0,
            "정점의 마지막 NS 삭제는 건너뛰되 실패로 답하지 않습니다"
        );
        assert_eq!(
            ddns_count(&store, "skip.test", ApRt::NS),
            1,
            "정점에 권한 서버가 하나도 없는 영역을 만들지 않습니다"
        );

        assert_eq!(
            srv.handle(
                &ddns_update(vec![drop_ns("sub.skip.test", "ns.sub.skip.test")]),
                &tcp
            )
            .unwrap()
            .header
            .rcode,
            ResponseCode::NoError.0
        );
        assert_eq!(
            store.load().zones()[0]
                .query(&ApName::from_str("sub.skip.test").unwrap(), ApRt::NS)
                .answers
                .len(),
            0,
            "위임의 마지막 NS 는 지워야 위임을 걷을 수 있습니다"
        );

        let (store, srv) = ddns_fixture();
        let wks = |bitmap: u8| ApRecord {
            name: ApName::from_str("wks.skip.test").unwrap(),
            rtype: ApRt(11),
            class: DnsClass::IN,
            ttl: 60,
            rdata: ApRData::Unknown(11, vec![10, 0, 0, 7, 6, 0, 0, 0, bitmap]),
        };
        assert_eq!(
            srv.handle(&ddns_update(vec![wks(0x02)]), &tcp)
                .unwrap()
                .header
                .rcode,
            ResponseCode::NoError.0
        );
        assert_eq!(
            srv.handle(&ddns_update(vec![wks(0x04)]), &tcp)
                .unwrap()
                .header
                .rcode,
            ResponseCode::NoError.0
        );
        assert_eq!(
            ddns_count(&store, "wks.skip.test", ApRt(11)),
            1,
            "주소와 프로토콜이 같은 WKS 는 하나만 둘 수 있어 덧붙지 않습니다"
        );
    }

    #[test]
    /**
     * @brief 영역부 클래스가 다른 UPDATE 와 선행조건 검사 차례가 규격대로인지.
     *
     * @details RFC 2136은 영역부 개수와 ZTYPE 만 형식 오류로 보고, ZCLASS 가 이 서버가
     *          맡은 영역과 다르면 NOTAUTH 로 답하게 한다. 형식 오류로 답하면 요청자는 자기
     *          메시지가 깨진 줄 알고 고치려 들지만 실제로는 서버를 잘못 고른 것이다.
     *          선행조건은 3.2.5 의사코드가 TTL 을 영역 범위보다 먼저 보게 정한다.
     */
    fn ddns_reports_a_foreign_zone_class_as_notauth() {
        let tcp = RequestCtx {
            src: "127.0.0.1:5555".parse().unwrap(),
            transport: RtTransport::Do53Tcp,
            raw: None,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };
        let (store, srv) = ddns_fixture();

        let mut foreign = ddns_update(vec![ApRecord::new(
            ApName::from_str("x.skip.test").unwrap(),
            60,
            ApRData::A(Ipv4Addr::new(10, 0, 0, 9)),
        )]);
        foreign.questions[0].qclass = DnsClass(3);
        assert_eq!(
            srv.handle(&foreign, &tcp).unwrap().header.rcode,
            9,
            "이 서버가 맡지 않은 클래스의 영역은 NOTAUTH 입니다"
        );
        assert_eq!(
            ddns_count(&store, "x.skip.test", ApRt::A),
            0,
            "다른 클래스의 요청으로 IN 영역을 고치지 않습니다"
        );

        let outside = |ttl: u32| {
            let mut m = ddns_update(vec![]);
            m.answers.push(ApRecord {
                name: ApName::from_str("x.other.test").unwrap(),
                rtype: ApRt::A,
                class: DnsClass(255),
                ttl,
                rdata: ApRData::Unknown(ApRt::A.0, vec![]),
            });
            m
        };
        assert_eq!(
            srv.handle(&outside(0), &tcp).unwrap().header.rcode,
            10,
            "영역 밖 선행조건은 NOTZONE 입니다"
        );
        assert_eq!(
            srv.handle(&outside(300), &tcp).unwrap().header.rcode,
            ResponseCode::FormErr.0,
            "TTL 을 영역 범위보다 먼저 보므로 둘 다 어긋나면 FORMERR 입니다"
        );
    }

    #[test]
    /**
     * @brief 갱신이 담아 온 SOA 일련번호를 그대로 두는지.
     *
     * @details RFC 2136은 되돌리는 SOA 교체만 무시하고, 갱신이 일련번호를 직접 바꾸면
     *          서버가 또 올리지 말라고 정한다. 비교는 RFC 1982 모듈로 산술이다. 예전에는
     *          SOA 추가를 늘 버리고 언제나 하나를 올려, 요청자가 적어 준 값이 영역에 남지
     *          않았다.
     */
    fn ddns_keeps_an_explicit_soa_serial() {
        let tcp = RequestCtx {
            src: "127.0.0.1:5555".parse().unwrap(),
            transport: RtTransport::Do53Tcp,
            raw: None,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };
        let soa_add = |serial: u32| {
            let soa = onetdns_proto::Soa {
                mname: ApName::from_str("ns.skip.test").unwrap(),
                rname: ApName::from_str("admin.skip.test").unwrap(),
                serial,
                refresh: 300,
                retry: 60,
                expire: 86400,
                minimum: 60,
            };
            ApRecord::new(
                ApName::from_str("skip.test").unwrap(),
                300,
                ApRData::Soa(Box::new(soa)),
            )
        };

        let (store, srv) = ddns_fixture();
        assert_eq!(
            srv.handle(&ddns_update(vec![soa_add(500)]), &tcp)
                .unwrap()
                .header
                .rcode,
            ResponseCode::NoError.0
        );
        assert_eq!(
            store.load().zones()[0].soa().serial,
            500,
            "갱신이 지정한 일련번호 위에 서버가 또 올리지 않습니다"
        );

        let (store, srv) = ddns_fixture();
        assert_eq!(
            srv.handle(
                &ddns_update(vec![
                    soa_add(500),
                    ApRecord::new(
                        ApName::from_str("fresh.skip.test").unwrap(),
                        60,
                        ApRData::A(Ipv4Addr::new(10, 0, 0, 9)),
                    ),
                ]),
                &tcp
            )
            .unwrap()
            .header
            .rcode,
            ResponseCode::NoError.0
        );
        assert_eq!(
            store.load().zones()[0].soa().serial,
            500,
            "다른 변경이 함께 와도 지정한 일련번호를 씁니다"
        );

        let (store, srv) = ddns_fixture();
        assert_eq!(
            srv.handle(&ddns_update(vec![soa_add(1)]), &tcp)
                .unwrap()
                .header
                .rcode,
            ResponseCode::NoError.0
        );
        assert_eq!(
            store.load().zones()[0].soa().serial,
            10,
            "되돌리는 일련번호는 조용히 무시합니다"
        );
    }

    #[test]
    /**
     * @brief 무할당 경로로 답해도 지표에 남는지.
     *
     * @details 이 경로가 기록하지 못하던 시절의 조건(기록기가 있으면 막는다)이 그대로
     *          남아 있으면, 컨트롤 플레인을 만들어 두는 모든 배치에서 경로가 전부 죽는다. 반대로
     *          조건만 지우고 기록을 안 붙이면 대시보드에서 권한 응답이 조용히 사라진다.
     *          Personal 모드처럼 ACL이 클라이언트를 요구해도 식별과 기록은 같은 기능 세대
     *          snapshot 하나를 써야 한다. 셋 다 조용한 사고라 여기서 붙든다.
     */
    fn authority_wire_answers_are_recorded_like_the_structured_path() {
        let zone_text = "$ORIGIN rec.test.\n$TTL 300\n@ IN SOA ns admin 1 300 60 3600 60\n@ IN NS ns\nns IN A 192.0.2.53\nwww IN A 192.0.2.9\n";
        let mut zones = onetdns_authority::ZoneStore::new();
        zones.add(onetdns_authority::parse_zone(zone_text, "rec.test").unwrap());
        let store = Arc::new(ArcSwap::new(Arc::new(zones)));
        let authority = Arc::new(crate::layers::AuthorityLayer::new(
            Arc::new(FixedAnswer),
            store.clone(),
        ));
        let (recorder, stats) = onetdns_control::channel(
            256,
            256,
            0,
            onetdns_control::RecorderOpts {
                querylog: true,
                anonymize: false,
                ignored: Vec::new(),
                stats_retention_secs: 0,
            },
            onetdns_control::PersistOpts::default(),
        );
        let mut features = NativeFeatures::default();
        features.recorder = Some(recorder);
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::new(
                vec!["127.0.0.0/8".parse().unwrap()],
                vec![],
                false,
            )),
            vec![],
            authority,
            60,
        )
        .with_features(features)
        .with_authority_wire_path(Some(store), true);

        let mut output = onetdns_proto::Writer::with_limit(1232);
        for (name, expected) in [
            ("www.rec.test", ResponseCode::NoError),
            ("nope.rec.test", ResponseCode::NXDomain),
        ] {
            let request = Message::query(0x1234, ApName::from_str(name).unwrap(), RecordType::A);
            output.clear();
            server.features.take_test_loads();
            assert_eq!(
                server.handle_udp_wire(
                    &request.try_encode().unwrap(),
                    &ctx(),
                    &mut output,
                    Instant::now()
                ),
                onetdns_runtime::WireDisposition::Respond,
                "{name}은 무할당 경로가 맡아야 합니다"
            );
            assert_eq!(
                Message::parse(&output.buf).unwrap().header.rcode,
                expected.0
            );
            assert_eq!(
                server.features.take_test_loads(),
                1,
                "ACL 식별과 기록이 질의 세대 snapshot 하나를 공유해야 합니다"
            );
        }

        for _ in 0..200 {
            if stats.metrics.snapshot().total >= 2 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let snapshot = stats.metrics.snapshot();
        assert_eq!(
            snapshot.total, 2,
            "무할당 경로로 답한 질의가 지표에 남지 않았습니다"
        );
    }

    #[test]
    /**
     * @brief 묻지 않은 쪽에는 DNSSEC 레코드를 보내지 않는지.
     *
     * @details 재귀 리졸버는 검증 여부와 무관하게 업스트림에 DO=1로 묻는다. 그래야 DO=1로 묻는
     *          질의자에게 줄 서명을 가지고 있을 수 있다. 그 대신 묻지 않은 쪽에 담아 보내면
     *          응답만 커지고 절단으로 이어진다.
     * @warning DNSKEY와 DS는 질의자가 직접 물을 수 있는 종류라 걷어내면 안 된다.
     */
    fn dnssec_records_go_only_to_clients_that_asked_for_them() {
        let name = ApName::from_str("signed.example").unwrap();
        let signed_response = || {
            let mut response = Message::query(1, name.clone(), ApRt::A);
            response.header.response = true;
            for (rtype, section) in [
                (ApRt::A, 0usize),
                (ApRt::RRSIG, 0),
                (ApRt::DNSKEY, 0),
                (ApRt::NSEC, 1),
                (ApRt::RRSIG, 1),
                (ApRt::DS, 1),
            ] {
                let record = ApRecord::new(
                    name.clone(),
                    60,
                    ApRData::Unknown(rtype.0, vec![1, 2, 3, 4]),
                );
                let mut record = record;
                record.rtype = rtype;
                if section == 0 {
                    response.answers.push(record);
                } else {
                    response.authorities.push(record);
                }
            }
            response
        };
        let count = |message: &Message, rtype: ApRt| {
            message
                .answers
                .iter()
                .chain(message.authorities.iter())
                .filter(|record| record.rtype == rtype)
                .count()
        };

        let mut plain_request = Message::query(1, name.clone(), ApRt::A);
        plain_request.additionals.push(
            Edns::default()
                .try_to_record()
                .expect("OPT를 만들 수 있어야 합니다"),
        );
        assert!(!wants_dnssec(&plain_request));
        let mut plain = signed_response();
        strip_dnssec_unless_requested(&plain_request, &mut plain);
        assert_eq!(count(&plain, ApRt::RRSIG), 0, "서명을 걷어내지 않았습니다");
        assert_eq!(
            count(&plain, ApRt::NSEC),
            0,
            "부재 증명을 걷어내지 않았습니다"
        );
        assert_eq!(count(&plain, ApRt::A), 1, "답까지 걷어냈습니다");
        assert_eq!(
            count(&plain, ApRt::DNSKEY),
            1,
            "직접 물을 수 있는 종류를 걷어냈습니다"
        );
        assert_eq!(
            count(&plain, ApRt::DS),
            1,
            "직접 물을 수 있는 종류를 걷어냈습니다"
        );

        // 대조군. DO를 설정한 쪽에는 그대로 나가야 한다. 걷어내기가 언제나 실행되는 것을 막는다.
        let mut do_request = Message::query(1, name.clone(), ApRt::A);
        let mut edns = Edns::default();
        edns.dnssec_ok = true;
        do_request
            .additionals
            .push(edns.try_to_record().expect("OPT를 만들 수 있어야 합니다"));
        assert!(wants_dnssec(&do_request));
        let mut asked = signed_response();
        strip_dnssec_unless_requested(&do_request, &mut asked);
        assert_eq!(
            count(&asked, ApRt::RRSIG),
            2,
            "물어본 쪽의 서명을 걷어냈습니다"
        );
        assert_eq!(
            count(&asked, ApRt::NSEC),
            1,
            "물어본 쪽의 증명을 걷어냈습니다"
        );
    }

    #[test]
    /**
     * @brief 요청에 OPT가 있으면 응답에도 반드시 넣고, 없으면 넣지 않는지.
     * @details RFC 6891이 양쪽을 다 MUST로 정한다. 빼면 상대는 이 서버가 EDNS를 모르는 것으로
     *          보고 512바이트로 전환하고, 쿠키·NSID·패딩·EDE를 담을 슬롯도 사라진다.
     *          반대로 EDNS 없는 요청에 붙이면 이전 클라이언트가 응답을 거부한다.
     */
    fn edns_request_gets_an_opt_back_and_a_plain_one_does_not() {
        let srv = server("");
        let ctx = RequestCtx {
            src: "127.0.0.1:5555".parse().unwrap(),
            transport: RtTransport::Do53Udp,
            raw: None,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };
        let name = ApName::from_str("allowed.test").unwrap();

        let mut with_edns = Message::query(1, name.clone(), ApRt::A);
        with_edns
            .additionals
            .push(Edns::default().try_to_record().unwrap());
        let response = srv.handle(&with_edns, &ctx).expect("응답이 없습니다");
        let opt = response.opt().expect("EDNS 질의인데 응답에 OPT가 없습니다");
        let echoed = Edns::from_record(opt).expect("OPT를 읽지 못했습니다");
        assert_eq!(echoed.version, 0, "응답 OPT의 버전 번호는 0이어야 합니다");
        assert!(
            echoed.udp_payload >= 512,
            "이 서버의 UDP 크기를 알려야 합니다: {}",
            echoed.udp_payload
        );

        let plain = Message::query(2, name, ApRt::A);
        let response = srv.handle(&plain, &ctx).expect("응답이 없습니다");
        assert!(
            response.opt().is_none(),
            "EDNS 없는 질의에 OPT를 붙이면 안 됩니다"
        );
    }

    #[test]
    /**
     * @brief 질문이 둘인 질의에 FORMERR을 주되 그것을 그대로 돌려주지 않는지.
     *
     * @details RFC 9619는 opcode 0인 DNS 메시지가 QDCOUNT를 1보다 크게 담을 수 없다고
     *          정한다. 응답도 opcode 0이므로 질문부를 그대로 돌려주면 이 서버의 답이 같은
     *          규칙을 어긴다. BIND도 이 자리에서 질문부를 비운다.
     */
    fn a_multi_question_query_gets_formerr_without_echoing_it() {
        let srv = server("");
        let ctx = RequestCtx {
            src: "127.0.0.1:5555".parse().unwrap(),
            transport: RtTransport::Do53Udp,
            raw: None,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };

        let mut request = Message::query(1, ApName::from_str("a.example.com").unwrap(), ApRt::A);
        let second = request.questions[0].clone();
        request.questions.push(second);

        let response = srv.handle(&request, &ctx).expect("응답이 없습니다");
        assert_eq!(
            response.header.rcode,
            ResponseCode::FormErr.0,
            "질문이 둘이면 FORMERR입니다"
        );
        assert!(
            response.questions.is_empty(),
            "1보다 큰 QDCOUNT를 그대로 돌려주면 응답이 같은 규칙을 어깁니다"
        );

        // 질문이 없는 질의도 같은 분기를 지난다. 비우는 것이 무해해야 한다.
        let mut empty = Message::default();
        empty.header.id = 7;
        let response = srv.handle(&empty, &ctx).expect("응답이 없습니다");
        assert_eq!(response.header.rcode, ResponseCode::FormErr.0);
        assert!(response.questions.is_empty());
    }

    #[test]
    /**
     * @brief 구현하지 않은 opcode에 NOTIMP로 답하는지.
     * @details FORMERR은 요청이 깨졌다는 뜻이라 보낸 쪽이 질의를 고쳐 다시 보낸다. 모르는
     *          opcode는 요청이 멀쩡한데 이 서버가 못 하는 것이므로 뜻이 다르고, 진단하는
     *          쪽에서 둘을 갈라 봐야 한다.
     */
    fn unimplemented_opcodes_answer_not_implemented() {
        let srv = server("");
        let ctx = RequestCtx {
            src: "127.0.0.1:5555".parse().unwrap(),
            transport: RtTransport::Do53Udp,
            raw: None,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };

        for opcode in [1u8, 2, 3, 6, 15] {
            let mut request = Message::query(1, ApName::from_str("example.com").unwrap(), ApRt::A);
            request.header.opcode = opcode;
            let response = srv.handle(&request, &ctx).expect("응답이 없습니다");
            assert_eq!(
                response.header.rcode,
                ResponseCode::NotImp.0,
                "opcode {opcode}에 NOTIMP가 아닌 답을 냈습니다"
            );
            assert_eq!(
                response.header.opcode, opcode,
                "opcode {opcode}를 그대로 되돌려야 합니다"
            );
        }

        let empty = Message::default();
        assert_eq!(
            srv.handle(&empty, &ctx)
                .expect("응답이 없습니다")
                .header
                .rcode,
            ResponseCode::FormErr.0,
            "질문이 없는 QUERY는 FORMERR로 남아야 합니다"
        );
    }

    #[test]
    /** @brief 특수 요청이 올바른 질문 하나만 담았는지 확인하는지. */
    fn special_opcodes_require_exactly_one_well_formed_zone_question() {
        let srv = server("");
        let tcp = RequestCtx {
            src: "127.0.0.1:5555".parse().unwrap(),
            transport: RtTransport::Do53Tcp,
            raw: None,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };
        let zone_question = onetdns_proto::Question {
            name: ApName::from_str("example.com").unwrap(),
            qtype: ApRt::SOA,
            qclass: DnsClass::IN,
        };

        let mut update = Message::default();
        update.header.opcode = 5;
        update.questions = vec![zone_question.clone(), zone_question.clone()];
        assert_eq!(
            srv.handle(&update, &tcp).unwrap().header.rcode,
            ResponseCode::FormErr.0
        );

        let mut notify = Message::default();
        notify.header.opcode = 4;
        notify.questions.push(onetdns_proto::Question {
            qtype: ApRt::A,
            ..zone_question.clone()
        });
        assert_eq!(
            srv.handle(&notify, &tcp).unwrap().header.rcode,
            ResponseCode::FormErr.0
        );

        let mut axfr = Message::query(1, zone_question.name.clone(), ApRt(252));
        axfr.questions.push(zone_question);
        let responses = srv.handle_multi(&axfr, &tcp).unwrap();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].header.rcode, ResponseCode::FormErr.0);
    }

    #[test]
    /**
     * @brief 카탈로그 주 서버가 보낸 NOTIFY로 카탈로그와 구성원 영역을 다시 받아 오는지.
     * @details 구성원 영역은 카탈로그를 받은 뒤에야 알게 되므로 설정에 이름이 없다. 다른 주소가
     *          보낸 NOTIFY는 여전히 무시한다.
     */
    fn notify_from_catalog_primary_wakes_member_refresh() {
        let kick = Arc::new(NotifyKick::default());
        let srv = server("").with_notify_secondaries(Vec::new(), kick.clone());
        srv.edit_authority(|authority| {
            authority.notify_catalog_primaries = vec![("192.0.2.53".parse().unwrap(), None)];
        });
        let mut request = Message::default();
        request.header.opcode = 4;
        request.header.authoritative = true;
        request.questions.push(onetdns_proto::Question {
            name: ApName::from_str("member.test").unwrap(),
            qtype: ApRt::SOA,
            qclass: DnsClass::IN,
        });
        let context = |src: &str| RequestCtx {
            src: src.parse().unwrap(),
            transport: RtTransport::Do53Udp,
            raw: None,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };

        assert!(srv
            .handle(&request, &context("198.51.100.9:53000"))
            .is_none());
        assert!(kick.wait_take(Duration::ZERO).is_empty());

        let response = srv
            .handle(&request, &context("192.0.2.53:53000"))
            .expect("NOTIFY ACK");
        assert_eq!(response.header.rcode, ResponseCode::NoError.0);
        assert!(kick.wait_take(Duration::ZERO).contains("member.test"));
    }

    #[test]
    /** @brief 아는 업스트림에서 온 알림만 받아들이고 다시 받아 오게 하는지. */
    fn notify_only_acknowledges_known_master_requests_and_wakes_refresh() {
        let origin = ApName::from_str("secondary.test").unwrap();
        let kick = Arc::new(NotifyKick::default());
        let srv = server("").with_notify_secondaries(
            vec![(origin.clone(), "127.0.0.1".parse().unwrap(), None)],
            kick.clone(),
        );
        let mut request = Message::default();
        request.header.id = 0x4e4f;
        request.header.opcode = 4;
        request.header.authoritative = true;
        request.questions.push(onetdns_proto::Question {
            name: origin,
            qtype: ApRt::SOA,
            qclass: DnsClass::IN,
        });
        let context = RequestCtx {
            src: "127.0.0.1:53000".parse().unwrap(),
            transport: RtTransport::Do53Udp,
            raw: None,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };

        let response = srv.handle(&request, &context).expect("NOTIFY ACK");
        assert!(response.header.response);
        assert!(
            response.header.authoritative,
            "RFC 1996 NOTIFY ACK에는 AA가 필요"
        );
        assert!(!response.header.recursion_available);
        assert_eq!(response.header.id, request.header.id);
        assert_eq!(response.header.opcode, 4);
        assert_eq!(response.header.rcode, ResponseCode::NoError.0);
        assert!(
            kick.wait_take(Duration::ZERO).contains("secondary.test"),
            "수신 즉시 갱신 작업을 깨워야 함"
        );

        request.header.response = true;
        assert!(
            srv.handle(&request, &context).is_none(),
            "NOTIFY 응답에 다시 응답하면 패킷 루프가 생김"
        );

        request.header.response = false;
        let unknown = RequestCtx {
            src: "127.0.0.2:53000".parse().unwrap(),
            ..context
        };
        assert!(
            srv.handle(&request, &unknown).is_none(),
            "RFC 1996은 알 수 없는 master의 NOTIFY를 무시하도록 요구"
        );
    }

    #[test]
    /** @brief 하위 서버마다 정해 둔 키로 알리는지. */
    fn notify_uses_the_secondary_specific_tsig_identity() {
        use onetdns_dnssec::tsig;

        let origin = ApName::from_str("signed-secondary.test").unwrap();
        let key = tsig::TsigKey::new(
            ApName::from_str("notify-key.test").unwrap(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();
        let kick = Arc::new(NotifyKick::default());
        let srv = server("")
            .with_tsig(vec![key.clone()], false)
            .with_notify_secondaries(
                vec![(
                    origin.clone(),
                    "127.0.0.1".parse().unwrap(),
                    Some(key.name.clone()),
                )],
                kick.clone(),
            );
        let mut request = Message::default();
        request.header.id = 0x5453;
        request.header.opcode = 4;
        request.header.authoritative = true;
        request.questions.push(onetdns_proto::Question {
            name: origin,
            qtype: ApRt::SOA,
            qclass: DnsClass::IN,
        });
        let unsigned_context = RequestCtx {
            src: "127.0.0.1:53000".parse().unwrap(),
            transport: RtTransport::Do53Udp,
            raw: None,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };
        assert_eq!(
            srv.handle(&request, &unsigned_context)
                .expect("unsigned refusal")
                .header
                .rcode,
            ResponseCode::Refused.0
        );
        assert!(kick.wait_take(Duration::ZERO).is_empty());

        let request_mac = tsig::sign_message(&mut request, &key, now_unix(), None).unwrap();
        let wire = request.try_encode().unwrap();
        let signed_context = RequestCtx {
            raw: Some(&wire),
            ..unsigned_context
        };
        let response = srv.handle(&request, &signed_context).expect("signed ACK");
        assert_eq!(response.header.rcode, ResponseCode::NoError.0);
        tsig::verify_message(&response, &key, now_unix(), Some(&request_mac))
            .expect("NOTIFY ACK TSIG 검증");
        assert!(kick
            .wait_take(Duration::ZERO)
            .contains("signed-secondary.test"));
    }

    #[test]
    /** @brief 고친 뒤 바뀐 부분만 보내는지. */
    fn ixfr_returns_incremental_after_ddns() {
        let zone_text = "$ORIGIN ix.test.\n$TTL 300\n@ IN SOA ns1 admin 10 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.1\nold IN A 10.0.0.5\nkeep1 IN A 10.0.0.11\nkeep2 IN A 10.0.0.12\nkeep3 IN A 10.0.0.13\nkeep4 IN A 10.0.0.14\nkeep5 IN A 10.0.0.15\nkeep6 IN A 10.0.0.16\nkeep7 IN A 10.0.0.17\nkeep8 IN A 10.0.0.18\n";
        let zone = onetdns_authority::parse_zone(zone_text, "ix.test").unwrap();
        let mut zs = onetdns_authority::ZoneStore::new();
        zs.add(zone);
        let store = Arc::new(ArcSwap::new(Arc::new(zs)));
        let notified = Arc::new(std::sync::Mutex::new(Vec::new()));
        let notified_sink = notified.clone();
        let srv = server("")
            .with_xfr(store.clone(), vec!["127.0.0.0/8".parse().unwrap()])
            .with_ddns(
                vec!["127.0.0.0/8".parse().unwrap()],
                false,
                vec![],
                vec![ApName::from_str("ix.test").unwrap()],
            )
            .with_update_notify(Arc::new(move |origin, serial| {
                notified_sink
                    .lock_recover()
                    .push((origin.to_ascii_lower(), serial));
            }));
        let tcp = RequestCtx {
            src: "127.0.0.1:5555".parse().unwrap(),
            transport: RtTransport::Do53Tcp,
            raw: None,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };

        let mut up = Message::default();
        up.header.opcode = 5;
        up.questions = vec![onetdns_proto::Question {
            name: ApName::from_str("ix.test").unwrap(),
            qtype: ApRt::SOA,
            qclass: DnsClass::IN,
        }];
        up.authorities.push(ApRecord::new(
            ApName::from_str("new.ix.test").unwrap(),
            120,
            ApRData::A(Ipv4Addr::new(10, 0, 0, 9)),
        ));
        assert_eq!(
            srv.handle(&up, &tcp).unwrap().header.rcode,
            ResponseCode::NoError.0
        );
        assert_eq!(
            *notified.lock_recover(),
            vec![("ix.test".to_string(), 11)],
            "실제 변경을 적용한 DDNS 경로도 NOTIFY를 발행해야 함"
        );

        let mut ixfr = Message::query(5, ApName::from_str("ix.test").unwrap(), ApRt(251));
        ixfr.authorities.push(ApRecord {
            name: ApName::from_str("ix.test").unwrap(),
            rtype: ApRt::SOA,
            class: DnsClass::IN,
            ttl: 300,
            rdata: ApRData::soa(onetdns_proto::Soa {
                mname: ApName::from_str("ns1.ix.test").unwrap(),
                rname: ApName::from_str("admin.ix.test").unwrap(),
                serial: 10,
                refresh: 300,
                retry: 60,
                expire: 86400,
                minimum: 60,
            }),
        });
        let resp = srv.handle(&ixfr, &tcp).unwrap();

        let soas = resp.answers.iter().filter(|r| r.rtype == ApRt::SOA).count();
        assert_eq!(soas, 4, "증분 SOA 경계 4개(전 영역 AXFR 아님)");
        assert!(
            resp.answers
                .iter()
                .any(|r| r.rdata == ApRData::A(Ipv4Addr::new(10, 0, 0, 9))),
            "추가분 new A 포함"
        );

        assert!(
            !resp
                .answers
                .iter()
                .any(|r| r.rdata == ApRData::A(Ipv4Addr::new(10, 0, 0, 5))),
            "미변경 레코드(old)는 증분에 없습니다"
        );

        let mut ixfr0 = ixfr.clone();
        if let ApRData::Soa(s) = &mut ixfr0.authorities[0].rdata {
            s.serial = 1;
        }
        let resp = srv.handle(&ixfr0, &tcp).unwrap();
        assert!(
            resp.answers
                .iter()
                .any(|r| r.rdata == ApRData::A(Ipv4Addr::new(10, 0, 0, 5))),
            "미보유 serial → 전 영역 폴백(old 포함)"
        );

        let mut malformed = ixfr.clone();
        malformed.authorities[0].name = ApName::from_str("other.test").unwrap();
        assert_eq!(
            srv.handle(&malformed, &tcp).unwrap().header.rcode,
            ResponseCode::FormErr.0
        );

        let udp = RequestCtx {
            transport: RtTransport::Do53Udp,
            ..tcp
        };
        let stale = srv.handle(&ixfr, &udp).unwrap();
        assert!(stale.header.truncated, "오래된 UDP IXFR은 TCP 재시도 지시");
        assert_eq!(stale.answers.len(), 1);

        let mut current = ixfr;
        if let ApRData::Soa(soa) = &mut current.authorities[0].rdata {
            soa.serial = 11;
        }
        let current = srv.handle(&current, &udp).unwrap();
        assert!(!current.header.truncated);
        assert_eq!(current.answers.len(), 1, "최신 client에는 SOA 하나만 반환");

        let missing = Message::query(7, ApName::from_str("missing.test").unwrap(), ApRt(252));
        let tcp = RequestCtx {
            transport: RtTransport::Do53Tcp,
            ..udp
        };
        assert_eq!(
            srv.handle(&missing, &tcp).unwrap().header.rcode,
            9,
            "미보유 zone XFR은 timeout이 아니라 NOTAUTH"
        );
    }

    #[test]
    /** @brief 쌓인 변경이 전체를 보내는 것보다 커지면 버리는지. */
    fn ixfr_journal_does_not_retain_deltas_larger_than_axfr() {
        let old = onetdns_authority::parse_zone(
            "$ORIGIN budget.test.\n@ IN SOA ns admin 1 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\na IN A 192.0.2.10\nb IN A 192.0.2.11\nc IN A 192.0.2.12\nd IN A 192.0.2.13\n",
            "budget.test",
        )
        .unwrap();
        let new = onetdns_authority::parse_zone(
            "$ORIGIN budget.test.\n@ IN SOA ns admin 2 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\nw IN A 198.51.100.10\nx IN A 198.51.100.11\ny IN A 198.51.100.12\nz IN A 198.51.100.13\n",
            "budget.test",
        )
        .unwrap();
        let mut old_records = old.axfr_records();
        let mut new_records = new.axfr_records();
        old_records.pop();
        new_records.pop();

        let mut journal = ZoneJournal::default();
        journal.record(1, 2, &old_records, &new_records);
        assert!(
            journal.deltas.is_empty(),
            "AXFR보다 큰 증분은 메모리에 보존하지 않습니다"
        );
    }

    #[test]
    /** @brief 남겨 두는 변경 기록이 영역 크기 안에 머무는지. */
    fn ixfr_journal_retention_is_bounded_by_current_zone_size() {
        let zone = onetdns_authority::parse_zone(
            "$ORIGIN bounded.test.\n@ IN SOA ns admin 1 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\nseed IN A 192.0.2.2\n",
            "bounded.test",
        )
        .unwrap();
        let mut current = zone.axfr_records();
        current.pop();
        let mut journal = ZoneJournal::default();
        for serial in 2..=65 {
            let old = current.clone();
            current[0] = soa_with_serial(&current[0], serial);
            current.push(ApRecord::new(
                ApName::from_str(&format!("added-{serial}.bounded.test")).unwrap(),
                60,
                ApRData::A(Ipv4Addr::new(198, 51, 100, serial as u8)),
            ));
            journal.record(serial - 1, serial, &old, &current);
        }
        assert!(
            journal.deltas.len() < ZoneJournal::MAX,
            "작은 zone의 저널이 고정 개수 상한까지 비대해지지 않습니다"
        );
        let oldest = journal.deltas.front().unwrap().from;
        assert!(journal.path_from(oldest, 65).is_some());
    }

    #[test]
    /** @brief 감추기로 했으면 서버 이름과 버전을 답하지 않는지. */
    fn chaos_id_version_respects_hide_flags() {
        let mut feat = NativeFeatures::default();
        feat.server_identity = b"onetdns".to_vec();
        feat.server_version = b"onetdns".to_vec();
        let srv_open = server("").with_features(feat.clone());
        let ch = |name: &str| {
            let mut m = Message::query(7, ApName::from_str(name).unwrap(), ApRt::TXT);
            m.questions[0].qclass = DnsClass(3);
            m
        };
        let resp = srv_open.handle(&ch("version.server"), &ctx()).unwrap();
        assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
        assert!(
            resp.answers.iter().any(|r| r.rtype == RecordType::TXT),
            "version.server TXT 응답"
        );

        let mut hidden = feat.clone();
        hidden.hide_identity = true;
        hidden.hide_version = true;
        let srv_hidden = server("").with_features(hidden);
        assert_eq!(
            srv_hidden
                .handle(&ch("version.server"), &ctx())
                .unwrap()
                .header
                .rcode,
            ResponseCode::Refused.0,
            "hide_version → REFUSED"
        );
        assert_eq!(
            srv_hidden
                .handle(&ch("id.server"), &ctx())
                .unwrap()
                .header
                .rcode,
            ResponseCode::Refused.0,
            "hide_identity → REFUSED"
        );
    }

    #[test]
    /** @brief 암호화 전송으로 왔다는 사실이 정책까지 전해지는지. */
    fn encrypted_runtime_transport_is_preserved() {
        assert_eq!(core_transport(RtTransport::DoT), Transport::DoT);
        assert_eq!(core_transport(RtTransport::DoH), Transport::DoH);
        assert_eq!(core_transport(RtTransport::DoQ), Transport::DoQ);
        assert_eq!(core_transport(RtTransport::DnsCrypt), Transport::DnsCrypt);
        assert_eq!(
            dnstap_proto(RtTransport::DoT),
            onetdns_control::DnstapProtocol::Dot
        );
        assert_eq!(
            dnstap_proto(RtTransport::DoH),
            onetdns_control::DnstapProtocol::Doh
        );
        assert_eq!(
            dnstap_proto(RtTransport::DoQ),
            onetdns_control::DnstapProtocol::Doq
        );
        assert_eq!(
            dnstap_proto(RtTransport::DnsCrypt),
            onetdns_control::DnstapProtocol::DnscryptUdp
        );
    }

    #[test]
    /** @brief 클라이언트에 맞는 업스트림이 먼저 쓰이는지. */
    fn per_client_upstream_match_prefers_specific_resolver() {
        let default = mock_upstream();
        let specific = mock_upstream();
        let s = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::build_from_str(
                "",
                "",
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            Arc::new(NativeBackend::Forward(Forwarder::new(
                vec![default],
                Duration::from_secs(2),
            ))),
            60,
        )
        .with_client_upstreams(vec![ClientUpstream::new(
            vec!["127.0.0.1/32".parse().unwrap()],
            vec![],
            Arc::new(NativeBackend::Forward(Forwarder::new(
                vec![specific],
                Duration::from_secs(2),
            ))),
        )]);
        update_features(&s, |features| features.rrset_roundrobin = false);
        let resp = s.handle(&q("client-route.test"), &ctx()).unwrap();
        assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
        assert_eq!(resp.answers.len(), 1);
    }

    #[test]
    /** @brief 허용된 이름이 업스트림으로 가는지. */
    fn allowed_forwards_to_upstream() {
        let s = server("||blocked.test^\n");
        let resp = s.handle(&q("allowed.test"), &ctx()).unwrap();
        assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0].rdata {
            ApRData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(7, 7, 7, 7)),
            _ => panic!("A 기대"),
        }
    }

    #[test]
    /** @brief 차단된 이름이 없다고 답하는지. */
    fn blocked_returns_nxdomain() {
        let s = server("||blocked.test^\n");
        let resp = s.handle(&q("blocked.test"), &ctx()).unwrap();
        assert_eq!(resp.header.rcode, ResponseCode::NXDomain.0);
        assert!(resp.answers.is_empty());
    }

    #[test]
    /**
     * @brief 목록 규칙에 막힌 질의가 그 목록을 기록에 남기는지.
     * @details 질의 기록 화면은 이 값으로 어느 구독이 막았는지 보여 주고 허용 버튼을 고른다.
     *          목록 밖에서 직접 넣은 규칙은 목록을 남기지 않아야 한다.
     */
    fn filter_block_records_the_subscription_list() {
        let lines = vec!["||listed.test^".to_string()];
        let subscriptions = [onetdns_filter::SubscriptionSource {
            name: "https://lists.example/ads.txt",
            rules: onetdns_filter::SubscriptionRules::Lines(&lines),
        }];
        let parts = onetdns_filter::load_parts_with_subscriptions(
            &[] as &[&str],
            &[] as &[&str],
            &subscriptions,
            &["||typed.test^"],
            &[],
        )
        .expect("구독 규칙");
        let (recorder, stats) = onetdns_control::channel(
            64,
            64,
            3600,
            onetdns_control::RecorderOpts {
                querylog: true,
                anonymize: false,
                ignored: vec![],
                stats_retention_secs: 3600,
            },
            onetdns_control::PersistOpts::default(),
        );
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::new(
                parts,
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            Arc::new(NativeBackend::Forward(Forwarder::new(
                vec![mock_upstream()],
                Duration::from_secs(2),
            ))),
            60,
        );
        let mut features = (*server.features.load()).clone();
        features.recorder = Some(recorder);
        let server = server.with_features(features);

        for (name, list) in [
            ("listed.test", "https://lists.example/ads.txt"),
            ("typed.test", ""),
        ] {
            let response = server.handle(&q(name), &ctx()).unwrap();
            assert_eq!(response.header.rcode, ResponseCode::NXDomain.0, "{name}");
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            let event = loop {
                let found = stats.recent(8).into_iter().find(|event| {
                    event.name.as_ref().map(ApName::to_string).as_deref()
                        == Some(&format!("{name}."))
                });
                if let Some(event) = found {
                    break event;
                }
                assert!(std::time::Instant::now() < deadline, "{name}: 기록이 없다");
                std::thread::sleep(Duration::from_millis(5));
            };
            assert_eq!(event.action, "blocked", "{name}");
            assert_eq!(event.rule, name, "{name}");
            assert_eq!(event.list, list, "{name}");
        }
    }

    #[test]
    /** @brief 재작성 답이 고정해 둔 주소의 수명을 쓰는지. */
    fn rewrite_uses_local_ttl_instead_of_block_ttl() {
        let mut parts = onetdns_filter::EngineParts::default();
        parts.block.add_exact("blocked.test");
        parts.rewrites.add_exact(
            "rewrite.test",
            RewriteTarget::ip(Ipv4Addr::new(192, 0, 2, 17).into()),
        );
        let engine = onetdns_filter::BlockEngine::new(parts, BlockResponse::NxDomain);
        let block_ttl = Arc::new(AtomicU32::new(60));
        let local_ttl = Arc::new(AtomicU32::new(17));
        let s = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(engine)),
            Arc::new(IpAcl::allow_all()),
            vec![],
            Arc::new(NativeBackend::Forward(Forwarder::new(
                vec![mock_upstream()],
                Duration::from_secs(2),
            ))),
            60,
        )
        .with_ttl_sources(block_ttl.clone(), local_ttl.clone());

        let response = s.handle(&q("rewrite.test"), &ctx()).unwrap();
        assert_eq!(response.answers[0].ttl, 17);
        local_ttl.store(23, Ordering::Release);
        let response = s.handle(&q("rewrite.test"), &ctx()).unwrap();
        assert_eq!(response.answers[0].ttl, 23, "로컬 TTL 핫 변경");

        let blocked = s.handle(&q("blocked.test"), &ctx()).unwrap();
        assert_eq!(blocked.authorities[0].ttl, 60, "차단 TTL은 독립 설정");
        block_ttl.store(29, Ordering::Release);
        let blocked = s.handle(&q("blocked.test"), &ctx()).unwrap();
        assert_eq!(blocked.authorities[0].ttl, 29, "차단 TTL 핫 변경");
    }

    #[test]
    /** @brief 안전 검색으로 바꾼 답이 고정해 둔 수명을 쓰는지. */
    fn safe_search_cname_uses_local_ttl() {
        let s = server("");
        s.local_ttl.store(41, Ordering::Release);
        s.features.load().safe_search.store(true, Ordering::Release);

        let response = s.handle(&q("google.com"), &ctx()).unwrap();
        let cname = response
            .answers
            .iter()
            .find(|record| record.rtype == RecordType::CNAME)
            .expect("safe-search CNAME");
        assert_eq!(cname.ttl, 41);
    }

    #[test]
    /** @brief 정책이 막은 답이 차단 수명을 쓰는지. */
    fn query_policy_block_uses_blocked_response_ttl() {
        let rules = onetdns_policy::RuleEngine::new(vec![onetdns_policy::Rule::new(
            onetdns_policy::Action::Block,
        )
        .with_suffixes(&["policy-block.test".to_string()])]);
        let s = server("").with_policy(Arc::new(GatedSwap::from_pointee(
            onetdns_policy::PolicyEngine::new(rules, vec![]),
        )));
        s.block_ttl.store(71, Ordering::Release);

        let response = s.handle(&q("policy-block.test"), &ctx()).unwrap();
        assert_eq!(response.header.rcode, ResponseCode::NXDomain.0);
        assert_eq!(negative_soa_ttl(&response), 71);
    }

    #[test]
    /**
     * @brief 모든 것을 묻는 질의에 RFC 8482의 합성 HINFO로 답하는지.
     *
     * @details 온전한 ANY는 큰 답을 끌어내 증폭에 쓰인다. 다만 RFC 8482는 답하지 않는
     *          방법을 셋만 열거하고 그 밖에는 표준 알고리즘을 따르라고 하므로, 거절이
     *          아니라 합성 HINFO가 규격이 정한 모양이다.
     * @note DO를 설정한 질의자에게는 관례대로 답한다. 4.2가 서명된 영역이면 RRSIG를 함께
     *       요구하는데 합성한 레코드에는 붙일 서명이 없다.
     */
    fn any_query_answers_with_the_minimal_hinfo() {
        let s = server("");
        let mut query = q("any.test");
        query.questions[0].qtype = RecordType::ANY;
        let resp = s.handle(&query, &ctx()).unwrap();

        assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
        assert!(!resp.header.truncated, "잘린 것이 아니라 이것이 답이다");
        assert_eq!(resp.answers.len(), 1, "RRSet 하나만 실는다");
        let answer = &resp.answers[0];
        assert_eq!(answer.rtype, RecordType(13), "HINFO");
        assert!(answer
            .name
            .eq_ignore_case(&ApName::from_str("any.test").unwrap()));
        match &answer.rdata {
            ApRData::Unknown(13, wire) => {
                assert_eq!(
                    wire.as_slice(),
                    b"\x07RFC8482\x00",
                    "CPU는 RFC8482, OS는 빈 문자열"
                );
            }
            other => panic!("HINFO wire를 기대했습니다: {other:?}"),
        }

        // DO를 설정하면 합성하지 않는다. 이 서버에는 any.test 영역이 없으므로 관례 경로로 간다.
        let mut signed_query = query.clone();
        signed_query.additionals.push(ApRecord {
            name: ApName::root(),
            rtype: ApRt::OPT,
            class: DnsClass(1232),
            ttl: 0x0000_8000,
            rdata: ApRData::Unknown(ApRt::OPT.0, Vec::new()),
        });
        let resp = s.handle(&signed_query, &ctx()).unwrap();
        assert!(
            resp.answers
                .iter()
                .all(|record| record.rtype != RecordType(13)),
            "DO를 설정한 질의에는 합성 HINFO를 주지 않는다"
        );
    }

    #[test]
    /** @brief 최소 응답과 채우기가 설정대로 적용되는지. */
    fn postprocess_minimal_responses_and_padding() {
        let mut f = NativeFeatures {
            minimal_responses: true,
            padding_block: 128,
            ..NativeFeatures::default()
        };

        let mut msg = Message::query(9, ApName::from_str("x.test").unwrap(), RecordType::A);
        msg.header.response = true;
        msg.answers.push(ApRecord::new(
            ApName::from_str("x.test").unwrap(),
            60,
            ApRData::A(Ipv4Addr::new(1, 2, 3, 4)),
        ));
        msg.authorities.push(ApRecord::new(
            ApName::from_str("ns.test").unwrap(),
            60,
            ApRData::A(Ipv4Addr::new(9, 9, 9, 9)),
        ));
        msg.additionals
            .push(Edns::default().try_to_record().unwrap());

        let mut req = Message::query(9, ApName::from_str("x.test").unwrap(), RecordType::A);
        let mut e = Edns::default();
        e.options.push((onetdns_proto::EDNS_PADDING, vec![]));
        req.additionals.push(e.try_to_record().unwrap());

        postprocess(&f, &mut msg, &req, &ctx()).unwrap();
        assert!(
            msg.authorities.is_empty(),
            "minimal-responses가 권한 섹션 제거"
        );
        assert_eq!(
            msg.try_encode().unwrap().len() % 128,
            0,
            "padding으로 block 배수 정렬"
        );

        let mut msg2 = Message::query(9, ApName::from_str("x.test").unwrap(), RecordType::A);
        msg2.header.response = true;
        msg2.additionals
            .push(Edns::default().try_to_record().unwrap());
        let plain = Message::query(9, ApName::from_str("x.test").unwrap(), RecordType::A);
        f.minimal_responses = false;
        let before = msg2.try_encode().unwrap().len();
        postprocess(&f, &mut msg2, &plain, &ctx()).unwrap();
        assert_eq!(
            msg2.try_encode().unwrap().len(),
            before,
            "padding 미요청 시 변화 없음"
        );
    }

    #[test]
    /** @brief 뷰에 드는 클라이언트면 다르게 답하는지. */
    fn view_local_overrides_for_matching_client() {
        let s = server("").with_views(vec![NativeView {
            nets: vec!["127.0.0.1/32".parse().unwrap()],
            ids: vec![],
            local_a: vec![(
                ApName::from_str("printer.lan").unwrap().canonical_key(),
                Ipv4Addr::new(192, 168, 1, 5),
            )],
            local_aaaa: vec![],
        }]);
        s.local_ttl.store(27, Ordering::Release);

        let resp = s.handle(&q("printer.lan"), &ctx()).unwrap();
        assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
        assert_eq!(resp.answers[0].ttl, 27);
        match &resp.answers[0].rdata {
            ApRData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(192, 168, 1, 5)),
            other => panic!("A 레코드를 예상했지만 실제 값은 {other:?}입니다"),
        }
        s.local_ttl.store(33, Ordering::Release);
        assert_eq!(
            s.handle(&q("printer.lan"), &ctx()).unwrap().answers[0].ttl,
            33,
            "뷰도 로컬 TTL 핫 변경을 공유"
        );

        let resp = s.handle(&q("other.example"), &ctx()).unwrap();
        match &resp.answers[0].rdata {
            ApRData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(7, 7, 7, 7)),
            other => panic!("A 레코드를 예상했지만 실제 값은 {other:?}입니다"),
        }
    }

    #[test]
    /** @brief 뷰 이름의 원래 바이트가 바뀌지 않는지. */
    fn view_local_key_preserves_raw_name_octets() {
        let configured = ApName::from_str("�").unwrap();
        let s = server("").with_views(vec![NativeView {
            nets: vec!["127.0.0.1/32".parse().unwrap()],
            ids: vec![],
            local_a: vec![(configured.canonical_key(), Ipv4Addr::new(192, 168, 1, 5))],
            local_aaaa: vec![],
        }]);

        let configured_query = Message::query(1, configured, RecordType::A);
        let configured_response = s.handle(&configured_query, &ctx()).unwrap();
        assert!(matches!(
            configured_response.answers[0].rdata,
            ApRData::A(ip) if ip == Ipv4Addr::new(192, 168, 1, 5)
        ));

        let raw_query = Message::query(
            2,
            ApName::from_labels(vec![vec![0xff]]).unwrap(),
            RecordType::A,
        );
        let raw_response = s.handle(&raw_query, &ctx()).unwrap();
        assert!(matches!(
            raw_response.answers[0].rdata,
            ApRData::A(ip) if ip == Ipv4Addr::new(7, 7, 7, 7)
        ));
    }

    #[test]
    /** @brief 접근 제어가 막은 질의를 거절하는지. */
    fn acl_deny_refuses() {
        let mut s = server("");
        s.acl = Arc::new(IpAcl::new(
            vec![],
            vec!["127.0.0.1/32".parse().unwrap()],
            true,
        ));
        let resp = s.handle(&q("x.test"), &ctx()).unwrap();
        assert_eq!(resp.header.rcode, ResponseCode::Refused.0);
    }

    #[test]
    /** @brief IPv6 답을 끄면 없다가 아니라 비어 있다고 답하는지. */
    fn block_aaaa_returns_nodata() {
        let s = server("");
        update_features(&s, |features| features.block_aaaa = true);
        let mut query = q("ipv6.test");
        query.questions[0].qtype = RecordType::AAAA;
        let resp = s.handle(&query, &ctx()).unwrap();
        assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
        assert!(resp.answers.is_empty(), "AAAA 비활성 → NODATA");
        assert!(
            resp.authorities
                .iter()
                .any(|record| matches!(&record.rdata, ApRData::Soa(_))),
            "정책 NODATA에는 음성 캐시용 SOA가 필요"
        );
    }

    #[test]
    /** @brief 임의로 만든 답의 수명이 근거보다 길지 않은지. */
    fn dns64_synthesis_caps_ttl_with_negative_soa() {
        let owner = ApName::from_str("v4only.test").unwrap();
        let answers = vec![ApRecord::new(
            owner.clone(),
            300,
            ApRData::A(Ipv4Addr::new(192, 0, 2, 10)),
        )];
        let mut prefix = [0u8; 16];
        prefix[..4].copy_from_slice(&[0x00, 0x64, 0xff, 0x9b]);
        let synthesized = synthesize_dns64(&answers, &prefix, Some(45));
        assert_eq!(synthesized.len(), 1);
        assert_eq!(synthesized[0].ttl, 45);
        assert!(matches!(&synthesized[0].rdata, ApRData::Aaaa(_)));
    }

    #[test]
    /** @brief 응답 쪽 정책이 최종 답을 막을 수 있는지. */
    fn response_hook_verdict_blocks_final_answer() {
        /** @brief 테스트용 정책 플러그인. */
        const HOOK_WAT: &str = r#"
            (module
              (memory (export "memory") 1)
              (global $next (mut i32) (i32.const 1024))
              (func (export "alloc") (param $len i32) (result i32)
                (local $p i32)
                (local.set $p (global.get $next))
                (global.set $next (i32.add (global.get $next) (local.get $len)))
                (local.get $p))
              (func (export "evaluate") (param i32 i32) (result i32) (i32.const 0))
              (func (export "on_response") (param $ptr i32) (param $len i32) (result i32)
                (local $addr0 i32)
                (if (result i32)
                    (i32.eqz (i32.load8_u (i32.add (local.get $ptr) (i32.const 6))))
                  (then (i32.const 0))
                  (else
                    (local.set $addr0
                      (i32.add (i32.add (local.get $ptr) (i32.const 10))
                               (i32.load16_u (i32.add (local.get $ptr) (i32.const 8)))))
                    (if (result i32)
                        (i32.eq (i32.load8_u (i32.add (local.get $addr0) (i32.const 1)))
                                (i32.const 7))
                      (then (i32.const 2))
                      (else (i32.const 0)))))))
        "#;
        let wasm = wat::parse_str(HOOK_WAT).unwrap();
        let plugin = onetdns_policy::WasmPolicy::from_wasm(&wasm).unwrap();
        let engine = onetdns_policy::PolicyEngine::new(
            onetdns_policy::RuleEngine::new(vec![]),
            vec![plugin],
        );
        let s = server("");
        s.policy.store(Arc::new(engine));

        let mut req = q("hooked.example.");
        req.additionals
            .push(onetdns_proto::Edns::default().try_to_record().unwrap());
        let resp = s.handle(&req, &ctx()).expect("응답");
        assert_eq!(resp.header.rcode, ResponseCode::NXDomain.0, "verdict 차단");
        assert_eq!(negative_soa_ttl(&resp), 60);
        let ede = resp
            .opt()
            .and_then(onetdns_proto::Edns::from_record)
            .and_then(|e| e.ede())
            .map(|(code, _)| code);
        assert_eq!(ede, Some(onetdns_proto::ede_code::FILTERED));
    }

    #[test]
    /** @brief 내부망 주소가 답에서 빠지는지. */
    fn rebind_protection_strips_private() {
        let s = server("");
        update_features(&s, |features| features.rebind_protection = true);
        let resp = s.handle(&q("pub.test"), &ctx()).unwrap();
        assert_eq!(resp.answers.len(), 1, "공인 IP는 보존");
    }

    #[test]
    /** @brief 주소 때문에 막은 답이 차단 수명을 쓰는지. */
    fn response_address_blocks_use_blocked_response_ttl() {
        let bogus = server("");
        bogus.block_ttl.store(73, Ordering::Release);
        update_features(&bogus, |features| {
            features.bogus_nxdomain = vec!["7.7.7.7/32".parse().unwrap()]
        });
        let response = bogus.handle(&q("bogus-address.test"), &ctx()).unwrap();
        assert_eq!(response.header.rcode, ResponseCode::NXDomain.0);
        assert_eq!(negative_soa_ttl(&response), 73);

        let denied = server("");
        denied.block_ttl.store(79, Ordering::Release);
        update_features(&denied, |features| {
            features.recurse_deny_answers = vec!["7.7.7.7/32".parse().unwrap()]
        });
        let response = denied.handle(&q("denied-address.test"), &ctx()).unwrap();
        assert_eq!(response.header.rcode, ResponseCode::NXDomain.0);
        assert_eq!(negative_soa_ttl(&response), 79);
    }

    #[cfg(unix)]
    #[test]
    /** @brief 레인이 처리하지 않는 검사는 보통 경로로 넘기는지. 안 넘기면 그 검사가 없는 것처럼 답이 나간다. */
    fn reactor_lane_defers_answer_address_filters_and_ns_rpz_to_sync_path() {
        use onetdns_runtime::ReactorDisposition;

        let lane_server = |engine: onetdns_filter::BlockEngine| {
            let (backend, cache) = lane_backend_and_cache();
            let recursor = Arc::new(
                onetdns_recurse::Recursor::new(
                    vec!["127.0.0.1:5399".parse().unwrap()],
                    std::time::Duration::from_millis(50),
                )
                .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]),
            );
            NativeServer::new(
                shared_filter(ArcSwap::from_pointee(engine)),
                Arc::new(IpAcl::allow_all()),
                vec![],
                backend,
                60,
            )
            .with_reactor_lane(recursor, cache, 32)
        };
        let plain = || onetdns_filter::build_from_str("", "", BlockResponse::NxDomain);
        let packet = Message::query(0x7, ApName::from_str("ok.example").unwrap(), ApRt::A)
            .try_encode()
            .unwrap();
        let submit = |server: &NativeServer| {
            let mut out = onetdns_proto::Writer::with_limit(1232);
            server.reactor_submit(&packet, &ctx(), &mut out, std::time::Instant::now())
        };

        assert_eq!(
            submit(&lane_server(plain())),
            ReactorDisposition::Submitted,
            "필터가 없으면 레인에 제출된다"
        );

        let rebind = lane_server(plain());
        update_features(&rebind, |features| features.rebind_protection = true);
        assert_eq!(submit(&rebind), ReactorDisposition::Fallback);

        let bogus = lane_server(plain());
        update_features(&bogus, |features| {
            features.bogus_nxdomain = vec!["7.7.7.7/32".parse().unwrap()]
        });
        assert_eq!(submit(&bogus), ReactorDisposition::Fallback);

        let denied = lane_server(plain());
        update_features(&denied, |features| {
            features.recurse_deny_answers = vec!["7.7.7.7/32".parse().unwrap()]
        });
        assert_eq!(submit(&denied), ReactorDisposition::Fallback);

        let mut parts = onetdns_filter::EngineParts::default();
        parts.rpz_nsdname.push(
            onetdns_filter::RpzNameRule::new(
                "evil-ns.example",
                FilterVerdict::Block(BlockResponse::NxDomain),
            )
            .unwrap(),
        );
        assert_eq!(
            submit(&lane_server(onetdns_filter::BlockEngine::new(
                parts,
                BlockResponse::NxDomain
            ))),
            ReactorDisposition::Fallback
        );
    }

    #[cfg(unix)]
    #[test]
    /** @brief DDR을 켠 재귀 레인이 특수 이름만 체인에 양보하고 일반 콜드미스는 계속 맡는지. */
    fn ddr_only_preempts_its_owner_in_the_reactor_lane() {
        use onetdns_runtime::ReactorDisposition;

        let (backend, cache) = lane_backend_and_cache();
        let recursor = Arc::new(
            onetdns_recurse::Recursor::new(
                vec!["127.0.0.1:5399".parse().unwrap()],
                std::time::Duration::from_millis(50),
            )
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]),
        );
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            backend,
            60,
        )
        .with_reactor_lane(recursor, cache, 32);
        update_features(&server, |features| features.ddr_enabled = true);

        let submit = |name: &str| {
            let packet = Message::query(7, ApName::from_str(name).unwrap(), ApRt::A)
                .try_encode()
                .unwrap();
            let mut out = onetdns_proto::Writer::with_limit(1232);
            server.reactor_submit(&packet, &ctx(), &mut out, std::time::Instant::now())
        };
        assert_eq!(submit("_DNS.Resolver.ARPA"), ReactorDisposition::Fallback);
        assert_eq!(submit("ordinary.example"), ReactorDisposition::Submitted);
    }

    #[cfg(unix)]
    #[test]
    /** @brief lenient 쿠키의 무쿠키 콜드미스만 리액터가 맡고 COOKIE 질의는 발급 경로로 넘기는지. */
    fn lenient_cookie_keeps_plain_reactor_and_defers_cookie_requests() {
        use onetdns_runtime::ReactorDisposition;

        let (backend, cache) = lane_backend_and_cache();
        let recursor = Arc::new(
            onetdns_recurse::Recursor::new(
                vec!["127.0.0.1:5399".parse().unwrap()],
                std::time::Duration::from_millis(50),
            )
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]),
        );
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            backend,
            60,
        )
        .with_reactor_lane(recursor, cache, 32);
        update_features(&server, |features| {
            features.cookies = CookiePolicy {
                keeper: Some(Arc::new(CookieKeeper::from_secret(&[3; 16]))),
                strict: false,
            };
        });

        let mut with_cookie = q("cookie-reactor.example");
        let mut edns = Edns::default();
        edns.options.push((OPT_COOKIE, vec![1; 8]));
        with_cookie.additionals.push(edns.try_to_record().unwrap());
        let submit = |request: &Message| {
            let packet = request.try_encode().unwrap();
            let mut out = onetdns_proto::Writer::with_limit(1232);
            server.reactor_submit(&packet, &ctx(), &mut out, Instant::now())
        };
        assert_eq!(
            submit(&with_cookie),
            ReactorDisposition::Fallback,
            "COOKIE 질의는 서버 쿠키를 발급하는 구조적 경로가 맡습니다"
        );
        assert_eq!(
            submit(&q("plain-reactor.example")),
            ReactorDisposition::Submitted,
            "쿠키 없는 질의는 lenient 때문에 콜드 경로를 잃지 않습니다"
        );

        update_features(&server, |features| features.cookies.strict = true);
        assert_eq!(
            submit(&q("strict-reactor.example")),
            ReactorDisposition::Fallback,
            "strict는 무쿠키 질의를 BADCOOKIE 경로로 넘깁니다"
        );
    }

    #[test]
    /** @brief 클라이언트마다 달라지는 차단이 담긴 바이트로 새 나가지 않는지. */
    fn wire_store_does_not_leak_client_specific_cname_block() {
        use onetdns_runtime::WireDisposition;

        /** @brief 별칭 뒤에 차단 대상을 숨긴 답을 내는 테스트용 체인. */
        struct CloakedAnswer;
        impl Resolver for CloakedAnswer {
            /** @brief 별칭 뒤에 차단 대상을 숨긴 답을 돌려준다. */
            fn resolve(&self, request: &Message) -> Option<Message> {
                let mut response = base_response(request);
                let name = request.questions.first().unwrap().name.clone();
                let tracker = ApName::from_str("tracker.evil.example").unwrap();
                response
                    .answers
                    .push(ApRecord::new(name, 300, ApRData::Cname(tracker.clone())));
                response.answers.push(ApRecord::new(
                    tracker,
                    300,
                    ApRData::A(Ipv4Addr::new(203, 0, 113, 9)),
                ));
                Some(response)
            }
        }

        let engine =
            onetdns_filter::build_from_str("", "", BlockResponse::ZeroIp).with_clients(vec![
                onetdns_filter::ClientPolicy::with_options(
                    vec!["10.0.0.0/8".parse().unwrap()],
                    vec![],
                    vec![],
                    &["tracker.evil.example".to_string()],
                    &[],
                    false,
                    None,
                ),
            ]);
        let layer =
            crate::cache::CacheLayer::new(Arc::new(CloakedAnswer), 64, 1, 0, 86_400, 0, 86_400);
        let cache = layer.handle();
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(engine)),
            Arc::new(IpAcl::allow_all()),
            vec![],
            Arc::new(layer),
            60,
        )
        .with_wire_fast_path(Some((
            crate::wirecache::WireEntryFactory::new(0, 86_400),
            cache,
        )));

        let packet = Message::query(
            0x21,
            ApName::from_str("cdn.publisher.example").unwrap(),
            ApRt::A,
        )
        .try_encode()
        .unwrap();
        let blocked_ctx = RequestCtx {
            src: "10.0.0.1:5555".parse().unwrap(),
            transport: RtTransport::Do53Udp,
            raw: None,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };

        let mut out = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.handle_udp_wire(&packet, &blocked_ctx, &mut out, std::time::Instant::now()),
            WireDisposition::Fallback,
            "클라이언트별 규칙이 있으면 공유 wire 표현을 만들지 않는다"
        );

        let mut out2 = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.handle_udp_wire(&packet, &ctx(), &mut out2, std::time::Instant::now()),
            WireDisposition::Fallback
        );

        let request = Message::parse(&packet).unwrap();
        let blocked = server
            .handle(&request, &blocked_ctx)
            .expect("동기 경로 응답");
        assert!(
            blocked
                .answers
                .iter()
                .any(|r| matches!(&r.rdata, ApRData::A(ip) if ip.is_unspecified())),
            "차단 대상 클라이언트는 동기 경로에서 0.0.0.0을 받는다"
        );
        assert!(
            server
                .handle(&request, &ctx())
                .expect("동기 경로 응답")
                .answers
                .iter()
                .any(
                    |r| matches!(&r.rdata, ApRData::A(ip) if *ip == Ipv4Addr::new(203, 0, 113, 9))
                ),
            "차단 대상이 아닌 클라이언트는 참 응답을 받는다"
        );

        let plain_layer =
            crate::cache::CacheLayer::new(Arc::new(CloakedAnswer), 64, 1, 0, 86_400, 0, 86_400);
        let plain_cache = plain_layer.handle();
        let plain = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::build_from_str(
                "",
                "",
                BlockResponse::ZeroIp,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            Arc::new(plain_layer),
            60,
        )
        .with_wire_fast_path(Some((
            crate::wirecache::WireEntryFactory::new(0, 86_400),
            plain_cache,
        )));
        let mut out3 = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            plain.handle_udp_wire(&packet, &ctx(), &mut out3, std::time::Instant::now()),
            WireDisposition::Respond,
            "클라이언트별 규칙이 없으면 기존대로 wire 경로가 동작한다"
        );
    }

    #[cfg(unix)]
    #[test]
    /** @brief 레인에서 일반 경로로 넘어가도 제한을 두 번 세지 않는지. */
    fn reactor_submit_charges_rate_limit_once_across_fallback() {
        use onetdns_runtime::ReactorDisposition;

        /** @brief 호출 수를 세는 테스트용 제한기. */
        struct CountingLimiter(AtomicUsize);
        impl RateLimiter for CountingLimiter {
            /** @brief 세고 통과시킨다. */
            fn check(&self, _client: &ClientInfo) -> RateDecision {
                self.0.fetch_add(1, Ordering::Relaxed);
                RateDecision::Permit
            }
        }

        let packet = Message::query(0x31, ApName::from_str("ok.example").unwrap(), ApRt::A)
            .try_encode()
            .unwrap();
        let build = |engine: onetdns_filter::BlockEngine, limiter: Arc<CountingLimiter>| {
            let (backend, cache) = lane_backend_and_cache();
            let recursor = Arc::new(
                onetdns_recurse::Recursor::new(
                    vec!["127.0.0.1:5399".parse().unwrap()],
                    std::time::Duration::from_millis(50),
                )
                .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]),
            );
            NativeServer::new(
                shared_filter(ArcSwap::from_pointee(engine)),
                Arc::new(IpAcl::allow_all()),
                vec![limiter],
                backend,
                60,
            )
            .with_reactor_lane(recursor, cache, 32)
        };

        let mut parts = onetdns_filter::EngineParts::default();
        parts.rpz_nsdname.push(
            onetdns_filter::RpzNameRule::new(
                "evil-ns.example",
                FilterVerdict::Block(BlockResponse::NxDomain),
            )
            .unwrap(),
        );
        let falling = Arc::new(CountingLimiter(AtomicUsize::new(0)));
        let server = build(
            onetdns_filter::BlockEngine::new(parts, BlockResponse::NxDomain),
            falling.clone(),
        );
        let mut out = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.reactor_submit(&packet, &ctx(), &mut out, std::time::Instant::now()),
            ReactorDisposition::Fallback
        );
        assert_eq!(
            falling.0.load(Ordering::Relaxed),
            0,
            "동기 경로로 넘기는 질의는 레인에서 토큰을 소비하지 않아야 한다"
        );

        let taking = Arc::new(CountingLimiter(AtomicUsize::new(0)));
        let plain = build(
            onetdns_filter::build_from_str("", "", BlockResponse::NxDomain),
            taking.clone(),
        );
        let mut out2 = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            plain.reactor_submit(&packet, &ctx(), &mut out2, std::time::Instant::now()),
            ReactorDisposition::Submitted
        );
        assert_eq!(
            taking.0.load(Ordering::Relaxed),
            1,
            "떠맡을 때는 한 번 소비한다"
        );
    }

    #[cfg(unix)]
    /** @brief 두 경로 비교에 쓸 테스트용 권한 서버. */
    fn spawn_parity_authority() -> std::net::SocketAddr {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("mock bind");
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let Ok(req) = Message::parse(&buf[..n]) else {
                    continue;
                };
                let Some(q) = req.questions.first().cloned() else {
                    continue;
                };
                let mut resp = base_response(&req);
                resp.header.authoritative = true;
                resp.questions = vec![q.clone()];
                let soa = || {
                    ApRecord::new(
                        ApName::root(),
                        60,
                        ApRData::soa(onetdns_proto::Soa {
                            mname: ApName::from_str("ns.").unwrap(),
                            rname: ApName::from_str("hostmaster.").unwrap(),
                            serial: 1,
                            refresh: 3600,
                            retry: 600,
                            expire: 86_400,
                            minimum: 60,
                        }),
                    )
                };
                match q.name.to_ascii_lower().as_str() {
                    "dead" => continue,

                    "alias2" => resp.answers.push(ApRecord::new(
                        q.name.clone(),
                        60,
                        ApRData::Cname(ApName::from_str("alias.").unwrap()),
                    )),
                    "nodata" => resp.authorities.push(soa()),
                    "nx" => {
                        resp.header.rcode = ResponseCode::NXDomain.0;
                        resp.authorities.push(soa());
                    }
                    "alias" => resp.answers.push(ApRecord::new(
                        q.name.clone(),
                        60,
                        ApRData::Cname(ApName::from_str("ok.").unwrap()),
                    )),
                    "extra" => {
                        resp.answers.push(ApRecord::new(
                            q.name.clone(),
                            60,
                            ApRData::A(Ipv4Addr::new(192, 0, 2, 1)),
                        ));

                        resp.answers.push(ApRecord::new(
                            ApName::from_str("bank.").unwrap(),
                            60,
                            ApRData::A(Ipv4Addr::new(198, 51, 100, 66)),
                        ));
                        resp.authorities.push(ApRecord::new(
                            ApName::from_str("unrelated.").unwrap(),
                            60,
                            ApRData::Ns(ApName::from_str("ns.evil.").unwrap()),
                        ));
                        resp.additionals.push(ApRecord::new(
                            ApName::from_str("ns.evil.").unwrap(),
                            60,
                            ApRData::A(Ipv4Addr::new(198, 51, 100, 67)),
                        ));
                    }
                    "forgedad" => {
                        resp.header.authentic_data = true;
                        resp.answers.push(ApRecord::new(
                            q.name.clone(),
                            60,
                            ApRData::A(Ipv4Addr::new(192, 0, 2, 1)),
                        ));
                    }
                    _ => resp.answers.push(ApRecord::new(
                        q.name.clone(),
                        60,
                        ApRData::A(Ipv4Addr::new(192, 0, 2, 1)),
                    )),
                }
                let _ = sock.send_to(&resp.try_encode().unwrap(), from);
            }
        });
        addr
    }

    #[cfg(unix)]
    /** @brief 기록을 남기는 테스트용 핸들러. */
    fn parity_server_recording(
        authority: std::net::SocketAddr,
        with_lane: bool,
    ) -> (NativeServer, onetdns_control::Stats) {
        let (recorder, stats) = onetdns_control::channel(
            64,
            64,
            3600,
            onetdns_control::RecorderOpts {
                querylog: true,
                anonymize: false,
                ignored: vec![],
                stats_retention_secs: 3600,
            },
            onetdns_control::PersistOpts::default(),
        );
        let server = parity_server_with(authority, with_lane, Some(recorder.clone()));
        let features = server.features.load();
        let mut features = (*features).clone();
        features.recorder = Some(recorder);
        (server.with_features(features), stats)
    }

    #[cfg(unix)]
    /** @brief 레인을 켜거나 끈 테스트용 핸들러. */
    fn parity_server(authority: std::net::SocketAddr, with_lane: bool) -> NativeServer {
        parity_server_with(authority, with_lane, None)
    }

    #[cfg(unix)]
    /** @brief 설정을 지정한 테스트용 핸들러. */
    fn parity_server_with(
        authority: std::net::SocketAddr,
        with_lane: bool,
        recorder: Option<onetdns_control::Recorder>,
    ) -> NativeServer {
        let recursor = Arc::new(
            onetdns_recurse::Recursor::new(vec![authority], std::time::Duration::from_millis(800))
                .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]),
        );
        let backend = Arc::new(NativeBackend::Recurse {
            recursor: recursor.clone(),
            ns_rpz: None,
            block_ttl: Arc::new(AtomicU32::new(60)),
            local_ttl: Arc::new(AtomicU32::new(60)),
        });
        let layer = crate::cache::CacheLayer::new(backend, 64, 1, 0, 86_400, 0, 86_400)
            .with_recorder(recorder);
        let cache = layer.handle();
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            Arc::new(layer),
            60,
        );
        if with_lane {
            server.with_reactor_lane(recursor, cache, 32)
        } else {
            server
        }
    }

    #[cfg(unix)]
    /** @brief 레인으로 답 하나를 받는다. */
    fn lane_answer(server: &NativeServer, request: &Message) -> Message {
        use onetdns_runtime::ReactorDisposition;
        let packet = request.try_encode().expect("질의 인코딩");
        let mut w = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.reactor_submit(&packet, &ctx(), &mut w, std::time::Instant::now()),
            ReactorDisposition::Submitted,
            "레인이 받아야 대조가 의미 있다. Fallback이면 게이트가 막은 것"
        );
        let mut out = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while out.is_empty() && std::time::Instant::now() < deadline {
            let mut fds = Vec::new();
            let mut map = Vec::new();
            server.reactor_collect(&mut fds, &mut map);

            if fds.is_empty() {
                std::thread::sleep(std::time::Duration::from_millis(2));
            } else {
                unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 100) };
                server.reactor_pump(&fds, 0, &map, std::time::Instant::now(), &mut out);
            }
            server.reactor_tick(std::time::Instant::now(), &mut out);
        }
        assert_eq!(out.len(), 1, "레인 응답이 정확히 하나 나와야 한다");
        Message::parse(&out[0].1).expect("레인 응답 파싱")
    }

    /** @brief 기록들을 비교할 문자열 목록으로. */
    fn record_keys(records: &[ApRecord]) -> Vec<String> {
        let mut keys: Vec<String> = records
            .iter()
            .filter(|record| record.rtype != ApRt::OPT)
            .map(|record| {
                format!(
                    "{}|{:?}|{:?}",
                    record.name.to_ascii_lower(),
                    record.rtype,
                    record.rdata
                )
            })
            .collect();
        keys.sort();
        keys
    }

    #[cfg(unix)]
    #[test]
    /** @brief 레인의 답이 보통 경로와 같은지. 다르면 어느 경로로 갔느냐에 따라 답이 갈린다. */
    fn reactor_lane_answers_match_the_sync_path() {
        let authority = spawn_parity_authority();
        for (name, qtype) in [
            ("ok.", ApRt::A),
            ("nodata.", ApRt::A),
            ("nx.", ApRt::A),
            ("alias.", ApRt::A),
            ("alias2.", ApRt::A),
            ("extra.", ApRt::A),
            ("forgedad.", ApRt::A),
            ("dead.", ApRt::A),
        ] {
            let mut request = Message::query(0x33, ApName::from_str(name).unwrap(), qtype);

            request
                .additionals
                .push(onetdns_proto::Edns::default().try_to_record().unwrap());
            let sync = parity_server(authority, false)
                .handle(&request, &ctx())
                .unwrap_or_else(|| panic!("{name}: 동기 응답이 없다"));
            let lane = lane_answer(&parity_server(authority, true), &request);

            assert_eq!(lane.header.rcode, sync.header.rcode, "{name}: rcode 불일치");
            assert_eq!(
                (
                    lane.header.authentic_data,
                    lane.header.authoritative,
                    lane.header.truncated,
                    lane.header.recursion_available,
                ),
                (
                    sync.header.authentic_data,
                    sync.header.authoritative,
                    sync.header.truncated,
                    sync.header.recursion_available,
                ),
                "{name}: 헤더 비트 불일치(AD/AA/TC/RA)"
            );
            assert_eq!(
                record_keys(&lane.answers),
                record_keys(&sync.answers),
                "{name}: 답변 구획 불일치"
            );
            if name == "alias2." {
                assert_eq!(lane.answers.len(), 3, "2홉 추적의 답 누적이 어긋났다");
            }
            assert_eq!(
                record_keys(&lane.authorities),
                record_keys(&sync.authorities),
                "{name}: 권한 구획 불일치"
            );
            assert_eq!(
                record_keys(&lane.additionals),
                record_keys(&sync.additionals),
                "{name}: 부가 구획 불일치"
            );

            let ede_of = |m: &Message| {
                m.opt()
                    .and_then(onetdns_proto::Edns::from_record)
                    .and_then(|e| e.ede())
                    .map(|(code, _)| code)
            };
            assert_eq!(ede_of(&lane), ede_of(&sync), "{name}: EDE 불일치");
        }
    }

    #[cfg(unix)]
    /** @brief 최근 기록을 가져간다. */
    fn drain_recent(stats: &onetdns_control::Stats) -> Vec<onetdns_control::QueryEvent> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            let recent = stats.recent(8);
            if !recent.is_empty() || std::time::Instant::now() >= deadline {
                return recent;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    #[cfg(unix)]
    #[test]
    /** @brief 레인도 보통 경로와 같은 기록을 남기는지. */
    fn reactor_lane_records_query_events_like_the_sync_path() {
        let authority = spawn_parity_authority();

        for qname in ["ok.", "dead."] {
            let request = Message::query(0x44, ApName::from_str(qname).unwrap(), ApRt::A);

            let (sync_server, sync_stats) = parity_server_recording(authority, false);
            sync_server.handle(&request, &ctx()).expect("동기 응답");
            let sync_events = drain_recent(&sync_stats);

            let (lane_server, lane_stats) = parity_server_recording(authority, true);
            lane_answer(&lane_server, &request);
            let lane_events = drain_recent(&lane_stats);

            assert_eq!(sync_events.len(), 1, "동기: 질의당 이벤트 하나");
            assert_eq!(
                lane_events.len(),
                1,
                "레인: 질의당 이벤트 하나여야 한다(0이면 대시보드가 비고, 2면 이중 계상)"
            );
            let (s, l) = (&sync_events[0], &lane_events[0]);
            assert_eq!(
                (
                    l.action,
                    l.name.as_ref().map(ApName::to_string),
                    l.qtype.as_str(),
                    l.rcode.as_str()
                ),
                (
                    s.action,
                    s.name.as_ref().map(ApName::to_string),
                    s.qtype.as_str(),
                    s.rcode.as_str()
                ),
                "레인 이벤트가 동기 경로와 다르다"
            );
            assert_eq!(l.answers, s.answers, "답변 요약 불일치");
            assert_eq!(
                (l.reason.as_str(), l.stage.as_str(), l.detail.as_str()),
                (s.reason.as_str(), s.stage.as_str(), s.detail.as_str()),
                "진단(사유·단계·상세) 불일치"
            );
            assert!(
                l.latency_us > 0,
                "레인 처리시간이 0이다. 떠맡은 시각이 아니라 완료 시각으로 쟀다"
            );

            assert!(
                sync_stats.metrics.snapshot().avg_latency_ms > 0.0,
                "동기 기준선이 지연을 안 남겼다면 대조가 공허하다"
            );
            assert!(
                lane_stats.metrics.snapshot().avg_latency_ms > 0.0,
                "레인이 지연 지표를 남기지 않았다"
            );

            assert_eq!(
                lane_stats.metrics.snapshot().cache_lookups,
                sync_stats.metrics.snapshot().cache_lookups,
                "캐시 조회 계상 불일치"
            );
            assert_eq!(
                lane_stats.metrics.snapshot().cache_hits,
                sync_stats.metrics.snapshot().cache_hits,
                "캐시 적중 계상 불일치"
            );
        }
    }

    #[cfg(unix)]
    /** @brief 레인 테스트에 쓸 체인과 캐시. */
    fn lane_backend_and_cache() -> (Arc<dyn Resolver>, crate::cache::CacheHandle) {
        let layer =
            crate::cache::CacheLayer::new(Arc::new(FixedAnswer), 64, 1, 0, 86_400, 0, 86_400);
        let handle = layer.handle();
        (Arc::new(layer), handle)
    }

    #[cfg(unix)]
    /** @brief 언제나 잘린 응답을 내는 테스트용 권한 서버. */
    fn spawn_truncating_authority() -> std::net::SocketAddr {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("mock bind");
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let Ok(req) = Message::parse(&buf[..n]) else {
                    continue;
                };
                let Some(q) = req.questions.first().cloned() else {
                    continue;
                };
                let mut resp = base_response(&req);
                resp.header.authoritative = true;
                resp.header.truncated = true;
                resp.questions = vec![q.clone()];
                resp.answers.push(ApRecord::new(
                    q.name.clone(),
                    60,
                    ApRData::A(Ipv4Addr::new(192, 0, 2, 7)),
                ));
                let _ = sock.send_to(&resp.try_encode().unwrap(), from);
            }
        });
        addr
    }

    #[cfg(unix)]
    /** @brief 일부만 잘린 응답을 내는 테스트용 권한 서버. */
    fn spawn_mixed_truncating_authority() -> std::net::SocketAddr {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("mock bind");
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let Ok(req) = Message::parse(&buf[..n]) else {
                    continue;
                };
                let Some(q) = req.questions.first().cloned() else {
                    continue;
                };
                let mut resp = base_response(&req);
                resp.header.authoritative = true;
                resp.header.truncated = q.name.to_ascii_lower().starts_with("tc");
                resp.questions = vec![q.clone()];
                resp.answers.push(ApRecord::new(
                    q.name.clone(),
                    60,
                    ApRData::A(Ipv4Addr::new(192, 0, 2, 7)),
                ));
                let _ = sock.send_to(&resp.try_encode().unwrap(), from);
            }
        });
        addr
    }

    #[cfg(unix)]
    /** @brief 느리게 답하는 테스트용 체인. */
    struct SlowAnswer(std::time::Duration);

    #[cfg(unix)]
    impl Resolver for SlowAnswer {
        /** @brief 미리 정해 둔 응답을 돌려준다. */
        fn resolve(&self, request: &Message) -> Option<Message> {
            std::thread::sleep(self.0);
            let mut response = base_response(request);
            let name = request.questions.first()?.name.clone();
            response.answers.push(ApRecord::new(
                name,
                60,
                ApRData::A(Ipv4Addr::new(9, 9, 9, 9)),
            ));
            Some(response)
        }
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "꼬리 지연 프로브: cargo test -p onetdns --release -- --ignored --nocapture"]
    /** @brief 다시 묻는 하나가 뒤의 질의를 막지 않는지. */
    fn probe_lane_retry_fallback_head_of_line_delay() {
        use onetdns_runtime::ReactorDisposition;

        /** @brief 대체 경로로 넘어가기까지 기다릴 시간. */
        const FALLBACK: std::time::Duration = std::time::Duration::from_millis(400);
        let authority = spawn_mixed_truncating_authority();
        let recursor = Arc::new(
            onetdns_recurse::Recursor::new(vec![authority], std::time::Duration::from_millis(800))
                .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]),
        );
        let layer =
            crate::cache::CacheLayer::new(Arc::new(SlowAnswer(FALLBACK)), 64, 1, 0, 86_400, 0, 0);
        let cache = layer.handle();
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            Arc::new(layer),
            60,
        )
        .with_reactor_lane(recursor, cache, 32);

        let names = ["tc0.", "ok1.", "ok2.", "ok3.", "ok4."];
        let start = std::time::Instant::now();
        for name in names {
            let packet = Message::query(0x60, ApName::from_str(name).unwrap(), ApRt::A)
                .try_encode()
                .unwrap();
            let mut w = onetdns_proto::Writer::with_limit(1232);
            assert_eq!(
                server.reactor_submit(&packet, &ctx(), &mut w, std::time::Instant::now()),
                ReactorDisposition::Submitted,
                "{name}: 레인이 받아야 프로브가 성립한다"
            );
        }

        let mut done: Vec<(std::time::Duration, usize)> = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while done.len() < names.len() && std::time::Instant::now() < deadline {
            let mut fds = Vec::new();
            let mut map = Vec::new();
            server.reactor_collect(&mut fds, &mut map);
            let mut out = Vec::new();
            if !fds.is_empty() {
                unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 50) };
            }
            let now = std::time::Instant::now();
            server.reactor_pump(&fds, 0, &map, now, &mut out);
            server.reactor_tick(now, &mut out);
            for (_, wire) in &out {
                let parsed = Message::parse(wire).expect("응답 파싱");
                let is_fallback = parsed
                    .answers
                    .iter()
                    .any(|record| matches!(record.rdata, ApRData::A(ip) if ip.octets()[0] == 9));
                done.push((start.elapsed(), usize::from(is_fallback)));
            }
        }

        assert_eq!(done.len(), names.len(), "전원 완료해야 한다");
        let lane_max = done
            .iter()
            .filter(|(_, fallback)| *fallback == 0)
            .map(|(at, _)| *at)
            .max()
            .expect("레인 응답이 있어야 한다");
        println!(
            "PROBE 동기 폴백 {:?} 동안 레인 질의 최대 지연 {:?} (완료 {}건)",
            FALLBACK,
            lane_max,
            done.len()
        );
        println!(
            "PROBE 인질 여부: 레인 최대 지연이 폴백 시간의 {:.0}%",
            lane_max.as_secs_f64() / FALLBACK.as_secs_f64() * 100.0
        );
    }

    #[cfg(unix)]
    #[test]
    /** @brief 레인이 다시 물어야 할 것을 보통 체인이 마저 푸는지. 안 풀면 그 질의만 오류가 된다. */
    fn reactor_lane_retry_is_resolved_by_the_sync_chain_not_servfail() {
        use onetdns_runtime::ReactorDisposition;

        let authority = spawn_truncating_authority();
        let (backend, cache) = lane_backend_and_cache();
        let recursor = Arc::new(
            onetdns_recurse::Recursor::new(vec![authority], std::time::Duration::from_millis(500))
                .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]),
        );
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            backend,
            60,
        )
        .with_reactor_lane(recursor, cache, 32);

        let packet = Message::query(0x21, ApName::from_str("tcexample.").unwrap(), ApRt::A)
            .try_encode()
            .unwrap();
        let mut w = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.reactor_submit(&packet, &ctx(), &mut w, std::time::Instant::now()),
            ReactorDisposition::Submitted
        );

        let mut out = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while out.is_empty() && std::time::Instant::now() < deadline {
            let mut fds = Vec::new();
            let mut map = Vec::new();
            server.reactor_collect(&mut fds, &mut map);

            if fds.is_empty() {
                std::thread::sleep(std::time::Duration::from_millis(2));
            } else {
                unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 100) };
                server.reactor_pump(&fds, 0, &map, std::time::Instant::now(), &mut out);
            }
            server.reactor_tick(std::time::Instant::now(), &mut out);
        }

        assert_eq!(out.len(), 1, "레인이 응답을 냈다");
        let resp = Message::parse(&out[0].1).expect("응답 파싱");
        assert_eq!(
            resp.header.rcode,
            ResponseCode::NoError.0,
            "동기 체인이 풀어야 한다. SERVFAIL이면 레인이 절단 응답을 실패로 종결한 것"
        );
        assert!(
            resp.answers.iter().any(
                |record| matches!(record.rdata, ApRData::A(ip) if ip == Ipv4Addr::new(1, 2, 3, 4))
            ),
            "동기 체인의 답이 나와야 한다: {:?}",
            resp.answers
        );
    }

    #[cfg(unix)]
    #[test]
    /**
     * @brief 레인이 넘긴 질의를 동기 체인도 풀지 못하면 그 실패 사유가 그대로 나가는지.
     * @details 대체 처리 결과를 없음으로 접으면 영구 실패도 전송 실패로 보여, 클라이언트가
     *          사실과 다른 network error 사유를 받는다.
     */
    fn reactor_lane_fallback_failure_keeps_its_reason() {
        use onetdns_runtime::ReactorDisposition;

        /** @brief 언제나 영구 실패를 내는 테스트용 체인. */
        struct PermanentFailure;
        impl Resolver for PermanentFailure {
            /** @brief 언제나 답하지 않는다. */
            fn resolve(&self, _req: &Message) -> Option<Message> {
                None
            }
            /** @brief 닿을 권한 서버가 없다고 알린다. */
            fn resolve_outcome(&self, _req: &Message) -> ResolveOutcome {
                ResolveOutcome::Failure(ResolveFailure::Permanent(Some(
                    onetdns_proto::ede_code::NO_REACHABLE_AUTHORITY,
                )))
            }
        }

        let authority = spawn_truncating_authority();
        let layer =
            crate::cache::CacheLayer::new(Arc::new(PermanentFailure), 64, 1, 0, 86_400, 0, 86_400);
        let cache = layer.handle();
        let recursor = Arc::new(
            onetdns_recurse::Recursor::new(vec![authority], std::time::Duration::from_millis(500))
                .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]),
        );
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            Arc::new(layer),
            60,
        )
        .with_reactor_lane(recursor, cache, 32);

        let mut request = Message::query(0x22, ApName::from_str("tcfail.").unwrap(), ApRt::A);
        request
            .additionals
            .push(onetdns_proto::Edns::default().try_to_record().unwrap());
        let packet = request.try_encode().unwrap();
        let mut w = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.reactor_submit(&packet, &ctx(), &mut w, std::time::Instant::now()),
            ReactorDisposition::Submitted
        );

        let mut out = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while out.is_empty() && std::time::Instant::now() < deadline {
            let mut fds = Vec::new();
            let mut map = Vec::new();
            server.reactor_collect(&mut fds, &mut map);

            if fds.is_empty() {
                std::thread::sleep(std::time::Duration::from_millis(2));
            } else {
                unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 100) };
                server.reactor_pump(&fds, 0, &map, std::time::Instant::now(), &mut out);
            }
            server.reactor_tick(std::time::Instant::now(), &mut out);
        }

        assert_eq!(out.len(), 1, "레인이 응답을 냈다");
        let resp = Message::parse(&out[0].1).expect("응답 파싱");
        assert_eq!(resp.header.rcode, ResponseCode::ServFail.0);
        let ede = resp
            .opt()
            .and_then(onetdns_proto::Edns::from_record)
            .and_then(|edns| edns.ede())
            .map(|(code, _)| code);
        assert_eq!(
            ede,
            Some(onetdns_proto::ede_code::NO_REACHABLE_AUTHORITY),
            "동기 체인이 알린 사유가 나가야 한다. 23이면 실패를 전송 실패로 뭉갠 것"
        );
    }

    #[cfg(unix)]
    /** @brief 별칭 뒤에 숨긴 답을 내는 테스트용 권한 서버. */
    fn spawn_cloaking_authority() -> std::net::SocketAddr {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("mock bind");
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let tracker = ApName::from_str("tracker.evil.example").unwrap();
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let Ok(req) = Message::parse(&buf[..n]) else {
                    continue;
                };
                let Some(q) = req.questions.first().cloned() else {
                    continue;
                };
                let mut resp = base_response(&req);
                resp.header.authoritative = true;
                resp.questions = vec![q.clone()];
                if q.name.eq_ignore_case(&tracker) {
                    resp.answers.push(ApRecord::new(
                        q.name.clone(),
                        60,
                        ApRData::A(Ipv4Addr::new(203, 0, 113, 9)),
                    ));
                } else {
                    resp.answers.push(ApRecord::new(
                        q.name.clone(),
                        60,
                        ApRData::Cname(tracker.clone()),
                    ));
                }
                let _ = sock.send_to(&resp.try_encode().unwrap(), from);
            }
        });
        addr
    }

    #[cfg(unix)]
    #[test]
    /** @brief 레인의 답에도 별칭 뒤를 들추는 검사가 걸리는지. */
    fn reactor_lane_applies_cname_uncloaking_to_resolved_answers() {
        use onetdns_runtime::ReactorDisposition;

        let authority = spawn_cloaking_authority();
        let (backend, cache) = lane_backend_and_cache();
        let recursor = Arc::new(
            onetdns_recurse::Recursor::new(vec![authority], std::time::Duration::from_millis(800))
                .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]),
        );
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::build_from_str(
                "||tracker.evil.example^",
                "",
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            backend,
            60,
        )
        .with_reactor_lane(recursor, cache, 32);

        let packet = Message::query(
            0x11,
            ApName::from_str("cdn.publisher.example").unwrap(),
            ApRt::A,
        )
        .try_encode()
        .unwrap();
        let mut w = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.reactor_submit(&packet, &ctx(), &mut w, std::time::Instant::now()),
            ReactorDisposition::Submitted,
            "질의 이름 자체는 Allow라 레인에 제출된다"
        );

        let mut out = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while out.is_empty() && std::time::Instant::now() < deadline {
            let mut fds = Vec::new();
            let mut map = Vec::new();
            server.reactor_collect(&mut fds, &mut map);

            if fds.is_empty() {
                std::thread::sleep(std::time::Duration::from_millis(2));
            } else {
                unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 100) };
                server.reactor_pump(&fds, 0, &map, std::time::Instant::now(), &mut out);
            }
            server.reactor_tick(std::time::Instant::now(), &mut out);
        }

        assert_eq!(out.len(), 1, "레인이 응답을 냈다");
        let resp = Message::parse(&out[0].1).expect("응답 파싱");
        assert_eq!(
            resp.header.rcode,
            ResponseCode::NXDomain.0,
            "클로킹 CNAME 대상이 차단이면 답이 아니라 차단 응답이 나가야 한다"
        );
    }

    #[test]
    /** @brief 밖에 있을 수 없는 주소를 표기와 무관하게 모두 거르는지. */
    fn rebind_address_classification_blocks_all_non_public_forms() {
        for address in [
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(198, 18, 0, 1),
            Ipv4Addr::new(224, 0, 0, 1),
        ] {
            assert!(is_private_rdata(&ApRData::A(address)), "{address}");
        }
        assert!(!is_private_rdata(&ApRData::A(Ipv4Addr::new(8, 8, 8, 8))));

        let mapped_loopback = "::ffff:127.0.0.1".parse().unwrap();
        let documentation = "2001:db8::1".parse().unwrap();
        let public = "2606:4700:4700::1111".parse().unwrap();
        assert!(is_private_rdata(&ApRData::Aaaa(mapped_loopback)));
        assert!(is_private_rdata(&ApRData::Aaaa(documentation)));
        assert!(!is_private_rdata(&ApRData::Aaaa(public)));

        let mapped_hint = ApRData::Https {
            priority: 1,
            target: ApName::root(),
            params: vec![(6, Box::from(mapped_loopback.octets()))].into_boxed_slice(),
        };
        assert!(is_private_rdata(&mapped_hint));
    }

    #[test]
    /** @brief 내부망 주소가 어느 구간에 실려도 빠지는지. */
    fn rebind_filter_removes_private_data_from_every_dns_section() {
        let owner = ApName::from_str("mail.example").unwrap();
        let mut response = Message::default();
        response.answers.push(ApRecord::new(
            owner.clone(),
            60,
            ApRData::Mx {
                preference: 10,
                exchange: owner.clone(),
            },
        ));
        response.authorities.push(ApRecord::new(
            owner.clone(),
            60,
            ApRData::A(Ipv4Addr::new(192, 0, 2, 1)),
        ));
        response.additionals.push(ApRecord::new(
            owner,
            60,
            ApRData::Aaaa("::ffff:127.0.0.1".parse().unwrap()),
        ));
        response
            .additionals
            .push(onetdns_proto::Edns::default().try_to_record().unwrap());

        assert!(strip_private_records(&mut response));
        assert_eq!(response.answers.len(), 1, "공개 MX 의미는 유지");
        assert!(response.authorities.is_empty());
        assert_eq!(response.additionals.len(), 1, "OPT는 유지");
        assert_eq!(response.additionals[0].rtype, ApRt::OPT);
    }

    /** @brief IPv4 답만 내는 테스트용 업스트림. */
    fn dns64_upstream() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                if let Ok(req) = Message::parse(&buf[..n]) {
                    let mut m = base_response(&req);
                    m.header.rcode = ResponseCode::NoError.0;
                    if let Some(q) = req.questions.first() {
                        if q.qtype == RecordType::A {
                            m.answers.push(ApRecord::new(
                                q.name.clone(),
                                60,
                                ApRData::A(Ipv4Addr::new(7, 7, 7, 7)),
                            ));
                        } else {
                            m.authorities.push(ApRecord::new(
                                q.name.clone(),
                                60,
                                ApRData::soa(onetdns_proto::Soa {
                                    mname: ApName::from_str("ns.v4only.test").unwrap(),
                                    rname: ApName::from_str("hostmaster.v4only.test").unwrap(),
                                    serial: 1,
                                    refresh: 3600,
                                    retry: 600,
                                    expire: 86400,
                                    minimum: 60,
                                }),
                            ));
                        }
                    }
                    let _ = sock.send_to(&m.try_encode().unwrap(), from);
                }
            }
        });
        addr
    }

    #[test]
    /** @brief IPv4 답으로 IPv6 답을 지어내는지. */
    fn dns64_synthesizes_aaaa() {
        let engine = onetdns_filter::build_from_str("", "", BlockResponse::NxDomain);
        let s = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(engine)),
            Arc::new(IpAcl::allow_all()),
            vec![],
            Arc::new(NativeBackend::Forward(Forwarder::new(
                vec![dns64_upstream()],
                Duration::from_secs(2),
            ))),
            60,
        );

        let mut prefix = [0u8; 16];
        prefix[0] = 0x00;
        prefix[1] = 0x64;
        prefix[2] = 0xff;
        prefix[3] = 0x9b;
        update_features(&s, |features| features.dns64_prefix = Some(prefix));
        let mut query = q("v4only.test");
        query.questions[0].qtype = RecordType::AAAA;
        let resp = s.handle(&query, &ctx()).unwrap();

        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0].rdata {
            ApRData::Aaaa(ip) => {
                let o = ip.octets();
                assert_eq!(&o[0..4], &[0x00, 0x64, 0xff, 0x9b]);
                assert_eq!(&o[12..16], &[7, 7, 7, 7]);
            }
            _ => panic!("합성 AAAA 기대"),
        }
    }

    #[test]
    /** @brief 서버 식별이 응답에 담기는지. */
    fn nsid_attached_to_response() {
        let s = server("");
        update_features(&s, |features| features.nsid = Some(b"onetdns".to_vec()));

        let mut req = q("allowed.test");
        let mut edns = Edns::default();
        edns.options.push((OPT_NSID, Vec::new()));
        req.additionals.push(edns.try_to_record().unwrap());
        let resp = s.handle(&req, &ctx()).unwrap();
        let opt = resp.opt().expect("OPT 부착");
        let edns = Edns::from_record(opt).unwrap();
        assert!(edns
            .options
            .iter()
            .any(|(c, v)| *c == OPT_NSID && v == b"onetdns"));
    }

    #[test]
    /** @brief 점 없는 이름과 내부망 역조회 판정. */
    fn domain_needed_and_bogus_priv_predicates() {
        assert!(is_single_label(&ApName::from_str("wpad").unwrap()));
        assert!(!is_single_label(&ApName::from_str("foo.bar").unwrap()));

        assert!(is_private_reverse(
            &ApName::from_str("1.0.168.192.in-addr.arpa").unwrap()
        ));
        assert!(is_private_reverse(
            &ApName::from_str("5.10.in-addr.arpa").unwrap()
        ));
        assert!(is_private_reverse(
            &ApName::from_str("20.172.in-addr.arpa").unwrap()
        ));
        assert!(!is_private_reverse(
            &ApName::from_str("8.8.8.8.in-addr.arpa").unwrap()
        ));
        assert!(!is_private_reverse(
            &ApName::from_str("40.172.in-addr.arpa").unwrap()
        ));
        assert!(is_private_reverse(
            &ApName::from_str("d.f.ip6.arpa").unwrap()
        ));
        assert!(!is_private_reverse(
            &ApName::from_str("1.0.0.2.ip6.arpa").unwrap()
        ));
    }

    #[test]
    /** @brief 밖에 새 나가면 안 되는 이름을 막는지. */
    fn empty_zone_predicate_and_block() {
        assert!(is_empty_zone(&ApName::from_str("home.arpa").unwrap()));
        assert!(is_empty_zone(&ApName::from_str("foo.home.arpa").unwrap()));
        assert!(is_empty_zone(
            &ApName::from_str("1.2.0.192.in-addr.arpa").unwrap()
        ));
        assert!(is_empty_zone(
            &ApName::from_str("5.10.in-addr.arpa").unwrap()
        ));
        assert!(!is_empty_zone(&ApName::from_str("example.com").unwrap()));
        assert!(!is_empty_zone(
            &ApName::from_str("8.8.8.8.in-addr.arpa").unwrap()
        ));

        let s = server_local_only(false, false, true);
        let resp = s.handle(&q("nas.home.arpa"), &ctx()).unwrap();
        assert_eq!(
            resp.header.rcode,
            ResponseCode::NXDomain.0,
            "home.arpa는 업스트림 미전달 NXDOMAIN"
        );
        assert_eq!(negative_soa_ttl(&resp), 60);
    }

    #[test]
    /**
     * @brief 밖에 못 묻게 한 이름이라도 로컬이 답할 수 있으면 그 답이 먼저 나가는지.
     * @details 자기 설정으로 만든 home.arpa 영역을 자기 empty_zones 설정이 덮으면 안 된다.
     */
    fn local_answers_win_over_the_local_only_cut() {
        let local: Arc<dyn Resolver> = Arc::new(StaticAnswer {
            name: ApName::from_str("nas.home.arpa").unwrap(),
        });
        let names = Arc::new(crate::layers::LocalOnlyNames::new(true, true, true));
        let ttl = Arc::new(std::sync::atomic::AtomicU32::new(60));
        let base: Arc<dyn Resolver> = Arc::new(NativeBackend::Forward(Forwarder::new(
            vec![mock_upstream()],
            Duration::from_secs(2),
        )));
        let cut: Arc<dyn Resolver> = Arc::new(crate::layers::LocalOnlyLayer::new(base, names, ttl));
        let engine = onetdns_filter::build_from_str("", "", BlockResponse::NxDomain);
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(engine)),
            Arc::new(IpAcl::allow_all()),
            vec![],
            Arc::new(StaticFirst { local, inner: cut }),
            60,
        );

        let answered = server.handle(&q("nas.home.arpa"), &ctx()).unwrap();
        assert_eq!(
            answered.header.rcode,
            ResponseCode::NoError.0,
            "로컬 권한 영역이 있는 이름은 로컬 답이 나가야 합니다"
        );
        assert_eq!(answered.answers.len(), 1);

        let cut_off = server.handle(&q("other.home.arpa"), &ctx()).unwrap();
        assert_eq!(
            cut_off.header.rcode,
            ResponseCode::NXDomain.0,
            "로컬이 답하지 못하면 업스트림으로 새지 않고 NXDOMAIN이어야 합니다"
        );
    }

    #[test]
    /** @brief 업데이트 정책 규칙이 허용과 거절을 제대로 구분하는지. */
    fn update_policy_grant_deny_matching() {
        let rules = vec![
            UpdateRule::new(false, "*", "locked.example", vec![]).unwrap(),
            UpdateRule::new(true, "dhcp-key", "*.dyn.example", vec![1, 28]).unwrap(),
        ];

        let identity = ApName::from_str("dhcp-key").unwrap();
        let upper_identity = ApName::from_str("DHCP-KEY").unwrap();
        let other_identity = ApName::from_str("other").unwrap();
        let locked = ApName::from_str("locked.example").unwrap();
        let dynamic = ApName::from_str("host.dyn.example").unwrap();
        let dynamic_apex = ApName::from_str("dyn.example").unwrap();
        let elsewhere = ApName::from_str("elsewhere.example").unwrap();

        assert!(!update_granted(&rules, Some(&identity), &locked, 1));

        assert!(update_granted(&rules, Some(&identity), &dynamic, 1));
        assert!(update_granted(&rules, Some(&upper_identity), &dynamic, 28));
        assert!(
            !update_granted(&rules, Some(&identity), &dynamic_apex, 1),
            "*.dyn.example은 영역 정점 자체에 권한을 주면 안 됨"
        );

        assert!(!update_granted(&rules, Some(&identity), &dynamic, 16));

        assert!(!update_granted(&rules, Some(&other_identity), &dynamic, 1));

        assert!(!update_granted(&rules, Some(&identity), &elsewhere, 1));
    }

    #[test]
    /** @brief 없앤 범위 표기를 거부하는지. 남겨 두면 뜻이 다른 규칙이 조용히 통과한다. */
    fn update_policy_rejects_removed_subtree_alias() {
        assert!(UpdateRule::new(true, "*", ".dyn.example", vec![1]).is_none());
    }

    #[test]
    /** @brief 규칙 이름의 원래 바이트가 바뀌지 않는지. */
    fn update_policy_preserves_raw_name_octets() {
        let rules = vec![UpdateRule::new(true, "*", "�", vec![1]).unwrap()];
        let configured = ApName::from_str("�").unwrap();
        let raw = ApName::from_labels(vec![vec![0xff]]).unwrap();

        assert!(update_granted(&rules, None, &configured, 1));
        assert!(!update_granted(&rules, None, &raw, 1));
    }

    #[test]
    /** @brief 예외 이름의 원래 바이트가 바뀌지 않는지. */
    fn rebind_allow_suffix_preserves_raw_name_octets() {
        let configured = ApName::from_str("�").unwrap();
        let child = ApName::from_str("host.�").unwrap();
        let raw = ApName::from_labels(vec![b"host".to_vec(), vec![0xff]]).unwrap();

        assert!(name_ends_with(&child, &configured));
        assert!(!name_ends_with(&raw, &configured));
    }

    #[test]
    /** @brief 올바르지 않은 문자를 고쳐서 통과시키지 않는지. 고치면 다른 이름이 규칙에 걸린다. */
    fn text_policy_name_rejects_invalid_utf8_without_repair() {
        let configured = ApName::from_str("�.Example").unwrap();
        let raw = ApName::from_labels(vec![vec![0xff], b"Example".to_vec()]).unwrap();

        assert_eq!(
            normalized_text_name(&configured).as_deref(),
            Some("�.example")
        );
        assert_eq!(normalized_text_name(&raw), None);
    }

    #[test]
    /** @brief 검증 실패가 세어지는지. */
    fn dnssec_bogus_counter_accumulates() {
        let name = onetdns_proto::Name::from_str("dnssec-failed.example").unwrap();
        let before = DNSSEC_BOGUS_TOTAL.load(Ordering::Relaxed);
        note_dnssec_bogus(&name);
        note_dnssec_bogus(&name);
        assert_eq!(
            DNSSEC_BOGUS_TOTAL.load(Ordering::Relaxed),
            before + 2,
            "bogus 발생마다 누적"
        );
    }

    #[test]
    /** @brief 점 없는 이름을 밖에 묻지 않는지. */
    fn domain_needed_blocks_dotless_forward() {
        let s = server_local_only(true, false, false);
        let resp = s.handle(&q("wpad"), &ctx()).unwrap();
        assert_eq!(
            resp.header.rcode,
            ResponseCode::NXDomain.0,
            "점 없는 이름은 NXDOMAIN(업스트림 미전달)"
        );
        assert_eq!(negative_soa_ttl(&resp), 60);
    }

    #[test]
    /** @brief 지나치게 큰 질의를 버리는지. */
    fn harden_large_queries_drops_oversized() {
        let s = server("");
        update_features(&s, |features| features.harden_large_queries = true);

        let oversized_wire = vec![0u8; MAX_LARGE_QUERY_BYTES + 1];
        let mut oversized = ctx();
        oversized.raw = Some(&oversized_wire);
        assert!(
            s.handle(&q("example.com"), &oversized).is_none(),
            "한도 초과 질의는 응답 없이 폐기"
        );

        let normal_wire = vec![0u8; MAX_LARGE_QUERY_BYTES];
        let mut normal = ctx();
        normal.raw = Some(&normal_wire);
        assert!(
            s.handle(&q("example.com"), &normal).is_some(),
            "한도 이하 질의는 정상 처리"
        );
    }
}
