/*!
 * @brief 네이티브 정책 규칙: 클라이언트·이름·타입·시간대 조건.
 */

use std::net::IpAddr;

use crate::{Action, PolicyInput};

/**
 * @brief 요일과 하루 중 구간으로 정의한 시간 구간.
 * @details 시각은 지역 시각 기준이다. start_min > end_min이면 자정을 넘는 창으로 해석한다.
 */
#[derive(Debug, Clone, Copy)]
pub struct TimeWindow {
    /** @brief 요일 비트마스크(비트 0이 일요일). 0이면 모든 요일이다. */
    pub days: u8,
    /** @brief 시작 시각. 자정부터 흐른 분. */
    pub start_min: u16,
    /** @brief 끝 시각. 자정부터 흐른 분. */
    pub end_min: u16,
}

impl TimeWindow {
    /**
     * @brief 이 시각이 구간 안인지.
     * @details 자정을 넘는 구간에서는 앞부분이 오늘 요일, 뒷부분이 전날 요일에 속한다.
     *          이걸 구분하지 않으면 "금요일 22시~2시" 같은 구간이 토요일 새벽에 어긋난다.
     * @param minute_of_week 일요일 0시부터 흐른 분. 지역 시각 기준이다.
     */
    fn contains(&self, minute_of_week: u32) -> bool {
        let weekday = ((minute_of_week / 1_440) % 7) as u8;
        let minute = (minute_of_week % 1_440) as u16;
        if self.start_min < self.end_min {
            (self.days == 0 || (self.days & (1 << weekday)) != 0)
                && minute >= self.start_min
                && minute < self.end_min
        } else {
            let previous_weekday = (weekday + 6) % 7;
            (minute >= self.start_min && (self.days == 0 || (self.days & (1 << weekday)) != 0))
                || (minute < self.end_min
                    && (self.days == 0 || (self.days & (1 << previous_weekday)) != 0))
        }
    }
}

/** @brief 규칙이 쓰는 CIDR. 접두사가 없으면 호스트 경로다. */
#[derive(Debug, Clone, Copy)]
struct Cidr {
    /** @brief 대역의 시작 주소. */
    base: IpAddr,
    /** @brief 대역 길이. */
    prefix: u8,
}

impl Cidr {
    /** @brief CIDR 문자열을 해석한다. 계열 최대 길이를 넘는 접두사는 거부한다. */
    fn parse(s: &str) -> Option<Cidr> {
        let (ip_s, pfx) = match s.split_once('/') {
            Some((a, b)) => (a, b.parse::<u8>().ok()?),
            None => (s, u8::MAX),
        };
        let base: IpAddr = ip_s.trim().parse().ok()?;
        let max = if base.is_ipv4() { 32 } else { 128 };
        let prefix = if pfx == u8::MAX { max } else { pfx };
        if prefix > max {
            return None;
        }
        Some(Cidr { base, prefix })
    }

    /** @brief 주소가 이 대역에 속하는지. 계열이 다르면 언제나 거짓이다. */
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.base, ip) {
            (IpAddr::V4(b), IpAddr::V4(x)) => mask_match(&b.octets(), &x.octets(), self.prefix),
            (IpAddr::V6(b), IpAddr::V6(x)) => mask_match(&b.octets(), &x.octets(), self.prefix),
            _ => false,
        }
    }
}

/** @brief 앞의 prefix비트가 같은지. 온전한 바이트를 먼저 보고 남은 비트를 마스크로 비교한다. */
fn mask_match(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full = (prefix / 8) as usize;
    if a[..full] != b[..full] {
        return false;
    }
    let rem = prefix % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    (a[full] & mask) == (b[full] & mask)
}

/**
 * @brief 이름이 접미사에 속하는지.
 * @warning 라벨 경계에서만 맞춘다. 단순 ends_with를 쓰면 evil-example.com이
 *          example.com 규칙에 걸려 의도하지 않은 대상까지 적용된다.
 */
fn suffix_match(qname: &str, suffix: &str) -> bool {
    let s = suffix.trim_matches('.');
    if s.is_empty() {
        return true;
    }
    qname == s
        || (qname.len() > s.len()
            && qname.ends_with(s)
            && qname.as_bytes()[qname.len() - s.len() - 1] == b'.')
}

/**
 * @brief 규칙 하나. 조건은 모두 만족해야 하고, 한 조건 안의 여러 값은 하나만 맞으면 된다.
 * @details 비어 있는 조건은 "무엇이든"으로 본다. 모든 조건을 만족해야 판정이 적용된다.
 */
#[derive(Debug, Clone)]
pub struct Rule {
    /** @brief 이 클라이언트들에만 건다. */
    clients: Vec<Cidr>,
    /** @brief 이 이름들에만 건다. */
    suffixes: Vec<String>,
    /** @brief 이 질의 종류에만 건다. */
    qtypes: Vec<u16>,
    /** @brief 이 시간대에만 건다. */
    window: Option<TimeWindow>,
    /** @brief 맞았을 때 할 일. */
    action: Action,
}

impl Rule {
    /** @brief 조건이 하나도 없는(=모든 질의에 맞는) 규칙을 만든다. */
    pub fn new(action: Action) -> Self {
        Rule {
            clients: vec![],
            suffixes: vec![],
            qtypes: vec![],
            window: None,
            action,
        }
    }
    /**
     * @brief 클라이언트 대역 조건을 건다.
     * @note 해석할 수 없는 항목은 조용히 버린다. 규칙 하나의 오타가 서버 시작을 막지
     *       않게 하려는 것이며, 설정 검증이 별도로 형식을 확인한다.
     */
    pub fn with_clients(mut self, cidrs: &[String]) -> Self {
        self.clients = cidrs.iter().filter_map(|c| Cidr::parse(c)).collect();
        self
    }
    /** @brief 이름 접미사 조건을 건다. 소문자로 정규화해 보관한다. */
    pub fn with_suffixes(mut self, suffixes: &[String]) -> Self {
        self.suffixes = suffixes
            .iter()
            .map(|s| s.trim().trim_matches('.').to_ascii_lowercase())
            .collect();
        self
    }
    /** @brief 레코드 타입 조건을 건다. */
    pub fn with_qtypes(mut self, qtypes: &[u16]) -> Self {
        self.qtypes = qtypes.to_vec();
        self
    }
    /** @brief 시간대 조건을 건다. */
    pub fn with_window(mut self, w: TimeWindow) -> Self {
        self.window = Some(w);
        self
    }

    /** @brief 이 질의가 모든 조건을 만족하는지. */
    fn matches(&self, input: &PolicyInput) -> bool {
        if !self.clients.is_empty() && !self.clients.iter().any(|c| c.contains(input.client)) {
            return false;
        }
        if !self.suffixes.is_empty() && !self.suffixes.iter().any(|s| suffix_match(input.qname, s))
        {
            return false;
        }
        if !self.qtypes.is_empty() && !self.qtypes.contains(&input.qtype) {
            return false;
        }
        if let Some(w) = &self.window {
            if !w.contains(input.local_minute_of_week) {
                return false;
            }
        }
        true
    }
}

/** @brief 규칙 목록. 설정에 적힌 순서가 곧 우선순위다. */
#[derive(Default)]
pub struct RuleEngine {
    /** @brief 순서대로 보는 규칙들. 먼저 맞은 것이 이긴다. */
    rules: Vec<Rule>,
}

impl RuleEngine {
    /** @brief 규칙 목록으로 엔진을 만든다. */
    pub fn new(rules: Vec<Rule>) -> Self {
        RuleEngine { rules }
    }
    /** @brief 규칙이 하나도 없는지. */
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
    /**
     * @brief 처음으로 맞는 규칙의 판정을 돌려준다.
     * @return 아무 규칙에도 맞지 않으면 Continue.
     */
    pub fn evaluate(&self, input: &PolicyInput) -> Action {
        for r in &self.rules {
            if r.matches(input) {
                return r.action;
            }
        }
        Action::Continue
    }
}

#[cfg(test)]
/** @brief 규칙이 맞는 것만 걸고, 앞선 규칙이 이기는지. */
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /** @brief 테스트용 입력. t는 일요일 0시부터 흐른 분이다. */
    fn input<'a>(client: &str, qname: &'a str, qtype: u16, t: u32) -> PolicyInput<'a> {
        PolicyInput {
            client: client.parse().unwrap(),
            qname,
            qtype,
            unix_time: 0,
            local_minute_of_week: t,
            transport: crate::QueryTransport::Do53Udp,
            client_id: None,
            authenticated: false,
        }
    }

    #[test]
    /** @brief 대역 판정. */
    fn cidr_match_v4() {
        let c = Cidr::parse("192.168.1.0/24").unwrap();
        assert!(c.contains("192.168.1.50".parse().unwrap()));
        assert!(!c.contains("192.168.2.50".parse().unwrap()));
        let host = Cidr::parse("10.0.0.5").unwrap();
        assert!(host.contains("10.0.0.5".parse().unwrap()));
        assert!(!host.contains("10.0.0.6".parse().unwrap()));
    }

    #[test]
    /** @brief 접미사가 조각 경계에서만 맞는지. 아니면 다른 이름이 걸린다. */
    fn suffix_is_label_bounded() {
        assert!(suffix_match("ads.example.com", "example.com"));
        assert!(suffix_match("example.com", "example.com"));
        assert!(!suffix_match("notexample.com", "example.com"));
        assert!(!suffix_match("example.com.evil.com", "example.com"));
    }

    #[test]
    /** @brief 클라이언트와 이름 조건이 함께 걸리는지. */
    fn rule_combines_client_and_suffix() {
        let r = Rule::new(Action::Block)
            .with_clients(&["192.168.1.0/24".into()])
            .with_suffixes(&["social.example".into()]);
        let eng = RuleEngine::new(vec![r]);

        assert_eq!(
            eng.evaluate(&input("192.168.1.10", "x.social.example", 1, 0)),
            Action::Block
        );

        assert_eq!(
            eng.evaluate(&input("10.0.0.1", "x.social.example", 1, 0)),
            Action::Continue
        );

        assert_eq!(
            eng.evaluate(&input("192.168.1.10", "work.example", 1, 0)),
            Action::Continue
        );
    }

    #[test]
    /** @brief 먼저 맞은 규칙이 이기는지. */
    fn first_match_wins() {
        let allow = Rule::new(Action::Allow).with_suffixes(&["good.example".into()]);
        let block = Rule::new(Action::Block).with_suffixes(&["example".into()]);
        let eng = RuleEngine::new(vec![allow, block]);

        assert_eq!(
            eng.evaluate(&input("1.1.1.1", "good.example", 1, 0)),
            Action::Allow
        );

        assert_eq!(
            eng.evaluate(&input("1.1.1.1", "bad.example", 1, 0)),
            Action::Block
        );
    }

    #[test]
    /** @brief 질의 종류 조건. */
    fn qtype_filter() {
        let r = Rule::new(Action::Refuse).with_qtypes(&[28]);
        let eng = RuleEngine::new(vec![r]);
        assert_eq!(
            eng.evaluate(&input("1.1.1.1", "a.com", 28, 0)),
            Action::Refuse
        );
        assert_eq!(
            eng.evaluate(&input("1.1.1.1", "a.com", 1, 0)),
            Action::Continue
        );
    }

    #[test]
    /** @brief 요일과 시각 조건. */
    fn time_window_weekday_and_minute() {
        let wed_midnight = 3 * 1_440u32;

        let w = TimeWindow {
            days: 1 << 3,
            start_min: 0,
            end_min: 60,
        };
        assert!(w.contains(wed_midnight));

        assert!(!w.contains(wed_midnight + 120));

        assert!(!w.contains(wed_midnight + 1_440));
        let r = Rule::new(Action::Block).with_window(w);
        let eng = RuleEngine::new(vec![r]);
        assert_eq!(
            eng.evaluate(&input("1.1.1.1", "x", 1, wed_midnight)),
            Action::Block
        );
        assert_eq!(
            eng.evaluate(&input("1.1.1.1", "x", 1, wed_midnight + 120)),
            Action::Continue
        );
    }

    #[test]
    /** @brief 자정을 넘는 구간이 다음 날 새벽에도 전날 요일로 걸리는지. */
    fn time_window_across_midnight_uses_previous_weekday() {
        let w = TimeWindow {
            days: 1 << 5,
            start_min: 22 * 60,
            end_min: 2 * 60,
        };

        assert!(w.contains(5 * 1_440 + 23 * 60));

        assert!(w.contains(6 * 1_440 + 60));

        assert!(!w.contains(5 * 1_440 + 60));

        assert!(!w.contains(6 * 1_440 + 23 * 60));
    }

    #[test]
    /** @brief 재작성이 답할 주소를 포함하는지. */
    fn rewrite_action_carries_ip() {
        let r = Rule::new(Action::Rewrite(Ipv4Addr::new(10, 0, 0, 1)))
            .with_suffixes(&["router.lan".into()]);
        let eng = RuleEngine::new(vec![r]);
        assert_eq!(
            eng.evaluate(&input("1.1.1.1", "router.lan", 1, 0)),
            Action::Rewrite(Ipv4Addr::new(10, 0, 0, 1))
        );
    }
}
