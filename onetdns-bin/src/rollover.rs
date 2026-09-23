/*!
 * @brief 키 롤오버 단계 관리.
 *
 * @details 새 키를 바로 쓰지 않는다. 먼저 공표해 검증기들이 보게 하고, 그다음 서명을
 *          옮기고, 마지막에 이전 키를 뺀다. 각 단계 사이에 충분히 기다린다.
 * @warning 단계를 건너뛰면 그 사이 응답이 검증 실패한다. 캐시에 남은 이전 키를 쓰는
 *          검증기가 새 서명을 확인하지 못하기 때문이다.
 */

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/** @brief 롤오버 진행 단계. */
pub enum Phase {
    /** @brief 교체 중이 아니다. */
    Stable,
    /** @brief 새 키를 알리고 퍼지기를 기다린다. */
    Publish,
    /** @brief 새 키로 서명하기 시작한다. */
    Activate,
}

impl Phase {
    /** @brief 상태 파일에 적을 이름. */
    fn as_str(self) -> &'static str {
        match self {
            Phase::Stable => "stable",
            Phase::Publish => "publish",
            Phase::Activate => "activate",
        }
    }
    /** @brief 상태 파일의 이름을 단계로. */
    fn from_str(s: &str) -> Option<Phase> {
        match s {
            "stable" => Some(Phase::Stable),
            "publish" => Some(Phase::Publish),
            "activate" => Some(Phase::Activate),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
/** @brief 각 단계에서 기다릴 시간. */
pub struct RollTiming {
    /** @brief 교체를 시작할 간격. */
    pub interval: u64,

    /** @brief 새 키를 알린 뒤 기다릴 시간. 짧으면 검증이 끊긴다. */
    pub publish_wait: u64,

    /** @brief 새 키로 바꾼 뒤 이전 키를 지우기까지 기다릴 시간. */
    pub activate_wait: u64,
}

impl RollTiming {
    /**
     * @brief 전체 주기에서 단계별 대기 시간을 나눈다.
     * @note 0이면 롤오버를 하지 않는다. 대기 시간에 하한이 있어, 주기를 아무리 짧게 잡아도
     *       검증기가 새 키를 볼 틈은 남는다.
     */
    pub fn from_interval(interval: u64) -> Self {
        RollTiming {
            interval,
            publish_wait: (interval / 24).max(1),
            activate_wait: (interval / 12).max(1),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/** @brief 지금 단계와 그 단계에 들어간 시각. */
pub struct RollState {
    /** @brief 지금 어느 단계인지. */
    pub phase: Phase,
    /** @brief 이 단계에 들어온 시각. */
    pub since: u64,
}

impl RollState {
    /** @brief 롤오버 중이 아닌 상태. */
    pub fn stable(now: u64) -> Self {
        RollState {
            phase: Phase::Stable,
            since: now,
        }
    }

    /** @brief 상태를 파일에 적을 형태로. */
    pub fn serialize(&self) -> String {
        format!("phase {}\nsince {}\n", self.phase.as_str(), self.since)
    }

    /** @brief 상태 파일을 읽는다. 형식이 어긋나면 없다. */
    pub fn parse(s: &str) -> Option<RollState> {
        let mut lines = s.lines();
        let phase = Phase::from_str(lines.next()?.strip_prefix("phase ")?)?;
        let since_text = lines.next()?.strip_prefix("since ")?;
        if since_text.is_empty() || !since_text.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let since = since_text.parse::<u64>().ok()?;
        if lines.next().is_some() {
            return None;
        }
        Some(RollState { phase, since })
    }
}

/**
 * @brief 대기 시간이 지났으면 다음 단계로 넘어간다.
 * @return 아직 기다릴 때가 남았으면 없다. 호출자는 다음 주기에 다시 묻는다.
 */
pub fn advance(state: RollState, now: u64, t: RollTiming) -> Option<RollState> {
    if t.interval == 0 {
        return None;
    }
    let elapsed = now.saturating_sub(state.since);
    let due = match state.phase {
        Phase::Stable => t.interval,
        Phase::Publish => t.publish_wait,
        Phase::Activate => t.activate_wait,
    };
    if elapsed < due {
        return None;
    }
    let next = match state.phase {
        Phase::Stable => Phase::Publish,
        Phase::Publish => Phase::Activate,
        Phase::Activate => Phase::Stable,
    };
    Some(RollState {
        phase: next,
        since: now,
    })
}

/** @brief 다음 키 파일 경로. */
pub fn next_path(active: &Path) -> PathBuf {
    with_ext(active, "next")
}
/** @brief 이전 키 파일 경로. 이전 키를 아직 공표해야 할 때 쓴다. */
pub fn prev_path(active: &Path) -> PathBuf {
    with_ext(active, "prev")
}
/** @brief 상태 파일 경로. */
pub fn state_path(active: &Path) -> PathBuf {
    with_ext(active, "roll")
}

/** @brief 경로에 확장자를 붙인다. */
fn with_ext(p: &Path, ext: &str) -> PathBuf {
    let mut s = p.as_os_str().to_os_string();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

#[cfg(test)]
/** @brief 단계가 순서대로 나아가고 대기 시간이 지켜지는지. */
mod tests {
    use super::*;

    #[test]
    /** @brief 상태가 파일 왕복에서 보존되는지. */
    fn state_roundtrips() {
        let s = RollState {
            phase: Phase::Activate,
            since: 1_700_000_000,
        };
        let parsed = RollState::parse(&s.serialize()).unwrap();
        assert_eq!(parsed, s);
        assert!(RollState::parse("garbage").is_none());
        assert!(RollState::parse("phase stable\nsince 1\nextra value\n").is_none());
        assert!(RollState::parse("phase stable\n").is_none());
    }

    #[test]
    /** @brief 주기가 0이면 롤오버하지 않는지. */
    fn disabled_when_interval_zero() {
        let t = RollTiming::from_interval(0);
        assert!(advance(RollState::stable(0), 1_000_000, t).is_none());
    }

    #[test]
    /** @brief 단계가 건너뛰지 않고 순서대로 도는지. */
    fn full_cycle_advances_in_order() {
        let t = RollTiming {
            interval: 1000,
            publish_wait: 100,
            activate_wait: 200,
        };
        let mut st = RollState::stable(0);

        assert!(advance(st, 999, t).is_none());

        st = advance(st, 1000, t).unwrap();
        assert_eq!(st.phase, Phase::Publish);
        assert_eq!(st.since, 1000);

        assert!(advance(st, 1099, t).is_none());

        st = advance(st, 1100, t).unwrap();
        assert_eq!(st.phase, Phase::Activate);

        assert!(advance(st, 1299, t).is_none());
        st = advance(st, 1300, t).unwrap();
        assert_eq!(st.phase, Phase::Stable);
    }

    #[test]
    /** @brief 키 파일 경로들이 서로 겹치지 않는지. */
    fn path_slots() {
        let p = Path::new("/etc/onetdns/example.com.zone.key");
        assert_eq!(
            next_path(p),
            Path::new("/etc/onetdns/example.com.zone.key.next")
        );
        assert_eq!(
            prev_path(p),
            Path::new("/etc/onetdns/example.com.zone.key.prev")
        );
        assert_eq!(
            state_path(p),
            Path::new("/etc/onetdns/example.com.zone.key.roll")
        );
    }

    #[test]
    /** @brief 주기를 짧게 잡아도 대기 시간에 하한이 남는지. */
    fn from_interval_waits_are_bounded() {
        let t = RollTiming::from_interval(30 * 86_400);
        assert!(t.publish_wait >= 1 && t.publish_wait < t.interval);
        assert!(t.activate_wait >= 1 && t.activate_wait < t.interval);
        assert!(t.activate_wait > t.publish_wait);
    }
}
