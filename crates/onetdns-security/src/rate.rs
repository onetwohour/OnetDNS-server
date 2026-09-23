use std::net::IpAddr;

use onetdns_core::{ClientInfo, IpNet, RateDecision, RateLimiter};

use crate::bucket::TokenBucket;

/**
 * @brief 출발지 주소별 속도 제한기.
 * @details 주소 하나가 하나의 예산을 갖는다. NAT 뒤 다수 클라이언트에는 부적합하며, 그
 *          경우 서브넷 단위 제한기를 쓴다.
 */
pub struct KeyedRateLimiter {
    /** @brief 주소별 몫을 나눠 주는 것. */
    inner: TokenBucket<IpAddr>,

    /** @brief 제한을 받지 않는 대역들. */
    allow: Vec<IpNet>,
}

impl KeyedRateLimiter {
    /** @brief 제한기를 만든다. 속도가 0이면 None을 돌려주며, 제한을 걸지 않는다는 뜻이다. */
    pub fn new(per_second: u32, burst: u32) -> Option<Self> {
        Some(Self {
            inner: TokenBucket::new(per_second, burst)?,
            allow: vec![],
        })
    }

    /** @brief 제한을 면제할 대역을 지정한다. 내부 관측 시스템 같은 신뢰 출발지용이다. */
    pub fn with_allow(mut self, allow: Vec<IpNet>) -> Self {
        self.allow = allow;
        self
    }
}

impl RateLimiter for KeyedRateLimiter {
    /** @brief 면제 대역을 먼저 보고, 아니면 토큰을 소비한다. */
    fn check(&self, client: &ClientInfo) -> RateDecision {
        if self.allow.iter().any(|n| n.contains(&client.source_ip)) {
            return RateDecision::Permit;
        }
        if self.inner.check(&client.source_ip) {
            RateDecision::Permit
        } else {
            RateDecision::Throttle
        }
    }
}

#[cfg(test)]
/** @brief 몫이 떨어지면 막고, 예외 대역은 통과하는지. */
mod tests {
    use super::*;
    use onetdns_core::Transport;

    /** @brief 테스트용 클라이언트. */
    fn client(ip: &str) -> ClientInfo {
        ClientInfo {
            source_ip: ip.parse().unwrap(),
            client_id: None,
            transport: Transport::Do53Udp,
            authenticated: false,
        }
    }

    #[test]
    /** @brief 한꺼번에 쓰고 나면 막히는지. */
    fn throttles_after_burst() {
        let rl = KeyedRateLimiter::new(1, 2).unwrap();
        let c = client("198.51.100.7");
        assert_eq!(rl.check(&c), RateDecision::Permit);
        assert_eq!(rl.check(&c), RateDecision::Permit);

        assert_eq!(rl.check(&c), RateDecision::Throttle);

        assert_eq!(rl.check(&client("198.51.100.8")), RateDecision::Permit);
    }

    #[test]
    /** @brief 0으로 두면 제한이 꺼지는지. */
    fn disabled_when_zero() {
        assert!(KeyedRateLimiter::new(0, 0).is_none());
    }

    #[test]
    /** @brief 예외 대역이 제한을 받지 않는지. */
    fn allowlist_bypasses_limit() {
        let rl = KeyedRateLimiter::new(1, 1)
            .unwrap()
            .with_allow(vec!["10.0.0.0/8".parse().unwrap()]);
        let c = client("10.1.2.3");

        for _ in 0..5 {
            assert_eq!(rl.check(&c), RateDecision::Permit);
        }
    }
}
