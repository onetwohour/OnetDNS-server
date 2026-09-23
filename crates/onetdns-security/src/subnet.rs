use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use onetdns_core::{ClientInfo, IpNet, RateDecision, RateLimiter};

use crate::bucket::TokenBucket;

/**
 * @brief 서브넷 단위 속도 제한기.
 *
 * @details 주소별 제한은 IPv6에서 사실상 무력하다. 공격자가 /64 하나만 있어도 사실상 무한한
 *          출발지를 만들 수 있다. 접두사로 바꿔서 예산을 공유시키면 그 회피가 막힌다.
 */
pub struct SubnetRateLimiter {
    /** @brief 대역별 몫을 나눠 주는 것. */
    inner: TokenBucket<IpAddr>,
    /** @brief IPv4를 묶을 대역 길이. */
    v4_prefix: u8,
    /** @brief IPv6를 묶을 대역 길이. */
    v6_prefix: u8,
    /** @brief 제한을 받지 않는 대역들. */
    allow: Vec<IpNet>,
}

impl SubnetRateLimiter {
    /**
     * @brief 제한기를 만든다.
     * @param v4_prefix IPv4 집계 접두사. 계열 최대치로 잘린다.
     * @param v6_prefix IPv6 집계 접두사. 통상 /56이나 /64를 쓴다.
     */
    pub fn new(per_second: u32, burst: u32, v4_prefix: u8, v6_prefix: u8) -> Option<Self> {
        Some(Self {
            inner: TokenBucket::new(per_second, burst)?,
            v4_prefix: v4_prefix.min(32),
            v6_prefix: v6_prefix.min(128),
            allow: vec![],
        })
    }

    /** @brief 제한을 면제할 대역을 지정한다. */
    pub fn with_allow(mut self, allow: Vec<IpNet>) -> Self {
        self.allow = allow;
        self
    }

    /**
     * @brief 주소를 접두사로 바꿔 예산 키로 만든다.
     * @note 접두사 0은 따로 처리한다. 폭과 같은 시프트는 정의되지 않는다.
     */
    fn key(&self, ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(v4) => {
                let bits = u32::from(v4);
                let mask = if self.v4_prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.v4_prefix)
                };
                IpAddr::V4(Ipv4Addr::from(bits & mask))
            }
            IpAddr::V6(v6) => {
                let bits = u128::from(v6);
                let mask = if self.v6_prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.v6_prefix)
                };
                IpAddr::V6(Ipv6Addr::from(bits & mask))
            }
        }
    }
}

impl RateLimiter for SubnetRateLimiter {
    /**
     * @brief 면제 대역을 먼저 보고, 아니면 프리픽스로 줄인 키로 토큰을 소비한다.
     * @note 면제 판정은 줄이기 전 원래 주소로 한다. 줄인 뒤 보면 면제 대역과 그 이웃이
     *       같은 키로 뭉쳐 면제가 의도보다 넓게 적용된다.
     */
    fn check(&self, client: &ClientInfo) -> RateDecision {
        if self.allow.iter().any(|n| n.contains(&client.source_ip)) {
            return RateDecision::Permit;
        }
        if self.inner.check(&self.key(client.source_ip)) {
            RateDecision::Permit
        } else {
            RateDecision::Throttle
        }
    }
}

#[cfg(test)]
/** @brief 같은 대역이 몫을 나눠 쓰는지. */
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
    /** @brief 같은 대역의 주소들이 몫을 함께 쓰는지. 안 그러면 대역 하나로 얼마든지 퍼부을 수 있다. */
    fn same_subnet_shares_budget() {
        let rl = SubnetRateLimiter::new(1, 2, 24, 56).unwrap();

        assert_eq!(rl.check(&client("203.0.113.1")), RateDecision::Permit);
        assert_eq!(rl.check(&client("203.0.113.99")), RateDecision::Permit);
        assert_eq!(rl.check(&client("203.0.113.250")), RateDecision::Throttle);

        assert_eq!(rl.check(&client("198.51.100.1")), RateDecision::Permit);
    }
}
