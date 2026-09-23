/*!
 * @brief 주소·클라이언트 ID 기반 접근 제어 목록.
 */

use std::net::IpAddr;

use onetdns_core::{AccessControl, AclDecision, ClientInfo, IpNet};

/**
 * @brief CIDR과 클라이언트 ID로 판정하는 ACL.
 *
 * @invariant 거부가 항상 이긴다. 어떤 순서로 넣든 거부 목록에 걸린 요청은 허용 목록에도
 *            있든 없든 거부된다. 이 성질이 없으면 규칙을 추가하는 것만으로 기존 차단이
 *            뚫릴 수 있다.
 */
pub struct IpAcl {
    /** @brief 허용할 대역들. */
    allow: Vec<IpNet>,
    /** @brief 막을 대역들. 허용보다 먼저 본다. */
    deny: Vec<IpNet>,

    /** @brief 허용할 클라이언트 식별자들. */
    allow_ids: Vec<String>,
    /** @brief 막을 클라이언트 식별자들. */
    deny_ids: Vec<String>,
    /** @brief 허용 목록이 비었을 때 다 받을지. */
    default_allow: bool,
}

impl IpAcl {
    /**
     * @brief 주소 규칙만 가진 ACL을 만든다.
     * @param default_allow 어느 목록에도 걸리지 않은 요청의 처리. Personal 모드는 false,
     *                      Public 모드는 true다.
     */
    pub fn new(allow: Vec<IpNet>, deny: Vec<IpNet>, default_allow: bool) -> Self {
        Self {
            allow,
            deny,
            allow_ids: vec![],
            deny_ids: vec![],
            default_allow,
        }
    }

    /**
     * @brief 클라이언트 ID 규칙을 덧붙인다.
     * @details ID는 암호화 전송에서만 나온다. DoH 경로 접미사, DNSCrypt 이름 등. 평문
     *          Do53에는 ID가 없으므로 주소 규칙만 적용된다.
     */
    pub fn with_ids(mut self, allow_ids: Vec<String>, deny_ids: Vec<String>) -> Self {
        self.allow_ids = allow_ids;
        self.deny_ids = deny_ids;
        self
    }

    /** @brief 규칙이 없는 전면 허용 ACL. Public 모드의 기본 상태다. */
    pub fn allow_all() -> Self {
        Self::new(vec![], vec![], true)
    }

    /** @brief 주소가 목록 중 하나에 속하는지. */
    fn contained(nets: &[IpNet], ip: IpAddr) -> bool {
        nets.iter().any(|n| n.contains(&ip))
    }
}

impl AccessControl for IpAcl {
    /**
     * @brief 판정한다. 거부 → 허용 → 기본값 순서다.
     * @note 거부 검사를 먼저, 그것도 전부 끝낸 뒤에 허용을 본다. 순서를 섞으면 넓은 허용
     *       규칙이 좁은 거부 규칙을 가려 버린다.
     */
    fn check(&self, client: &ClientInfo) -> AclDecision {
        let ip = client.source_ip;
        let id = client.client_id.as_deref();

        if Self::contained(&self.deny, ip) {
            return AclDecision::Deny;
        }
        if let Some(id) = id {
            if self.deny_ids.iter().any(|x| x == id) {
                return AclDecision::Deny;
            }
        }

        if Self::contained(&self.allow, ip) {
            return AclDecision::Allow;
        }
        if let Some(id) = id {
            if self.allow_ids.iter().any(|x| x == id) {
                return AclDecision::Allow;
            }
        }
        if self.default_allow {
            AclDecision::Allow
        } else {
            AclDecision::Deny
        }
    }

    /**
     * @brief 어떤 요청도 막지 않는 ACL인지.
     * @details 허용 목록은 봐도 상관없다. 기본이 허용이면 거기 걸리지 않아도 통과하기
     *          때문이다. 거부 목록이 비어 있는지가 유일한 조건이며, 이걸 잘못 판정하면
     *          wire 고속 경로가 ACL 재검사를 건너뛰어 차단이 우회된다.
     */
    fn is_trivially_allow(&self) -> bool {
        self.default_allow && self.deny.is_empty() && self.deny_ids.is_empty()
    }
}

#[cfg(test)]
/** @brief 거부가 허용을 이기는지, 그리고 아무것도 막지 않는 설정의 판정. */
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
    /** @brief 허용 목록이 있으면 그 밖을 막는지. */
    fn deny_unlisted_when_closed() {
        let acl = IpAcl::new(vec!["192.168.0.0/16".parse().unwrap()], vec![], false);
        assert_eq!(acl.check(&client("192.168.1.5")), AclDecision::Allow);
        assert_eq!(acl.check(&client("8.8.8.8")), AclDecision::Deny);
    }

    #[test]
    /** @brief 거부가 허용을 이기는지. */
    fn deny_takes_precedence() {
        let acl = IpAcl::new(
            vec!["10.0.0.0/8".parse().unwrap()],
            vec!["10.6.6.0/24".parse().unwrap()],
            true,
        );
        assert_eq!(acl.check(&client("10.1.2.3")), AclDecision::Allow);
        assert_eq!(acl.check(&client("10.6.6.9")), AclDecision::Deny);
    }

    #[test]
    /** @brief 허용 목록이 없으면 다 받는지. */
    fn default_allow_when_open() {
        let acl = IpAcl::allow_all();
        assert!(acl.is_trivially_allow());
        assert_eq!(acl.check(&client("203.0.113.1")), AclDecision::Allow);
    }

    #[test]
    /** @brief 정말 아무것도 막지 않을 때만 그렇다고 답하는지. 빠른 경로가 이 판정을 믿는다. */
    fn only_unconditional_acl_reports_trivial_allow() {
        assert!(!IpAcl::new(vec![], vec![], false).is_trivially_allow());
        assert!(
            IpAcl::new(vec!["192.0.2.0/24".parse().unwrap()], vec![], true,).is_trivially_allow()
        );
        assert!(
            !IpAcl::new(vec![], vec!["192.0.2.0/24".parse().unwrap()], true,).is_trivially_allow()
        );
    }

    /** @brief 식별자가 붙은 테스트용 클라이언트. */
    fn client_id(ip: &str, id: &str) -> ClientInfo {
        ClientInfo {
            source_ip: ip.parse().unwrap(),
            client_id: Some(id.to_string()),
            transport: Transport::DoT,
            authenticated: true,
        }
    }

    #[test]
    /** @brief 식별자 기준 허용과 거부. */
    fn clientid_allow_and_deny() {
        let acl =
            IpAcl::new(vec![], vec![], false).with_ids(vec!["vip".into()], vec!["banned".into()]);
        assert_eq!(acl.check(&client_id("8.8.8.8", "vip")), AclDecision::Allow);
        assert_eq!(acl.check(&client_id("8.8.8.8", "other")), AclDecision::Deny);

        let acl2 = IpAcl::new(vec![], vec![], true).with_ids(vec![], vec!["banned".into()]);
        assert_eq!(
            acl2.check(&client_id("8.8.8.8", "banned")),
            AclDecision::Deny
        );
    }
}
