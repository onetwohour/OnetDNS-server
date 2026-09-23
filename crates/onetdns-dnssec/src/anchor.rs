/*!
 * @brief RFC 5011 신뢰 앵커 자동 갱신.
 *
 * @details 앵커는 검증의 출발점이라 아무 근거 없이 바꿀 수 없다. 새 키는 이미 신뢰하는
 *          키가 서명한 DNSKEY RRset에서 관찰되어야 하고, 그 상태로 hold-down 기간을
 *          견뎌야 비로소 신뢰된다. 폐기는 그 키 자신의 서명이 있어야만 인정한다.
 * @warning 이 파일의 판정이 느슨해지면 공격자가 자기 키를 앵커로 심을 수 있다. 갱신을
 *          받아들이지 못하는 쪽은 서비스가 멈추지만, 잘못 받아들이는 쪽은 전부 뚫린다.
 */

use onetdns_proto::{Name, Record, RecordType};

use crate::{validate_rrset_in_zone, Dnskey, Ds, Rrsig};

/** @brief 새 키를 신뢰하기까지 관찰을 이어가야 하는 기간. RFC 5011이 권하는 30일이다. */
pub const DEFAULT_HOLD_DOWN_SECS: u64 = 30 * 86_400;

/** @brief 관리 중인 앵커 키의 상태. */
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyState {
    /** @brief 신뢰한다. 이 키만 active_ds에 실려 검증의 기준이 된다. */
    Valid,

    /** @brief 관찰은 됐으나 아직 hold-down 중이다. since는 관찰이 끊기면 다시 시작한다. */
    AddPend { since: u64 },

    /** @brief 자기 서명으로 폐기가 확인됐다. 다시 Valid로 돌아가지 않는다. */
    Revoked,
}

/** @brief 앵커 키 하나와 그 상태, 마지막 관찰 시각. */
#[derive(Debug, Clone)]
pub struct ManagedKey {
    /** @brief 키 자체. */
    pub key: Dnskey,
    /** @brief 현재 상태. */
    pub state: KeyState,
    /** @brief 이 키를 마지막으로 본 시각. 관찰 공백 판정에 쓴다. */
    pub last_seen: u64,
}

/** @brief 한 zone의 앵커 집합과 갱신 상태 기계. */
#[derive(Debug, Clone)]
pub struct AnchorManager {
    /** @brief 이 앵커들이 속한 zone. 보통 루트다. */
    pub zone: Name,
    /** @brief 관리 중인 키 전부. Valid가 아닌 것도 상태 추적을 위해 남는다. */
    pub keys: Vec<ManagedKey>,
    /** @brief hold-down 기간. 테스트에서만 줄여 쓴다. */
    pub hold_down_secs: u64,
}

impl AnchorManager {
    /**
     * @brief 설정에서 받은 키들을 그대로 Valid로 놓고 시작한다.
     * @note 최초 키는 운영자가 대역 밖에서 확인해 넣은 것이므로 hold-down을 거치지 않는다.
     *       이후 추가되는 키만 관찰과 대기를 거친다.
     */
    pub fn bootstrap(zone: Name, initial: Vec<Dnskey>, now: u64) -> AnchorManager {
        let keys = initial
            .into_iter()
            .map(|key| ManagedKey {
                key,
                state: KeyState::Valid,
                last_seen: now,
            })
            .collect();
        AnchorManager {
            zone,
            keys,
            hold_down_secs: DEFAULT_HOLD_DOWN_SECS,
        }
    }

    /** @brief 현재 신뢰하는 키들. 갱신 검증의 기준이자 유일한 판단 근거다. */
    fn valid_keys(&self) -> Vec<Dnskey> {
        self.keys
            .iter()
            .filter(|k| k.state == KeyState::Valid)
            .map(|k| k.key.clone())
            .collect()
    }

    /**
     * @brief 검증기에 넘길 DS 형태의 앵커.
     * @details Valid 상태만 내보낸다. AddPend는 아직 신뢰 대상이 아니고 Revoked는 폐기됐다.
     */
    pub fn active_ds(&self) -> Vec<Ds> {
        self.keys
            .iter()
            .filter(|k| k.state == KeyState::Valid)
            .filter_map(|k| Ds::from_dnskey(&k.key, &self.zone, 2))
            .collect()
    }

    /**
     * @brief 관찰한 DNSKEY RRset으로 앵커 상태를 갱신한다.
     *
     * @details 순서가 곧 안전성이다. 먼저 현재 Valid 키로 RRset 서명을 검증하고, 실패하면
     *          아무것도 건드리지 않는다. 그다음 폐기 표시된 키를 처리하는데, 이때는 그 키
     *          자신이 서명한 것만 인정한다. 다른 키의 서명으로 폐기를 허용하면 침해된 키
     *          하나가 나머지를 전부 지울 수 있다. 마지막으로 새 키를 AddPend로 넣고,
     *          hold-down을 채운 것을 Valid로 올린다.
     * @note 관찰 공백은 hold-down을 처음부터 다시 시작시킨다. 기준은 RRset의 최소 TTL
     *       두 배다. 그보다 오래 못 봤다면 연속 관찰이 끊긴 것이므로, 공격자가 잠깐
     *       시작한 키가 시간만 흘러 승격되는 것을 막는다.
     * @param dnskeys 관찰한 DNSKEY 레코드들.
     * @param rrsigs  그 RRset을 덮는 서명들.
     * @param now     현재 시각(Unix 초).
     * @return 상태가 바뀌어 저장이 필요하면 참.
     * @invariant Valid 키가 하나도 없으면 갱신을 거부한다. 검증 기준이 없기 때문이다.
     */
    pub fn update(&mut self, dnskeys: &[Record], rrsigs: &[Rrsig], now: u64) -> bool {
        let valid = self.valid_keys();
        if valid.is_empty() {
            return false;
        }

        if validate_rrset_in_zone(dnskeys, rrsigs, &valid, &self.zone, now as u32).is_err() {
            return false;
        }
        let observed: Vec<Dnskey> = dnskeys.iter().filter_map(Dnskey::from_record).collect();
        let observation_gap = dnskeys
            .iter()
            .map(|record| u64::from(record.ttl.max(1)))
            .min()
            .unwrap_or(3600)
            .saturating_mul(2)
            .max(60);
        let mut changed = false;

        for obs in &observed {
            let tag = obs.key_tag();
            if obs.is_revoked() {
                let self_signed = rrsigs.iter().any(|sig| {
                    sig.signer.eq_ignore_case(&self.zone)
                        && crate::rrsig_time_valid_accepting(sig, now as u32, false)
                        && crate::verify_rrsig(dnskeys, sig, obs).is_ok()
                });
                if !self_signed {
                    continue;
                }
                let mut base = obs.clone();
                base.flags &= !0x0080;
                let base_tag = base.key_tag();
                if let Some(k) = self
                    .keys
                    .iter_mut()
                    .find(|k| k.key.key_tag() == base_tag && k.key.public_key == obs.public_key)
                {
                    if k.state != KeyState::Revoked {
                        k.state = KeyState::Revoked;
                        k.last_seen = now;
                        changed = true;
                    }
                }
                continue;
            }
            match self
                .keys
                .iter_mut()
                .find(|k| k.key.key_tag() == tag && k.key.public_key == obs.public_key)
            {
                Some(k) => {
                    if let KeyState::AddPend { since } = k.state {
                        if now < k.last_seen || now.saturating_sub(k.last_seen) > observation_gap {
                            k.state = KeyState::AddPend { since: now };
                            changed = true;
                        } else {
                            k.state = KeyState::AddPend { since };
                        }
                    }
                    k.last_seen = now;
                }
                None => {
                    self.keys.push(ManagedKey {
                        key: obs.clone(),
                        state: KeyState::AddPend { since: now },
                        last_seen: now,
                    });
                    changed = true;
                }
            }
        }

        for k in &mut self.keys {
            if let KeyState::AddPend { since } = k.state {
                if k.last_seen == now && now.saturating_sub(since) >= self.hold_down_secs {
                    k.state = KeyState::Valid;
                    changed = true;
                }
            }
        }

        let present: Vec<u16> = observed.iter().map(|k| k.key_tag()).collect();
        let before = self.keys.len();
        self.keys.retain(|k| {
            let seen = present.contains(&k.key.key_tag()) || k.last_seen == now;
            match k.state {
                KeyState::Valid => true,
                _ => seen,
            }
        });
        if self.keys.len() != before {
            changed = true;
        }
        changed
    }

    /**
     * @brief 앵커 상태를 텍스트로 직렬화한다.
     * @details 재시작해도 hold-down 진행 상황이 남아야 한다. 상태를 잃으면 진행 중이던
     *          대기가 처음부터 다시 시작돼 롤오버를 놓친다.
     * @note 루트 zone은 빈 문자열이 아니라 점 하나로 적는다. 역직렬화가 필드 수로 형식을
     *       검사하기 때문에 공백이 들어가면 줄이 깨진다.
     */
    pub fn serialize(&self) -> String {
        let zone = if self.zone.is_root() {
            ".".to_string()
        } else {
            self.zone.to_ascii_lower()
        };
        let mut out = format!(
            "ONETDNS-ANCHOR\nzone {zone}\nhold_down {}\n",
            self.hold_down_secs
        );
        for k in &self.keys {
            let st = match k.state {
                KeyState::Valid => "valid 0".to_string(),
                KeyState::AddPend { since } => format!("addpend {since}"),
                KeyState::Revoked => "revoked 0".to_string(),
            };
            out.push_str(&format!(
                "key {} {} {} {} {}\n",
                st,
                k.key.flags,
                k.key.algorithm,
                k.last_seen,
                crate::tsig::b64_encode(&k.key.public_key)
            ));
        }
        out
    }

    /**
     * @brief 직렬화된 앵커 상태를 되읽는다.
     *
     * @details 형식을 엄격히 본다. 헤더, 줄 순서, 필드 수, 상태 이름과 since의 정합성이
     *          하나라도 어긋나면 전체를 거부한다. 같은 키가 두 번 나오는 것도 거부한다.
     *          중복이 있으면 어느 상태가 진짜인지 정할 수 없다.
     * @warning 이 파일은 디스크에 있으므로 신뢰 입력이 아니다. 절반만 읽고 나머지를 기본값으로
     *          채우면 조작된 파일이 임의 키를 Valid로 만들 수 있다.
     * @return 한 군데라도 어긋나면 None. 그 경우 호출자는 설정의 초기 앵커로 되돌아간다.
     */
    pub fn deserialize(text: &str) -> Option<AnchorManager> {
        let mut lines = text.lines();
        if lines.next()? != "ONETDNS-ANCHOR" {
            return None;
        }
        let zone_line: Vec<_> = lines.next()?.split_whitespace().collect();
        if zone_line.len() != 2 || zone_line[0] != "zone" {
            return None;
        }
        let zone = Name::from_str(zone_line[1]).ok()?;
        let hold_line: Vec<_> = lines.next()?.split_whitespace().collect();
        if hold_line.len() != 2 || hold_line[0] != "hold_down" {
            return None;
        }
        let hold_down_secs = hold_line[1].parse::<u64>().ok()?;
        let mut keys = Vec::new();
        for line in lines {
            let t: Vec<&str> = line.split_whitespace().collect();
            if t.len() != 7 || t[0] != "key" {
                return None;
            }
            let since = t[2].parse::<u64>().ok()?;
            let state = match t[1] {
                "valid" if since == 0 => KeyState::Valid,
                "revoked" if since == 0 => KeyState::Revoked,
                "addpend" => KeyState::AddPend { since },
                _ => return None,
            };
            let flags: u16 = t[3].parse().ok()?;
            let algorithm: u8 = t[4].parse().ok()?;
            let last_seen: u64 = t[5].parse().ok()?;
            let public_key = crate::tsig::b64_decode(t[6])?;
            if public_key.is_empty() {
                return None;
            }
            let key = Dnskey {
                flags,
                protocol: 3,
                algorithm,
                public_key,
            };
            if keys.iter().any(|existing: &ManagedKey| {
                existing.key.key_tag() == key.key_tag() && existing.key.public_key == key.public_key
            }) {
                return None;
            }
            keys.push(ManagedKey {
                key,
                state,
                last_seen,
            });
        }
        if keys.is_empty() {
            return None;
        }
        Some(AnchorManager {
            zone,
            keys,
            hold_down_secs,
        })
    }
}

/**
 * @brief 응답에서 zone apex의 DNSKEY RRset과 그것을 덮는 서명만 골라낸다.
 * @details 소유자 이름과 type_covered를 모두 확인한다. 다른 이름이나 다른 타입을 덮는
 *          서명이 섞이면 갱신 판정이 엉뚱한 데이터를 근거로 삼게 된다.
 */
pub fn extract_dnskey_rrset(records: &[Record], zone: &Name) -> (Vec<Record>, Vec<Rrsig>) {
    let keys: Vec<Record> = records
        .iter()
        .filter(|r| r.rtype == RecordType::DNSKEY && r.name.eq_ignore_case(zone))
        .cloned()
        .collect();
    let sigs: Vec<Rrsig> = records
        .iter()
        .filter(|r| r.rtype == RecordType(46) && r.name.eq_ignore_case(zone))
        .filter_map(Rrsig::from_record)
        .filter(|s| s.type_covered == RecordType::DNSKEY.0)
        .collect();
    (keys, sigs)
}

/** @brief 앵커 갱신 규칙: hold-down, 자기서명 폐기, 미검증 갱신 거부, 상태 보존. */
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::ZoneSigner;
    use onetdns_proto::{DnsClass, RData};

    /** @brief 이름 문자열을 Name으로. */
    fn n(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    /** @brief 주어진 키들로 DNSKEY RRset을 만들고 signer로 서명해 붙인다. */
    fn dnskey_rrset(keys: &[Dnskey], signer: &ZoneSigner, zone: &Name, now: u64) -> Vec<Record> {
        let mut recs: Vec<Record> = keys
            .iter()
            .map(|k| Record {
                name: zone.clone(),
                rtype: RecordType::DNSKEY,
                class: DnsClass::IN,
                ttl: 3600,
                rdata: RData::Unknown(48, k.rdata_bytes()),
            })
            .collect();
        let sig = signer.sign_rrset(&recs, now).unwrap();
        recs.push(sig);
        recs
    }

    /** @brief 새 키가 hold-down을 채우기 전에는 앵커로 쓰이지 않음을 고정한다. */
    #[test]
    fn new_key_held_down_then_promoted() {
        let zone = n("example.com");
        let now = 1_700_000_000u64;
        let k1 = ZoneSigner::generate(zone.clone(), [1u8; 32]);
        let k2 = ZoneSigner::generate(zone.clone(), [2u8; 32]);

        let mut mgr = AnchorManager::bootstrap(zone.clone(), vec![k1.dnskey()], now);
        mgr.hold_down_secs = 1000;
        assert_eq!(mgr.active_ds().len(), 1);

        let rr = dnskey_rrset(&[k1.dnskey(), k2.dnskey()], &k1, &zone, now);
        let (keys, sigs) = extract_dnskey_rrset(&rr, &zone);
        assert!(mgr.update(&keys, &sigs, now), "k2 새로 관찰 → 변경");
        assert_eq!(mgr.active_ds().len(), 1, "hold-down 전 k2 미신뢰");

        let later = now + 1001;
        let rr2 = dnskey_rrset(&[k1.dnskey(), k2.dnskey()], &k1, &zone, later);
        let (keys2, sigs2) = extract_dnskey_rrset(&rr2, &zone);
        mgr.update(&keys2, &sigs2, later);
        assert_eq!(mgr.active_ds().len(), 2, "hold-down 후 k2 신뢰");

        let rr3 = dnskey_rrset(&[k2.dnskey()], &k2, &zone, later);
        let (keys3, sigs3) = extract_dnskey_rrset(&rr3, &zone);
        assert!(
            validate_rrset_in_zone(&keys3, &sigs3, &mgr.valid_keys(), &mgr.zone, later as u32)
                .is_ok()
        );
    }

    /** @brief 자기 서명이 붙은 폐기는 그 키를 즉시 앵커에서 뺀다. */
    #[test]
    fn revoked_key_removed() {
        let zone = n("example.com");
        let now = 1_700_000_000u64;
        let k1 = ZoneSigner::generate(zone.clone(), [3u8; 32]);
        let k2 = ZoneSigner::generate(zone.clone(), [4u8; 32]);

        let mut mgr = AnchorManager::bootstrap(zone.clone(), vec![k1.dnskey(), k2.dnskey()], now);
        assert_eq!(mgr.active_ds().len(), 2);

        let mut revoked = k1.dnskey();
        revoked.flags |= 0x0080;
        let rr = dnskey_rrset(&[revoked, k2.dnskey()], &k1, &zone, now);
        let (keys, sigs) = extract_dnskey_rrset(&rr, &zone);
        assert!(mgr.update(&keys, &sigs, now), "k1 revoke → 변경");
        let ds = mgr.active_ds();
        assert_eq!(ds.len(), 1, "k1 제거, k2만 신뢰");
        assert_eq!(ds[0].key_tag, k2.dnskey().key_tag());
    }

    /**
     * @brief 침해된 키 하나가 다른 앵커를 지우지 못하게 막는다.
     * @details 폐기 표시가 붙었더라도 서명이 그 키 자신의 것이 아니면 무시해야 한다.
     */
    #[test]
    fn revoke_requires_self_signature_not_other_key() {
        let zone = n("example.com");
        let now = 1_700_000_000u64;
        let k1 = ZoneSigner::generate(zone.clone(), [11u8; 32]);
        let k2 = ZoneSigner::generate(zone.clone(), [12u8; 32]);
        let mut mgr = AnchorManager::bootstrap(zone.clone(), vec![k1.dnskey(), k2.dnskey()], now);
        assert_eq!(mgr.active_ds().len(), 2);

        let mut revoked_k2 = k2.dnskey();
        revoked_k2.flags |= 0x0080;
        let rr = dnskey_rrset(&[k1.dnskey(), revoked_k2], &k1, &zone, now);
        let (keys, sigs) = extract_dnskey_rrset(&rr, &zone);
        mgr.update(&keys, &sigs, now);
        assert_eq!(mgr.active_ds().len(), 2, "타 키 서명으로는 폐기 불가");
    }

    /** @brief 현재 앵커로 검증되지 않는 RRset은 공격자 키를 심지 못한다. */
    #[test]
    fn unsigned_update_ignored() {
        let zone = n("example.com");
        let now = 1_700_000_000u64;
        let k1 = ZoneSigner::generate(zone.clone(), [5u8; 32]);
        let attacker = ZoneSigner::generate(zone.clone(), [6u8; 32]);
        let mut mgr = AnchorManager::bootstrap(zone.clone(), vec![k1.dnskey()], now);

        let rr = dnskey_rrset(&[k1.dnskey(), attacker.dnskey()], &attacker, &zone, now);
        let (keys, sigs) = extract_dnskey_rrset(&rr, &zone);
        assert!(
            !mgr.update(&keys, &sigs, now),
            "검증에 실패했습니다 → 변경 없음"
        );
        assert_eq!(mgr.active_ds().len(), 1, "공격자 키 미추가");
    }

    /**
     * @brief 관찰이 끊겼다 돌아온 키는 대기 시간을 처음부터 다시 채워야 한다.
     * @details 시간 경과만으로 승격되면 잠깐 띄웠다 사라진 키가 나중에 신뢰된다.
     */
    #[test]
    fn pending_key_gap_restarts_hold_down() {
        let zone = n("example.com");
        let now = 1_700_000_000u64;
        let k1 = ZoneSigner::generate(zone.clone(), [9u8; 32]);
        let k2 = ZoneSigner::generate(zone.clone(), [10u8; 32]);
        let mut mgr = AnchorManager::bootstrap(zone.clone(), vec![k1.dnskey()], now);
        mgr.hold_down_secs = 1000;

        let rr = dnskey_rrset(&[k1.dnskey(), k2.dnskey()], &k1, &zone, now);
        let (keys, sigs) = extract_dnskey_rrset(&rr, &zone);
        mgr.update(&keys, &sigs, now);

        let later = now + 10_000;
        let rr2 = dnskey_rrset(&[k1.dnskey(), k2.dnskey()], &k1, &zone, later);
        let (keys2, sigs2) = extract_dnskey_rrset(&rr2, &zone);
        mgr.update(&keys2, &sigs2, later);
        assert_eq!(mgr.active_ds().len(), 1, "관찰 공백 뒤 즉시 승격 금지");
    }

    /** @brief 상태가 왕복해도 보존되고, 형식이 깨진 입력은 전체를 거부된다. */
    #[test]
    fn serialize_roundtrip() {
        let zone = n("example.com");
        let now = 1_700_000_000u64;
        let k1 = ZoneSigner::generate(zone.clone(), [7u8; 32]);
        let mut mgr = AnchorManager::bootstrap(zone.clone(), vec![k1.dnskey()], now);
        mgr.keys.push(ManagedKey {
            key: ZoneSigner::generate(zone.clone(), [8u8; 32]).dnskey(),
            state: KeyState::AddPend { since: now },
            last_seen: now,
        });
        let text = mgr.serialize();
        let restored = AnchorManager::deserialize(&text).expect("역직렬화");
        assert_eq!(restored.keys.len(), 2);
        assert_eq!(restored.active_ds().len(), 1, "Valid만 활성");
        assert_eq!(restored.hold_down_secs, mgr.hold_down_secs);
        assert!(AnchorManager::deserialize(text.trim_start_matches("ONETDNS-ANCHOR\n")).is_none());
        assert!(AnchorManager::deserialize(&text.replacen("hold_down", "removed", 1)).is_none());
        assert!(AnchorManager::deserialize(&(text.clone() + "extra value\n")).is_none());
    }

    /**
     * @brief 루트 앵커가 왕복에서 살아남는지. 실제로 쓰이는 유일한 zone이다.
     * @details 루트 이름을 빈 문자열로 적으면 줄의 필드 수가 어긋나 상태를 전부 잃는다.
     */
    #[test]
    fn root_zone_state_survives_serialize_roundtrip() {
        let root = Name::root();
        let key = ZoneSigner::generate(root.clone(), [9u8; 32]);
        let mgr = AnchorManager::bootstrap(root.clone(), vec![key.dnskey()], 1_700_000_000);
        let text = mgr.serialize();
        assert!(text.contains("zone ."), "루트는 '.'로 직렬화");
        let restored = AnchorManager::deserialize(&text).expect("루트 상태 역직렬화");
        assert!(restored.zone.is_root());
        assert_eq!(restored.active_ds().len(), 1);
    }
}
