/*!
 * @brief 인증서 폐기 확인.
 *
 * @details OCSP 응답과 폐기 목록 두 가지를 다룬다. 어느 쪽이든 발급자가 서명한 것이어야
 *          하고, 그 서명을 이쪽이 직접 검증한다.
 * @warning 응답에 다음 갱신 시각이 없으면 무한정 믿을 수 없다. 오래된 응답을 계속 쓰면
 *          이미 폐기된 인증서가 살아 있는 것으로 보인다.
 */

use crate::der::{self, bit_string_bytes, Der, Tlv};
use crate::x509::{parse_time, scheme_from_sig_algid, X509};
use crate::TlsError;

use sha1::{Digest, Sha1};

/** @brief 기본 OCSP 응답 종류. */
const OID_OCSP_BASIC: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
/** @brief SHA-1. OCSP 식별자 계산이 이 해시를 쓰도록 정해져 있다. */
const OID_SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
/** @brief 시계 차이를 감안해 봐 주는 폭. */
const OCSP_CLOCK_SKEW_SECS: i64 = 300;
/** @brief 다음 갱신 시각이 없는 응답을 믿어 줄 기간. 상한이 없으면 오래된 응답이 영원히 유효해진다. */
const OCSP_MAX_AGE_WITHOUT_NEXT_UPDATE_SECS: i64 = 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/** @brief 폐기 확인 결과. */
pub enum RevocationStatus {
    /** @brief 폐기되지 않았다. */
    Good,
    /** @brief 폐기됐다. */
    Revoked,
    /** @brief 알 수 없다. */
    Unknown,
}

/** @brief SHA-1. 규격이 정한 것이라 선택지가 없다. */
fn sha1(data: &[u8]) -> Vec<u8> {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().to_vec()
}

/** @brief DER 길이를 쓴다. */
fn der_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let mut b = Vec::new();
        let mut l = len;
        while l > 0 {
            b.push((l & 0xff) as u8);
            l >>= 8;
        }
        b.reverse();
        out.push(0x80 | b.len() as u8);
        out.extend_from_slice(&b);
    }
}

/** @brief 태그와 내용으로 DER 값을 만든다. */
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    der_len(content.len(), &mut v);
    v.extend_from_slice(content);
    v
}

/** @brief SEQUENCE DER 값을 만든다. */
fn seq(content: &[u8]) -> Vec<u8> {
    tlv(der::SEQUENCE, content)
}

/** @brief 이 인증서에 대한 OCSP 질의를 만든다. 발급자 이름과 키의 해시가 식별자가 된다. */
pub fn build_ocsp_request(leaf: &X509, issuer: &X509) -> Vec<u8> {
    let name_hash = sha1(&issuer.subject_raw);
    let key_hash = sha1(&issuer.public_key);

    let mut alg_inner = tlv(der::OID, OID_SHA1);
    alg_inner.extend_from_slice(&[0x05, 0x00]);
    let alg = seq(&alg_inner);

    let mut cert_id = alg;
    cert_id.extend(tlv(der::OCTET_STRING, &name_hash));
    cert_id.extend(tlv(der::OCTET_STRING, &key_hash));
    cert_id.extend(tlv(der::INTEGER, &leaf.serial));
    let cert_id = seq(&cert_id);

    let request = seq(&cert_id);
    let request_list = seq(&request);
    let tbs_request = seq(&request_list);
    seq(&tbs_request)
}

/**
 * @brief OCSP 응답을 검증하고 상태를 정한다.
 * @warning 서명자가 발급자이거나 발급자가 OCSP 서명 권한을 준 인증서여야 한다. 확인하지
 *          않으면 아무나 폐기 상태를 지어낼 수 있다.
 */
pub fn check_ocsp_response(
    der_bytes: &[u8],
    issuer: &X509,
    leaf_serial: &[u8],
    now: i64,
) -> Result<RevocationStatus, TlsError> {
    let mut top = Der::new(der_bytes);
    let body = top.expect(der::SEQUENCE)?;
    if !top.is_empty() {
        return Err(TlsError::BadCert);
    }
    let mut r = Der::new(body);

    let status = r.next()?;
    if status.tag != 0x0a || status.value != [0] {
        return Err(TlsError::BadCert);
    }

    let rb = r.next()?;
    if rb.tag != der::context(0) || !r.is_empty() {
        return Err(TlsError::BadCert);
    }
    let mut rbd = Der::new(rb.value);
    let inner = rbd.expect(der::SEQUENCE)?;
    if !rbd.is_empty() {
        return Err(TlsError::BadCert);
    }
    let mut ib = Der::new(inner);
    let resp_type = ib.expect(der::OID)?;
    if resp_type != OID_OCSP_BASIC {
        return Err(TlsError::BadCert);
    }
    let basic_der = ib.expect(der::OCTET_STRING)?;
    if !ib.is_empty() {
        return Err(TlsError::BadCert);
    }
    parse_basic_ocsp(basic_der, issuer, leaf_serial, now)
}

#[derive(Debug)]
/** @brief 응답자를 가리키는 방식. 이름이나 키 해시다. */
enum ResponderId {
    /** @brief 이름으로 가리킨다. */
    ByName(Vec<u8>),
    /** @brief 키 지문으로 가리킨다. */
    ByKey(Vec<u8>),
}

/** @brief 기본 OCSP 응답을 읽고 서명을 검증한다. */
fn parse_basic_ocsp(
    der_bytes: &[u8],
    issuer: &X509,
    leaf_serial: &[u8],
    now: i64,
) -> Result<RevocationStatus, TlsError> {
    let mut top = Der::new(der_bytes);
    let body = top.expect(der::SEQUENCE)?;
    if !top.is_empty() {
        return Err(TlsError::BadCert);
    }
    let mut b = Der::new(body);

    let (tbs_raw, tbs_tlv) = b.next_raw()?;
    if tbs_tlv.tag != der::SEQUENCE {
        return Err(TlsError::BadCert);
    }

    let sig_alg = b.expect(der::SEQUENCE)?;
    let scheme = scheme_from_sig_algid(sig_alg)?;
    if scheme == 0 {
        return Err(TlsError::BadCert);
    }
    let signature = bit_string_bytes(b.expect(der::BIT_STRING)?)?.to_vec();

    let mut responder_certs: Vec<X509> = Vec::new();
    if !b.is_empty() {
        let c = b.next()?;
        if c.tag != der::context(0) {
            return Err(TlsError::BadCert);
        }
        let mut cd = Der::new(c.value);
        let certs_seq = cd.expect(der::SEQUENCE)?;
        if !cd.is_empty() {
            return Err(TlsError::BadCert);
        }
        let mut cs = Der::new(certs_seq);
        while !cs.is_empty() {
            let (raw, t) = cs.next_raw()?;
            if t.tag != der::SEQUENCE {
                return Err(TlsError::BadCert);
            }
            responder_certs.push(X509::parse(raw)?);
        }
    }
    if !b.is_empty() {
        return Err(TlsError::BadCert);
    }

    let (responder_id, produced_at, status) =
        parse_response_data(tbs_tlv.value, issuer, leaf_serial, now)?;

    let issuer_signed = responder_id_matches(&responder_id, issuer)
        && issuer.allows_digital_signature()
        && issuer.verify_signature(scheme, tbs_raw, &signature).is_ok();
    let delegated_signed = responder_certs.iter().any(|responder| {
        responder.issuer_raw == issuer.subject_raw
            && responder.allows_ocsp_signing()
            && responder.allows_digital_signature()
            && responder.valid_at(now)
            && responder.verify_signed_by(issuer).is_ok()
            && responder_id_matches(&responder_id, responder)
            && responder
                .verify_signature(scheme, tbs_raw, &signature)
                .is_ok()
    });
    if !issuer_signed && !delegated_signed {
        return Err(TlsError::BadSignature);
    }

    if produced_at > now + OCSP_CLOCK_SKEW_SECS {
        return Ok(RevocationStatus::Unknown);
    }
    Ok(status)
}

/** @brief 응답 본문을 읽는다. */
fn parse_response_data(
    tbs: &[u8],
    issuer: &X509,
    leaf_serial: &[u8],
    now: i64,
) -> Result<(ResponderId, i64, RevocationStatus), TlsError> {
    let mut d = Der::new(tbs);
    let mut responder = d.next()?;

    if responder.tag == der::context(0) {
        let version = Der::new(responder.value).expect(der::INTEGER)?;
        if version.iter().any(|&byte| byte != 0) {
            return Err(TlsError::BadCert);
        }
        responder = d.next()?;
    }
    let responder_id = parse_responder_id(responder)?;

    let produced_at = parse_time(d.next()?)?;
    let responses = d.expect(der::SEQUENCE)?;

    if !d.is_empty() {
        let extensions = d.next()?;
        if extensions.tag != der::context(1) || !d.is_empty() {
            return Err(TlsError::BadCert);
        }
    }

    let mut rs = Der::new(responses);
    while !rs.is_empty() {
        let single = rs.expect(der::SEQUENCE)?;
        if let Some(status) = parse_single_response(single, issuer, leaf_serial, produced_at, now)?
        {
            return Ok((responder_id, produced_at, status));
        }
    }
    Ok((responder_id, produced_at, RevocationStatus::Unknown))
}

/** @brief 응답자 식별자를 읽는다. */
fn parse_responder_id(value: Tlv<'_>) -> Result<ResponderId, TlsError> {
    match value.tag {
        t if t == der::context(1) => {
            let mut name = Der::new(value.value);
            let (raw, tlv) = name.next_raw()?;
            if tlv.tag != der::SEQUENCE || !name.is_empty() {
                return Err(TlsError::BadCert);
            }
            Ok(ResponderId::ByName(raw.to_vec()))
        }

        0x82 => Ok(ResponderId::ByKey(value.value.to_vec())),
        t if t == der::context(2) => {
            let mut key = Der::new(value.value);
            let bytes = key.expect(der::OCTET_STRING)?;
            if !key.is_empty() {
                return Err(TlsError::BadCert);
            }
            Ok(ResponderId::ByKey(bytes.to_vec()))
        }
        _ => Err(TlsError::BadCert),
    }
}

/** @brief 이 식별자가 그 인증서를 가리키는지. */
fn responder_id_matches(id: &ResponderId, certificate: &X509) -> bool {
    match id {
        ResponderId::ByName(name) => name == &certificate.subject_raw,
        ResponderId::ByKey(key_hash) => {
            let expected = sha1(&certificate.public_key);
            key_hash.as_slice() == expected.as_slice()
        }
    }
}

/** @brief 인증서 하나에 대한 상태를 읽는다. 시각 구간도 여기서 본다. */
fn parse_single_response(
    single: &[u8],
    issuer: &X509,
    leaf_serial: &[u8],
    produced_at: i64,
    now: i64,
) -> Result<Option<RevocationStatus>, TlsError> {
    let mut s = Der::new(single);

    let cert_id = s.expect(der::SEQUENCE)?;
    let mut ci = Der::new(cert_id);
    let alg = ci.expect(der::SEQUENCE)?;
    if !ocsp_hash_algorithm_is_sha1(alg)? {
        return Err(TlsError::BadCert);
    }
    let name_hash = ci.expect(der::OCTET_STRING)?;
    let key_hash = ci.expect(der::OCTET_STRING)?;
    let serial = ci.expect(der::INTEGER)?;
    if !ci.is_empty() {
        return Err(TlsError::BadCert);
    }
    let expected_name_hash = sha1(&issuer.subject_raw);
    let expected_key_hash = sha1(&issuer.public_key);
    if name_hash != expected_name_hash.as_slice()
        || key_hash != expected_key_hash.as_slice()
        || normalize_positive_integer(serial) != normalize_positive_integer(leaf_serial)
    {
        return Ok(None);
    }

    let cs = s.next()?;
    let status = match cs.tag {
        0x80 if cs.value.is_empty() => RevocationStatus::Good,
        0xA1 => {
            let mut revoked = Der::new(cs.value);
            let revocation_time = parse_time(revoked.next()?)?;
            if !revoked.is_empty() {
                let reason = revoked.next()?;
                if reason.tag != der::context(0) || !revoked.is_empty() {
                    return Err(TlsError::BadCert);
                }
                let mut value = Der::new(reason.value);
                let code = value.next()?;
                if code.tag != 0x0a || code.value.len() != 1 || !value.is_empty() {
                    return Err(TlsError::BadCert);
                }
            }
            if revocation_time > now + OCSP_CLOCK_SKEW_SECS {
                RevocationStatus::Unknown
            } else {
                RevocationStatus::Revoked
            }
        }
        0x82 if cs.value.is_empty() => RevocationStatus::Unknown,
        _ => return Err(TlsError::BadCert),
    };

    let this = parse_time(s.next()?)?;
    let mut next: Option<i64> = None;
    let mut seen_extensions = false;
    while !s.is_empty() {
        let field = s.next()?;
        if field.tag == der::context(0) && next.is_none() && !seen_extensions {
            let mut inner = Der::new(field.value);
            next = Some(parse_time(inner.next()?)?);
            if !inner.is_empty() {
                return Err(TlsError::BadCert);
            }
        } else if field.tag == der::context(1) && !seen_extensions {
            seen_extensions = true;
        } else {
            return Err(TlsError::BadCert);
        }
    }

    if this > now + OCSP_CLOCK_SKEW_SECS
        || produced_at + OCSP_CLOCK_SKEW_SECS < this
        || next.is_some_and(|next_update| next_update < this)
    {
        return Ok(Some(RevocationStatus::Unknown));
    }

    if status == RevocationStatus::Revoked {
        return Ok(Some(RevocationStatus::Revoked));
    }

    match next {
        Some(next_update) if next_update < now - OCSP_CLOCK_SKEW_SECS => {
            Ok(Some(RevocationStatus::Unknown))
        }
        None if this < now - OCSP_MAX_AGE_WITHOUT_NEXT_UPDATE_SECS
            || produced_at < now - OCSP_MAX_AGE_WITHOUT_NEXT_UPDATE_SECS =>
        {
            Ok(Some(RevocationStatus::Unknown))
        }
        _ => Ok(Some(status)),
    }
}

/** @brief 식별자 해시가 SHA-1인지. 다른 해시는 이쪽이 만든 질의와 맞지 않는다. */
fn ocsp_hash_algorithm_is_sha1(algid: &[u8]) -> Result<bool, TlsError> {
    let mut alg = Der::new(algid);
    if alg.expect(der::OID)? != OID_SHA1 {
        return Ok(false);
    }
    if !alg.is_empty() {
        let null = alg.next()?;
        if null.tag != 0x05 || !null.value.is_empty() || !alg.is_empty() {
            return Err(TlsError::BadCert);
        }
    }
    Ok(true)
}

/** @brief 일련번호 비교를 위해 앞의 0을 걷어낸다. */
fn normalize_positive_integer(value: &[u8]) -> &[u8] {
    let mut offset = 0;
    while offset + 1 < value.len() && value[offset] == 0 {
        offset += 1;
    }
    &value[offset..]
}

/** @brief 검증을 마친 폐기 목록. */
pub struct Crl {
    /** @brief 폐기된 일련번호와 그 시각. */
    revoked: Vec<(Vec<u8>, i64)>,
    /** @brief 이 목록을 만든 시각. */
    pub this_update: i64,
    /** @brief 다음 목록이 나올 시각. */
    pub next_update: Option<i64>,
}

impl Crl {
    /** @brief 폐기 목록을 읽고 발급자 서명을 검증한다. */
    pub fn parse(der_bytes: &[u8], issuer: &X509) -> Result<Crl, TlsError> {
        let mut top = Der::new(der_bytes);
        let body = top.expect(der::SEQUENCE)?;
        if !top.is_empty() {
            return Err(TlsError::BadCert);
        }
        let mut c = Der::new(body);
        let (tbs_raw, tbs_tlv) = c.next_raw()?;
        if tbs_tlv.tag != der::SEQUENCE {
            return Err(TlsError::BadCert);
        }
        let sig_alg = c.expect(der::SEQUENCE)?;
        let scheme = scheme_from_sig_algid(sig_alg)?;
        if scheme == 0 {
            return Err(TlsError::BadCert);
        }
        let signature = bit_string_bytes(c.expect(der::BIT_STRING)?)?.to_vec();
        if !c.is_empty() {
            return Err(TlsError::BadCert);
        }
        issuer.verify_signature(scheme, tbs_raw, &signature)?;

        Self::parse_tbs(tbs_tlv.value, sig_alg, issuer)
    }

    /** @brief 서명 대상 부분을 읽는다. 바깥 알고리즘과 안쪽이 같아야 한다. */
    fn parse_tbs(tbs: &[u8], outer_sig_alg: &[u8], issuer: &X509) -> Result<Crl, TlsError> {
        let mut d = Der::new(tbs);
        let mut cur = d.next()?;

        if cur.tag == der::INTEGER {
            if cur.value != [1] {
                return Err(TlsError::BadCert);
            }
            cur = d.next()?;
        }

        if cur.tag != der::SEQUENCE || cur.value != outer_sig_alg {
            return Err(TlsError::BadCert);
        }

        let (crl_issuer_raw, crl_issuer) = d.next_raw()?;
        if crl_issuer.tag != der::SEQUENCE || crl_issuer_raw != issuer.subject_raw.as_slice() {
            return Err(TlsError::BadCert);
        }

        let this_update = parse_time(d.next()?)?;

        let mut next_update = None;
        let mut revoked = Vec::new();
        let mut seen_revoked = false;
        while !d.is_empty() {
            let field = d.next()?;
            match field.tag {
                0x17 | 0x18 if next_update.is_none() && !seen_revoked => {
                    next_update = Some(parse_time(field)?);
                }
                der::SEQUENCE if !seen_revoked => {
                    Self::collect_revoked(field.value, &mut revoked)?;
                    seen_revoked = true;
                }

                t if t == der::context(0) => return Err(TlsError::BadCert),
                _ => return Err(TlsError::BadCert),
            }
        }
        if next_update.is_some_and(|next| next < this_update) {
            return Err(TlsError::BadCert);
        }
        Ok(Crl {
            revoked,
            this_update,
            next_update,
        })
    }

    /** @brief 폐기된 일련번호들을 모은다. */
    fn collect_revoked(seq_of: &[u8], out: &mut Vec<(Vec<u8>, i64)>) -> Result<(), TlsError> {
        let mut entries = Der::new(seq_of);
        while !entries.is_empty() {
            let entry = entries.next()?;
            if entry.tag != der::SEQUENCE {
                return Err(TlsError::BadCert);
            }
            let mut fields = Der::new(entry.value);
            let serial = fields.expect(der::INTEGER)?.to_vec();
            let revoked_at = parse_time(fields.next()?)?;

            if !fields.is_empty() {
                return Err(TlsError::BadCert);
            }
            out.push((serial, revoked_at));
        }
        Ok(())
    }

    /** @brief 이 일련번호가 폐기됐는지. */
    pub fn is_revoked(&self, serial: &[u8]) -> bool {
        self.revoked
            .iter()
            .any(|(value, _)| value.as_slice() == serial)
    }

    /** @brief 이 시각 기준의 상태. 목록 자체가 오래됐으면 알 수 없음이다. */
    pub fn status(&self, serial: &[u8], now: i64) -> RevocationStatus {
        if let Some((_, revoked_at)) = self
            .revoked
            .iter()
            .find(|(value, _)| value.as_slice() == serial)
        {
            return if *revoked_at <= now + OCSP_CLOCK_SKEW_SECS {
                RevocationStatus::Revoked
            } else {
                RevocationStatus::Unknown
            };
        }

        if self.this_update > now + 300 {
            return RevocationStatus::Unknown;
        }
        match self.next_update {
            Some(nu) if nu < now - 300 => RevocationStatus::Unknown,

            None => RevocationStatus::Unknown,
            _ => RevocationStatus::Good,
        }
    }
}

#[cfg(test)]
/** @brief 서명 검증, 식별자 대조, 그리고 시각 구간 적용. */
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    /** @brief 테스트용 CA와 리프. */
    fn gen_ca_and_leaf() -> (X509, X509, SigningKey, Vec<u8>) {
        gen_ca_and_leaf_with_name("ca.test")
    }

    /** @brief 이름을 지정해 테스트용 CA와 리프를 만든다. */
    fn gen_ca_and_leaf_with_name(ca_name: &str) -> (X509, X509, SigningKey, Vec<u8>) {
        let mut p = rcgen::CertificateParams::new(vec![ca_name.into()]).unwrap();
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.distinguished_name
            .push(rcgen::DnType::CommonName, ca_name);
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_kp = rcgen::KeyPair::generate().unwrap();
        let ca = p.self_signed(&ca_kp).unwrap();
        let ca_der = ca.der().to_vec();
        let ca_x = X509::parse(&ca_der).unwrap();

        let leaf_p = rcgen::CertificateParams::new(vec!["leaf.test".into()]).unwrap();
        let leaf_kp = rcgen::KeyPair::generate().unwrap();
        let leaf = leaf_p.signed_by(&leaf_kp, &ca, &ca_kp).unwrap();
        let leaf_der = leaf.der().to_vec();
        let leaf_x = X509::parse(&leaf_der).unwrap();

        let pkcs8 = ca_kp.serialize_der();
        use p256::pkcs8::DecodePrivateKey;
        let sk = p256::SecretKey::from_pkcs8_der(&pkcs8).unwrap();
        let signing = SigningKey::from(sk);
        (ca_x, leaf_x, signing, leaf_der)
    }

    /** @brief ECDSA with SHA-256 알고리즘 식별자. */
    fn ecdsa_sha256_algid() -> Vec<u8> {
        seq(&tlv(
            der::OID,
            &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02],
        ))
    }

    /** @brief 서명 대상에 서명한다. */
    fn sign_tbs(signing: &SigningKey, tbs: &[u8]) -> Vec<u8> {
        let sig: Signature = signing.sign(tbs);
        let mut bits = vec![0x00];
        bits.extend_from_slice(sig.to_der().as_bytes());
        tlv(der::BIT_STRING, &bits)
    }

    #[test]
    /** @brief 질의에 일련번호가 담기는지. */
    fn ocsp_request_has_certid_with_serial() {
        let (ca, leaf, _sk, _) = gen_ca_and_leaf();
        let req = build_ocsp_request(&leaf, &ca);

        assert!(window_contains(&req, &leaf.serial));

        assert_eq!(req[0], der::SEQUENCE);
    }

    /** @brief 바이트열에 부분열이 있는지. */
    fn window_contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    /** @brief 테스트용 OCSP 응답을 만든다. */
    fn build_basic_ocsp(
        signing: &SigningKey,
        ca: &X509,
        leaf: &X509,
        status_tag: u8,
        now: i64,
    ) -> Vec<u8> {
        build_basic_ocsp_custom(
            signing,
            ca,
            leaf,
            status_tag,
            now,
            sha1(&ca.subject_raw),
            sha1(&ca.public_key),
            leaf.serial.clone(),
            now - 600,
            Some(now + 3600),
            ca.subject_raw.clone(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    /** @brief 필드를 지정해 테스트용 OCSP 응답을 만든다. */
    fn build_basic_ocsp_custom(
        signing: &SigningKey,
        _ca: &X509,
        _leaf: &X509,
        status_tag: u8,
        produced_at: i64,
        name_hash: Vec<u8>,
        key_hash: Vec<u8>,
        serial: Vec<u8>,
        this_update_at: i64,
        next_update_at: Option<i64>,
        responder_name: Vec<u8>,
    ) -> Vec<u8> {
        let alg = seq(&{
            let mut a = tlv(der::OID, OID_SHA1);
            a.extend_from_slice(&[0x05, 0x00]);
            a
        });
        let mut cert_id = alg;
        cert_id.extend(tlv(der::OCTET_STRING, &name_hash));
        cert_id.extend(tlv(der::OCTET_STRING, &key_hash));
        cert_id.extend(tlv(der::INTEGER, &serial));
        let cert_id = seq(&cert_id);

        let cert_status = if status_tag == 0 {
            vec![0x80, 0x00]
        } else {
            let t = gen_time(this_update_at);
            tlv(0xA1, &t)
        };

        let mut single = cert_id;
        single.extend(cert_status);
        single.extend(gen_time(this_update_at));
        if let Some(next_update_at) = next_update_at {
            single.extend(tlv(der::context(0), &gen_time(next_update_at)));
        }
        let single = seq(&single);
        let responses = seq(&single);

        let responder_id = tlv(der::context(1), &responder_name);
        let mut rd = responder_id;
        rd.extend(gen_time(produced_at));
        rd.extend(responses);
        let tbs = seq(&rd);

        let sig = sign_tbs(signing, &tbs);
        let mut basic = tbs;
        basic.extend(ecdsa_sha256_algid());
        basic.extend(sig);
        seq(&basic)
    }

    /** @brief Unix 초를 인증서 시각 형식으로. */
    fn gen_time(unix: i64) -> Vec<u8> {
        let days = unix.div_euclid(86400);
        let secs = unix.rem_euclid(86400);
        let (y, m, d) = civil_from_days(days);
        let h = secs / 3600;
        let mi = (secs % 3600) / 60;
        let s = secs % 60;
        let txt = format!("{y:04}{m:02}{d:02}{h:02}{mi:02}{s:02}Z");
        tlv(0x18, txt.as_bytes())
    }

    /** @brief 날 수를 연월일로. */
    fn civil_from_days(z: i64) -> (i64, i64, i64) {
        let z = z + 719468;
        let era = z.div_euclid(146097);
        let doe = z - era * 146097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        (if m <= 2 { y + 1 } else { y }, m, d)
    }

    #[test]
    /** @brief 정상과 폐기 상태가 제대로 읽히는지. */
    fn ocsp_good_and_revoked_verify() {
        let (ca, leaf, sk, _) = gen_ca_and_leaf();
        let now = 1_700_000_000i64;

        let good = wrap_ocsp(&build_basic_ocsp(&sk, &ca, &leaf, 0, now));
        assert_eq!(
            check_ocsp_response(&good, &ca, &leaf.serial, now).unwrap(),
            RevocationStatus::Good
        );

        let revoked = wrap_ocsp(&build_basic_ocsp(&sk, &ca, &leaf, 1, now));
        assert_eq!(
            check_ocsp_response(&revoked, &ca, &leaf.serial, now).unwrap(),
            RevocationStatus::Revoked
        );
    }

    #[test]
    /** @brief 서명이 틀린 응답을 거부하는지. */
    fn ocsp_bad_signature_rejected() {
        let (ca, leaf, _sk, _) = gen_ca_and_leaf();
        let (_ca2, _l2, other_sk, _) = gen_ca_and_leaf();
        let now = 1_700_000_000i64;

        let forged = wrap_ocsp(&build_basic_ocsp(&other_sk, &ca, &leaf, 0, now));
        assert!(check_ocsp_response(&forged, &ca, &leaf.serial, now).is_err());
    }

    #[test]
    /** @brief 다른 인증서에 대한 응답을 거부하는지. */
    fn ocsp_rejects_wrong_certid_issuer_hashes() {
        let (ca, leaf, sk, _) = gen_ca_and_leaf();
        let now = 1_700_000_000i64;
        let response = build_basic_ocsp_custom(
            &sk,
            &ca,
            &leaf,
            0,
            now,
            vec![0x55; 20],
            sha1(&ca.public_key),
            leaf.serial.clone(),
            now - 60,
            Some(now + 3600),
            ca.subject_raw.clone(),
        );
        assert_eq!(
            check_ocsp_response(&wrap_ocsp(&response), &ca, &leaf.serial, now).unwrap(),
            RevocationStatus::Unknown
        );
    }

    #[test]
    /** @brief 다음 갱신 시각이 없는 응답이 결국 만료되는지. */
    fn ocsp_good_without_next_update_expires() {
        let (ca, leaf, sk, _) = gen_ca_and_leaf();
        let now = 1_700_000_000i64;
        let response = build_basic_ocsp_custom(
            &sk,
            &ca,
            &leaf,
            0,
            now - OCSP_MAX_AGE_WITHOUT_NEXT_UPDATE_SECS - 1,
            sha1(&ca.subject_raw),
            sha1(&ca.public_key),
            leaf.serial.clone(),
            now - OCSP_MAX_AGE_WITHOUT_NEXT_UPDATE_SECS - 1,
            None,
            ca.subject_raw.clone(),
        );
        assert_eq!(
            check_ocsp_response(&wrap_ocsp(&response), &ca, &leaf.serial, now).unwrap(),
            RevocationStatus::Unknown
        );
    }

    #[test]
    /** @brief 응답자 식별자가 실제 서명자와 맞아야 하는지. */
    fn ocsp_responder_id_must_match_signer() {
        let (ca, leaf, sk, _) = gen_ca_and_leaf();
        let (other_ca, _, _, _) = gen_ca_and_leaf_with_name("other-ca.test");
        let now = 1_700_000_000i64;
        let response = build_basic_ocsp_custom(
            &sk,
            &ca,
            &leaf,
            0,
            now,
            sha1(&ca.subject_raw),
            sha1(&ca.public_key),
            leaf.serial.clone(),
            now - 60,
            Some(now + 3600),
            other_ca.subject_raw,
        );
        assert!(check_ocsp_response(&wrap_ocsp(&response), &ca, &leaf.serial, now).is_err());
    }

    /** @brief 기본 응답을 바깥 껍데기로 감싼다. */
    fn wrap_ocsp(basic: &[u8]) -> Vec<u8> {
        let status = vec![0x0a, 0x01, 0x00];
        let rt = tlv(der::OID, OID_OCSP_BASIC);
        let mut rb_inner = rt;
        rb_inner.extend(tlv(der::OCTET_STRING, basic));
        let response_bytes = tlv(der::context(0), &seq(&rb_inner));
        let mut body = status;
        body.extend(response_bytes);
        seq(&body)
    }

    /** @brief 테스트용 폐기 목록을 만든다. */
    fn build_crl(
        signing: &SigningKey,
        issuer: &X509,
        revoked_serials: &[&[u8]],
        now: i64,
    ) -> Vec<u8> {
        let mut revoked_list = Vec::new();
        for s in revoked_serials {
            let mut entry = tlv(der::INTEGER, s);
            entry.extend(gen_time(now - 3600));
            revoked_list.extend(seq(&entry));
        }
        let mut tbs = ecdsa_sha256_algid();
        tbs.extend_from_slice(&issuer.subject_raw);
        tbs.extend(gen_time(now - 600));
        tbs.extend(gen_time(now + 86400));
        if !revoked_list.is_empty() {
            tbs.extend(seq(&revoked_list));
        }
        let tbs = seq(&tbs);
        let sig = sign_tbs(signing, &tbs);
        let mut crl = tbs;
        crl.extend(ecdsa_sha256_algid());
        crl.extend(sig);
        seq(&crl)
    }

    #[test]
    /** @brief 폐기와 정상을 가려내는지. */
    fn crl_detects_revoked_and_good() {
        let (ca, leaf, sk, _) = gen_ca_and_leaf();
        let now = 1_700_000_000i64;
        let crl_der = build_crl(&sk, &ca, &[&leaf.serial], now);
        let crl = Crl::parse(&crl_der, &ca).unwrap();
        assert_eq!(crl.status(&leaf.serial, now), RevocationStatus::Revoked);
        assert_eq!(crl.status(&[0x99, 0x88], now), RevocationStatus::Good);
    }

    #[test]
    /** @brief 서명이 틀린 목록을 거부하는지. */
    fn crl_bad_signature_rejected() {
        let (ca, leaf, _sk, _) = gen_ca_and_leaf();
        let (_c2, _l2, other, _) = gen_ca_and_leaf();
        let now = 1_700_000_000i64;
        let crl_der = build_crl(&other, &ca, &[&leaf.serial], now);
        assert!(Crl::parse(&crl_der, &ca).is_err());
    }
}
