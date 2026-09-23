/*!
 * @brief 핸드셰이크 메시지 인코딩과 파싱.
 *
 * @details 클라이언트와 서버의 인사말, 그리고 그 안의 확장들을 다룬다.
 * @warning 비정규 인코딩을 거부한다. 같은 뜻을 여러 형태로 쓸 수 있으면 구현마다 다르게
 *          읽고, 그 차이가 곧 협상을 조종하는 경로가 된다.
 */

use crate::handshake::{HandshakeMsg, HandshakeType};
use crate::wire::{Reader, Writer};
use crate::TlsError;

/** @brief 프로토콜 상수들. */
pub mod consts {

    /** @brief AES-128-GCM 스위트. */
    pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
    /** @brief AES-256-GCM 스위트. */
    pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
    /** @brief ChaCha20-Poly1305 스위트. */
    pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

    /** @brief X25519 곡선. */
    pub const X25519: u16 = 0x001d;
    /** @brief P-256 곡선. */
    pub const SECP256R1: u16 = 0x0017;
    /** @brief P-384 곡선. */
    pub const SECP384R1: u16 = 0x0018;

    /** @brief Ed25519 서명. */
    pub const ED25519: u16 = 0x0807;
    /** @brief P-256 ECDSA 서명. */
    pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
    /** @brief P-384 ECDSA 서명. */
    pub const ECDSA_SECP384R1_SHA384: u16 = 0x0503;
    /** @brief RSA PSS 서명, SHA-256. */
    pub const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
    /** @brief RSA PSS 서명, SHA-384. */
    pub const RSA_PSS_RSAE_SHA384: u16 = 0x0805;
    /** @brief RSA PSS 서명, SHA-512. */
    pub const RSA_PSS_RSAE_SHA512: u16 = 0x0806;
    /** @brief RSA PKCS#1 서명, SHA-256. 1.3에서는 인증서 서명에만 쓴다. */
    pub const RSA_PKCS1_SHA256: u16 = 0x0401;
    /** @brief RSA PKCS#1 서명, SHA-384. */
    pub const RSA_PKCS1_SHA384: u16 = 0x0501;
    /** @brief RSA PKCS#1 서명, SHA-512. */
    pub const RSA_PKCS1_SHA512: u16 = 0x0601;

    /** @brief 서버 이름 확장. 어느 이름으로 접속하는지 알린다. */
    pub const EXT_SERVER_NAME: u16 = 0;
    /** @brief 지원 곡선 확장. */
    pub const EXT_SUPPORTED_GROUPS: u16 = 10;
    /** @brief 지원 서명 방식 확장. */
    pub const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
    /** @brief 응용 프로토콜 협상 확장. */
    pub const EXT_ALPN: u16 = 16;
    /** @brief 미리 공유된 키 확장. 반드시 마지막에 와야 한다. */
    pub const EXT_PRE_SHARED_KEY: u16 = 41;
    /** @brief 조기 데이터 확장. */
    pub const EXT_EARLY_DATA: u16 = 42;
    /** @brief 지원 버전 확장. 1.3 협상이 이것으로 이뤄진다. */
    pub const EXT_SUPPORTED_VERSIONS: u16 = 43;
    /** @brief 재개 시 키 교환 방식 확장. */
    pub const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
    /** @brief 키 공유 확장. 공개값을 미리 보내 왕복을 아낀다. */
    pub const EXT_KEY_SHARE: u16 = 51;

    /** @brief 재개하면서 키 교환도 하는 방식. 전방 비밀성을 지킨다. */
    pub const PSK_DHE_KE: u8 = 1;
    /** @brief 쿠키 확장. 다시 시도 요청에 실려 온다. */
    pub const EXT_COOKIE: u16 = 44;

    /** @brief TLS 1.3 버전 번호. */
    pub const TLS13: u16 = 0x0304;
    /** @brief TLS 1.2 버전 번호. */
    pub const TLS12: u16 = 0x0303;
}

/**
 * @brief 다시 시도 요청을 나타내는 고정 무작위 값.
 * @note 이 값이면 그것은 서버 인사말이 아니라 다시 시도 요청이다. 구분하지 않으면
 *       핸드셰이크가 어긋난다.
 */
pub const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

use consts::*;

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief 확장 하나. */
pub struct Extension {
    /** @brief 확장 종류. */
    pub ext_type: u16,
    /** @brief 확장 내용. */
    pub data: Vec<u8>,
}

impl Extension {
    /** @brief 확장을 만든다. */
    pub fn new(ext_type: u16, data: Vec<u8>) -> Self {
        Self { ext_type, data }
    }

    /** @brief 확장을 쓴다. */
    pub fn encode_into(&self, w: &mut Writer) {
        w.u16(self.ext_type);
        w.vec16(|w| w.bytes(&self.data));
    }

    /** @brief 확장 목록을 읽는다. 중복은 거부한다. */
    pub fn parse_list(bytes: &[u8]) -> Result<Vec<Extension>, TlsError> {
        let mut r = Reader::new(bytes);
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        while !r.is_empty() {
            let ext_type = r.u16()?;
            if !seen.insert(ext_type) {
                return Err(TlsError::Decode);
            }
            let data = r.vec16()?.to_vec();
            out.push(Extension { ext_type, data });
        }
        Ok(out)
    }

    /** @brief 길이 접두사가 붙은 확장 목록을 읽는다. */
    pub(crate) fn parse_vector(bytes: &[u8]) -> Result<Vec<Extension>, TlsError> {
        let mut reader = Reader::new(bytes);
        let extensions = Self::parse_list(reader.vec16()?)?;
        if !reader.is_empty() {
            return Err(TlsError::Decode);
        }
        Ok(extensions)
    }

    /** @brief 목록에서 그 종류의 확장을 찾는다. */
    pub fn find(exts: &[Extension], ext_type: u16) -> Option<&Extension> {
        exts.iter().find(|e| e.ext_type == ext_type)
    }

    /** @brief 클라이언트의 지원 버전 확장. */
    pub fn supported_versions_client(versions: &[u16]) -> Extension {
        let mut w = Writer::new();
        w.vec8(|w| {
            for v in versions {
                w.u16(*v);
            }
        });
        Extension::new(EXT_SUPPORTED_VERSIONS, w.buf)
    }

    /** @brief 서버가 고른 버전 확장. */
    pub fn supported_versions_server(version: u16) -> Extension {
        let mut w = Writer::new();
        w.u16(version);
        Extension::new(EXT_SUPPORTED_VERSIONS, w.buf)
    }

    /** @brief 클라이언트의 키 공유 확장. */
    pub fn key_share_client(entries: &[(u16, Vec<u8>)]) -> Extension {
        let mut w = Writer::new();
        w.vec16(|w| {
            for (g, k) in entries {
                w.u16(*g);
                w.vec16(|w| w.bytes(k));
            }
        });
        Extension::new(EXT_KEY_SHARE, w.buf)
    }

    /** @brief 서버가 고른 키 공유 확장. */
    pub fn key_share_server(group: u16, key: &[u8]) -> Extension {
        let mut w = Writer::new();
        w.u16(group);
        w.vec16(|w| w.bytes(key));
        Extension::new(EXT_KEY_SHARE, w.buf)
    }

    /** @brief 지원 곡선 확장. */
    pub fn supported_groups(groups: &[u16]) -> Extension {
        let mut w = Writer::new();
        w.vec16(|w| {
            for g in groups {
                w.u16(*g);
            }
        });
        Extension::new(EXT_SUPPORTED_GROUPS, w.buf)
    }

    /** @brief 지원 서명 방식 확장. */
    pub fn signature_algorithms(schemes: &[u16]) -> Extension {
        let mut w = Writer::new();
        w.vec16(|w| {
            for s in schemes {
                w.u16(*s);
            }
        });
        Extension::new(EXT_SIGNATURE_ALGORITHMS, w.buf)
    }

    /** @brief 서버 이름 확장. */
    pub fn server_name(host: &str) -> Extension {
        let mut w = Writer::new();
        w.vec16(|w| {
            w.u8(0);
            w.vec16(|w| w.bytes(host.as_bytes()));
        });
        Extension::new(EXT_SERVER_NAME, w.buf)
    }

    /** @brief 응용 프로토콜 목록 확장. */
    pub fn alpn(protocols: &[&[u8]]) -> Extension {
        let mut w = Writer::new();
        w.vec16(|w| {
            for p in protocols {
                w.vec8(|w| w.bytes(p));
            }
        });
        Extension::new(EXT_ALPN, w.buf)
    }

    /** @brief 재개 시 키 교환 방식 확장. */
    pub fn psk_key_exchange_modes(modes: &[u8]) -> Extension {
        let mut w = Writer::new();
        w.vec8(|w| w.bytes(modes));
        Extension::new(EXT_PSK_KEY_EXCHANGE_MODES, w.buf)
    }

    /** @brief 클라이언트의 재개 제안. 티켓과 바인더가 들어간다. */
    pub fn pre_shared_key_client(
        identity: &[u8],
        obfuscated_age: u32,
        binder_len: usize,
    ) -> Extension {
        let mut w = Writer::new();
        w.vec16(|w| {
            w.vec16(|w| w.bytes(identity));
            w.u32(obfuscated_age);
        });
        w.vec16(|w| {
            w.vec8(|w| w.bytes(&vec![0u8; binder_len]));
        });
        Extension::new(EXT_PRE_SHARED_KEY, w.buf)
    }

    /** @brief 서버가 고른 재개 제안 번호. */
    pub fn pre_shared_key_server(selected: u16) -> Extension {
        let mut w = Writer::new();
        w.u16(selected);
        Extension::new(EXT_PRE_SHARED_KEY, w.buf)
    }

    /** @brief 조기 데이터를 쓰겠다는 표시. */
    pub fn early_data() -> Extension {
        Extension::new(EXT_EARLY_DATA, Vec::new())
    }

    /** @brief 티켓에 담는 조기 데이터 허용 크기. */
    pub fn early_data_nst(max: u32) -> Extension {
        let mut w = Writer::new();
        w.u32(max);
        Extension::new(EXT_EARLY_DATA, w.buf)
    }

    /** @brief 다시 시도 요청의 곡선 지정. */
    pub fn key_share_hrr(group: u16) -> Extension {
        let mut w = Writer::new();
        w.u16(group);
        Extension::new(EXT_KEY_SHARE, w.buf)
    }

    /** @brief 다시 시도 요청의 곡선을 읽는다. */
    pub fn as_key_share_hrr(&self) -> Option<u16> {
        let mut r = Reader::new(&self.data);
        let group = r.u16().ok()?;
        r.is_empty().then_some(group)
    }

    /** @brief 쿠키 확장. */
    pub fn cookie(data: &[u8]) -> Extension {
        let mut w = Writer::new();
        w.vec16(|w| w.bytes(data));
        Extension::new(EXT_COOKIE, w.buf)
    }

    /** @brief 쿠키를 읽는다. */
    pub fn as_cookie(&self) -> Option<Vec<u8>> {
        let mut r = Reader::new(&self.data);
        let cookie = r.vec16().ok()?.to_vec();
        (!cookie.is_empty() && r.is_empty()).then_some(cookie)
    }

    /** @brief 클라이언트의 지원 버전 목록을 읽는다. */
    pub fn as_supported_versions_client(&self) -> Option<Vec<u16>> {
        let mut r = Reader::new(&self.data);
        let list = r.vec8().ok()?;
        if !r.is_empty() || list.is_empty() {
            return None;
        }
        let mut lr = Reader::new(list);
        let mut out = Vec::new();
        while !lr.is_empty() {
            out.push(lr.u16().ok()?);
        }
        Some(out)
    }

    /** @brief 서버가 고른 버전을 읽는다. */
    pub fn as_supported_versions_server(&self) -> Option<u16> {
        let mut r = Reader::new(&self.data);
        let version = r.u16().ok()?;
        r.is_empty().then_some(version)
    }

    /** @brief 클라이언트의 키 공유들을 읽는다. */
    pub fn as_key_share_client(&self) -> Option<Vec<(u16, Vec<u8>)>> {
        let mut r = Reader::new(&self.data);
        let list = r.vec16().ok()?;
        if !r.is_empty() {
            return None;
        }
        let mut lr = Reader::new(list);
        let mut out = Vec::new();
        while !lr.is_empty() {
            let group = lr.u16().ok()?;
            let key = lr.vec16().ok()?.to_vec();
            if key.is_empty() {
                return None;
            }
            out.push((group, key));
        }
        Some(out)
    }

    /** @brief 서버의 키 공유를 읽는다. */
    pub fn as_key_share_server(&self) -> Option<(u16, Vec<u8>)> {
        let mut r = Reader::new(&self.data);
        let group = r.u16().ok()?;
        let key = r.vec16().ok()?.to_vec();
        (!key.is_empty() && r.is_empty()).then_some((group, key))
    }

    /** @brief 서버 이름을 읽는다. */
    pub fn as_server_name(&self) -> Option<String> {
        let mut r = Reader::new(&self.data);
        let list = r.vec16().ok()?;
        if !r.is_empty() || list.is_empty() {
            return None;
        }
        let mut lr = Reader::new(list);
        let mut host = None;
        while !lr.is_empty() {
            let ntype = lr.u8().ok()?;
            let name = lr.vec16().ok()?;
            if ntype == 0 {
                if name.is_empty() || host.is_some() {
                    return None;
                }
                host = String::from_utf8(name.to_vec()).ok();
            }
        }
        host
    }

    /** @brief 응용 프로토콜 목록을 읽는다. */
    pub fn as_alpn(&self) -> Option<Vec<Vec<u8>>> {
        let mut r = Reader::new(&self.data);
        let list = r.vec16().ok()?;
        if !r.is_empty() || list.is_empty() {
            return None;
        }
        let mut lr = Reader::new(list);
        let mut out = Vec::new();
        while !lr.is_empty() {
            let protocol = lr.vec8().ok()?.to_vec();
            if protocol.is_empty() {
                return None;
            }
            out.push(protocol);
        }
        Some(out)
    }

    /** @brief 재개 방식 목록을 읽는다. */
    pub fn as_psk_modes(&self) -> Option<Vec<u8>> {
        let mut r = Reader::new(&self.data);
        let modes = r.vec8().ok()?.to_vec();
        (!modes.is_empty() && r.is_empty()).then_some(modes)
    }

    /** @brief 지원 곡선 목록을 읽는다. */
    pub fn as_supported_groups(&self) -> Option<Vec<u16>> {
        let mut r = Reader::new(&self.data);
        let list = r.vec16().ok()?;
        if !r.is_empty() || list.is_empty() {
            return None;
        }
        let mut lr = Reader::new(list);
        let mut out = Vec::new();
        while !lr.is_empty() {
            out.push(lr.u16().ok()?);
        }
        Some(out)
    }

    /** @brief 지원 서명 방식 목록을 읽는다. */
    pub fn as_signature_algorithms(&self) -> Option<Vec<u16>> {
        let mut reader = Reader::new(&self.data);
        let list = reader.vec16().ok()?;
        if !reader.is_empty() || list.is_empty() {
            return None;
        }
        let mut list_reader = Reader::new(list);
        let mut algorithms = Vec::new();
        while !list_reader.is_empty() {
            algorithms.push(list_reader.u16().ok()?);
        }
        Some(algorithms)
    }

    /** @brief 재개 제안의 티켓들과 바인더들을 읽는다. */
    pub fn as_pre_shared_key_client(&self) -> Option<(Vec<(Vec<u8>, u32)>, Vec<Vec<u8>>)> {
        let mut r = Reader::new(&self.data);
        let ids_raw = r.vec16().ok()?;
        let mut ir = Reader::new(ids_raw);
        let mut identities = Vec::new();
        while !ir.is_empty() {
            let identity = ir.vec16().ok()?.to_vec();
            if identity.is_empty() {
                return None;
            }
            let age = ir.u32().ok()?;
            identities.push((identity, age));
        }
        let binders_raw = r.vec16().ok()?;
        if !r.is_empty() || identities.is_empty() {
            return None;
        }
        let mut br = Reader::new(binders_raw);
        let mut binders = Vec::new();
        while !br.is_empty() {
            let binder = br.vec8().ok()?.to_vec();
            if binder.len() < 32 {
                return None;
            }
            binders.push(binder);
        }
        (identities.len() == binders.len()).then_some((identities, binders))
    }

    /** @brief 서버가 고른 제안 번호를 읽는다. */
    pub fn as_pre_shared_key_server(&self) -> Option<u16> {
        let mut r = Reader::new(&self.data);
        let selected = r.u16().ok()?;
        r.is_empty().then_some(selected)
    }

    /** @brief 티켓의 조기 데이터 허용 크기를 읽는다. */
    pub fn as_early_data_max(&self) -> Option<u32> {
        let mut r = Reader::new(&self.data);
        let max = r.u32().ok()?;
        r.is_empty().then_some(max)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief 새 세션 티켓 메시지. */
pub struct NewSessionTicket {
    /** @brief 이 티켓이 유효한 기간. */
    pub lifetime_secs: u32,
    /** @brief 나이를 가리는 데 더할 값. */
    pub age_add: u32,
    /** @brief 이 티켓만의 nonce. */
    pub nonce: Vec<u8>,
    /** @brief 티켓 자체. */
    pub ticket: Vec<u8>,
    /** @brief 이 티켓에 딸린 확장. */
    pub extensions: Vec<Extension>,
}

impl NewSessionTicket {
    /** @brief 티켓 메시지를 읽는다. */
    pub fn parse(body: &[u8]) -> Result<NewSessionTicket, TlsError> {
        let mut r = Reader::new(body);
        let lifetime_secs = r.u32()?;
        let age_add = r.u32()?;
        let nonce = r.vec8()?.to_vec();
        let ticket = r.vec16()?.to_vec();
        let extensions = Extension::parse_list(r.vec16()?)?;
        if !r.is_empty() || ticket.is_empty() {
            return Err(TlsError::Decode);
        }
        Ok(NewSessionTicket {
            lifetime_secs,
            age_add,
            nonce,
            ticket,
            extensions,
        })
    }

    /** @brief 티켓 메시지를 쓴다. */
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(self.lifetime_secs);
        w.u32(self.age_add);
        w.vec8(|w| w.bytes(&self.nonce));
        w.vec16(|w| w.bytes(&self.ticket));
        w.vec16(|w| {
            for e in &self.extensions {
                e.encode_into(w);
            }
        });
        w.buf
    }

    /** @brief 이 티켓으로 보낼 수 있는 조기 데이터 크기. */
    pub fn max_early_data(&self) -> u32 {
        Extension::find(&self.extensions, EXT_EARLY_DATA)
            .and_then(|e| e.as_early_data_max())
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief 클라이언트 인사말. */
pub struct ClientHello {
    /** @brief 이전 규격과 맞추기 위한 버전 표기. */
    pub legacy_version: u16,
    /** @brief 클라이언트가 고른 난수. */
    pub random: [u8; 32],
    /** @brief 이전 규격과 맞추기 위한 세션 번호. */
    pub session_id: Vec<u8>,
    /** @brief 쓸 수 있는 암호 스위트들. */
    pub cipher_suites: Vec<u16>,
    /** @brief 이전 규격과 맞추기 위한 압축 방식. */
    pub compression_methods: Vec<u8>,
    /** @brief 실제 협상이 오가는 확장들. */
    pub extensions: Vec<Extension>,
}

impl ClientHello {
    /** @brief 이 인사말이 별도 힙 버퍼에 보유한 바이트. */
    pub(crate) fn retained_payload_bytes(&self) -> usize {
        self.session_id
            .capacity()
            .saturating_add(
                self.cipher_suites
                    .capacity()
                    .saturating_mul(std::mem::size_of::<u16>()),
            )
            .saturating_add(self.compression_methods.capacity())
            .saturating_add(
                self.extensions
                    .capacity()
                    .saturating_mul(std::mem::size_of::<Extension>()),
            )
            .saturating_add(self.extensions.iter().fold(0usize, |total, extension| {
                total.saturating_add(extension.data.capacity())
            }))
    }

    /**
     * @brief 1.3 인사말로서 형태가 맞는지.
     * @warning 재개 확장은 반드시 마지막이어야 한다. 바인더가 그 앞까지의 바이트에
     *          걸리므로, 뒤에 뭔가 오면 그 부분이 인증되지 않는다.
     */
    pub(crate) fn is_valid_tls13(&self) -> bool {
        self.legacy_version == TLS12
            && self.compression_methods == [0]
            && self
                .ext(EXT_SUPPORTED_VERSIONS)
                .and_then(Extension::as_supported_versions_client)
                .is_some_and(|versions| versions.contains(&TLS13))
            && self
                .extensions
                .iter()
                .position(|extension| extension.ext_type == EXT_PRE_SHARED_KEY)
                .is_none_or(|position| position + 1 == self.extensions.len())
    }

    /** @brief HelloRetryRequest 뒤 두 번째 인사말이 허용된 항목만 바꿨는지. */
    pub(crate) fn is_valid_retry_of(&self, first: &ClientHello) -> bool {
        if self.legacy_version != first.legacy_version
            || self.random != first.random
            || self.session_id != first.session_id
            || self.cipher_suites != first.cipher_suites
            || self.compression_methods != first.compression_methods
            || self.ext(EXT_EARLY_DATA).is_some()
        {
            return false;
        }

        let unchanged = |extension: &Extension, other: &ClientHello| {
            other
                .ext(extension.ext_type)
                .is_some_and(|candidate| candidate.data == extension.data)
        };
        for extension in &first.extensions {
            if !matches!(
                extension.ext_type,
                EXT_KEY_SHARE | EXT_COOKIE | EXT_EARLY_DATA | EXT_PRE_SHARED_KEY
            ) && !unchanged(extension, self)
            {
                return false;
            }
        }
        for extension in &self.extensions {
            if !matches!(
                extension.ext_type,
                EXT_KEY_SHARE | EXT_COOKIE | EXT_PRE_SHARED_KEY
            ) && !unchanged(extension, first)
            {
                return false;
            }
        }

        let first_psks = first
            .ext(EXT_PRE_SHARED_KEY)
            .map(Extension::as_pre_shared_key_client);
        let retry_psks = self
            .ext(EXT_PRE_SHARED_KEY)
            .map(Extension::as_pre_shared_key_client);
        match (first_psks, retry_psks) {
            (Some(None), _) | (_, Some(None)) | (None, Some(Some(_))) => false,
            (_, None) => true,
            (Some(Some((first_ids, _))), Some(Some((retry_ids, _)))) => {
                let mut remaining = first_ids.as_slice();
                retry_ids.into_iter().all(|(retry_id, _)| {
                    let Some(position) = remaining
                        .iter()
                        .position(|(first_id, _)| *first_id == retry_id)
                    else {
                        return false;
                    };
                    remaining = &remaining[position + 1..];
                    true
                })
            }
        }
    }

    /** @brief 인사말을 읽는다. */
    pub fn parse(body: &[u8]) -> Result<ClientHello, TlsError> {
        let mut r = Reader::new(body);
        let legacy_version = r.u16()?;
        let random: [u8; 32] = r.take(32)?.try_into().map_err(|_| TlsError::Decode)?;
        let session_id = r.vec8()?.to_vec();
        if session_id.len() > 32 {
            return Err(TlsError::Decode);
        }
        let cs = r.vec16()?;
        if cs.is_empty() {
            return Err(TlsError::Decode);
        }
        let mut csr = Reader::new(cs);
        let mut cipher_suites = Vec::new();
        while !csr.is_empty() {
            cipher_suites.push(csr.u16()?);
        }
        let compression_methods = r.vec8()?.to_vec();
        if compression_methods.is_empty() {
            return Err(TlsError::Decode);
        }
        let extensions = Extension::parse_list(r.vec16()?)?;

        if !r.is_empty() {
            return Err(TlsError::Decode);
        }
        Ok(ClientHello {
            legacy_version,
            random,
            session_id,
            cipher_suites,
            compression_methods,
            extensions,
        })
    }

    /** @brief 인사말을 쓴다. */
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(self.legacy_version);
        w.bytes(&self.random);
        w.vec8(|w| w.bytes(&self.session_id));
        w.vec16(|w| {
            for cs in &self.cipher_suites {
                w.u16(*cs);
            }
        });
        w.vec8(|w| w.bytes(&self.compression_methods));
        w.vec16(|w| {
            for e in &self.extensions {
                e.encode_into(w);
            }
        });
        w.buf
    }

    /** @brief 핸드셰이크 메시지에서 인사말을 꺼낸다. 종류가 다르면 오류다. */
    pub fn from_handshake(msg: &HandshakeMsg) -> Result<ClientHello, TlsError> {
        if msg.msg_type != HandshakeType::ClientHello {
            return Err(TlsError::Decode);
        }
        ClientHello::parse(&msg.body)
    }

    /** @brief 핸드셰이크 메시지로 감싼다. */
    pub fn to_handshake(&self) -> HandshakeMsg {
        HandshakeMsg::new(HandshakeType::ClientHello, self.encode())
    }

    /** @brief 이 종류의 확장을 찾는다. */
    pub fn ext(&self, ext_type: u16) -> Option<&Extension> {
        Extension::find(&self.extensions, ext_type)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief 서버 인사말. */
pub struct ServerHello {
    /** @brief 이전 규격과 맞추기 위한 버전 표기. */
    pub legacy_version: u16,
    /** @brief 서버가 고른 난수. */
    pub random: [u8; 32],
    /** @brief 클라이언트가 보낸 세션 번호를 그대로 되비춘다. */
    pub session_id_echo: Vec<u8>,
    /** @brief 서버가 고른 암호 스위트. */
    pub cipher_suite: u16,
    /** @brief 실제 협상이 오가는 확장들. */
    pub extensions: Vec<Extension>,
}

impl ServerHello {
    /**
     * @brief 1.3 인사말로서 형태가 맞는지.
     * @note 세션 번호를 클라이언트가 보낸 것과 대조한다. 다르면 중간자가 바꾼 것이다.
     */
    pub(crate) fn is_valid_tls13(&self, expected_session_id: &[u8], hrr: bool) -> bool {
        if self.legacy_version != TLS12
            || self.session_id_echo != expected_session_id
            || self
                .ext(EXT_SUPPORTED_VERSIONS)
                .and_then(Extension::as_supported_versions_server)
                != Some(TLS13)
        {
            return false;
        }
        self.extensions.iter().all(|extension| {
            matches!(extension.ext_type, EXT_SUPPORTED_VERSIONS | EXT_KEY_SHARE)
                || (hrr && extension.ext_type == EXT_COOKIE)
                || (!hrr && extension.ext_type == EXT_PRE_SHARED_KEY)
        })
    }

    /** @brief 서버가 보낸 첫 메시지를 읽는다. */
    pub fn parse(body: &[u8]) -> Result<ServerHello, TlsError> {
        let mut r = Reader::new(body);
        let legacy_version = r.u16()?;
        let random: [u8; 32] = r.take(32)?.try_into().map_err(|_| TlsError::Decode)?;
        let session_id_echo = r.vec8()?.to_vec();
        if session_id_echo.len() > 32 {
            return Err(TlsError::Decode);
        }
        let cipher_suite = r.u16()?;
        let legacy_compression = r.u8()?;
        if legacy_compression != 0 {
            return Err(TlsError::Decode);
        }
        let extensions = Extension::parse_list(r.vec16()?)?;

        if !r.is_empty() {
            return Err(TlsError::Decode);
        }
        Ok(ServerHello {
            legacy_version,
            random,
            session_id_echo,
            cipher_suite,
            extensions,
        })
    }

    /** @brief 서버가 보낼 첫 메시지를 적는다. */
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(self.legacy_version);
        w.bytes(&self.random);
        w.vec8(|w| w.bytes(&self.session_id_echo));
        w.u16(self.cipher_suite);
        w.u8(0);
        w.vec16(|w| {
            for e in &self.extensions {
                e.encode_into(w);
            }
        });
        w.buf
    }

    /** @brief 핸드셰이크 메시지에서 꺼낸다. */
    pub fn from_handshake(msg: &HandshakeMsg) -> Result<ServerHello, TlsError> {
        if msg.msg_type != HandshakeType::ServerHello {
            return Err(TlsError::Decode);
        }
        ServerHello::parse(&msg.body)
    }

    /** @brief 핸드셰이크 메시지로 감싼다. */
    pub fn to_handshake(&self) -> HandshakeMsg {
        HandshakeMsg::new(HandshakeType::ServerHello, self.encode())
    }

    /** @brief 이 확장. 없으면 없다. */
    pub fn ext(&self, ext_type: u16) -> Option<&Extension> {
        Extension::find(&self.extensions, ext_type)
    }
}

#[cfg(test)]
/** @brief 인사말 왕복과 비정규 인코딩 거부. */
mod tests {
    use super::*;

    #[test]
    /** @brief 확장이 든 클라이언트 인사말 왕복. */
    fn client_hello_roundtrip_with_extensions() {
        let ch = ClientHello {
            legacy_version: TLS12,
            random: [0x11; 32],
            session_id: vec![0xAB; 32],
            cipher_suites: vec![TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256],
            compression_methods: vec![0],
            extensions: vec![
                Extension::supported_versions_client(&[TLS13]),
                Extension::server_name("dns.example.com"),
                Extension::key_share_client(&[(X25519, vec![0x42; 32])]),
                Extension::alpn(&[b"dot", b"h2"]),
            ],
        };
        let body = ch.encode();
        let back = ClientHello::parse(&body).unwrap();
        assert_eq!(back, ch);

        assert_eq!(
            back.ext(EXT_SUPPORTED_VERSIONS)
                .unwrap()
                .as_supported_versions_client(),
            Some(vec![TLS13])
        );
        assert_eq!(
            back.ext(EXT_SERVER_NAME)
                .unwrap()
                .as_server_name()
                .as_deref(),
            Some("dns.example.com")
        );
        let ks = back
            .ext(EXT_KEY_SHARE)
            .unwrap()
            .as_key_share_client()
            .unwrap();
        assert_eq!(ks.len(), 1);
        assert_eq!(ks[0].0, X25519);
        assert_eq!(ks[0].1, vec![0x42; 32]);
        assert_eq!(
            back.ext(EXT_ALPN).unwrap().as_alpn().unwrap(),
            vec![b"dot".to_vec(), b"h2".to_vec()]
        );
    }

    #[test]
    /** @brief 서버 인사말 왕복. */
    fn server_hello_roundtrip() {
        let sh = ServerHello {
            legacy_version: TLS12,
            random: [0x55; 32],
            session_id_echo: vec![0xAB; 32],
            cipher_suite: TLS_AES_128_GCM_SHA256,
            extensions: vec![
                Extension::supported_versions_server(TLS13),
                Extension::key_share_server(X25519, &[0x99; 32]),
            ],
        };
        let body = sh.encode();
        let back = ServerHello::parse(&body).unwrap();
        assert_eq!(back, sh);
        assert_eq!(
            back.ext(EXT_SUPPORTED_VERSIONS)
                .unwrap()
                .as_supported_versions_server(),
            Some(TLS13)
        );
        let (g, k) = back
            .ext(EXT_KEY_SHARE)
            .unwrap()
            .as_key_share_server()
            .unwrap();
        assert_eq!(g, X25519);
        assert_eq!(k, vec![0x99; 32]);
    }

    #[test]
    /** @brief 핸드셰이크 메시지로 감싸고 푸는 왕복. */
    fn handshake_wrapping() {
        let ch = ClientHello {
            legacy_version: TLS12,
            random: [0; 32],
            session_id: vec![],
            cipher_suites: vec![TLS_AES_128_GCM_SHA256],
            compression_methods: vec![0],
            extensions: vec![Extension::supported_versions_client(&[TLS13])],
        };
        let hs = ch.to_handshake();
        assert_eq!(hs.msg_type, HandshakeType::ClientHello);
        let back = ClientHello::from_handshake(&hs).unwrap();
        assert_eq!(back, ch);
    }

    #[test]
    /** @brief 종류가 다른 메시지를 거부하는지. */
    fn wrong_handshake_type_rejected() {
        let hs = HandshakeMsg::new(HandshakeType::Finished, vec![0; 10]);
        assert!(ClientHello::from_handshake(&hs).is_err());
    }

    #[test]
    /** @brief 비정규 인코딩을 거부하는지. 허용하면 구현 차이가 협상을 조종한다. */
    fn noncanonical_extensions_and_hello_fields_are_rejected() {
        let extension = Extension::supported_versions_server(TLS13);
        let mut encoded = Writer::new();
        extension.encode_into(&mut encoded);
        extension.encode_into(&mut encoded);
        assert!(Extension::parse_list(&encoded.buf).is_err());
        let mut vector = Writer::new();
        vector.vec16(|writer| extension.encode_into(writer));
        assert_eq!(
            Extension::parse_vector(&vector.buf).unwrap(),
            vec![extension]
        );
        vector.buf.push(0);
        assert!(Extension::parse_vector(&vector.buf).is_err());

        let with_trailing = Extension::new(EXT_SUPPORTED_VERSIONS, vec![0x03, 0x04, 0]);
        assert_eq!(with_trailing.as_supported_versions_server(), None);
        let empty_alpn = Extension::new(EXT_ALPN, vec![0, 1, 0]);
        assert_eq!(empty_alpn.as_alpn(), None);

        let mut sh = ServerHello {
            legacy_version: TLS12,
            random: [0; 32],
            session_id_echo: Vec::new(),
            cipher_suite: TLS_AES_128_GCM_SHA256,
            extensions: vec![
                Extension::supported_versions_server(TLS13),
                Extension::key_share_server(X25519, &[1; 32]),
            ],
        };
        assert!(sh.is_valid_tls13(&[], false));
        sh.extensions.push(Extension::alpn(&[b"h2"]));
        assert!(!sh.is_valid_tls13(&[], false));

        let mut body = sh.encode();
        let compression_offset = 2 + 32 + 1 + sh.session_id_echo.len() + 2;
        body[compression_offset] = 1;
        assert!(ServerHello::parse(&body).is_err());
    }

    #[test]
    /** @brief 재개 확장이 마지막이 아니면 거부하는지. 바인더가 덮는 범위가 어긋난다. */
    fn tls13_psk_extension_must_be_last() {
        let mut ch = ClientHello {
            legacy_version: TLS12,
            random: [0; 32],
            session_id: Vec::new(),
            cipher_suites: vec![TLS_AES_128_GCM_SHA256],
            compression_methods: vec![0],
            extensions: vec![
                Extension::supported_versions_client(&[TLS13]),
                Extension::pre_shared_key_client(b"ticket", 0, 32),
                Extension::server_name("dns.example"),
            ],
        };
        assert!(!ch.is_valid_tls13());
        ch.extensions.swap(1, 2);
        assert!(ch.is_valid_tls13());
    }

    #[test]
    /** @brief 빈 PSK identity와 SHA-256보다 짧은 binder를 정규 입력으로 받지 않는지. */
    fn tls13_psk_identity_and_binder_minimums_are_enforced() {
        assert!(Extension::pre_shared_key_client(b"", 0, 32)
            .as_pre_shared_key_client()
            .is_none());
        assert!(Extension::pre_shared_key_client(b"ticket", 0, 31)
            .as_pre_shared_key_client()
            .is_none());
        assert!(Extension::pre_shared_key_client(b"ticket", 0, 32)
            .as_pre_shared_key_client()
            .is_some());
    }

    #[test]
    /** @brief 두 번째 ClientHello가 HRR에서 허용된 항목 외에는 바꾸지 못하는지. */
    fn tls13_retry_client_hello_preserves_the_first_context() {
        let first = ClientHello {
            legacy_version: TLS12,
            random: [7; 32],
            session_id: vec![9; 32],
            cipher_suites: vec![TLS_AES_128_GCM_SHA256],
            compression_methods: vec![0],
            extensions: vec![
                Extension::supported_versions_client(&[TLS13]),
                Extension::supported_groups(&[X25519]),
                Extension::signature_algorithms(&[ECDSA_SECP256R1_SHA256]),
                Extension::key_share_client(&[]),
                Extension::server_name("dns.example"),
                Extension::psk_key_exchange_modes(&[PSK_DHE_KE]),
                Extension::early_data(),
                Extension::pre_shared_key_client(b"ticket", 1, 32),
            ],
        };
        let mut retry = first.clone();
        *retry
            .extensions
            .iter_mut()
            .find(|extension| extension.ext_type == EXT_KEY_SHARE)
            .unwrap() = Extension::key_share_client(&[(X25519, vec![3; 32])]);
        retry
            .extensions
            .retain(|extension| extension.ext_type != EXT_EARLY_DATA);
        let psk_at = retry.extensions.len() - 1;
        retry
            .extensions
            .insert(psk_at, Extension::cookie(b"retry-cookie"));
        *retry.extensions.last_mut().unwrap() = Extension::pre_shared_key_client(b"ticket", 2, 32);
        assert!(retry.is_valid_tls13());
        assert!(retry.is_valid_retry_of(&first));

        let mut changed_name = retry.clone();
        *changed_name
            .extensions
            .iter_mut()
            .find(|extension| extension.ext_type == EXT_SERVER_NAME)
            .unwrap() = Extension::server_name("other.example");
        assert!(!changed_name.is_valid_retry_of(&first));

        let mut new_psk = retry.clone();
        *new_psk.extensions.last_mut().unwrap() =
            Extension::pre_shared_key_client(b"other-ticket", 2, 32);
        assert!(!new_psk.is_valid_retry_of(&first));

        let mut retained_early_data = retry;
        let psk_at = retained_early_data.extensions.len() - 1;
        retained_early_data
            .extensions
            .insert(psk_at, Extension::early_data());
        assert!(!retained_early_data.is_valid_retry_of(&first));
    }

    #[test]
    /** @brief 어떤 바이트에도 패닉하지 않는지. */
    fn tls_parsers_no_panic_on_adversarial_input() {
        use crate::cert::{CertificateMsg, CertificateRequestMsg, CertificateVerify};
        use crate::handshake::HandshakeMsg;
        use crate::record::TlsRecord;
        use crate::x509::X509;

        let feed = |b: &[u8]| {
            let _ = TlsRecord::parse(b);
            let _ = HandshakeMsg::parse(b);
            let _ = ClientHello::parse(b);
            let _ = ServerHello::parse(b);
            let _ = Extension::parse_list(b);
            let _ = NewSessionTicket::parse(b);
            let _ = CertificateMsg::parse(b);
            let _ = CertificateRequestMsg::parse(b);
            let _ = CertificateVerify::parse(b);
            let _ = X509::parse(b);
        };

        let mut seed: u32 = 0x9e37_79b9;
        let mut rng = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed
        };
        for _ in 0..20000 {
            let len = (rng() % 96) as usize;
            let v: Vec<u8> = (0..len).map(|_| (rng() & 0xff) as u8).collect();
            feed(&v);
        }

        let ch = ClientHello {
            legacy_version: TLS12,
            random: [0x11; 32],
            session_id: vec![0xAB; 32],
            cipher_suites: vec![TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256],
            compression_methods: vec![0],
            extensions: vec![
                Extension::supported_versions_client(&[TLS13]),
                Extension::server_name("dns.example.com"),
                Extension::key_share_client(&[(X25519, vec![0x42; 32])]),
                Extension::alpn(&[b"dot", b"h2"]),
            ],
        };
        let sh = ServerHello {
            legacy_version: TLS12,
            random: [0x55; 32],
            session_id_echo: vec![0xAB; 32],
            cipher_suite: TLS_AES_128_GCM_SHA256,
            extensions: vec![
                Extension::supported_versions_server(TLS13),
                Extension::key_share_server(X25519, &[0x99; 32]),
            ],
        };
        let hs = HandshakeMsg::new(HandshakeType::ClientHello, ch.encode());

        let frag = hs.encode();
        let mut rec = vec![22u8, 0x03, 0x03];
        rec.extend_from_slice(&(frag.len() as u16).to_be_bytes());
        rec.extend_from_slice(&frag);

        let valids: Vec<Vec<u8>> = vec![ch.encode(), sh.encode(), hs.encode(), rec];
        for v in &valids {
            for cut in 0..=v.len() {
                feed(&v[..cut]);
                if cut < v.len() {
                    let mut m = v.clone();
                    m[cut] ^= 0xff;
                    feed(&m);
                }
            }
        }
    }
}
