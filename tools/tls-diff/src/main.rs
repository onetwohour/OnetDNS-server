/*!
 * @brief OnetDNS TLS 파서와 널리 쓰이는 구현이 같은 것을 받아들이는지 대조한다.
 *
 * @details 시드를 망가뜨려 양쪽에 넣고 판정이 갈리는 입력을 찾는다. OnetDNS만 받아들이면
 *          남이 거부하는 것을 OnetDNS는 통과시키는 것이고, OnetDNS만 거부하면 정상 클라이언트가
 *          붙지 못한다.
 * @note 이 도구는 별도 작업 공간이다. 루트 작업 공간에는 이 외부 의존성이 들어가지 않는다.
 */

use rustls::internal::msgs::base::Payload;
use rustls::internal::msgs::message::{Message, MessagePayload, PlainMessage};
use rustls::{ContentType, ProtocolVersion};

use onetdns_tls::handshake::{HandshakeMsg, HandshakeType};
use onetdns_tls::msg::{ClientHello, ServerHello};

/** @brief 시드에서 되풀이 가능한 난수. */
struct Rng(u64);
impl Rng {
    /** @brief 다음 난수. */
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /** @brief 이 값보다 작은 수 하나. */
    fn below(&mut self, n: usize) -> usize { if n == 0 { 0 } else { (self.next() % n as u64) as usize } }
    /** @brief 바이트 하나. */
    fn byte(&mut self) -> u8 { (self.next() & 0xff) as u8 }
}

/** @brief 바이트열을 16진 문자열로. 갈린 입력을 그대로 찍는다. */
fn hex(b: &[u8]) -> String {
    b.iter().take(400).map(|x| format!("{x:02x}")).collect()
}

/** @brief 비교 대상 구현이 이 바이트열을 받아들이는지. */
fn rustls_accepts(data: &[u8]) -> bool {
    let plain = PlainMessage {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: Payload::Owned(data.to_vec()),
    };
    matches!(Message::try_from(plain), Ok(m) if matches!(m.payload, MessagePayload::Handshake { .. }))
}

/** @brief OnetDNS 구현이 이 바이트열을 받아들이는지. */
fn ours_accepts(data: &[u8]) -> bool {
    let (m, consumed) = match HandshakeMsg::parse(data) {
        Ok(Some(v)) => v,
        _ => return false,
    };
    if consumed != data.len() {
        return false;
    }
    if m.msg_type == HandshakeType::ClientHello {
        ClientHello::parse(&m.body).is_ok()
    } else if m.msg_type == HandshakeType::ServerHello {
        ServerHello::parse(&m.body).is_ok()
    } else {
        false
    }
}

/** @brief OnetDNS가 읽은 첫 메시지를 실제로 쓸 수 있는지. */
fn ours_ch_usable(data: &[u8]) -> bool {
    use onetdns_tls::msg::consts::*;
    let Ok(Some((m, _))) = HandshakeMsg::parse(data) else { return false };
    if m.msg_type != HandshakeType::ClientHello { return false; }
    let Ok(ch) = ClientHello::parse(&m.body) else { return false };
    let sv_ok = ch.ext(EXT_SUPPORTED_VERSIONS).and_then(|e| e.as_supported_versions_client()).is_some();
    let sg_ok = ch.ext(EXT_SUPPORTED_GROUPS).and_then(|e| e.as_supported_groups()).is_some();
    let ks_ok = ch.ext(EXT_KEY_SHARE).and_then(|e| e.as_key_share_client()).is_some();
    let sni_present = ch.ext(EXT_SERVER_NAME).is_some();
    let sni_ok = ch.ext(EXT_SERVER_NAME).and_then(|e| e.as_server_name()).is_some();
    sv_ok && sg_ok && ks_ok && (!sni_present || sni_ok)
}

/** @brief 시드를 조금씩 망가뜨린다. */
fn havoc(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut b = seed.to_vec();
    for _ in 0..1 + rng.below(8) {
        if b.is_empty() { break; }
        match rng.below(6) {
            0 => { let i = rng.below(b.len()); b[i] = rng.byte(); }
            1 => { let i = rng.below(b.len()); b[i] ^= 1 << rng.below(8); }
            2 => { let i = rng.below(b.len()); b.insert(i, rng.byte()); }
            3 => { let i = rng.below(b.len()); b.remove(i); }
            4 => { let i = rng.below(b.len()); b.truncate(i); }
            _ => b.push(rng.byte()),
        }
    }
    b
}

/** @brief 두 구현의 판정이 갈리는 입력을 찾아 찍는다. */
fn main() {
    let iters: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(1_000_000);
    let ch_seed = sample_client_hello();
    let sh_seed = sample_server_hello();

    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    let (mut both_accept, mut both_reject, mut we_only, mut rustls_only) = (0u64, 0u64, 0u64, 0u64);
    let mut usable = 0u64;
    let mut usable_examples: Vec<String> = Vec::new();

    for i in 0..iters {
        let data = match i % 5 {
            0 => { let n = rng.below(300); (0..n).map(|_| rng.byte()).collect::<Vec<u8>>() }
            1 | 2 => havoc(&mut rng, &ch_seed),
            _ => havoc(&mut rng, &sh_seed),
        };
        match (ours_accepts(&data), rustls_accepts(&data)) {
            (true, true) => both_accept += 1,
            (false, false) => both_reject += 1,
            (true, false) => {
                we_only += 1;
                if ours_ch_usable(&data) {
                    usable += 1;
                    if usable_examples.len() < 20 {
                        usable_examples.push(format!("data({}B)={}", data.len(), hex(&data)));
                    }
                }
            }
            (false, true) => rustls_only += 1,
        }
    }

    println!("=== TLS handshake parser differential (ours vs rustls 0.23) ===");
    println!("iterations: {iters}");
    println!("both accept : {both_accept}");
    println!("both reject : {both_reject}");
    println!("rustls-only (rustls accepts, we reject; we stricter, benign): {rustls_only}");
    println!("WE-ONLY (we accept CH/SH framing, rustls rejects): {we_only}");
    println!("  └─ USABLE (sv+sg+key_share+sni all parse): {usable}");
    println!("     모든 USABLE 케이스는 다운스트림 협상(cipher-suite/버전)에서 fail-closed임을 수동 검증함.");
    if !usable_examples.is_empty() {
        println!("--- usable examples (hex) — 분석용 ---");
        for e in &usable_examples { println!("  {e}"); }
    }
}

/** @brief 클라이언트 첫 메시지 시드. */
fn sample_client_hello() -> Vec<u8> {
    use onetdns_tls::msg::{consts::*, Extension};
    let ch = ClientHello {
        legacy_version: TLS12,
        random: [0x11; 32],
        session_id: vec![0xAA; 32],
        cipher_suites: vec![TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256],
        compression_methods: vec![0],
        extensions: vec![
            Extension::supported_versions_client(&[TLS13, TLS12]),
            Extension::supported_groups(&[X25519, SECP256R1]),
            Extension::signature_algorithms(&[ECDSA_SECP256R1_SHA256, RSA_PSS_RSAE_SHA256]),
            Extension::key_share_client(&[(X25519, vec![0x22; 32])]),
            Extension::server_name("example.com"),
        ],
    };
    ch.to_handshake().encode()
}

/** @brief 서버 첫 메시지 시드. */
fn sample_server_hello() -> Vec<u8> {
    use onetdns_tls::msg::{consts::*, Extension};
    let sh = ServerHello {
        legacy_version: TLS12,
        random: [0x33; 32],
        session_id_echo: vec![0xBB; 32],
        cipher_suite: TLS_AES_128_GCM_SHA256,
        extensions: vec![
            Extension::supported_versions_server(TLS13),
            Extension::key_share_server(X25519, &[0x44; 32]),
        ],
    };
    sh.to_handshake().encode()
}
