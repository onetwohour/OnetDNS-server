/*!
 * @brief 빠른 경로 조건과 계층 순서가 말없이 바뀌지 않게 붙든다.
 *
 * @details 소스에서 표시 사이 구간을 그대로 잘라 조건 목록과 계층 순서를 비교한다.
 *          조건 하나가 빠지거나 순서가 바뀌면 여기서 걸린다.
 * @warning 여기 적힌 수와 목록은 계산해서 나온 값이 아니라 일부러 고정해 둔 것이다. 새
 *          설정을 넣었다면 그 설정이 빠른 경로를 막아야 하는지 스스로 판단하고 손으로
 *          고쳐야 한다.
 */

/** @brief 검사할 소스. */
const MAIN_RS: &str = include_str!("../src/main.rs");

/** @brief 표시 사이의 소스 구간. */
fn gate_body(begin: &str, end: &str) -> String {
    let start = MAIN_RS
        .find(begin)
        .unwrap_or_else(|| panic!("{begin} 표시를 찾지 못했습니다"));
    let stop = MAIN_RS
        .find(end)
        .unwrap_or_else(|| panic!("{end} 표시를 찾지 못했습니다"));
    assert!(start < stop, "{begin}이 {end}보다 앞이어야 합니다");
    MAIN_RS[start..stop].to_string()
}

/** @brief 조건 구간에서 조건 하나하나를 추출한다. */
fn conjuncts(body: &str) -> Vec<String> {
    let stripped: String = body
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//"))
        .collect::<Vec<_>>()
        .join(" ");
    stripped
        .split("&&")
        .map(|part| part.split_whitespace().collect::<Vec<_>>().join(" "))
        .map(|part| part.trim_end_matches(';').trim().to_string())
        .filter(|part| !part.is_empty())
        .collect()
}

#[test]
/** @brief 두 빠른 경로의 조건 목록이 그대로인지. 하나라도 빠지면 그 기능이 없는 것처럼 답이 나간다. */
fn wire_and_reactor_gates_are_pinned() {
    let authority = conjuncts(&gate_body(
        "// authority-wire-gate:begin",
        "// authority-wire-gate:end",
    ));
    let expected_authority = [
        "let authority = authority_sources_configured(cfg)",
        "cfg.acme_directory_url.is_none()",
        "cfg.dynamic_records.is_empty()",
    ];
    assert_eq!(
        authority, expected_authority,
        "권한 wire 고속 경로 게이트가 바뀌었습니다. 바깥 계층이 권한 응답을 대체할 수 \
         있다면 고속 경로를 꺼야 합니다. 의도한 변경이면 이 목록을 갱신하십시오."
    );

    let wire = conjuncts(&gate_body("// wire-gate:begin", "// wire-gate:end"));
    let expected_wire = [
        "let wire = cfg.cache_enabled",
        "cfg.cache_size > 0",
        "cfg.min_ttl == 0",
        "!cfg.prefetch",
        "matches!(cfg.ecs_mode, EcsMode::Off)",
        "cfg.dns64_prefix.is_none()",
        "!cfg.rrset_roundrobin",
        "cfg.clients.iter().all(|c| c.upstreams.is_empty())",
        "!facts.views_present",
        "!facts.policy_present",
        "!cfg.cookies.is_strict()",
        "cfg.dnstap_file.is_none()",
        "!authority_sources_configured(cfg)",
        "cfg.secondary.is_empty()",
        "cfg.catalog.is_empty()",
        "cfg.acme_directory_url.is_none()",
        "cfg.dynamic_records.is_empty()",
        "(!facts.dhcp_pool || cfg.dhcp_local_domain.is_empty())",
        "!ipset_layer_active(cfg)",
        "cfg.name_ratelimit_per_sec == 0",
        "!cfg.domain_needed",
        "!cfg.bogus_priv",
        "!cfg.empty_zones",
        "!cfg.block_aaaa",
        "cfg.edns_padding_block == 0",
    ];
    assert_eq!(
        wire, expected_wire,
        "wire 고속 경로 게이트가 바뀌었습니다. 조건을 **뺐다면** 그 기능이 응답을 \
         요청 내용만으로 결정하는지 먼저 증명하십시오. 아니면 캐시가 다른 클라이언트의 \
         답을 돌려줍니다. 의도한 변경이면 이 목록을 갱신하십시오."
    );

    let reactor = conjuncts(&gate_body("// reactor-gate:begin", "// reactor-gate:end"));
    let expected_reactor = [
        "let reactor = cfg!(unix)",
        "wire",
        "matches!(cfg.backend, BackendKind::Recurse)",
        "cfg.serve_stale_secs == 0",
        "cfg.stub_zones.is_empty()",
        "cfg.name_ratelimit_per_sec == 0",
        "cfg.cachedb_redis_host.is_none()",
        "!cfg.aggressive_nsec",
        "!cfg.harden_below_nxdomain",
    ];
    assert_eq!(
        reactor, expected_reactor,
        "리액터 레인 게이트가 바뀌었습니다. 레인은 동기 경로가 하는 일을 대신하므로, \
         조건을 빼려면 레인이 그 계층의 의미를 똑같이 낸다는 것을 먼저 보여야 합니다."
    );

    assert!(
        reactor.iter().any(|part| part == "wire"),
        "리액터 레인은 wire 고속 경로 적격을 전제로만 켜져야 합니다"
    );
}

#[test]
/** @brief 설정을 새로 넣었을 때 빠른 경로 조건을 살펴보게 만든다. */
fn adding_a_config_key_forces_a_lane_gate_decision() {
    /** @brief 지금 설정 항목 수. 일부러 고정해 둔 값이다. */
    const PINNED_CONFIG_KEYS: usize = 251;
    let actual = onetdns_config::known_keys().len();
    assert_eq!(
        actual, PINNED_CONFIG_KEYS,
        "설정 키 수가 {PINNED_CONFIG_KEYS} → {actual}로 바뀌었습니다. 새 키가 응답을 \
         요청 내용만으로 결정하지 않게 만든다면 wire 고속 경로·리액터 레인 게이트에 \
         반드시 조건을 더하십시오(docs/architecture/fast-paths.md의 wire 경로 규칙). 판단을 마친 뒤 이 수를 \
         갱신하십시오."
    );
}

#[test]
/** @brief 계층을 쌓는 순서가 그대로인지. 순서가 곧 우선순위다. */
fn layer_stack_order_is_pinned() {
    let body = gate_body("// layer-order:begin", "// layer-order:end");
    let mut seen = Vec::new();
    let mut rest = body.as_str();
    while let Some(at) = rest.find("Layer::") {
        let head = &rest[..at + "Layer".len()];
        let start = head
            .rfind(|c: char| !c.is_alphanumeric() && c != '_')
            .map(|index| index + 1)
            .unwrap_or(0);
        let name = &head[start..];
        let tail = &rest[at + "Layer::".len()..];

        if tail.starts_with("new(") || tail.starts_with("with_policy(") {
            seen.push(name.to_string());
        }
        rest = &rest[at + "Layer::".len()..];
    }

    let expected = [
        "LocalOnlyLayer",
        "FallbackLayer",
        "ForwardValidateLayer",
        "CacheDbLayer",
        "EcsLayer",
        "CacheLayer",
        "ServeStaleLayer",
        "PrefetchLayer",
        "LocalAddressLayer",
        "NameRateLimitLayer",
        "StubLayer",
        "DhcpDnsLayer",
        "IpsetLayer",
        "AuthorityLayer",
        "AcmeChallengeLayer",
        "DdrLayer",
        "DynamicRecordLayer",
    ];
    assert_eq!(
        seen, expected,
        "계층 조립 순서가 바뀌었습니다. 상대 순서가 동작을 결정합니다. 캐시가 ECS보다          안쪽으로 가면 클라이언트 서브넷이 키에서 빠지고, 권한 계층이 캐시 안쪽으로          가면 로컬 존이 가려지며, LocalOnlyLayer가 권한·DHCP 계층 바깥으로 가면          자기 home.arpa 영역을 자기가 NXDOMAIN으로 덮습니다. 의도한 변경이면          docs/architecture/layer-order.md의 계층 표와 이 목록을 함께 갱신하십시오."
    );
}

#[test]
/**
 * @brief 교체가 전부 아니면 전무인지.
 *
 * @details 이 그룹을 처리할 코드가 있는지 보는 검사보다 먼저 무엇을 바꾸면, 처리하지 못하는
 *          그룹이 섞여 있을 때 이미 바꿔 놓고 "재시작해야 한다"고 답하게 된다. 인증서를
 *          교체하고 DHCP를 재시작한 뒤에 그렇게 답한 적이 실제로 있었다.
 * @warning 새 그룹 적용 코드는 반드시 이 검사 아래에 넣어야 한다.
 */
fn hot_apply_checks_before_it_changes_anything() {
    let guard = MAIN_RS
        .find("!HOT_APPLY_HANDLED_GROUPS.contains(group)")
        .expect("교체 가능 여부 검사를 찾지 못했습니다");
    let first_apply = MAIN_RS
        .find("// hot-apply:begin")
        .expect("그룹 적용 구간 표시를 찾지 못했습니다");
    assert!(
        guard < first_apply,
        "그룹을 처리할 수 있는지 보기 전에 무언가를 바꾸고 있습니다. 적용 코드를 검사 \
         아래로 옮기십시오. 그러지 않으면 반쯤 바꿔 놓고 재시작하게 됩니다."
    );
}

#[test]
/**
 * @brief 교체가 파일만 보고 판단하지 않는지.
 *
 * @details 시작할 때 채워 넣은 기본값은 파일에 적히지 않는다. 파일만 다시 읽어 비교하면
 *          그 항목이 사라진 것으로 보인다. 실제로 질의 로그 스위치 하나를 껐을 뿐인데
 *          손대지 않은 관리 주소를 지운 것으로 처리해 웹 화면을 닫은 적이 있다.
 * @warning 이 정규화를 빼면 그 사고가 그대로 돌아온다.
 */
fn hot_apply_fills_startup_defaults_before_comparing() {
    let apply = MAIN_RS
        .find("let changed = config_changed_keys(&previous_cfg, next)?;")
        .expect("교체 비교 지점을 찾지 못했습니다");
    let normalize = MAIN_RS
        .find("let next = &normalize_config_for_comparison(&previous_cfg, next);")
        .expect(
            "교체 경로가 시작 기본값을 채우지 않습니다. 파일에 없는 기본값이 \
             지워진 것으로 보여 손대지 않은 항목을 끕니다.",
        );
    assert!(
        normalize < apply,
        "기본값을 채우기 전에 비교하고 있습니다. 정규화를 비교 위로 옮기십시오."
    );
}

#[test]
/**
 * @brief 교체가 통계를 모을지 여부를 다시 정하는지.
 *
 * @details 관리 수신 주소는 세대를 다시 만들지 않고 교체할 수 있다. 시작할 때 한 번
 *          정한 판정을 그대로 두면, 주소를 나중에 연 사람은 대시보드에 아무것도 보이지
 *          않고 주소를 닫은 사람은 아무도 읽지 않는 통계 비용을 계속 낸다.
 * @warning 이 호출을 지우면 두 증상이 조용히 돌아온다. 어느 쪽도 오류로 드러나지 않는다.
 */
fn hot_apply_redecides_whether_to_collect() {
    let end = MAIN_RS
        .find("// hot-apply:end")
        .expect("그룹 적용 구간 끝 표시를 찾지 못했습니다");
    let done = MAIN_RS[end..]
        .find("event = \"config.runtime_hot_applied\"")
        .expect("교체 성공 지점을 찾지 못했습니다");
    assert!(
        MAIN_RS[end..end + done].contains("set_collecting(telemetry_consumed(next))"),
        "교체 성공 경로가 통계 수집 여부를 다시 정하지 않습니다. 시작할 때의 \
         판정이 그대로 남아 관리 주소를 열어도 대시보드가 비어 있게 됩니다."
    );
}
