# OnetDNS

광고 필터링을 내장한 DNS 서버입니다.

> 아직 정식 배포판을 낸 적이 없는 개발 단계입니다. 설정 파일 형식과 관리 API 는 예고 없이
> 바뀔 수 있고, 과거 형식을 읽어 주거나 마이그레이션을 제공하지 않습니다.

## 무엇을 할 수 있나

- **광고 차단**: hosts 형식과 AdGuard·ABP 규칙(`||example.com^`)을 함께 읽습니다. 허용
  목록과 다른 주소로 바꿔 답하기를 지원하고, 추적 도메인이 CNAME 뒤에 숨어 있으면 그
  체인을 따라가 차단합니다.
- **여러 전송 방식**: 53번(UDP/TCP)은 물론 DoT, DoQ, DoH, DoH3, DNSCrypt 로도 질의를
  받습니다. 업스트림으로 넘길 때도 암호화해서 보낼 수 있습니다. 53번으로 물어본
  클라이언트에게 암호화 주소를 알려 주어 스스로 옮겨 가게 할 수 있습니다.
- **재귀 해석**: 업스트림에 맡기지 않고 루트부터 직접 찾아갈 수 있습니다. DNSSEC 서명을
  검증하며, 도메인별로 업스트림 위임과 재귀 해석을 갈라 쓸 수도 있습니다.
- **내 영역 서비스**: 직접 관리하는 도메인을 여기서 답하게 할 수 있습니다. 영역 전송과
  변경 통지, 동적 갱신, 온라인 서명을 지원합니다.
- **주소 배포**: DHCPv4, DHCPv6, RA, PXE/TFTP 로 망 안의 기기에 주소를 나눠 줍니다. 나눠 준
  주소는 로컬 DNS 이름으로 바로 쓸 수 있습니다.
- **이중화**: 여러 대를 묶어 설정을 복제하고, 한 대가 죽으면 남은 쪽이 이어받습니다.
- **웹 화면**: 질의 흐름, 차단 현황, 업스트림 상태, 설정을 브라우저에서 봅니다.

## 설치

[릴리스](https://github.com/onetwohour/OnetDNS-server/releases)에서 운영체제와 CPU 에 맞는
압축 파일을 받아 풀면 됩니다. Linux 용은 musl 로 정적 링크해 배포판을 가리지 않고, Windows 용은
C 런타임을 넣어 두어 VC++ 재배포 패키지 없이 실행됩니다. 받은 파일은 같은 릴리스에 올린
`SHA256SUMS` 로 확인할 수 있습니다.

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

직접 빌드하려면 Rust 1.88 이상이 필요합니다.

```sh
cargo build --release          # target/release/OnetDNS
```

다른 운영체제용으로 만들려면 대상을 지정합니다.

```sh
cargo build --release --target x86_64-pc-windows-msvc
```

웹 화면을 실행 파일에 넣지 않으려면 `--no-default-features` 를 붙입니다.

## 실행

```sh
OnetDNS                                    # DNS 서버 + 웹 화면
OnetDNS --config /etc/OnetDNS/OnetDNS.toml # 설정 파일 지정
OnetDNS --no-web                           # 웹 화면 없이 DNS 서버만
```

실행하면 이렇게 동작합니다.

- `127.0.0.1:53` 에서 질의를 받기 시작합니다.
- 받은 질의는 `1.1.1.1` 과 `1.0.0.1` 로 넘깁니다.
  바꾸려면 아래 설정의 `upstream_urls` 를 고치십시오.
- `127.0.0.1:8553` 에 웹 화면이 열립니다. 처음 열면 관리자 계정을 만들라고 합니다.
- 기본값으로 사설 대역에서 오는 질의만 받습니다.

53 번 포트는 권한이 필요할 수 있습니다. Linux 는 `CAP_NET_BIND_SERVICE` 를 주거나
root 로 시작한 뒤 권한을 내려놓으면 되고, Windows 는 보통 권한으로 열립니다. 다만 Windows 는
인터넷 연결 공유나 DNS 서버 역할이 53 번을 먼저 잡고 있을 수 있으니 `netstat -ano` 로
확인하십시오.

Windows 서비스로 등록하려면 다음과 같이 합니다.

```sh
OnetDNS service install --config OnetDNS.toml
OnetDNS service uninstall
```

## 설정

TOML 파일 하나로 설정합니다. 파일이 없어도 안전한 기본값으로 돌아갑니다.

```toml
mode    = "personal"          # personal(집·사내망) | public(인터넷 노출)
backend = "forward"           # forward(업스트림에 위임) | recurse(재귀 해석) | split(도메인별)

listen = ["127.0.0.1:53", "[::1]:53"]

# 비워 두면 1.1.1.1 과 1.0.0.1 로 평문 전달합니다. 채우면 암호화해서 넘깁니다.
upstream_urls = ["https://1.1.1.1/dns-query", "https://9.9.9.9/dns-query"]

blocklist_urls    = ["https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"]
list_refresh_secs = 86400
block_response    = "nxdomain"      # nxdomain | zero_ip | refused | custom

control_listen = "127.0.0.1:8553"   # 웹 화면과 REST.
log_level      = "info"             # error | warn | info | debug | trace
```

고칠 수 있는 설정은 이보다 훨씬 많습니다. 전체 목록과 각 항목의 뜻은 웹 화면의 설정
화면에 있습니다. 파일을 고쳤다면 시작 전에 검사할 수 있습니다.

```sh
OnetDNS --cli check --config OnetDNS.toml
```

대부분의 설정은 웹 화면에서 고치거나 파일을 고친 뒤
`OnetDNS --cli reload` 를 부르면 다음 질의부터 새 설정이 적용됩니다.

## 관리

웹 화면에서 실시간 질의, 차단 현황, 업스트림 상태, 임대 목록, 클러스터 상태를 봅니다.
같은 기능을 명령으로도 쓸 수 있습니다.

```sh
OnetDNS --cli query example.com --type A   # 이 서버에 직접 물어보기
OnetDNS --cli block example.com            # 차단 목록에 추가
OnetDNS --cli allow example.com            # 허용 목록에 추가
OnetDNS --cli stats                        # 질의 통계
OnetDNS --cli top                          # 많이 물어본 이름
OnetDNS --cli reload                       # 설정 다시 읽기
OnetDNS --cli services                     # 떠 있는 수신 주소
OnetDNS --cli passwd --name 이름           # 웹 화면 계정 만들기
OnetDNS --cli cert --host example.com      # 자체 서명 인증서 만들기
```

## 집에서 쓸 때와 열어 둘 때

| | personal (집·사내망) | public (인터넷 노출) |
|---|---|---|
| 질의를 받는 범위 | 사설 대역과 지정한 대역 | 기본 전체. ACL 로 좁히기를 권합니다 |
| 속도 제한 | 권함 | **반드시 거십시오** |
| 암호화하지 않은 53번 | 망 안에서만 | 믿는 대역에서만 쓰기를 권합니다 |
| 웹 화면 | 내 컴퓨터나 망 안에서만 | 내 컴퓨터나 망 안에서만. 바깥 공개 금지 |

`public` 으로 두고 속도 제한을 걸지 않은 채 다른 호스트가 닿을 수 있는 주소에서 받으면
서버는 뜨지만 **시작할 때마다 경고를 남깁니다.** 누구나 쓸 수 있는 DNS 서버는 공격자가 남의
주소를 사칭해 질의를 보내 다른 곳을 때리는 데 쓰이기 때문입니다. 방화벽처럼 다른 수단으로
막아 두지 않았다면 속도 제한을 거십시오. 받는 주소가 전부 루프백이면 밖에서 닿을 수 없으므로
경고하지 않습니다.

## 라이선스

[Apache-2.0](LICENSE)
