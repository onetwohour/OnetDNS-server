# DNS hot-cache 비교 벤치

이 벤치는 세 엔진이 같은 로컬 권한 서버에서 같은 10,000개 A 레코드를 먼저 채운 뒤, UDP 캐시 히트 처리량과 프로세스 RSS를 비교한다. 외부 네트워크, 재귀 탐색, DNSSEC 검증, 필터 기능을 비교하는 벤치가 아니다.

## 고정 조건

- WSL2 Ubuntu 24.04.1, 28 vCPU, 15.8 GiB RAM
- `dnsperf` 2.14.0, Unbound 1.19.2, AdGuard Home v0.107.76
- 권한 서버 CPU 0, 부하 발생기 CPU 1, 대상 서버 CPU 2
- 서버 worker 1개(AdGuard Home은 `GOMAXPROCS=1`), UDP만 사용
- `dnsperf -q 100 -c 1 -T 1`, 2초 워밍업 뒤 10초씩 5회
- 쿼리 로그·통계·필터·DNSSEC·prefetch 비활성, 손실률 0%인 회차만 유효
- QPS와 평균 지연은 5회 중앙값, RSS는 워밍업 뒤 `/proc` 스냅샷

캐시 크기의 단위가 서로 다르다. OnetDNS는 엔트리 20,000개, Unbound는 message/rrset 각 64 MiB, AdGuard Home은 64 MiB로 설정했다. 따라서 RSS는 설정값이 아니라 실제 워밍업 뒤 프로세스 값을 함께 비교한다. **이 축의 고유 이름은 10,000개라 네 엔진 모두 전량을 보유할 수 있어 용량 차이가 결과를 가르지 않는다** — 고유 이름이 OnetDNS 용량을 넘는 재귀 콜드미스 축에서는 이 비대칭이 실제로 RSS 비를 왜곡했다([`../dns-recurse/README.md`](../dns-recurse/README.md) 참조).

> **2026-08-01 — 이 축의 지연이 −43.5%가 됐다.** 권한 축에서 고친 `scan_query`의 memcpy
> 호출이 wire 고속 경로 전체가 지나가는 곳이라 여기에도 그대로 듣는다. A-B 교대 3레그씩,
> 전 레그 유실 0, RSS 양쪽 8,736 KiB 동일:
>
> | 구성 | QPS | 지연 |
> |---|---:|---:|
> | 수정 전 | 543,421 ~ 547,461 | 0.119 ~ 0.122 ms |
> | **수정 후** | 533,371 ~ 538,338 | **0.067 ~ 0.069 ms** |
>
> **처리량은 늘지 않았다.** 그때는 하네스가 부하 생성기에 묶여 있다고 봤으나,
> **재 보니 그렇지 않았다.** 서버 레그를 그대로 두고 생성기 코어만 1→2로 올렸을 때
> QPS는 537,085 → 548,159로 **+2.1%(잡음 범위)**인데 지연은 0.067 → 0.156 ms로 **2.3배**가
> 됐다. 동시성을 올려도 처리량이 안 늘고 큐만 쌓이는 것은 **서버 쪽 천장**의 신호다.
> 따라서 아래 표들의 QPS는 그대로 유효하다. 핸들은
> `DNSPERF_CLIENTS`·`DNSPERF_THREADS`·`DNSPERF_OUTSTANDING`이고 기본값은 종전 그대로다.
>
> **중간에 얻은 "생성기 코어 1→2에서 +18.2%"는 철회한다** — 낮게 나온 레그 하나와 비교한
> 값이었고 깨끗한 구간에서 재현되지 않았다. 한 번의 계단 비교로 천장을 단정하면 안 된다.
>
> **더 밀어붙이는 시도는 전부 무효였다(2026-08-01).** 생성기 코어를 4·8로 올리면 폐루프
> QPS가 오히려 296k·274k로 떨어지고, 제공률 고정(`-Q`)으로 바꾸면 다중 스레드 버스트가
> 두 엔진을 다 무너뜨린다(OnetDNS 246k · dnsmasq 113k, 양쪽 유실 발생). 같은 회차에서 dnsmasq
> 레그가 58k로 붕괴한 것이 설정 자체가 성립하지 않았다는 증거다. **그 수치들은 하나도
> 인용하지 말 것.**
>
> 같은 구간 4엔진 재측정: OnetDNS 512,656~543,622 대 dnsmasq 348,394(+47.1%) ·
> CoreDNS 108,702(4.72배) · AdGuard 47,206(10.86배) — OnetDNS 최악 레그 기준이고 레그
> 드리프트가 5.89%로 게이트를 조금 넘어 하한으로만 쓴다. 지연은 0.067~0.071 대
> 0.278 · 0.915 · 2.114 ms로 **dnsmasq의 0.25배**다(종전 0.43배).

> **2026-08-01 — 이 축의 RSS는 검증됐다.** 권한 축에서 NSD가 자식을 fork해 단일 PID
> 관측이 8배 낮게 나오는 것을 확인한 뒤, `run-rss-interleave.sh`를
> [`../lib/procmem.sh`](../lib/procmem.sh)로 바꿔 프로세스 수를 함께 낸다. **다섯 엔진
> (OnetDNS·Unbound·dnsmasq·CoreDNS·AdGuard Home) 전부 `procs=1`**이라 이 문서의 단일 PID
> `VmRSS` 수치는 그대로 유효하다 — 같은 구간 재측정에서 OnetDNS 6,496/8,736,
> dnsmasq 6,944/6,944, Unbound 17,024/24,640이 KiB까지 재현됐다. 하네스는 이제 Pss도
> 함께 내지만, `procs=1`인 엔진은 VmRSS가 그 엔진이 혼자 돌 때 만지는 페이지이므로
> **비교에는 VmRSS를 쓴다**(Pss는 공유 libc를 나눠 계상해 정적 musl 빌드에 불리하다).

## 2026-07-29 공유 UDP 워커의 적응형 배치

전달 백엔드 자동값은 업스트림 응답 대기를 겹치기 위해 가용 CPU당 UDP worker 4개를 같은
소켓에 붙인다. 고정 배치 32는 단일 worker hot-cache에는 가장 빨랐지만, 28코어에서는
112개 worker가 수신·송신 배열을 선할당한다. 전역 배치 16은 두 번의 순방향·역방향
O–N–N–O–O–N에서 hot 중앙값을 1.5~2.3% 낮춰 기각했다.

현재 구현은 worker 수가 가용 CPU 이하인 전용 경로에서 32를 유지하고, worker가 CPU보다
많아 소켓을 공유할 때만 16을 쓴다. 단일-worker 최종 A/B는 기준
507,920~511,397 대 후보 506,021~511,510 QPS로 범위가 겹쳤고, 중앙 차이 0.74%는 후보
드리프트 1.08%보다 작았다. 양쪽 `VmData`도 8,504 KiB로 같아 실제 선택값 32를 확인했다.

`WORKERS=0 NO_CACHE=1 run-evict-interleave.sh`의 1코어 A–B–dnsmasq 3회 결과는 다음과 같다.
모든 레그가 정답 확인과 유실 0을 통과했다.

| 배치 | 중앙 QPS 범위 | 평균 지연 범위 | RSS |
|---|---:|---:|---:|
| 고정 32 | 68,169~68,667 | 1.443~1.453 ms | 6,272 KiB |
| 적응형 16 | 68,094~68,944 | 1.440~1.458 ms | **5,824 KiB** |
| dnsmasq 2.90 | 48,255~48,396 | 2.061~2.066 ms | 4,704 KiB |

적응형의 중앙 처리량 차이는 +0.09%로 없고 RSS는 세 쌍 모두 448 KiB(7.1%) 낮았다.
28코어 자동 전달 구성에서는 worker 수에 비례하는 같은 고정 비용이 약 12.25 MiB 줄어든다.
하네스도 함께 고쳐 `run-dnsperf.sh | tail` 파이프가 앞 명령의 실패를 숨기지 않으며, 각
레그의 실제 RSS를 결과에 포함한다.

## 2026-07-17 affinity 정정 후 측정 결과

| 엔진 | QPS 5회 | 중앙 QPS | 중앙 평균 지연 | RSS | 손실 |
|---|---|---:|---:|---:|---:|
| OnetDNS 현재 | 269,938 / 263,584 / 242,186 / 260,993 / 262,825 | 262,825 | 0.358 ms | 14.66 MiB | 0% |
| Unbound 1.19.2 | 381,401 / 331,764 / 363,209 / 363,922 / 361,185 | 363,209 | 0.172 ms | 24.06 MiB | 0% |
| AdGuard Home v0.107.76 | 41,068 / 40,034 / 39,836 / 36,761 / 39,968 | 39,968 | 2.495 ms | 47.71 MiB | 0% |

이 workload에서 OnetDNS는 AdGuard Home보다 6.58배 높은 처리량, 85.7% 낮은 평균 지연, 69.3% 낮은 RSS를 기록했다. 반면 Unbound 처리량의 72.4%이며 평균 지연도 더 높으므로 아직 Unbound를 앞섰다고 주장할 수 없다. OnetDNS의 RSS는 Unbound보다 39.1% 낮았다.

초기 표를 만든 시점의 OnetDNS `pin_to_core(0)`은 `taskset -c 2`가 허용한 CPU 집합을 무시하고 절대 CPU 0을 선택했다. 따라서 그 표의 OnetDNS 수치를 CPU 2에서 실행한 경쟁 엔진과 직접 비교할 수 없었다. 런타임이 inherited affinity 안에서 worker를 선택하도록 수정한 뒤, 각 프로세스와 스레드의 `PSR`이 CPU 2인지 확인하고 위 표 전체를 다시 측정했다. 작업 시작 OnetDNS 119,957 QPS와 이름 공유 저장소 적용 후 254,944 QPS는 둘 다 이 오류가 있던 동일 CPU 0 조건의 내부 A/B이므로 112.5% 개선이라는 회귀 자료로만 남기며 경쟁 엔진 비교에는 사용하지 않는다.

WSL2가 일부 회차에서 약 0.86~0.89초 동안 프로세스를 정지시켰다. 해당 정지는 OnetDNS 1·4회, Unbound 2회, AdGuard Home 4회의 최대 지연에서 관측되며 표에는 그대로 포함했다. 이 결과는 제품 전체의 우열이 아니라 이 장비의 단일 worker hot-cache 회귀 기준이다.

캐시가 shard 하나만 쓸 때 불필요한 SipHash를 건너뛴 변경은 같은 CPU 2에서 직전 바이너리 243,496 QPS/0.385 ms와 변경 바이너리 252,610 QPS/0.374 ms를 각각 5회 측정해, 중앙값 기준 처리량 +3.74%와 평균 지연 -2.86%를 확인한 뒤 채택했다.

이어 DNS 이름을 라벨별 할당의 공유 벡터 대신 단일 연속 wire buffer로 저장한 변경은 같은 시간대에 직전 바이너리 250,395 QPS/0.375 ms/RSS 16.41 MiB와 변경 바이너리 262,825 QPS/0.358 ms/RSS 14.66 MiB를 각각 5회 측정했다. 중앙값 기준 처리량 +4.96%, 평균 지연 -4.53%, RSS -10.7%여서 채택했다. 변경 바이너리의 선행 5회도 중앙값 259,957 QPS/0.360 ms로 같은 방향을 보였다.

## 재현

도구는 제품 의존성이 아니라 벤치 환경에만 설치한다. 저장소의 설정은 `/home/ubuntu/onetdns-bench`를 고정 작업 디렉터리로 사용한다.

```sh
sudo apt-get install dnsperf unbound
mkdir -p /home/ubuntu/onetdns-bench
sh benchmarks/dns-cache/generate-data.sh /home/ubuntu/onetdns-bench
cp benchmarks/dns-cache/onetdns-*.toml /home/ubuntu/onetdns-bench/
cp benchmarks/dns-cache/unbound.conf benchmarks/dns-cache/AdGuardHome.yaml \
  /home/ubuntu/onetdns-bench/

RUSTFLAGS='-D warnings -C linker=rust-lld -C link-self-contained=yes' \
  cargo build -p onetdns --release --target x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/onetdns /home/ubuntu/onetdns-bench/
```

런타임 의존성에 C/asm 코드가 없으므로 위 명령만으로 크로스빌드가 끝난다
(별도 C 컴파일러·`CC_*` 환경변수 불필요). `rcgen`이 끌어오는 ring은
dev-dependency라 `cargo build`에는 들어오지 않지만, musl 타깃에서
`cargo test`를 돌리려면 musl용 C 컴파일러가 필요하다.

먼저 권한 서버를 CPU 0에 시작한다.

```sh
taskset -c 0 /home/ubuntu/onetdns-bench/onetdns \
  --config /home/ubuntu/onetdns-bench/onetdns-authority.toml \
  --no-web --no-supervisor
```

다른 터미널에서 한 대상만 CPU 2에 시작하고 대응 포트로 측정한다.

```sh
# OnetDNS, port 15353
taskset -c 2 /home/ubuntu/onetdns-bench/onetdns \
  --config /home/ubuntu/onetdns-bench/onetdns-cache.toml \
  --no-web --no-supervisor

# Unbound, port 15354
unbound-checkconf /home/ubuntu/onetdns-bench/unbound.conf
taskset -c 2 unbound -d -c /home/ubuntu/onetdns-bench/unbound.conf

# AdGuard Home, port 15355
mkdir -p /home/ubuntu/onetdns-bench/adguard-work
GOMAXPROCS=1 taskset -c 2 /home/ubuntu/onetdns-bench/AdGuardHome/AdGuardHome \
  -c /home/ubuntu/onetdns-bench/AdGuardHome.yaml \
  -w /home/ubuntu/onetdns-bench/adguard-work --no-check-update
```

```sh
sh benchmarks/dns-cache/run-dnsperf.sh 15353
sh benchmarks/dns-cache/run-dnsperf.sh 15354
sh benchmarks/dns-cache/run-dnsperf.sh 15355
```

측정에 사용한 AdGuard Home Linux AMD64 v0.107.76 archive의 SHA-256은 `23f364f13a452cf2d4f7c5b1465508a83fda803e56bd38297fa62ab31734e222`였다. 릴리스나 컴파일러가 바뀌면 기존 표와 섞지 말고 새 결과 구간을 추가한다.

## 2026-07-17 wire 고속 경로 + recvmmsg 배치 이후 측정 결과

이 날 WSL2 호스트 성능이 시간대에 따라 크게 출렁였다(같은 Unbound 바이너리가
278k→385k QPS). 따라서 세션 간 절대값 비교는 무효로 하고, 두 엔진을 같은 시간
구간에서 O–U–O 순서로 연속 측정한 인터리브 구간만 비교 근거로 남긴다.

| 순서 | 엔진 | 중앙 QPS | 중앙 평균 지연 | RSS |
|---|---|---:|---:|---:|
| 1 | OnetDNS(wire+mmsg) | 411,536 | 0.208 ms | 19.9 MiB |
| 2 | Unbound 1.19.2 | 385,031 | 0.175 ms | 24.4 MiB |
| 3 | OnetDNS(wire+mmsg) | 426,057 | 0.203 ms | 19.9 MiB |

이 인터리브 구간에서 OnetDNS 처리량은 Unbound 대비 +6.9%~+10.7%, RSS는 18% 낮았다.
같은 세션 내부 A/B(동일 시간대 연속 측정)로는 wire 경로 도입 전 기준선
242,660 QPS/0.381 ms → mmsg 배치만 252,073 QPS/0.317 ms → wire+mmsg
385,432 QPS/0.218 ms였다.

두 변경의 내용:
- Linux UDP 워커가 recvmmsg/sendmmsg로 배치(8) 단위 수신·송신. 포화 상태에서
  시스콜 비용을 상각한다(쿼리당 커널 2.26→1.62 µs 실측).
- UDP wire 고속 경로(`onetdns-bin/src/wirecache.rs`): 정책 판정(ACL·rate·filter)
  이후 완성 응답의 인코딩 결과를 필터 버전 태그와 함께 저장하고, 히트 시
  ID·질의 이름 케이스·TTL만 패치해 송신한다(쿼리당 유저 1.65→0.56 µs 실측).
  ECS/DNS64/프리패치/뷰/권한 영역/쿠키 등 응답을 요청·클라이언트 축으로
  변형하는 기능이 하나라도 켜지면 조립 단계에서 경로 자체가 비활성화된다.

정합성은 동일 서버에 대해 dig로 TTL 감소, EDNS/DO, +noedns, NXDOMAIN(부정
응답은 저장 안 함), 0x20 케이스 반사를 확인했다.

## 2026-07-17 회귀 확인 인터리브 (rate limit·기록 경로 정리 이후)

wire 히트 rate limit 순서 수정·기록 경로 중복 제거 커밋 이후 hot-cache 처리량이
회귀하지 않았는지, 같은 시간 구간에서 O–U–O 인터리브로 재확인했다. 이 벤치는
`querylog=false`·`--no-web`라 Recorder가 없어 기록 경로 최적화는 나타나지 않으며,
순수 wire 고속 경로 처리량의 회귀 여부만 본다.

| 순서 | 엔진 | 중앙 QPS | 중앙 평균 지연 |
|---|---|---:|---:|
| 1 | OnetDNS(HEAD) | 453,766 | 0.188 ms |
| 2 | Unbound 1.19.2 | 421,981 | 0.151 ms |
| 3 | OnetDNS(HEAD) | 450,311 | 0.194 ms |

두 OnetDNS 회차(453,766·450,311)가 Unbound(421,981)를 사이에 두어, 이 구간에서
처리량 +6.7%~+7.5% 우위를 유지했다(회귀 없음). musl 크로스빌드는 Windows에서
`x86_64-unknown-linux-musl` 타깃 + `RUSTFLAGS='-C linker=rust-lld
-C link-self-contained=yes'`로 생성했다.

### 자원 사용(워밍업 후 실측)

같은 20,000 엔트리 hot cache를 채운 뒤 `/proc/PID/status`의 VmRSS·VmHWM(피크)을
읽었다. 최소 자원 근거다.

| 엔진 | RSS | 피크(VmHWM) | 정적 바이너리 |
|---|---:|---:|---:|
| OnetDNS full(대시보드 포함) | 19.47 MiB | 19.47 MiB | 6.56 MiB (musl, glibc 비의존) |
| OnetDNS minimal(대시보드 없음) | 19.47 MiB | 19.47 MiB | 6.56 MiB |
| Unbound 1.19.2 | 23.84 MiB | 23.84 MiB | — |

OnetDNS는 Unbound보다 RSS 18.3% 낮고, 피크가 정상값과 같아 워크로드 중 메모리
스파이크가 없다. full·minimal 빌드의 런타임 RSS가 동일한 것은 대시보드 HTML이
정적 rodata라 서빙하지 않으면(`--no-web`) RSS에 들어가지 않기 때문이다. 정적 musl
바이너리는 glibc 비의존이라 최소 리눅스/임베디드에도 그대로 배포된다. 적대적
부하에서의 메모리 상한은 캐시(LruMap 고정 cap)·rate limiter(샤딩 LRU
`CAP_PER_SHARD=4096`)·메트릭(포화 시 드롭하는 bounded 채널)로 보장된다.

### 2026-07-26 레코드 레이아웃 Windows A/B

`RData/Record` 48/72B 후보와, 같은 소스에 도달 불가능한 56B payload만 추가해
64/88B를 복원한 대조 바이너리를 비교했다. WSL 권한 서버의 10,000개 고유 A 레코드를
매 회 새 Windows release 캐시에 정확히 한 번씩 넣고 두 후보를 각각 10회 측정했다.
시작 직후와 워밍 증가분은 각 후보의 반복 5회에서 별도로 기록했다.

| 레이아웃 | 워밍 Private 중앙값 | 워밍 Working Set 중앙값 | 시작 Private 중앙값 | Private 워밍 증가 중앙값 |
|---|---:|---:|---:|---:|
| `RData` 48B / `Record` 72B | **25.946 MiB** | **20.777 MiB** | 16.996 MiB | **8.977 MiB** |
| 패딩 대조 `RData` 64B / `Record` 88B | 26.502 MiB | 21.334 MiB | 17.004 MiB | 9.500 MiB |

시작 Private 차이는 0.008MiB뿐이지만 워밍 뒤에는 Private와 Working Set이 모두
0.557MiB 감소했다. 전체 Private는 2.1%, 기동분을 뺀 캐시 성장량은 5.5% 감소해
바이너리 크기나 시작 편차가 아니라 레코드 레이아웃 축소 효과임을 확인했다.

### 2026-07-26 LruMap 단일 키 저장 A/B

기존 `LruMap`은 실제 키를 해시 인덱스와 노드에 한 번씩 저장했다. 새 구현은 실제 키를
노드에만 두고, 프로세스마다 무작위화된 64비트 digest를 인덱스로 쓴다. digest가 같은
서로 다른 키는 노드 충돌 체인에서 원래 키의 `Eq`로 구분하므로 정확성과 HashDoS 방어를
유지한다. `K: Clone` 제약과 삽입·퇴거의 키 복제가 사라졌으며 외부 의존성은 추가하지
않았다.

32바이트 `Vec<u8>` 키 16,384개, 히트 1,000만 회, 삽입·퇴거 100만 회를 release에서
각 5회 측정했다. 시간은 중앙값이고, 보유 바이트는 사용자 키 버퍼까지 포함해 5회 모두
동일했다. 재현 명령은 `cargo bench -p onetdns-core --bench lrumap`이다.

| 구현 | 보유 메모리 | 엔트리당 | get hit | put + LRU 퇴거 |
|---|---:|---:|---:|---:|
| 기존 이중 키 | 2,916,368 B | 178.0 B | 45.85 ns | 180.94 ns |
| 단일 키 + digest 충돌 체인 | **1,998,864 B** | **122.0 B** | **43.54 ns** | **90.09 ns** |

따라서 보유 메모리는 정확히 917,504B, 엔트리당 56B, 전체 31.5% 줄었다. 히트는 5.0%,
삽입·퇴거는 50.2% 빨라져 메모리를 줄이기 위해 핫 경로를 희생하지 않았다.

실제 서버도 레코드 레이아웃이 같은 변경 전 release와 변경 후 release를 O–N–O 순서로
비교했다. WSL 권한 서버의 10,000개 고유 A 레코드를 매 회 새 Windows 캐시에 한 번씩
넣었고, 기존은 앞뒤 합계 10회, 신규는 5회 측정했다.

| 구현 | 시작 Private | 워밍 Private | Private 증가분 | 워밍 Working Set |
|---|---:|---:|---:|---:|
| 기존 이중 키 | 16.988 MiB | 25.959 MiB | 8.967 MiB | 20.846 MiB |
| 단일 키 + digest 충돌 체인 | **13.574 MiB** | **21.637 MiB** | **8.047 MiB** | **18.992 MiB** |

시작 Private는 20.1%, 워밍 Private는 16.6%, 캐시 증가분은 10.3% 감소했다. Working
Set도 중앙값 8.9% 감소했지만 OS 회수 타이밍에 따른 변동이 커 보조 지표로만 본다.
WSL에서 Windows 서버로 직접 QPS를 재려던 시도는 호스트 방화벽이 패킷을 전부 막아
무효 처리했으며, 위 성능 수치나 우위 주장에 포함하지 않았다.

### 2026-07-26 wire/구조화 캐시 단일 payload·단일 LRU A/B

UDP 응답은 이전에 wire 캐시의 인코딩 blob과 일반 응답 캐시의 파싱된 레코드로 두 번
보관됐다. 1단계 구현은 일반 캐시 항목을 같은 `Arc<WireEntry>`로 승격해 두 LRU가 payload
하나를 공유했다. UDP hit는 그대로 wire를 바로 내보내고, TCP·암호화 전송이 같은 항목에
적중할 때만 wire를 `Message`로 파싱한다. 승격 도중 더 최신 응답이 들어오면 포인터
동일성 검사가 오래된 wire의 덮어쓰기를 거부한다. 외부 의존성은 추가하지 않았다.

직전 release `6F045D4116C00B1701E89E880488B3F13EA9B21785396C336E684AEDA4E3AC17`와
최종 후보 `30D4539BDF3D07D0FDE4973C5A4AF666CBCCEDCD7514E9C739987DD3FD374202`를
Windows에서 O–N–N–O–O–N 순서로 교차 실행했다. 각 회차는 worker 1개와 동일한 로컬
권한 서버를 사용해 존재하는 A 레코드 10,000개를 새 캐시에 정확히 한 번씩 채웠다.
모든 회차가 정답 10,000개·실패 0개였고, 아래 값은 각 3회의 산술 평균이다.

| 구현 | 시작 Private | 워밍 Private | Private 증가분 | 캐시 채우기 |
|---|---:|---:|---:|---:|
| 별도 wire + 구조화 payload | 13.569 MiB | 21.630 MiB | 8.061 MiB | 5,946 qps |
| 단일 공유 wire payload | 13.605 MiB | **18.068 MiB** | **4.462 MiB** | **6,007 qps** |

워밍 Private는 3.563MiB(16.5%), 캐시가 늘린 Private는 44.6% 감소했다. 캐시 채우기
처리량은 1.0% 높아져 저장 표현 변경에 따른 회귀 신호가 없었다. UDP hit 전용 release
마이크로벤치 5회의 `scan + get + emit` 중앙값은 72.6ns(13.8Mops/s)였다.

TTL 정합성도 공유 경계에서 고정했다. wire 보존 수명과 실제 응답 TTL 필드 모두 사용자
`max_ttl`, 원래 레코드 TTL, 구조화 캐시가 계산한 DNSSEC/RRSIG 잔여 수명의 최솟값을
사용한다. `min_ttl > 0`은 TTL을 올릴 수 없는 wire 경로를 계속 비활성화한다. 따라서
300초 응답에 DNSSEC 잔여 수명이 5초면 즉시 TTL 5, 4초 뒤 TTL 1을 내보내고 5초에
만료된다.

그 뒤 남아 있던 두 번째 wire LRU도 제거했다. 일반 응답 LRU의 `Entry::Wire`가 UDP
fast path의 유일한 인덱스이므로 정규화 키, LRU 노드, digest 인덱스, 샤드 mutex가
이름마다 한 벌만 존재한다. 캐시 플러시도 단일 저장소만 비우며, 필터 세대가 다르면
항목을 버리지 않고 일반 경로에서 최신 정책으로 재검증한다. 의미가 사라진
`wire_cache_size` 설정은 호환 계층 없이 삭제했다.

정적 musl 기준선 `AD67CD1CC0DB92891F0B60CFE1AEBDF6D9D3E392A87277355878E15996107811`와
최종 후보 `C53BEB7FE9F525DB0E1D4D4FB0499831BE2E5B03486FE45A3E8DF49CB8687BBD`를
WSL2에서 O–N–N–O–O–N 순서로 실행했다. authority/부하/대상은 CPU 0/1/2에 각각
고정했고, 매 회 새 프로세스에 같은 10,000개 정답을 정확히 한 번 채웠다. 아래 값은
각 3회 중앙값이다.

| Linux musl 구현 | startup RSS | 10K 워밍 RSS | RSS 증가분 | 워밍 anonymous RSS |
|---|---:|---:|---:|---:|
| payload 공유 + LRU 2개 | 5.469 MiB | 12.688 MiB | 7.219 MiB | 7.656 MiB |
| payload·인덱스 모두 단일화 | 5.469 MiB | **11.375 MiB** | **5.906 MiB** | **6.125 MiB** |

워밍 RSS와 캐시 증가분은 각각 1.313MiB(10.3%, 18.2%) 줄었다. anonymous RSS는
1.531MiB, 캐시가 늘린 anonymous RSS는 22.6% 감소해 파일 매핑 변동과 무관하게 구조
효과가 확인됐다. 바이너리도 9,413,056→9,402,016B로 11,040B 작아졌다. 무손실 Linux
hot 회차 중앙값은 기준 520.6k, 후보 516.7k qps(−0.7%, WSL 실행간 드리프트 범위)였고,
인프로세스 300만 회 벤치는 lookup 38.7→38.4ns, 전체 72.6→73.7ns로 분포가 겹쳐
처리량 회귀 신호가 없었다. 재현은 다음 명령이다.

단일 LRU 뒤에도 wire 항목은 `Arc<Entry::Wire(Arc<WireEntry>)>`로 중첩돼 있었다.
`Entry`의 구조화 변형이 80B라 wire도 바깥 `Arc`에 80B 본체를 할당했다. 캐시 노드가
`Structured(Arc<_>) | Wire(Arc<_>)`라는 16B tagged pointer를 직접 갖게 바꿔 wire의
바깥 본체와 할당 한 번을 제거했다. stale promotion은 두 안쪽 `Arc`의 포인터 동일성으로
계속 거부하므로 동시성 의미는 바뀌지 않는다. 기준선은 위 단일-LRU 빌드 `C53B...`,
후보는 정적 musl 빌드
`0B0B5E4C12155ECED949BA9D80168DEA561C87AB5F6C5FD4505EEBA21E69CD0A`다.

동일 O–N–N–O–O–N을 독립 2세트(각 구현 6회) 실행했다. anonymous 값은 모든 회차가
동일했고, RSS는 파일 페이지 상주 차이 때문에 중앙값을 썼다.

| 단일-LRU 구현 | 10K 워밍 RSS | RSS 증가분 | 워밍 anonymous RSS | anonymous 증가분 |
|---|---:|---:|---:|---:|
| 중첩 `Arc<Entry::Wire(Arc<_>)>` | 11,424 KiB | 5,824 KiB | 6,272 KiB | 5,376 KiB |
| 16B tagged `Arc` 직접 보유 | **10,640 KiB** | **5,152 KiB** | **5,376 KiB** | **4,480 KiB** |

워밍 RSS는 784KiB(6.9%), 캐시 RSS 증가는 672KiB(11.5%) 감소했다. allocator와 파일
매핑 변동에 덜 민감한 anonymous 기준으로는 896KiB, 캐시 증가분 16.7%가 줄어 정적
예상(80B × 10,000 + 할당 메타데이터)과 일치했다. 손실이 있던 회차를 제외한 두 세트
합산 hot QPS 중앙값은 기준 542,031, 후보 546,240(+0.8%)로 CPU 회귀도 없었다.

그 다음 wire blob, TTL `(offset, original)` 배열, 답변 요약 문자열을 한 불변
`Box<[u8]>`에 연속 저장했다. retained 할당이 하나 줄고 `WireEntry` 고정 본체는
80→56B가 됐다. TTL 메타데이터는 native-endian 8B 쌍으로 읽되 모든 범위는 저장 시
확정한 `wire_len`·`ttl_count`로 나뉘며, 답변 요약은 `String`에서 복사한 UTF-8만
노출한다. 후보 정적 musl 바이너리는
`99401949AFCE4694FA3BF2E6329A7A622095492E6C0523E36A18F56257A8BD30`(9,403,584B)다.

직전 tagged-Arc 후보와 같은 교차 순서를 다시 2세트 실행했다.

| 16B tagged-Arc 구현 | 10K 워밍 RSS | RSS 증가분 | 워밍 anonymous RSS | VmData |
|---|---:|---:|---:|---:|
| blob·TTL 별도 할당 | 10,528 KiB | 5,152 KiB | 5,376 KiB | 19,196 KiB |
| 단일 packed storage | **10,304 KiB** | **4,704 KiB** | **4,928 KiB** | **18,860 KiB** |

anonymous 감소 448KiB는 6회 전부 같았고 캐시 RSS 증가분은 8.7% 줄었다. WSL 클록이
명백히 튄 기준선 974k 표본과 패킷 손실 표본은 성능 집계에서 제외했다. 남은 무손실
표본의 중앙값은 526,055→537,175qps(+2.1%)였고, 독립 두 번째 세트만 비교해도 약
+0.9%여서 TTL 메타데이터 디코딩으로 인한 회귀 신호가 없었다. Windows 300만 회
인프로세스 전체 경로 10회 중앙값은 75.0ns(13.3Mops/s)였다.

그 다음 실제 fixture와 같은 `capacity=20,000`, fill 10,000, key 30B, packed storage
62B 모델을 전용 tracking allocator로 분해했다. packed 후보의 LRU 선할당은
1,837,072B, 채운 엔트리의 요청량은 1,640,000B였고 musl 클래스 반올림을 적용하면
엔트리당 192B였다. 이 합계는 실서버 anonymous 증가와 약 275KiB 차이였다.

세 축을 순서대로 격리했다.

1. 저장된 qname 길이는 캐시 키가 이미 보장하므로 제거하고 DNS wire 길이를 프로토콜
   상한에 맞는 `u16`으로 좁혀 `WireEntry` 56→48B, musl `Arc` 클래스 96→64B로
   내렸다. `9940...`→`D83C6381041899D8A47B177A52F632AAD00C80EC7AEEF1C7A522FA3BFF849A90`.
2. 생성 뒤 불변인 30B 키를 `Vec<u8>` 대신 `Box<[u8]>`로 보유해 LRU 노드를
   64→56B로 줄였다. `D83C...`→`18EC097F42B5A020BC3E284C48015A109BA41FE14AF2957F2E735DC975986C28`.
3. 설정 상한 10,000,000보다 충분히 넓은 `u32`로 `prev/next/hash_next/free` 인덱스를
   좁혀 노드를 56→48B로 줄였다. digest는 64비트 그대로이며 충돌 시 실제 키를 계속
   비교한다. 최종 후보는
   `533C873F1F40ED0A1B170658EB9A4E01663C1105EB5AE6386B9E86A65F0C1674`
   (9,408,064B)다.

| 단계 | warm anonymous | VmData | tracking LRU 선할당 |
|---|---:|---:|---:|
| packed storage 기준 | 4,928 KiB | 18,860 KiB | 1,837,072B |
| `WireEntry` 48B | 4,704 KiB | 18,532 KiB | 1,837,072B |
| 불변 키 16B owner | 4,480 KiB | 18,348 KiB | 1,677,072B |
| 모든 LRU 링크 `u32` | **4,480 KiB** | **17,600 KiB** | **1,517,072B** |

각 단계는 O–N–N–O–O–N을 독립 2세트씩 실행했다. 첫 두 단계는 anonymous가 회차마다
224KiB씩 감소했고 마지막 단계는 여러 LRU의 예약 폭이 함께 줄어 VmData가 748KiB
감소했다. 마지막 단계의 완전 무손실 두 번째 세트는 517,423→517,246qps(−0.03%),
두 세트 정상 표본 합산은 +0.8%였다. Windows wire 전체 경로 5회 중앙값도
75.2→74.6ns로 회귀가 없었다. 최종 6회 워밍 RSS 중앙값은 9,744KiB(9.516MiB),
anonymous 증가분은 3,584KiB다. tracking 모델 재현은 다음 명령이다.

```sh
cargo bench -p onetdns-core --bench lrumap
```

그 뒤 557,072B digest index를 줄이려고 hash/head를 분리한 자체 오픈주소 배열도
구현·검증했다. 단일 fixture에서는 선할당 1,517,072→1,353,216B(−163,856B), get
34.92→31.35ns였지만 put+퇴거는 약 165→181ns로 느려졌다. 더 중요한 실제 제품 A/B는
startup anonymous 896→3,136KiB, 워밍 anonymous 4,480→6,272KiB로 악화됐다. 여러 작은
LRU에서 2의 거듭제곱 배열 두 개를 즉시 할당·초기화한 비용이 큰 response LRU 하나의
절감보다 컸기 때문이다. 후보
`A9D66EB34714EA80036397DC5DB018FCDB09F6323732A9D6B2C78BEF6A40F5DE`
(9,408,224B)는 거부하고 위 `HashMap` digest index로 되돌렸다. 다음 후보는 작은 map의
지연 할당과 조밀성을 보존해야 한다.

그 다음 `Arc<WireEntry>` 본체와 그 안의 packed `Box<[u8]>`를 합쳤다. 새 `WireEntry`는
8B thin owner이고, 한 allocator 객체에 32비트 atomic strong count·40B header·response
wire·TTL metadata·UTF-8 summary가 연속한다. weak owner는 없으며 clone은 Relaxed 증가,
마지막 drop은 Release 감소 뒤 Acquire fence로 해제한다. overflow는 wrap 전에 abort한다.
외부 의존성은 추가하지 않았다. 8스레드 × 10,000회 동시 clone/drop은 일반 테스트와
Miri에서 모두 통과했고 i686 전체 feature check도 통과했다. 후보 정적 musl 바이너리는
`DCA262974EE35574F2771E8251DC83DB9E4C4569B30349BAF1571AE64B3C9661`
(9,408,928B)다. header drop을 명시한 최종 소스 재빌드는 같은 크기의
`2E7F456DE118CC1913CE3FBBAB764441D03C1A50A40512F76BFE447D7FBD6360`이며,
측정 후보와 `.text`·`.rodata` 해시는 동일하고 panic 위치 메타데이터 15바이트만 다르다.

tracking allocator의 같은 20K/10K fixture는 다음과 같이 바뀌었다.

| wire 소유권 | LRU 선할당 | 채운 엔트리 요청량 | retained 요청량 | musl class 추정/entry |
|---|---:|---:|---:|---:|
| `Arc<48B>` + `Box<62B>` | 1,517,072B | 1,560,000B | 3,077,072B | 160B |
| 8B owner + 단일 102B allocation | 1,517,072B | **1,320,000B** | **2,837,072B** | **144B** |

원자 final-release까지 모델에 넣은 새 구현 3회 중앙값은 get 34.81ns, put+퇴거
126.07ns로 직전 34.62ns/166.76ns 대비 hit는 같은 범위이고 저장·퇴거는 빨랐다.
Windows 300만 회 전체 wire 경로 3회는 74.3·74.4·74.7ns로 직전 74.6ns와 겹쳤다.

Linux O–N–N–O–O–N도 독립 2세트, 구현별 6회 실행했다. 모든 회차는 손실 0이었다.

| 구현 | startup anonymous | 10K warm anonymous | VmData | 10K warm RSS |
|---|---:|---:|---:|---:|
| `Arc<WireEntry>` + packed `Box` | 896 KiB | 4,480 KiB | 17,600 KiB | 9,632 KiB |
| thin owner + 단일 allocation | 896 KiB | **4,256 KiB** | **17,360 KiB** | 9,632 KiB |

anonymous −224KiB와 VmData −240KiB는 6회 모두 같았다. 전체 RSS는 후보의 file page가
224KiB 더 상주해 중앙값이 같으므로 절감 근거로 쓰지 않는다. 두 세트 합산 WARM
중앙값은 26,268.8→26,105.6qps(−0.62%), HOT은 505,227.6→501,470.3qps(−0.74%)였다.
세트별 HOT 방향이 +3.0%와 −0.55%로 뒤집히고 Windows 고정 입력은 동일하므로 CPU
회귀 신호가 아니라 WSL 드리프트 범위로 판정했다.

그 뒤 16B `Instant`를 프로세스 단조시계 기준의 부호 있는 나노초 8B로 바꿔 단일
allocation header를 40→32B, 이 fixture의 allocation을 102→94B로 내렸다. 초 경계
정밀도는 유지하고 약 292년의 표현 범위를 넘으면 캐시를 fail-closed 만료한다. 처음에는
조회와 TTL patch가 시각을 각각 변환해 Windows 전체 wire hit가 중앙 71.6→74.75ns로
4.4% 느려져 거부 조건에 걸렸다. 조회가 계산한 경과 초를 patch에 넘겨 중복을 제거한
최종 후보는 같은 O–N–N–O–O–N 교차에서 기준 73.5ns, 후보 73.0ns로 회귀가 없었다.

현재 digest index·지연 예약까지 포함한 tracking allocator A/B는 다음과 같다.

| header | LRU 초기 예약 | 10K 채움 요청량 | retained 요청량 | 10K 채움 musl class |
|---|---:|---:|---:|---:|
| 40B (`Instant`) | 67,600B | 2,186,304B | 2,253,904B | 2,466,304B |
| 32B (epoch nanos) | 67,600B | **2,106,304B** | **2,173,904B** | **2,146,304B** |

요청량은 80KiB, musl class는 320KiB(엔트리당 32B) 줄었다. 독립 Linux
O–N–N–O–O–N 2세트에서도 구현별 6회 모두 startup anonymous 672KiB, 기준 warm
anonymous 3,808KiB·VmData 8,788KiB, 후보 **3,584KiB(−224KiB)**·**8,504KiB
(−284KiB)**였다. 전체 RSS 중앙값은 file page 반올림 때문에 7,392KiB로 같았다.
합산 HOT 중앙값은 502,495→508,989qps(+1.29%), 전 회차 손실 0이었다. 동일
`rust-lld` release-min 바이너리는 6,155,808→6,149,568B(−6,240B), 후보 SHA-256은
`D0078B36139D52525F1855DECD21D8C383EBA65EF42B1282E8A63219CDB3F4D4`다. i686 전체
feature check와 Miri 8스레드 × 10,000 clone/drop도 통과했다.

LRU 노드를 더 줄이기 위해 불변 key의 길이를 allocation header로 옮겨 owner를 16→8B,
`Entry` 판별자를 pointer 하위 비트에 넣어 16→8B로 만든 결합 후보도 시험했다. 노드는
48→32B, tracking retained는 2,173,904→1,931,760B, musl class는
2,213,904→1,951,760B(−256KiB)로 줄었다. 하지만 Windows 제품 wire hit 교차 중앙값이
72.45→75.6ns(+4.3%)로 악화됐다. key를 복원하고 tagged Entry만 남긴 분리판도
72.7→73.75ns로 느려 둘 다 되돌렸다. 메모리만 줄이는 hot-path 회귀는 채택하지 않는다.

반대로 구조화 캐시는 의미 있는 낭비가 남아 있었다. 한 레코드 `answers`를 filter/collect한
`Vec<Record>`가 여유 capacity까지 보유했기 때문이다. 삽입 뒤 불변인 answers를 authority·
additional과 같은 exact `Box<[Record]>`로 바꿔 `StructuredEntry`를 80→72B로 줄였다.
`Instant`까지 compact clock으로 바꾼 64B 후보는 동일 프로세스 hit가 52.7~54.5ns에서
55.0~55.5ns로 1~3ns 느려져 되돌렸고, 최종안은 기존 `Instant` TTL 의미를 그대로 쓴다.

구조화 전용 A/B는 `onetdns-cache-structured.toml`의 `min_ttl=1`로 응답 TTL은 건드리지
않고 wire gate만 끈다. 최종 O–N–N–O–O–N에서 구현별 3회 모두 startup anonymous는
672KiB, 기준 warm RSS/anonymous/VmData는 11,648/8,064/13,184KiB, 후보는
**9,184/5,376/10,272KiB**였다(각각 −2,464/−2,688/−2,912KiB). loss는 전부 0,
HOT 중앙값은 283,261→283,830qps(+0.2%)였다. 동일 프로세스 old–new–new–old 구조화
hit 10표본 중앙값도 55.05→53.85ns(−2.2%)였다. 동일 `rust-lld` release-min 후보는
6,149,632B, SHA-256 `D21A9AEF93B5BC62689606FCE5593C2E22706EEF4333713B57AE937CC79332A2`다.

```sh
sh benchmarks/dns-cache/run-memory-ab.sh BASELINE_BIN CANDIDATE_BIN
# 구조화 cache만 비교:
TARGET_CONFIG=/path/to/onetdns-cache-structured.toml \
  sh benchmarks/dns-cache/run-memory-ab.sh BASELINE_BIN CANDIDATE_BIN
```

스크립트의 `WARM` 행은 각 10,000개 채우기 회차의 qps와 손실도 함께 출력하므로,
메모리 절감이 캐시 생성 경로의 회귀와 맞바뀌지 않았는지 같은 실행에서 확인한다.

### 다엔진 인터리브 (같은 시간창, dnsmasq·AdGuard 추가)

Unbound 외 이름값 경쟁 엔진과도 같은 구간에서 비교했다. OnetDNS 두 회차가 나머지를
사이에 둔다(이 구간은 앞 Unbound 구간과 시간대가 달라 절대값이 낮지만 구간 내 상대비는
유효).

| 순서 | 엔진 | 중앙 QPS | 지연 | RSS |
|---|---|---:|---:|---:|
| 1 | OnetDNS(HEAD) | 343,365 | 0.231 ms | 19.5 MiB |
| 2 | dnsmasq 2.90 | 246,085 | 0.371 ms | 6.8 MiB |
| 3 | AdGuard Home v0.107.76 | 39,035 | 2.551 ms | 48.2 MiB |
| 4 | OnetDNS(HEAD) | 311,552 | 0.247 ms | 19.5 MiB |

이 구간에서 OnetDNS는 dnsmasq 대비 처리량 +27~40%(중앙 ~327k vs 246k), AdGuard 대비
약 8.4배였다. dnsmasq는 RSS 6.8 MiB로 더 가볍지만(순수 C 포워더, DoT/DoH/DoQ/
DNSSEC 등 기능 없음) 처리량이 낮고, AdGuard는 RSS·지연 모두 크다. OnetDNS는
Unbound·AdGuard를 처리량·메모리 양쪽에서, dnsmasq를 처리량에서 앞선다.

### 2026-07-19 CoreDNS 인터리브 (O-C-O, 같은 시간창)

CoreDNS 1.11.3(cache 플러그인 success 20000, GOMAXPROCS=1)을 같은 hot-cache
조건으로 브래킷 측정했다.

| 순서 | 엔진 | 중앙 QPS | 중앙 평균 지연 | RSS |
|---|---|---:|---:|---:|
| 1 | OnetDNS(HEAD) | 505,312 | 0.168 ms | 19.9 MiB |
| 2 | CoreDNS 1.11.3 | 100,273 | 0.991 ms | 59.9 MiB |
| 3 | OnetDNS(HEAD) | 493,222 | 0.170 ms | — |

이 구간에서 OnetDNS는 CoreDNS 대비 처리량 **4.9~5.0배**, 평균 지연 약 1/6,
RSS 약 1/3이었다.

### 적대적 캐시-미스 플러드에서의 메모리 상한

`cache_size=20000`의 10배인 200,000개 고유 NXDOMAIN 이름을 5회(총 100만 미스)
연속 질의해 RSS 성장을 관측했다. 캐시 소진(cache-exhaustion) DoS 검증이다.

| 단계 | RSS | 피크 |
|---|---:|---:|
| baseline(캐시 빔) | 4.4 MiB | 4.4 MiB |
| flood #1 | 24.9 MiB | 24.9 MiB |
| flood #2~#5 | 26.0 MiB | 26.9 MiB |

100만 개 고유 미스에도 RSS는 ~26 MiB에서 평탄해졌다 — 질의한 고유 이름 수(200k·
1M)에 비례해 커지지 않고 LruMap cap 부근에 머문다. 최악 부하에서도 메모리가
상한 안에 갇힘을 실측으로 확인했다.

## 2026-07-19 재검증 (감사 종결·이벤트 코드 완결 반영 바이너리)

이날의 10개 커밋(컨트롤 플레인 감사 종결, 핫리로드 ArcSwap 전환, 로그인 스로틀
재설계, 이벤트 코드 전 트리 부여, 전송·DNSSEC 관측성) 이후 hot path 회귀
여부를 같은 시간창 O-U-O 인터리브로 재확인했다. 커밋 14598a6 시점 HEAD를
Windows에서 musl 크로스빌드(toolchain 1.88.0)해 사용했다.

| 순서 | 엔진 | 중앙 QPS | 중앙 평균 지연 | 시작 직후 RSS |
|---|---|---:|---:|---:|
| 1 | OnetDNS(HEAD) | 506,786 | 0.166 ms | 5.25 MiB |
| 2 | Unbound 1.19.2 | 450,563 | 0.123 ms | 16.63 MiB |
| 3 | OnetDNS(HEAD) | 499,249 | 0.170 ms | 5.25 MiB |

두 OnetDNS 회차가 Unbound를 사이에 두어 처리량 +10.8%~+12.5% 우위를
유지했다(회귀 없음, 오히려 이전 창들보다 상단). RSS는 Unbound의 약 1/3이다.
평균 지연은 포화 처리량이 더 높은 상태의 값으로 Unbound가 여전히 낮다.
정적 musl 바이너리는 8.12 MiB로 6.56 MiB에서 커졌는데, 이 사이 추가된
기능(WASM 정책 파이프라인 확장, 대시보드 3개 언어, 감사·세션·복구 로직,
스키마 설명 단일화)에 따른 증가다.

### 2026-07-17 현재 세션 바이너리 재확인 (클록 상각·UDP 버퍼 반영)

이 세션 변경(`handle_udp_wire` 클록을 recvmmsg 배치당 1회로 상각, UDP 수신 버퍼
65535→4096)을 musl로 빌드해 `taskset -c 2`에서 각 스레드 PSR을 확인했다(main·
upstream-stats·onetdns-udp-0 모두 CPU 2 — 과거 pin-to-core(0) 회귀 없음). 그 뒤
O-U-O 인터리브를 5개 구간 연속 측정했고, 모든 구간에서 OnetDNS가 Unbound를 앞섰다.

| 구간 | OnetDNS(브래킷) | Unbound | 우위 |
|---|---:|---:|---:|
| 1 | 344.4k / 338.4k | 311.3k | +9% |
| 2 | 332.9k / 329.3k | 305.0k | +9% |
| 3 | 341.8k / 350.0k | 300.2k | +15% |
| (선행 2구간) | 392.8k, 327.7k | 313.4k, 287.9k | +25%, +14% |

startup RSS는 OnetDNS 4.16 MiB, Unbound 16.63 MiB로 약 4배 차이다(UDP 버퍼 축소로
직전 바이너리 4.375→4.156 MiB). 같은 구간의 다엔진 측정에서 OnetDNS 345k는 dnsmasq
2.90 246k(+40%)·AdGuard Home 40k(약 8.6배)를 앞섰다. WSL2 드리프트로 절대값은
창마다 출렁이나, 같은 구간 내 O-U-O 브래킷이 Unbound를 감싸므로 방향(OnetDNS 우위)은
드리프트 산물이 아니다.

## wire 레인은 속도와 메모리 양쪽에서 이긴다 (2026-08-01)

"메모리를 아끼려면 wire 승격을 끄면 된다"는 성립하지 않는다. 같은 구간에서 기본 프로필과
구조화 전용(`onetdns-cache-structured.toml`, `min_ttl = 1`로 승격만 끔)을 번갈아 쟀다.
2레그씩 전부 KiB까지 동일값이다.

| 프로필 | startup | 워밍 후 | 워밍 증가분 | 엔트리당 | QPS |
|---|---:|---:|---:|---:|---:|
| **wire(기본)** | 6,496 KiB | **8,736 KiB** | **2,240 KiB** | **229 B** | 507,590 ~ 520,139 |
| 구조화 전용 | 6,496 KiB | 10,528 KiB | 4,032 KiB | 413 B | 345,978 ~ 374,724 |

구조화 전용은 메모리를 **+20.5%** 쓰면서 처리량이 **−28%**다. 파싱된 `Record` 무리보다
wire 블롭이 촘촘하기 때문이다. 구조화 전용의 처리량이 같은 구간 dnsmasq(348~357k)와 겹치는
것도 같은 이야기다 — dnsmasq도 매번 응답을 다시 조립한다.

### 남은 격차의 해부

이 픽스처의 응답은 **54바이트**(`dig +noall +comments +stats`로 확인)인데 엔트리당
**229바이트**를 쓴다. **오버헤드가 175바이트(76%)**다.

| 몫 | 대략 | 비고 |
|---|---:|---|
| 키 `Box<[u8]>` | 32 B | musl 클래스. qname이 wire 블롭의 질문 절과 **중복** |
| `WireEntry` 단일 할당 | 128 B | 48B 헤더 + 54B wire + TTL 오프셋 → 128B 클래스 |
| LruMap 노드 | 약 44 B | 아레나 안 |
| 해시 인덱스 | 약 11 B | `HashMap<u32,u32>` + ctrl 바이트 |

**다음 지렛대는 키를 `WireEntry`와 같은 할당에 접는 것**이다. 엔트리당 할당 하나와
musl 32B 클래스가 전부 빠진다(약 14%). 이 경로는 이미 여러 번 깎였고 가장 뜨거운
곳이므로 설계를 먼저 합의하고 RSS로 확정한 뒤에 손댄다.

**dnsmasq의 6,944 KiB 고정을 이기는 것은 산술적으로 불가능하다** — 그러려면 엔트리당
45B 이하여야 하는데 응답 자체가 54B다. dnsmasq는 고정 크기 소형 구조체만 담고 매번
패킷을 다시 만든다. 그 대가가 처리량 1.5배·지연 2.4배 차이다. 대신 **지속 가능한 최소
주소공간은 동률**이다(양쪽 16,384 KiB, release-min 14,336 KiB).

## 이 축을 다시 측정할 때의 함정 (2026-08-02에 전부 밟았다)

**1. "생성기 천장에 가깝다"는 것만으로 artifact라고 말하지 마라.** `run-dnsperf.sh`가 적어
둔 대로 기본 생성기(클라이언트 1·스레드 1·CPU 1)는 이 호스트에서 약 54만 QPS가 천장이고
OnetDNS가 그 88~91%라 "OnetDNS 수치는 하한"이라고 판단했다가 기각했다. 생성기를 키우면 값이
오르는지를 봐야 한다 — 실제로는 `c=2 t=2`에서 **두 엔진 모두 유실**이 나서 1코어에 고정한
서버가 먼저 포화함이 드러났다. 즉 1.57배(496,953 대 315,710)는 실제 서버 천장의 비율이다.

**2. 남은 비용이 어디인지 먼저 갈라라.** 1코어 천장에서 질의당 CPU는 user 0.239 µs(14%),
sys 1.495 µs(86%)다. 유저공간은 이미 소진됐으므로 이 축에서 유저공간 최적화 후보를 새로
만드는 것은 값이 없다. 측정하는 법: 캐시 프로세스 트리의 `/proc/PID/stat` utime+stime을 부하
전후로 읽고 완료 질의 수로 나눈다(`(a-b)*1e6/100/n` µs). **strace·perf는 이 WSL 커널에
없다** — 설치 권한도 없으므로 시스콜 수는 상한 계산으로 대신한다(TECH_DEBT의 io_uring 거부
항목 참조).

**3. 회차마다 서버 프로세스를 반드시 회수하라.** 앞 회차가 포트를 물고 살아남으면 다음
회차가 7 ms에 "응답"해 버린다. 인터리브 하네스는 이미 `kill`+`wait`를 하지만, 직접 쓴
스크립트에서 이 함정을 밟았다.

**4. 캐시 설정은 업스트림 권한 레그가 떠 있어야 한다.** `onetdns-cache.toml`은
`udp://127.0.0.1:15400`으로 전달하므로 `onetdns-authority.toml` 레그를 먼저 시작하지 않으면
전 질의가 유실된다(하네스는 이것을 하지만 즉석 스크립트에서 빠뜨렸다).
