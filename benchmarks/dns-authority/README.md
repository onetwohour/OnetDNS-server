# 권한 서빙 벤치 (OnetDNS · BIND 9 · NSD · Knot)

권한(authoritative) 모드는 이 저장소에서 **가장 늦게 측정된 축**이다. 재귀·캐시·필터·
DNSSEC는 오래전부터 경쟁 엔진과 인터리브로 재 왔지만, 권한 서빙은 마이크로벤치
(`crates/onetdns-authority/benches/query.rs`)와 CI의 dig/kdig interop만 있었고 **전용
권한 서버와 나란히 측정한 적이 없었다**. 이 하네스가 그 공백을 메운다.

> **2026-08-01 정정 — 이 문서의 NSD RSS 수치는 대부분 무효다.** 하네스가 `$!`로 잡은
> PID 하나의 `VmRSS`만 읽었는데 NSD는 자식을 fork하므로 그 PID는 존 데이터를 거의 가지고
> 있지 않다(80만 레코드 존에서 11,200 KiB 대 트리 Pss 88,489 KiB). 아래 표들 중
> **"대형 RRset" 절만 트리 Pss로 재측정했고**, `11,200`·`11,424`·`10,592` 같은 UDP 축의
> NSD RSS는 전부 정정 전 값이다. 자세한 내용과 재발 방지는 그 절의 "정정" 항목과
> [`../lib/procmem.sh`](../lib/procmem.sh)를 볼 것. TCP/AXFR 절은 처음부터 프로세스
> 트리를 합산했으므로 영향이 없다.

## 실행

```sh
sh run-authority-interleave.sh WORKDIR ONETDNS_BIN [OWNERS=100000]
AUTHORITY_MIXED=1 sh run-authority-interleave.sh WORKDIR ONETDNS_BIN [OWNERS=100000]
sh run-authority-tcp-xfr-interleave.sh WORKDIR ONETDNS_BIN [OWNERS=100000]
AUTHORITY_TSIG_COMPETITORS=1 AUTHORITY_IXFR_RUNS=1000 \
  sh run-ixfr-tsig.sh WORKDIR ONETDNS_BIN [OWNERS=10000]
```

TSIG 하네스는 `dig`·`nsupdate`와 Python 3 표준 라이브러리만 사용한다. 제3자 Python
패키지는 필요 없다.

### 기본 텔레메트리 CPU A/B

가장 빠른 권한 경로에서 대시보드 기본 텔레메트리의 현재 종단 비용만 분리하려면 다음을
실행한다. 경쟁 엔진 대조가 아니라 같은 OnetDNS 바이너리의 off/on 자기 대조다.

```sh
sh run-telemetry-cpu-ab.sh WORKDIR ONETDNS_BIN [OWNERS=100000]
# 기본: 12라운드 × 6초. 필요할 때만 환경 변수로 바꾼다.
TELEMETRY_ROUNDS=12 TELEMETRY_SECONDS=6 \
  sh run-telemetry-cpu-ab.sh WORKDIR ONETDNS_BIN 100000
```

off는 `--no-web --no-supervisor`, on은 명시적인 loopback 제어 주소와 벤치 전용 bearer
token을 사용한다. 양쪽 모두 워커 1개, 같은 존, 캐시 off, 질의 로그 off다. 서버와 부하기
CPU는 `TELEMETRY_SERVER_CPU`·`TELEMETRY_CLIENT_CPU`로 바꿀 수 있다. 1초 워밍업은 CPU
측정 밖이고, 부하 뒤 collector drain 50ms는 양쪽 구간에 똑같이 들어간다. CPU는 마스터
스레드 하나가 아니라 서버 PID 전체의 `/proc/PID/stat` user+sys delta를 dnsperf 완료
질의로 나눈다.

수치보다 먼저 다음 gate를 전부 통과해야 한다.

- 모든 레그의 dnsperf 손실이 0이어야 한다.
- on 레그의 인증된 `/metrics` 전후 `onetdns_queries_total` delta가 완료 질의와 정확히
  같아야 한다.
- `onetdns_dropped_stat_events_total`과 `onetdns_dropped_log_events_total` delta가 모두
  0이어야 하고, 로그에도 slot/queue full이나 panic이 없어야 한다.
- off와 on을 따로 계산한 CPU 산포 `(max-min)/mean`이 각각 5% 이하여야 한다. 하나라도
  넘으면 대응 비율 중앙값도 인용하지 않는다.

2026-08-08 정식 12×6초 실행 두 세트는 각 24/24 레그의 손실·질의 delta·drop gate를 모두
통과했지만 off/on CPU 산포가 7.152%/3.922%, 7.249%/11.256%여서 둘 다 기각했다. 대응 중앙값
+13.24%와 +14.61%는 인용하지 않는다. 첫 실행에서 발견한 20ms idle 구간의 burst drop
(3118건)은 idle-only coalesced wake로 수정했고 이후 모든 레그의 drop은 0이었다.

**2026-08-09 샤드 계수 접기 전 musl release의 세 번째 12×6초 실행은 모든 gate를 통과했다.** off
1.7608~1.8143 µs/query(산포 2.985%), on 1.9724~2.0159(2.174%)이며, 24개 레그 모두 손실·
stat/log drop 0이고 on의 완료 질의와 `queries_total` delta가 정확히 일치했다. 대응 초과분은
0.1859~0.2371 µs, 중앙 **0.2066 µs**, on/off 중앙 **1.1146(+11.46%)**다. QPS는 실행 순서에
따라 크게 흔들렸으므로 인용하지 않는다. 상세 역사와 격리 마이크로벤치는
[`../../TECH_DEBT.md`](../../TECH_DEBT.md)의 “텔레메트리가 해석보다 비싸다”에 기록한다.

이후 기본 log-off 경로의 total·transport·action 전역 atomic 세 번을 기존 `StatSlot` 잠금에
접었다. 격리 release A/B는 34.12→22.88 ns/event(1.49배)였지만, Windows 6×15초 종단 A/B는
대응 비율 산포가 113.97%라 기각했다.

**같은 날 현행 소스의 Linux glibc release를 12×6초로 다시 측정해 모든 gate를 통과했다.** off는
1.6268~1.6701 µs/query(평균 1.6497, 산포 2.625%), on은 1.7876~1.8152(평균 1.8005,
산포 1.533%)다. 24개 레그·60,430,142개 완료 질의 전체에서 손실·stat/log drop은 0이고,
모든 on 레그의 완료 질의와 `queries_total` delta가 정확히 일치했다. 대응 on−off는
0.1175~0.1884 µs, 중앙 **0.1495 µs**, on/off 중앙 **1.0902(+9.02%)**다. 이것이 현행 소스의
종단 비용이다. 다만 위 +0.2066 µs 기준선은 musl·접기 전 바이너리이고 이번 값은 glibc·접기 후
바이너리이므로, 두 값의 차이를 계수 접기 하나의 개선율이나 libc 간 우위로 해석하면 안 된다.

### 온라인 서명 대조 (BIND 9, root 없이)

```sh
sh fetch-bind-userspace.sh          # apt-get download + dpkg -x, 홈 아래에만 푼다
sh run-sign-vs-bind.sh [OWNERS=100000]        # 28스레드, 파싱+쓰기 몫을 compilezone으로 분리
sh run-sign-vs-bind-single.sh                 # 같은 존을 -n 1로. 서명 1건당 비교용
# onetdns 쪽:
ONETDNS_SIGN_OWNERS=100000 ONETDNS_SIGN_ROUNDS=1 cargo bench -p onetdns-dnssec --bench sign
ONETDNS_SIGN_BREAKDOWN=1 <bench 바이너리>      # 서명 1건을 곡선 연산과 앞단으로 구분한다
```

`sudo`가 필요 없다 — 패키지를 내려받아 홈에 풀고 `LD_LIBRARY_PATH`로만 부른다. 시스템
경로는 건드리지 않는다.

**먼저 이미 설치돼 있는지 확인하라.** 이 호스트에는 BIND 9.18.39 · Knot 3.3.4 · NSD 4.8.0 ·
Unbound 1.19.2 · dnsmasq 2.90 · PowerDNS Recursor 4.9.3 · dnsperf 2.14.0이 전부 있었는데,
`command -v`를 한 줄짜리 루프로 훑다가 출력이 삼켜진 것을 "없음"으로 읽고 한동안 대조를
포기했었다. **도구 유무는 한 줄씩 찍어 확인한다.**

### 시작~서명된 응답까지 (OnetDNS 대 Knot)

```sh
sh run-sign-race.sh [OWNERS=100000]
```

BIND는 오프라인 도구로 재지만 Knot은 서버가 로드하며 서명하므로, 세 엔진을 하나의 축에
올리려면 **프로세스 시작부터 `dig +dnssec`이 RRSIG를 돌려줄 때까지**로 맞춰야 한다.
이 스크립트가 OnetDNS(알고리즘 13·15)와 Knot(같은 두 알고리즘)을 그 축으로 돌린다.
포트를 넷으로 나누고 회차마다 프로세스를 정리하므로, 앞 회차가 살아남아 다음 회차가
즉시 응답하는 오염이 없다.

**비교 전에 서명량을 먼저 맞춰라.** `dnssec-signzone`은 DNSKEY가 존에 이미 있어야 하고
(OnetDNS는 서명하면서 넣는다), `-z`가 없으면 KSK 하나로 전부 서명하지 않는다. 양쪽이
같은 일을 했는지는 `grep -cP '\tRRSIG\t'`와 `\tNSEC\t`로 확인한다 — `grep -c RRSIG`는
NSEC 타입 비트맵의 RRSIG까지 세어 틀린다.

**BIND는 파일→파일이고 OnetDNS는 메모리→메모리다.** 그 몫을 빼지 않으면 OnetDNS에 유리하게
기울어진다. `named-compilezone`이 정확히 파싱+쓰기이므로 그것을 차감해서 본다.

정답 확인 직후의 `/proc` 메모리 범주까지 분해하려면 같은 명령 앞에
`AUTHORITY_DUMP_MEMORY=1`을 붙인다. `1` 대신 `O1`, `bind`, `nsd`, `knot` 같은 레그
이름을 주면 해당 레그만 출력한다. 기본값에서는 추가 출력이나 계측 호출이 없다.

`generate-zone.sh`가 A 레코드 위주의 존과 질의 목록을 만든다(존 안의 이름만 담아 전부
NOERROR가 나오게 한다). `AUTHORITY_MIXED=1`은 `generate-mixed-zone.sh`로 exact 50%,
NXDOMAIN 35%, wildcard·empty non-terminal(ENT)·DNAME 각 5%인 목록을 만든다.
**netns로 감싸지 말 것** — 전부 높은 포트를 쓰므로 격리가
필요 없고, 비특권 user namespace 안에서는 nsd/named가 권한 강하에 실패해 기동조차
못 한다.

다른 벤치와 같은 규율을 따른다.

- 경쟁 엔진 사이사이에 OnetDNS 레그를 넣어 호스트 드리프트를 같은 구간에서 함께 잡고,
  라운드마다 경쟁 엔진의 순서를 뒤집어 순서 편향까지 통제한다. 라운드 수는
  `AUTHORITY_ROUNDS`(기본 2)로 준다.
- 각 레그는 측정 **직전에** `dig`로 정답을 확인한다. 존을 못 읽은 채 SERVFAIL을 빠르게
  뱉는 것이 가장 빠른 오답이므로, 정답 확인 없이는 QPS가 의미를 갖지 않는다.
- 마지막에 **엔진마다 따로** 산포를 판정한다. **드리프트가 5%를 넘으면 배율을 인용하지
  말 것** — 어느 레그와 짝지었느냐로 결론이 바뀐다. 한 엔진에 레그가 하나뿐이면 그 값이
  구간의 어느 지점을 잡았는지 알 수 없어 애초에 판정이 서지 않는다.
- **판정은 해석당 CPU로 한다.** 이 호스트에서 QPS 레그 드리프트는 10~31%라 몇 %의 마진을
  가릴 수 없다. 같은 구간에서 CPU 드리프트는 1~3%다.
- **메모리는 프로세스 트리 전체의 Pss**로 측정한다([`../lib/procmem.sh`](../lib/procmem.sh)).
  단일 PID `VmRSS`는 fork하는 엔진에서 8배 가까이 낮게 나온다.

## 혼합 의미론 결과 (2026-07-30, release-min, 10만 owner, 1코어 고정)

두 독립 브래킷 모두 exact A 3600초, wildcard A 3600초, NXDOMAIN, ENT NODATA,
DNAME+CNAME 3600초를 측정 직전에 확인했고 손실은 전 레그 0이었다. NXDOMAIN·NODATA의
SOA TTL은 [RFC 2308 §3](https://www.rfc-editor.org/rfc/rfc2308.html#section-3)에 따라
`min(SOA TTL 3600, SOA.MINIMUM 300) = 300`인지도 gate한다. NSD의 기본 RRL 200 QPS를
그대로 두면 반복 부정 응답을 의도적으로 버려 엔진 용량이 아니라 방어 정책을 재게 되므로,
이 처리량 비교에서만 `rrl-ratelimit: 0`과 `rrl-whitelist-ratelimit: 0`을 명시했다.

| 엔진 | QPS(두 브래킷 합집합) | 평균 지연 | 부하 후 RSS |
|---|---:|---:|---:|
| OnetDNS release-min | **403,954~419,880** | 0.063~0.065 ms | **10,812~10,820 KiB** |
| BIND 9.18.39 | 229,814~232,362 | 0.127~0.128 ms | 71,232 KiB |
| NSD 4.8.0 | 397,105~402,389 | **0.036~0.037 ms** | 11,200~11,424 KiB |
| Knot 3.3.4 | 401,300~404,666 | **0.037 ms** | 36,728~36,956 KiB |

OnetDNS 레그 드리프트는 3.729%·2.217%로 둘 다 5% gate를 통과했다. 보수적인 최저 대
상대 최고에서 BIND보다 +73.9%이고 RSS는 NSD보다 최소 3.39%, Knot보다 70.5%, BIND보다
84.8% 낮다. NSD 처리량 범위보다 높지만 +0.39% 마진은 드리프트보다 작고, Knot과는
0.18% 겹치므로 **NSD·Knot과 처리량 동급**으로 판정한다. NSD·Knot의 단건 지연은 여전히
낮다.

처음 의미론을 맞춘 후보는 wildcard·ENT·DNAME을 구조화 경로로 보내 328,982~333,890
QPS였다. sparse 이름 플래그와 직접 wire 응답을 적용한 최종 후보의 최저도 그 후보 최고보다
**21.0% 높고**, RSS 변화는 10,812~10,816→10,812~10,820 KiB뿐이다. 단독 분해에서도
wildcard 191,755→365,660(+90.7%), ENT 213,389→384,110(+80.0%), DNAME
175,895→368,277(+109.4%) QPS로 올랐다.

### 정적 정책 스냅샷 상각 후속 (2026-07-30)

동시성 스윕에서 OnetDNS·NSD·Knot의 `q=1` 평균 지연은 각각 30·29·30µs로 같았지만,
`q=40`에서는 89·45·36µs로 벌어졌다. 즉 기본 서비스 지연보다 포화 처리량이 남은 축이다.
빈 정책 구성에서도 매 질의 수행하던 동적 ACL 읽기 잠금, `NativeFeatures` 스냅샷과 14개
분기, 빈 필터 스냅샷을 값에서 직접 유도되는 원자 gate로 상각했다. ACL·기능·필터를
활성화하는 핫리로드는 gate를 먼저 닫고 값을 교체하며, 비활성화는 값을 먼저 교체한 뒤
gate를 연다. 알려지지 않은 ACL 구현은 기본적으로 비자명하고, 필터의 verdict·client·
RPZ 규칙 중 하나라도 있으면 일반 정책 경로를 그대로 탄다.

증분 A/B에서 기능 gate 후보는 ACL-only 후보 404,558~407,201 대비
407,759~409,866 QPS, 필터 gate 후보는 기능 gate 406,296~407,504 대비
408,515~415,894 QPS였다. 두 단계 모두 대응 레그가 같은 방향이고 보수적인 최저 대 최고도
각 +0.14%, +0.25%지만, 크기가 작으므로 큰 성능 향상으로 주장하지 않는다. 최초 기준과
최종 후보의 직접 범위도 400,817~414,569 대 410,830~421,015로 겹쳤다.

채택 코드의 최종 O–BIND–O–NSD–O–Knot–O 검증은 OnetDNS
**405,341~420,608 QPS**(드리프트 3.698%, 0.064~0.065ms, 10,592~10,600KiB),
BIND 234,788, NSD 403,376, Knot 401,622였고 전 레그 정답 확인·TTL gate·유실 0을
통과했다. 보수적으로 BIND보다 +72.6%이며, NSD·Knot보다 범위는 높아도 마진이 드리프트보다
작으므로 여전히 **NSD·Knot과 처리량 동급**으로 판정한다.

같은 날 Linux UDP 송신 배치가 정상 응답마다 오류 진단용 `SocketAddr`를 별도 벡터에
복사하던 것도 제거했다. 송신 헤더가 이미 원본 `sockaddr_storage`를 가리키므로, 실제
`sendmmsg` 오류 때만 그 포인터에서 주소를 다시 읽는다. `AUTHORITY_AB_BIN` 모드로
후보–기준–기준–후보와 역순을 각각 돌린 결과 후보/기준은 410,202~415,065 /
398,386~409,955와 408,092~415,343 / 405,635~408,007 QPS였다. 네 대응 레그가 모두
후보 방향(+0.61~2.97%)이지만 각 실행의 보수적 최저 대 최고 차이는 +0.06%·+0.02%뿐이라
큰 개선으로 주장하지 않는다. 고정 벡터와 정상 경로 쓰기를 없애면서 RSS 증가는 없다는
근거로만 채택한다.

채택 바이너리의 최종 7레그 재검증은 OnetDNS **407,818~416,470 QPS**(드리프트 2.105%,
0.064~0.065ms, 10,592~10,596KiB), BIND 231,362, NSD 408,715, Knot 398,758이었다.
전 레그 정답·TTL gate·유실 0을 통과했고 BIND보다 보수적으로 **+76.3%**다. NSD와 범위가
겹치며 Knot 대비 +2.27%도 OnetDNS 드리프트 2.105%와 너무 가까우므로 둘과는 계속 처리량
동급으로 판정한다.

거부 후보도 고정한다. 전용 UDP batch 32→64는 기준 410,774~411,440 대 후보
407,481~411,555 QPS로 이득 없이 버퍼만 두 배라 원복했다. 영역 `Arc` clone/drop을 없애는
짧은 read-guard 후보도 기준 407,817~418,591 대 후보 406,803~420,139로 완전히 겹쳐
원복했다. 이전에 거부된 8개 부분 flush와 함께 재시도하지 않는다.
클라이언트 주소 변환 자체를 생략하는 후보는 personal 모드의 기본 사설망 ACL 때문에
안전하게 fallback한 뒤 경로를 두 번 타 373,533~374,778 대 기준 407,081~431,666으로
크게 느려져 원복했다. IP-only ACL 단축과 안정 MAC-cache 포인터 후보도 두 번의 순·역순
A/B에서 대응 방향이 갈리거나 역전돼 전부 원복했다.

## 최신 결과 (2026-07-28, 10만 owner, 1코어 고정)

연속 master-file record builder·단일 owner-key arena·16바이트 해시 슬롯·16바이트 레코드와
권한 wire 직접 경로를 포함한 현재 musl 정적 바이너리를 `rust-lld`로 빌드해 기본 release와
release-min을 각각 독립 브래킷 2회로 실행했다. 모든 레그가 정답 확인 통과·손실 0이며,
기본 release의 OnetDNS 드리프트는 1.091%·4.386%, release-min은 3.632%·1.998%로 모두
5% 게이트를 통과했다. 각 표의 범위는 해당 프로필 두 회차의 합집합이다.

### 기본 release

| 엔진 | QPS | 평균 지연 | RSS |
|---|---:|---:|---:|
| OnetDNS | **409,870~428,237** | **0.038~0.040 ms** | 12,164~12,172 KiB |
| BIND 9.18.39 | 264,310~265,523 | 0.106 ms | 71,232 KiB |
| NSD 4.8.0 | 388,686~391,426 | 0.042~0.043 ms | **11,200 KiB** |
| Knot 3.3.4 | 400,024~404,769 | **0.036~0.037 ms** | 36,732~36,936 KiB |

처리량 범위는 네 엔진 중 OnetDNS가 가장 높고 서로 겹치지 않는다. 보수적인 OnetDNS 최저 대
상대 최고로 BIND보다 **+54.4%**, NSD보다 **+4.71%**, Knot보다 **+1.26%**다. NSD 마진은
두 브래킷의 최대 드리프트 4.386%보다 크고 지연 범위도 겹치지 않아 이 조건에서는 작지만
유효한 우위다. Knot 마진은 드리프트보다 작으므로 **“앞선다”가 아니라 “뒤지지 않는다”**로
판정한다. Knot 지연은 1~4µs 낮다.

### 최소 자원 release-min (`--no-default-features --profile release-min`)

| 엔진 | QPS | 평균 지연 | RSS |
|---|---:|---:|---:|
| OnetDNS release-min | **435,109~451,205** | 0.050~0.053 ms | **10,808~10,816 KiB** |
| BIND 9.18.39 | 257,260~267,107 | 0.105~0.110 ms | 71,232 KiB |
| NSD 4.8.0 | 390,509~398,248 | **0.039~0.042 ms** | 11,200 KiB |
| Knot 3.3.4 | 400,204~400,798 | **0.037 ms** | 36,744~36,892 KiB |

보수적 처리량 마진은 BIND **+62.9%**, NSD **+9.26%**, Knot **+8.56%**로 모두 최대
드리프트 3.632%보다 크다. RSS도 NSD보다 **3.43% 낮아** 이 A 위주 10만 owner 조건에서
처리량과 상주 자원을 동시에 앞선다. 대신 평균 지연은 기본 release보다 10~15µs 높고
NSD·Knot보다도 높다. 따라서 최고 단건 지연은 기본 release, 최소 상주 자원과 최고 처리량은
release-min이라는 실측 trade-off를 숨기지 않는다.

### TCP 질의와 AXFR (`release-min`, 2026-07-29)

TCP 하네스는 `dnsperf -m tcp -c 4 -q 100 -T 1 -l 6`을 쓰고, 1초 워밍 뒤
연결 종료를 1초 기다린다. AXFR는 각 레그에서 먼저 시작/종료 SOA와 **100,004개**
레코드를 모두 확인한 뒤 20회 전송한다. 서버 CPU/RSS는 master PID 하나가 아니라 자식까지
포함한 프로세스 트리 합계다. OnetDNS·BIND·NSD·Knot 전 레그가 TCP 정답, AXFR 완전성,
손실 0을 통과했다.

| 엔진 | TCP QPS(관측 범위) | TCP 평균 지연 | AXFR wall/회 | AXFR 서버 CPU/20회 | AXFR 후 RSS |
|---|---:|---:|---:|---:|---:|
| OnetDNS | 238,731~287,227 | 0.331~0.398 ms | **0.030~0.0305 s** | **0.01~0.02 s** | **13,136~13,368 KiB** |
| BIND 9.18.39 | 176,838~178,791 | 0.539~0.544 ms | 0.1705~0.201 s | 3.32~3.35 s | 72,032~72,044 KiB |
| NSD 4.8.0 | 124,923~134,285 | 0.716~0.775 ms | **0.030 s** | 계측 해상도 미만 | 104,272~104,644 KiB |
| Knot 3.3.4 | 217,396~231,423 | **0.175~0.190 ms** | **0.030~0.0305 s** | 0.16 s | 38,004~38,116 KiB |

TCP 처리량은 네 번의 전체 브래킷에서 매번 OnetDNS 범위가 세 경쟁 엔진보다 높았지만,
Windows 호스트가 비유휴였고 OnetDNS 레그 드리프트가 **6.95~16.34%**로 5% 게이트를
모두 넘었다. 따라서 표는 약점과 범위 확인용이며 **TCP 우위 배율은 인용하지 않는다**.
Knot은 처리량이 낮아도 평균 지연은 OnetDNS보다 0.14~0.22ms 낮았다.

AXFR 결론은 창마다 안정적이다. OnetDNS는 57개 envelope, BIND는 167개, NSD·Knot은
147개로 같은 약 2.4MB wire를 보냈다. OnetDNS wall은 NSD·Knot의 클라이언트 측 30ms
측정 바닥과 같고 BIND보다 5.6~6.7배 짧다. 20회 서버 CPU는 Knot보다 최소 8배,
BIND보다 최소 166배 작다. lazy wire cache가 보유하는 약 2.4MiB를 포함해도 RSS는 Knot의
약 1/2.85, BIND의 1/5.4다. NSD의 CPU는 10ms jiffy 계측 해상도 아래라 배율을 만들지
않는다.

최적화 전 OnetDNS AXFR는 회당 0.47~0.50초였다. nonblocking TCP listener가 유휴 시
500ms `sleep`하던 accept 지연을 fd readiness `poll`로 바꿔 0.120~0.127초로 줄였고,
레코드별 estimate `Writer` 재사용으로 서버 CPU를 32~46% 줄였다. unsigned AXFR는 immutable
zone별 완성 wire를 첫 허용 요청 때만 만들어 재사용해 최종 0.030초와 CPU 99% 이상 절감을
만든다. active rate-limit, recorder/dnstap, IXFR은 기존 정책 인지 스트리밍 경로를 탄다.
TSIG AXFR는 아래 후속에서 같은 immutable template에 검증된 HMAC 체인을 직접 붙이도록
확장했다. 일반 TCP A/AAAA/flat NXDOMAIN은 UDP와 동일한 fail-closed direct-wire 경로를
사용해 구조화 파싱을 생략한다.

### TSIG AXFR·DDNS·IXFR (`release-min`, 2026-07-30)

`run-ixfr-tsig.sh`는 BIND의 `dig`·`nsupdate`를 상호운용 기준으로 사용한다. 비서명 AXFR
거부, HMAC-SHA256 AXFR의 시작/종료 SOA와 전 레코드, 서명 DDNS의 serial 1→2, 이전
serial에서 레코드 5개·SOA 4개인 실제 IXFR, 최신 serial의 단일 SOA, UDP stale IXFR의
`TC`와 TSIG를 수치보다 먼저 gate한다. 독립 `probe-tsig-errors.py`는 TCP wire와 HMAC을
직접 구성해 정상 응답 MAC, BADSIG 16·BADKEY 17의 빈 MAC, BADTIME 18의 검증 가능한
32바이트 MAC·클라이언트 Time Signed·요청 Fudge·48비트 서버 시각을 매 실행마다 확인한다.
10,000 owner에 DDNS 레코드 하나를 더한 AXFR는 10,005개다. 서버와 부하기는 CPU 2/3에
고정했고, 아래 최종 표는 각 엔진 1,000회이며 프로세스 트리 전체의 user+system CPU와
RSS를 합산했다.

| 엔진 | TSIG AXFR/CPU-s | wall/회 | RSS |
|---|---:|---:|---:|
| OnetDNS release-min | **1,923.1** | 10.45 ms | **8,144 KiB** |
| BIND 9.18.39 | 61.1 | 20.51 ms | 39,872 KiB |
| NSD 4.8.0 | 1,428.6 | **9.93 ms** | 57,672 KiB |
| Knot 3.3.4 | 917.4 | **9.98 ms** | 12,692 KiB |

서버 CPU 효율은 BIND보다 **31.46배**, NSD보다 **34.6%**, Knot보다 **2.10배** 높다.
RSS는 각각 **79.6%·85.9%·35.8% 낮다**. wall은 매회 새 `dig` 프로세스를 시작하는 비용과
루프백 전송이 지배해 OnetDNS·NSD·Knot이 약 10ms로 사실상 같은 층이며, Knot/NSD보다
낮다고 주장하지 않는다. 후보의 500회 세 실행은 1,851.9~1,923.1 transfers/CPU-s로
3.75% 범위에 들었다.

최적화 전 정확한 바이너리의 200·500회 A/B는 66.0~66.6 transfers/CPU-s였고, 후보는
최저 대 기준 최고도 **27.81배**다. 원인은 TSIG가 붙으면 unsigned AXFR wire cache를 버리고
매 요청마다 존 전체 `Record`를 복제·재인코딩하던 데 있었다. 현재는 ACL·XFR 허용 대역·
rate/recorder/dnstap gate와 요청 TSIG를 먼저 검증한 뒤 cached envelope의 ID·RD·질문 case만
고치고, HMAC과 TSIG RR를 wire에 직접 연쇄 부착한다. 정책이 활성화됐거나 검증이 실패하면
기존 `Message` 경로로 fail-closed한다. 후보 정적 바이너리 SHA-256은
`44ae1f1b589bcc3ede4d92864bc2da687582f1dd9e1de2c5bd5b550256739919`다.

같은 사이클에 TSIG가 마지막 Additional RR이 아니면 선택적-TSIG AXFR가 unsigned로
강등되던 결함을 FORMERR로 막았다. TSIG는 Additional의 유일한 마지막 RR, CLASS ANY,
TTL 0, 정확한 RDATA 길이여야 하며 요청 Error도 0이어야 한다. IXFR journal도 단순 64개
보존 대신 누적 wire 추정이 현재 AXFR보다 작을 때만 오래된 delta를 유지한다. 단일 delta부터
AXFR보다 크면 저널을 비우고 전체 전송으로 폴백하므로 작은 존·대량 변경의 메모리 역전을
막는다. [RFC 8945 §5.2–5.3](https://www.rfc-editor.org/rfc/rfc8945.html#section-5.2)
순서대로 키·MAC·시간을 검증하므로 오래된 위조 MAC은 BADTIME으로
오분류되지 않는다. HMAC-SHA256은 16~32바이트 절단을 허용하고 그 밖의 길이는 FORMERR,
BADKEY/BADSIG는 반드시 unsigned TSIG, BADTIME은 검증된 요청 MAC으로만 서명한다.
forwarded Original ID와 DDNS 재생 캐시 만료(`Time Signed + Fudge`, 최대 Fudge 300초)도
회귀 테스트로 고정했다. 변경 뒤 같은 1,000회 Linux 재실측은 AXFR 1,923.077,
IXFR 8,333.333 transfers/CPU-s, RSS 7,924KiB로 기존 처리량과 동일했다. 외부 런타임
라이브러리는 추가하지 않았다.

기본 release RSS는 최초 72,392 KiB에서 최대 12,172 KiB로 **83.2% 감소**했고 Knot보다
**67.0% 낮으며** NSD보다 972 KiB 크다. release-min은 10,816 KiB로 NSD보다 384 KiB 작다.
추적 allocator 최종 보유량은 5.9 MiB다. `/proc/smaps_rollup` A/B의 anonymous는 owner 인덱스
전 16,116→인덱스 후 11,396→16바이트 레코드 후 10,376→연속 parser 후 **6,808 KiB**로
내려갔다. 기본 release의 시작 VmHWM도 46,308→25,536 KiB, release-min은 24,416 KiB다.
최종 pmap에는 수십~수백 개의 32/96 KiB 임시 allocation group 대신 큰 연속 매핑만 남아
구조 변경과 RSS 감소가 직접 대응한다.

최적화 전 같은 하네스의 기준선은 OnetDNS 356,717~360,923 QPS·0.077~0.079ms·72,392KiB,
NSD 362,238·0.042ms·11,424KiB, Knot 416,780·0.035ms·36,824KiB였다. 세션 간 절대 QPS는
호스트 구간이 달라 직접 빼지 않으며, 위 최신 표처럼 같은 브래킷의 상대 범위만 판정한다.

## 원인 분해와 현재 in-process 결과 (2026-07-28, Windows release)

`crates/onetdns-authority/benches/query.rs`에 요청 할당 추적과 exact/NXDOMAIN 분리 측정을
추가했다. 이 표의 메모리는 프로세스 RSS가 아니라 추적 allocator가 센 **요청 바이트**이고,
외부 엔진과 비교하는 수치가 아니다.

| 항목 | 최적화 전 | 현재 | 변화 |
|---|---:|---:|---:|
| 10만 owner 보유 요청 메모리 | 44.7 MiB | **5.9 MiB** | **−86.8%** |
| 빌드 중 요청 메모리 peak | 48.6 MiB | **16.6 MiB** | **−65.8%** |
| 존 빌드 | 247~251 ms | **130~134 ms** | **약 −46~48%** |
| master-file parse peak | 45.4 MiB | **16.5 MiB** | **−63.7%** |
| master-file parse | 321~327 ms | **179~192 ms** | **약 −40~45%** |
| exact A 구조화 조회 | 분리 기준선 없음 | **91~103 ns/query** | — |
| exact A 전체 wire 응답 | 772~780 ns | **171~175 ns** | **4.4~4.6배** |
| flat-zone NXDOMAIN 전체 wire 응답 | 1,167~1,189 ns | **156~167 ns** | **7.0~7.6배** |

지배 항을 실제로 제거했다. owner key는 개별 `Vec<u8>` 대신 단일 metadata arena에 두고,
표준 `RandomState`의 프로세스별 무작위 SipHash와 실제 key 바이트를 함께 검사하는 자체
open-addressing 인덱스의 16바이트 슬롯이 record range를 가리킨다. 따라서 외부 라이브러리나
충돌 시 오답 없이 10만 개 musl 소할당을 없앤다. A는 16바이트 `StoredRecord`에 직접 넣고,
AAAA 주소만 별도 연속 arena에 둬 IPv4 레코드가 IPv6 최대 변형 크기를 떠안지 않는다.
별도 sparse 이름 플래그에는 explicit owner를 중복하지 않고 empty non-terminal과
wildcard 부모·DNAME owner만 둔다. exact A/AAAA UDP 응답은 이미 검증된 question wire에서
header와 RR을 직접 써 `Message`·`Response`·answer `Vec` 할당을 UDP와 TCP에서 생략한다.
부재 이름은 이 작은 예외 인덱스로 질의 branch만 검사한다. 무관한 NXDOMAIN, wildcard
A/AAAA, ENT NODATA, 존 밖을 가리키는 DNAME+CNAME과 부정 SOA까지 allocation 없이 직접 쓴다.

master-file 파서는 전체 logical line을 `Vec<String>`으로 쌓지 않고 재사용 버퍼에서 한 줄씩
처리한다. 레코드는 owner별 `HashMap<Vec<u8>, Vec<Record>>`에 나눠 담지 않고 하나의 연속
`Vec<Record>`에 쓴 뒤 allocation-free canonical owner 정렬로 묶는다. 검증과 최종
`OwnerIndex`가 그 범위를 그대로 공유하고, compact arena로 바꿀 때 큰 임시 Vec 하나만
해제한다. 중간 A/B에서 스트리밍만 적용했을 때 peak 45.4 MiB·300~302 ms, owner별 첫
Vec 용량 4→1 적용 시 26.1 MiB·217~233 ms, 불필요한 suffix/CNAME 검증 할당 제거 시
24.6 MiB·185~203 ms였고, 최종 연속 builder가 위 16.5 MiB·179~192 ms를 만들었다.

직접 경로는 의미가 단순한 경우에만 fail-closed로 켜진다. EDNS/additional, 위임, DNSSEC,
정책·뷰·필터/RPZ·DNS64·cookie·padding·recorder/rate-limit 등 응답이나 부수효과를 바꿀 수
있는 조건은 모두 기존 구조화 경로로 돌아간다. wildcard CNAME, 더 가까운 encloser가
wildcard를 가리는 경우, 존 내부 DNAME target처럼 alias chase가 필요한 응답도 구조화 경로를
탄다. 일반 테스트가 대소문자를 섞은 exact·NXDOMAIN·wildcard·ENT·DNAME의 직접/구조화
응답 의미와 TTL을 고정하고, 게이트 조건 자체도 drift 테스트가 고정한다.

## 서명 NOTIFY·보조 수렴 (2026-07-30, XFR 수신 2026-08-01)

`run-notify.py`는 Python 표준 라이브러리만으로 OnetDNS primary와 secondary를 동시에
시작한다. secondary를 1.2초 늦게 시작해 첫 NOTIFY의 유실과 실제 재전송을 만들고,
HMAC-SHA256 TSIG가 설정된 NOTIFY/ACK 뒤 100~1,000회의 RFC 2136 UPDATE를 보낸다.
마지막에는 primary/secondary SOA serial, 복제된 A 값과 사용자가 지정한 TTL까지 직접
질의한다. secondary 목록 앞에는 같은 지연 primary를 향하는 서로 다른 영역 8개를 둔다.
하네스는 8개 SOA 요청이 1초 안에 모두 도착했는지 확인하고 유효한 새 serial을 돌려준 뒤,
TCP 연결 8개에서 XFR 질의까지 읽고 첫 응답 frame을 보내지 않는다. 8개 TCP admission과
그와 별개인 정상 영역의 최초 수렴이 각각 1초·1.25초를 넘으면 실패시켜 UDP와 TCP 양쪽의
영역 간 head-of-line blocking을 함께 검사한다.

```powershell
python benchmarks/dns-authority/run-notify.py C:/tmp/notify `
  target/release-min/OnetDNS.exe --updates 1000
```

Windows `release-min`, primary/secondary 각 1 worker의 1,000회 실측은 serial
**1→1,001**, UPDATE **124.7/s**, 8개 TCP 무응답 원본의 admission **82.54ms**, 그와
병렬인 정상 영역의 최초 수렴 **157.88ms**, 마지막 UPDATE 응답 뒤 secondary 수렴 **66.01ms**,
레코드 TTL
**120→120**이었다. 시작 시 유실된 NOTIFY는 두 번째 전송이 확인됐고, 변경 1,000회가
NOTIFY 발신 262회로 병합됐다. 두 프로세스 합산 working set은 부하 전 17,920KiB, 부하 뒤
22,044KiB, 구간 CPU는 6.7344초였다. 이 UPDATE 속도와 CPU에는 매번 영역 파일을 원자
저장하고 IXFR journal을 만드는 비용도 포함되므로 순수 NOTIFY 처리량으로 해석하지 않는다.

같은 소스를 별도 빈 target 디렉터리에서 `rust-lld`로 전체 musl 콜드 빌드한
`--no-default-features --profile release-min` 후보는 5,578,208B static PIE이며 SHA-256은
`01C5810EB0E5858218DA03E99409E9FE739EE6BBBE6DDE704A31B63B86147D99`이다.

구현은 변경 호출 스레드에서 소켓 생성·송수신을 하지 않는다. 단일 발신 워커가 IPv4/IPv6
소켓을 각각 한 번만 열고 `(영역, 대상)`별 최신 변경만 20ms 구간에서 병합한다. ACK는 RFC
1996의 source address/port, ID, QNAME, opcode, QR, AA를 모두 맞춰야 하며 TSIG 대상은
요청 MAC에 연결된 올바른 서명 없이는 재시도를 끝낼 수 없다. 응답이 없으면 1초부터 지수
backoff로 다섯 번 재전송한다. 수신 측도 알 수 없는 master와 QR 응답은 무응답으로 버리고,
보조 영역에 `tsig_key`가 있으면 그 정확한 identity만 허용한다. 유효 NOTIFY는 5초 폴링을
기다리지 않고 조건변수로 refresh 작업을 즉시 깨운다. secondary 최초 전송은 서비스 시작을
막지 않는다. 모든 due SOA는 IPv4/IPv6 nonblocking 장수 소켓으로 동시에 다중화하며 source·
ID·question·응답 의미·TSIG를 확인한 뒤에만 pending을 소비한다. pending은 영역당 하나이고
영역 전체나 secret을 복사하지 않는다. SOA에서 실제 변경을 확인하면 자체 Unix/Windows
nonblocking socket 상태머신이 TCP connect·질의 송신·모든 frame 수신·종료 SOA 판별을 최대
64개까지 동시에 진행한다. 연결별 한 순회 작업량은 4 frame 또는 256KiB이고, 모든
pending·prepared·parser 전송은 payload·길이 접두사·frame 벡터 여유분을 포함한 단일
65MiB 미만 raw-buffer 예산을 공유한다. 완결된 응답만 최대 4개 병렬 워커에서 TSIG 체인을
다시 검증하고 영역을 조립한다. IXFR `NOTIMP` fallback도 같은 nonblocking admission으로 AXFR를
새로 시작한다. 동일 영역 중복 실행, admission 도중 바뀐 local serial, 정확한 설정 identity가
달라진 작업의 결과 게시도 차단하며 catalog 제거 시 SOA pending과 대기 XFR를 즉시 폐기한다.

별도 회귀는 opening SOA 한 frame을 보낸 뒤 멈춘 원본 8개가 모두 존재한 다음 정상 원본의
SOA 응답을 허용한다. 디버그 빌드에서도 정상 영역은 **0.52초**에 갱신되어 2초 idle timeout을
기다리지 않았고, 요청 MAC에서 이어지는 2-frame TSIG 전송도 최종 TTL **120** 그대로
검증·게시됐다. 남은 동시성 상한은 admission 64개가 모두 찬 동안 65번째 연결이 기다리는 것과
전역 raw-buffer 예산이 찬 전송이 실패 후 retry로 돌아가는 경우다.

## 조건

- 존: 10만 owner, A 레코드. 위임·DNSSEC 서명 없음(순수 조회·조립 경로).
- 부하: `dnsperf -c 20 -q 40 -T 1 -l 6`, 서버는 `taskset -c 2`, 부하기는 `taskset -c 3`.
- OnetDNS는 `workers = 1`, `cache_enabled = false`. BIND는 `minimal-responses yes`,
  NSD·Knot은 워커 1개.
- 기본 release와 `--no-default-features --profile release-min`은 동일 소스·동일 설정·동일
  affinity로 각각 두 브래킷을 쟀다.
- TCP/AXFR 하네스는 `run-authority-tcp-xfr-interleave.sh`이며 CPU 2/3과 20/21 두 쌍에서
  반복했다. `AUTHORITY_AXFR_RUNS=20`이 위 표 조건이다.
- TSIG/IXFR 하네스는 `run-ixfr-tsig.sh`이며 `AUTHORITY_TSIG_COMPETITORS=1`에서 정적
  TSIG AXFR를 BIND·NSD·Knot과 같은 존·키·CPU로 측정한다.
- 측정하지 않은 것: DNSSEC 온라인 서명, 대형 단일 RRset.

## 대형 RRset 축 (2026-08-01 신설)

기본 존은 이름당 A가 하나라 응답이 54바이트에서 끝난다. 그래서 **RRset 순회와 응답 인코딩
비용이 거의 안 잡힌다.** 실제 배포에서 흔한 것은 CDN A 무리·MX·NS처럼 이름 하나에 RRset이
여럿 붙은 형태다. 이 축을 따로 측정한다.

```sh
AUTHORITY_RRSET=16 sh run-authority-interleave.sh /home/ubuntu/auth-rrset /path/to/onetdns 50000
```

`AUTHORITY_RRSET=N`(1~254)이면 [`generate-rrset-zone.sh`](generate-rrset-zone.sh)로 이름당
A를 N개 만든다. 주소는 `192.0.2.0/24`로 고정한다 — 하네스의 정답 확인이 그 대역을 기대하는데
RRset 안의 순서는 엔진마다 달라, 일부만 그 대역이면 확인이 순서에 좌우된다.

5만 owner × 16 = 80만 레코드, 같은 1코어, `AUTHORITY_ROUNDS=3`, 전 레그 유실 0,
라운드마다 순서 교대(2026-08-01):

| 엔진 | 해석당 CPU | CPU 드리프트 | 트리 Pss | 지연 |
|---|---:|---:|---:|---:|
| **OnetDNS** | **1.8294 ~ 1.8779 µs** | 2.606% | **15,420 ~ 15,456 KiB** | **0.034 ~ 0.038 ms** |
| NSD 4.8.0 | 1.9762 ~ 1.9957 µs | 0.982% | 88,501 ~ 88,623 KiB | 0.036 ~ 0.042 ms |
| Knot 3.3.4 | 2.0472 ~ 2.0707 µs | 1.139% | 23,480 ~ 23,656 KiB | 0.037 ~ 0.070 ms |
| BIND 9 | 4.4543 ~ 4.5702 µs | 2.575% | 48,731 ~ 49,539 KiB | 0.123 ~ 0.135 ms |

**네 엔진 전부 QPS 게이트를 넘고(7~33%) 전부 CPU 게이트를 통과한다(1.0~2.6%).** 이전 버전이
"NSD 대비 판정 불가"로 남겨 둔 곳이 이것이다 — 축을 바꾸면 되는 것이었다.

OnetDNS 최악 대 상대 최선으로 **NSD보다 5.2%, Knot보다 9.0% 싸고 BIND의 2.37배 싸다.**
NSD 마진이 드리프트의 2배다. 지연은 전 엔진 중 가장 낮다.

**바로 앞 회차는 OnetDNS CPU 드리프트가 6.057%로 게이트를 넘어 버렸다.** 그 구간에서도 최악
레그(1.9274)가 NSD 최선(1.9762)보다 낮았지만 규율대로 인용하지 않고 다시 쟀다.

**메모리는 압도한다** — NSD의 1/5.7, BIND의 1/3.2, Knot의 1/1.5다. Pss는 공유
라이브러리 페이지를 나눠 계상해 **동적 링크 엔진에 유리하고 정적 musl인 OnetDNS에 불리하므로**
(OnetDNS는 Pss ≈ VmRSS, BIND는 58,240 → 48,796) 이 배율은 보수적인 값이다.

### 이 축은 한때 졌다 — 격차의 정체는 작은 memcpy 호출이었다

처음 이 축을 해석당 CPU로 재니 **NSD보다 10.7%, Knot보다 8.0% 비쌌다**(2.2018~2.2640 µs).
`/proc/PID/stat`의 utime과 stime을 갈라 보니 **커널은 오히려 OnetDNS가 낮고**(1.3324~1.3914 대
NSD 1.4210~1.4337 µs) 격차가 전부 유저공간이었다:

| 엔진 | user | sys | total |
|---|---:|---:|---:|
| OnetDNS(before) | **0.8701 ~ 0.8908 µs** | 1.3324 ~ 1.3914 | 2.2232 ~ 2.2616 |
| NSD 4.8.0 | 0.5559 ~ 0.6041 µs | 1.4210 ~ 1.4337 | 1.9897 ~ 2.0252 |

perf 평면 프로파일에서 **UDP 워커 user의 36.98%가 `memcpy`**였다.
`write_address_response`가 레코드마다 `Writer::push_bytes`를 불렀는데 답변 하나가
16바이트뿐이라 **호출 비용이 옮기는 바이트보다 컸다.** `&answer[..filled]`의 길이가 실행
시점에 정해져 컴파일러가 이동을 펼치지 못하고 진짜 memcpy 호출을 냈다.

**같은 원인이 두 곳에 있었다.**

**① 답변 인코딩**(`write_address_response`). 같은 RRset의 답변은 길이·소유자·타입·
클래스·rdlength가 전부 같으므로 공간을 한 번에 확보하고(`Writer::reserve_block`) 헤더를
루프 밖에서 만든 뒤, qtype으로 루프를 갈라 **길이가 컴파일 시점 상수가 되게** 하여 고정
크기로 직접 쓴다.

**② 키 만들기**(`wirecache::scan_query`). ①을 넣고 다시 프로파일하니 memcpy가
36.98 → 20.22%로 내려갔는데 여전히 최상위였다. `perf report -g caller`로 가르니 **남은
것의 12.33%가 여기**였다:

```
--18.98%--authority_wire_dispatch
  |--12.33%--scan_query → memcpy
  |--5.48%--write_simple_response → write_address_response → memcpy
```

질의마다 255바이트 스택 배열을 0으로 채워 소문자 이름을 담았다가 키로 한 번 더 옮겼고,
`KeyBuf::extend`가 인라인되지 않아 **2바이트를 옮기는 데도 진짜 memcpy 호출**이 났다
(질의당 5회). 이름을 키에 곧장 쓰고, 고정 길이는 const 제네릭 `push_array`로 받아
이동이 펼쳐지게 했다.

**③ RRset 선택**(2026-08-08). 직접 writer는 같은 owner 배열을 전부 훑어 답 개수를 센 뒤
다시 타입을 필터링하며 썼다. 로드 시 owner 내부를 numeric RR type 순으로 정렬하고,
`stored_rrset`이 연속 slice를 돌려주게 해 선택한 RRset을 한 번만 순회한다. 단일 타입 owner는
첫·끝 확인만 하고 전부 반환하며, 혼합 owner만 이진 탐색한다. 구조화 경로의 `of_type`도
같은 slice를 쓴다. 저장 구조 크기와 wire 형식은 바뀌지 않는다.

254개 A RRset, 100만 조회, release 6회 순서 교대 격리 벤치:

| 선택 구간 | 관측 범위 | 종전 대비 |
|---|---:|---:|
| 종전 계수+필터 이중 순회 | 136.04~138.42 ns/query | — |
| 타입 slice+단일 순회 | **20.68~25.51 ns/query** | **5.33~6.65배** |

이는 전체 응답 인코딩이나 UDP 종단값이 아니라 제거한 선택/순회 구간의 마이크로벤치다.
현 호스트의 게임·IDE 부하에서는 종단 CPU 드리프트가 5%를 넘어, 종단 개선 폭은 아직
공표하지 않는다. 재현은 다음과 같다.

```sh
cargo test -p onetdns-authority --release bench_sorted_rrset_slice -- --ignored --nocapture
```

현행 musl release의 `AUTHORITY_RRSET=16`, 1,000 owner, 1라운드 production smoke에서는
OnetDNS 두 레그와 BIND·NSD·Knot 전 레그가 정답 확인·손실 0을 통과했다. OnetDNS CPU 산포는
3.706%였지만 QPS 산포가 5.492%이고 경쟁 엔진은 각 1레그뿐이라 성능 비교에는 쓰지 않는다.
새 정렬/slice의 실제 wire 정확성 확인일 뿐이다.

#### slice 적용 뒤 당시 user 프로파일

심볼을 보존한 당시 musl release, 같은 `AUTHORITY_RRSET=16`·1,000 owner 존, 서버 CPU 2·부하기
CPU 3, 2초 워밍업 뒤 30초 부하를 프로파일했다. `dnsperf -c 20 -q 40 -T 1`은
12,315,999질의 전부 완료·손실 0·응답 292B였다. 당시 호스트가 유휴가 아니었으므로 410,532
QPS는 비교값으로 쓰지 않는다.

```sh
# 출하 artifact와 섞지 않도록 별도 target에 심볼 보존 바이너리를 만든다.
CARGO_TARGET_DIR=target/perf-symbols \
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
  cargo rustc -p onetdns --release --target x86_64-unknown-linux-musl -- \
  -C strip=none -C debuginfo=1

# 이 WSL 설치에서 /usr/bin/perf는 현재 커널 도구를 찾지 못하므로 실제 설치본을 직접 썼다.
PERF=/usr/lib/linux-tools-6.8.0-137/perf
$PERF record -e cycles:u -F 999 -g --call-graph dwarf,16384 \
  -p "$SERVER_PID" -o perf.data -- sleep 32
$PERF report --header-only -i perf.data
$PERF report --stdio --no-children -i perf.data
```

명령은 `cycles:u`를 요청했지만 저장된 헤더의 실제 이벤트는 **`task-clock:uH`**였다. 4,425
samples, lost 0, kernel 제외이므로 다음은 user 표본 내부 비율일 뿐이다.

| flat symbol | user 표본 |
|---|---:|
| `memcpy` / `sccp` / `sendmsg` | 16.14% / 13.51% / 6.12% |
| `scan_query` / `write_address_response` | 5.04% / 5.04% |
| `record_authority_wire` / `ArcSwap::load` / `memset` | 3.98% / 2.85% / 2.76% |

`write_address_response`의 inclusive 9.97% 중 `Writer::push_bytes`는 2.28%,
`Writer::reserve_block`은 1.92%, **`stored_rrset`은 0.72%**였다. 따라서 RRset 선택을 더 만지는
것은 우선순위가 아니다. authority dispatch에서는 기본 ACL의 클라이언트 식별과 기록기가
`NativeFeatures` snapshot을 따로 읽는 두 call site가 2.64%·2.73%였다. 기록 활성 경로의 진단
함수까지 포함하면 최대 3회였다. 이제 조기 fallback 뒤 snapshot 하나를 잡아 ACL 식별과 기록에
같은 세대를 넘기고, DDR 때문에 먼저 잡았어도 재사용한다. 이미 고른 `Recorder`도 진단 함수에
직접 전달한다. 비자명 ACL+활성 recorder 회귀가 질의당 feature load 정확히 1회를 고정한다.

```sh
cargo test -p onetdns --release bench_native_feature_snapshot_reuse -- --ignored --nocapture
```

4백만 회·release 6회 순서 교대에서 두 load는 31.07~32.19 ns/query, 한 load 재사용은
**14.54~15.06 ns/query(2.09~2.21배)**였다. 실제 `AUTHORITY_RRSET=16`·1,000 owner·`--no-web`
old/new 12라운드는 기준 1.7887~1.8328, 후보 1.7838~1.8306 µs/query, CPU 산포
2.432%/2.588%, 손실 0이었다. 대응 old/new 중앙값은 1.002773이나 12회 중 7회만 개선 방향이고
범위가 겹치므로 **종단 개선이 아니라 무회귀**로만 판정한다.

답변 블록 zero-fill을 없애되 `unsafe`를 쓰지 않는 후보도 release 6회 교대로 분리 측정했다.
전체 길이를 한 번 검사하고 완전히 초기화한 `[u8; 16]`을 레코드별로 append하는 방식이다.
16개에서는 기존 12.21~16.61 대 후보 13.66~13.84 ns/query로 이득을 구분하지 못했고, 254개는
기존 **159.28~162.08** 대 후보 **194.97~197.20 ns/query**로 후보가 1.20~1.24배 느렸다.
반복되는 `Vec` 길이·용량 확인이 일괄 초기화보다 비쌌다. 구현과 회귀는 되돌렸고, 미초기화
slice나 `unsafe set_len`은 도입하지 않았다.

미초기화 저장소를 캡슐화한 두 번째 후보도 재었다. 전체 블록을 한 번 reserve하고
`spare_capacity_mut`에 완전 초기화 배열을 쓴 뒤 모든 항목이 성공했을 때만 한 번 `set_len`했다.
중간 실패·한도·panic 원자성 회귀는 통과했지만, release 6회 교대에서 16개는 기존
**11.59~12.93** 대 후보 **19.77~20.58 ns/query(1.53~1.78배 느림)**, 254개는 기존
**142.73~144.92** 대 후보 **274.38~284.45 ns/query(1.91~1.99배 느림)**였다. 격리 열세가
명확해 production A/B는 실행하지 않았고 API·unsafe·회귀·벤치를 전부 되돌렸다. 답변 블록의
연속 zero-fill은 현재 두 안전성 설계보다 싸다.

질문 헤더의 세 copy는 기존 `reserve_block` 하나로 합쳤다. 12바이트 header, 원본 QNAME,
4바이트 QTYPE/QCLASS를 전체 구간에 직접 써서 상한·용량 검사를 한 번만 한다. 새 API와
`unsafe`는 없고, 정확한 EDNS·대소문자 wire와 1바이트 부족 시 원자 실패를 회귀로 고정했다.

```sh
cargo test -p onetdns-authority --release bench_question_prologue_single_reserve -- --ignored --nocapture
```

4백만 회·release 6회 교대에서 기존 12.52~12.81 대 후보
**6.67~7.09 ns/query(1.77~1.89배)**였다. 같은 production 조건의 12라운드 A/B는 후보
1.7597~1.8092, 기준 1.7877~1.8434 µs/query, CPU 산포 2.773%/3.069%, 전 24레그 정답 확인·
손실 0이었다. 대응 12/12가 후보 방향이고 기준/후보 중앙 1.01679, 중앙 절감
**0.0301 µs/query(약 1.65%)**다. 절대 범위는 겹치므로 큰 종단 개선으로 읽지 않는다. 기준
QPS 산포 50.913% 때문에 QPS는 인용하지 않는다.

질문 헤더 적용 뒤·wire 키 축소 전 같은 16-A·1,000 owner 조건을 심볼 보존 musl release로
다시 프로파일했다.
30초 동안 13,842,375질의 전부 완료·손실 0, 3,962 samples·lost 0이었다. 요청 이벤트는
`cycles:u`였지만 저장된 실제 이벤트는 다시 **`task-clock:uH`**다.

| flat symbol | user 표본 |
|---|---:|
| `sccp` / `memcpy` / `authority_wire_dispatch` | 16.36% / 7.57% / 6.03% |
| `sendmsg` / `scan_query` / `memset` | 5.98% / 5.88% / 5.58% |
| `write_address_response` / `OwnerIndex::get` / `ArcSwap::load` | 4.22% / 3.51% / 3.10% |
| `write_question_prologue` / `stored_rrset` | **0.86% / 0.53%** |

`scan_query`에서 KeyBuf 길이를 바이트마다가 아니라 라벨마다 갱신하는 안전 후보는 격리
16.27~16.76 → 14.71~15.73 ns/query(1.04~1.14배)였지만 production 12라운드에서 후보
1.7532~1.8090, 기준 1.7614~1.8039 µs/query로 범위가 겹치고 대응 7/12만 개선됐다. 대응 평균
기준/후보 1.00024라 종단 이득이 없으며 구현과 벤치는 되돌렸다.

다음 후보는 라벨 루프가 아니라 매 질의의 **고정 저장소 크기**를 줄였다. 변경 전 `scan_query`
디스어셈블리는 312바이트 스택 프레임, 277바이트 `memset`, 반환 시 288바이트 `memcpy`를 냈다.
KeyBuf를 구조화 캐시와 같은 64바이트 인라인 상한으로 줄였고, 더 긴 정상 질의는 기존 구조화
경로에서 답한다. 정확히 64바이트인 일반·EDNS 키와 65바이트 폴백, 실제 폴백 A 응답을
회귀로 고정했다. 새 할당·외부 의존성·`unsafe`는 없다.

Windows release 6회 순서 교대에서 스캔은 **19.1~19.4 → 15.7~17.0 ns/query
(1.12~1.24배)**였다. 첫 production 12라운드는 CPU 산포 6.120%/6.636%라 기각했다. 독립
두 번째 12라운드는 기준 **1.7805~1.8177**, 후보 **1.7617~1.7816 µs/query**, CPU 산포
2.074%/1.124%, 24레그 정답 확인·손실 0, 대응 12/12 후보 방향이었다. 대응 중앙 기준/후보
1.01086, 중앙 절감 **0.0192 µs/query(약 1.07%)**다. 절대 범위는 조금 겹치며 후보 QPS 산포
65.521%라 큰 종단 개선이나 QPS 개선으로 읽지 않는다.

적용 뒤 같은 조건의 30초 프로파일은 12,517,462질의 전부 완료·손실 0, 3,751 samples·lost
0이었다. 실제 이벤트는 **`task-clock:uH`**다. 새 디스어셈블리에서 스택 프레임은 104바이트고
`scan_query` 안의 `memset`·`memcpy` 호출이 사라졌다.

| flat symbol | user 표본 |
|---|---:|
| `sccp` / `authority_wire_dispatch` / `scan_query` | 16.24% / 8.05% / 6.19% |
| `sendmsg` / `write_address_response` / `OwnerIndex::get` | 5.87% / 5.31% / 4.05% |
| `ArcSwap::load` / `NativeFeatureSwap::load` | 3.87% / 3.60% |
| `memset` / `memcpy` | **3.20% / 2.59%** |
| `write_question_prologue` / `stored_rrset` | 1.09% / 0.56% |

위 당시 flat 표의 `ArcSwap::load` 2.85%는 zone-store snapshot이고, feature 두 값은 인라인된
서로 다른 콜그래프 가지다. 세 값을 단순 합산하지 않는다.

같은 구간 A/B(`AUTHORITY_AB_BIN`, 라운드마다 순서 교대, 전 레그 유실 0):

| A/B | before | after | 드리프트 | 조건 |
|---|---:|---:|---:|---|
| ① 인코딩 | 2.1858 ~ 2.2149 µs | **1.9037 ~ 1.9301 µs** | 1.32 · 1.38% | 4라운드 |
| ② 키 | 1.9363 ~ 1.9579 µs | **1.8524 ~ 1.8829 µs** | 1.11 · 1.63% | 3라운드 |
| ③ feature snapshot | 1.7887 ~ 1.8328 µs | 1.7838 ~ 1.8306 µs | 2.432 · 2.588% | 12라운드, 범위 중첩 |
| ④ 질문 헤더 | 1.7877 ~ 1.8434 µs | **1.7597 ~ 1.8092 µs** | 3.069 · 2.773% | 12라운드, 대응 12/12 개선·범위 중첩 |
| ⑤ wire 키 64B 인라인 | 1.7805 ~ 1.8177 µs | **1.7617 ~ 1.7816 µs** | 2.074 · 1.124% | 12라운드, 대응 12/12 개선·범위 중첩 |

①·②는 범위가 겹치지 않는다. OnetDNS 최악 대 상대 최선으로 ①은 **−13.2%**(마진이 드리프트의
10배), ②는 **−2.8%**다. 누적 **2.1858~2.2149 → 1.8294~1.8779 µs**, 평균 지연
0.049~0.057 → **0.034~0.038 ms**, 트리 Pss는 변화 없음.

**이름당 A 하나인 주력 축은 무회귀다**(10만 owner, 3라운드 교대, 같은 구간 QPS 드리프트
0.7~1.5%): 후보 1.8672~1.8882 대 기준 1.8944~1.9068 µs. 범위가 겹치지 않아 방향은
좋으나 마진 약 1%가 드리프트와 비슷하므로 **개선으로 주장하지 않는다.** 답변이 하나면
줄일 호출도 하나뿐이라 이득이 작은 것이 셈과 맞는다.

### 정정: NSD 공표치 11,200 KiB는 세 프로세스 중 하나만 측정한 값이었다

`run-authority-interleave.sh`가 `$!`로 잡은 PID 하나의 `VmRSS`만 읽고 있었다. **NSD는
`server-count`만큼 자식을 fork하므로 그 PID는 존 데이터를 거의 가지고 있지 않다.** 같은
80만 레코드 존 실측:

| 프로세스 | VmRSS | Pss |
|---|---:|---:|
| 하네스가 읽던 PID | **11,200 KiB** | 4,802 KiB |
| 자식 1 | 83,528 KiB | 56,523 KiB |
| 자식 2 | 53,372 KiB | 27,164 KiB |
| **합계** | 148,100 KiB | **88,489 KiB** |

증상은 표에 이미 보였다 — NSD RSS가 5만·40만·80만 레코드에서 11,200 / 11,424 / 11,200으로
**16배 구간 내내 평평했다.** 존을 메모리에 올려 두고 서빙하는 서버에서 불가능한 값인데, OnetDNS는
그것을 "NSD는 선할당이라 평평하다"고 설명해 버렸다.

**같은 파일 안에 반증이 있었다.** 위 TCP/AXFR 절은 "서버 CPU/RSS는 master PID 하나가
아니라 자식까지 포함한 프로세스 트리 합계"라고 적고 NSD를 104,272~104,644 KiB로 낸다 —
더 작은 10만 레코드 존에서 9배 큰 값이다. **옳은 기법이 같은 디렉터리에 이미 있었다.**

이제 [`../lib/procmem.sh`](../lib/procmem.sh)가 명령줄로 트리를 찾아 **Pss를 더한다**.
자식 `VmRSS`를 그냥 더하면 fork로 공유된 페이지를 여러 번 세어 과대 계상한다
(148,100 대 88,489).

**따라 폐기하는 결론들**: "80만 레코드에서 NSD의 1.38배 무겁다"(실제 1/5.7),
"교차점은 약 42만 레코드", "작고 열악한 환경일수록 OnetDNS가 이긴다"(교차점이 없다.
모든 크기에서 OnetDNS가 가볍다), "레코드당 8 B를 4 B로 줄여 교차점을 90만으로 민다"
(동기가 사라졌다 — RRset 단위 TTL 설계 자체는 유효하고 약 3,125 KiB를 더 줄이지만,
격차를 메우는 일이 아니라 이미 이긴 축을 벌리는 일이다).

### RSS 부채를 갚은 과정

`StoredRecord` 8바이트 접기의 진단은 NSD와 무관하게 OnetDNS 축만 보고 한 것이라 유효하다.
같은 owner 수에서 이름당 1개(5만 레코드)와 16개(80만 레코드)를 측정해서 **한계 비용이
레코드당 17.4바이트**임을 먼저 확인했다. `StoredRecord`가 16바이트였으므로 그것이 사실상
전부였다.

`StoredRecord`를 **8바이트로 접었다** — 종류를 TTL의 상위 2비트에 넣고, A·AAAA가 아닌
레코드는 `Box` 대신 아레나 인덱스로 바꿨다. 예측 절감(80만 × 8B = 6,250 KiB)과 실측
(6,252 KiB)이 그대로 맞았다.

| 축 | before | after |
|---|---:|---:|
| 이름당 16개(80만 레코드) | 21,440 ~ 21,676 KiB | **15,412 ~ 15,424 KiB** (−28.8%) |
| 이름당 1개(5만 레코드) | 8,896 KiB | **8,568 KiB** |

처리량과 지연은 두 축 모두 종전 범위 안에 있다. OnetDNS 비용은 축을 하나씩 고정해 측정하면
**약 6,278 KiB + 레코드당 8 B + owner당 38 B**다. owner당 몫은 5만↔10만 owner를 같은
80만 레코드에서 측정해서(15,424 → 17,312 KiB) 갈랐다.

**owner당 38 B는 사실상 줄일 곳이 없다.** 뜯어 보면 `OwnerIndex`의 슬롯 배열
(`next_power_of_two(owner × 1.25)` × 12 B → 5만 owner에서 15.7 B/owner)과 메타데이터
아레나(키 길이 1 + 레코드 수 2 + 키 바이트 약 20 → 23 B/owner)다. 합이 38.7 B로 실측
37.8 B와 맞는다. 키 바이트는 조회 때 비교해야 하므로 없앨 수 없고, 슬롯 낭비는 2의
거듭제곱 반올림 5%뿐이다.

남아 있던 슬롯 축소 가설도 실제로 재고 닫았다. `tag:u8[] + metadata offset:u32[]`로 나눈
후보는 10만 owner 보유량 **4.6 → 4.1 MiB**, peak **15.3 → 14.8 MiB**였지만 6회 교대
분산 조회에서 5/6 느렸다. 두 배열 접근을 없앤 안전한 5바이트 밀집 슬롯
`tag:u8 + offset:[u8;4]`도 메모리 절감은 같았으나 분산 조회 중앙이 약 4.7% 느리고 4/6가
회귀 방향이었다. 같은 `rust-lld` production 12라운드는 정답·손실 0, CPU 산포
후보/기준 2.064%/2.248%, 대응 10/12와 중앙 약 0.51% 개선, Pss 약 512 KiB 절감이었다.
그러나 후보 QPS 산포가 **65.150%**(기준 4.944%)였고, 역할을 뒤집은 6라운드에서도 후보
**36.030%** 대 기준 1.835%로 불안정이 후보 바이너리를 따랐다. 처리율 신뢰성을 작은 CPU·
메모리 이득과 바꾸지 않고 두 구현과 회귀를 전부 원복했다. 원인을 밝히기 전에는 같은 축소를
다시 적용하지 않는다.

`name_flags`는 이 몫에 들어 있지 않다 — **빈 비단말·와일드카드 부모·DNAME 소유자만**
담는다(`!records.contains_key(key)` 조건). 평탄한 존에서는 비어 있고, 그래서
`simple_nxdomain`이 서서 무할당 NXDOMAIN 경로가 열린다.

40만 레코드 회차는 OnetDNS 드리프트 2.93%로 게이트를 통과했고 그 구간에서 처리량이 NSD보다
높았으나, **경쟁 엔진에 레그가 하나뿐이라 배율은 인용하지 않는다** — 오염은 OnetDNS에
유리한 방향이라 반드시 경쟁 엔진에도 게이트를 걸어야 한다.

### 용량 한계

`MAX_ZONE_RECORDS = 1_000_000`이라 **10만 owner × 16(160만 레코드) 존은 로드를 거부한다.**
fail-closed로 분명히 보고하지만, 같은 존을 BIND·NSD·Knot는 그대로 서빙한다.

`StoredRecord`가 8바이트가 되어 160만 레코드의 아레나는 25.6 MB에서 12.8 MB가 됐다.
그래도 **상한은 임의로 올리지 않는다** — 이 값은 자원 소진 방어이고 보조 영역은 AXFR로
들어오므로 원격이 채우는 입력이다. 전송 상한 64 MiB와 함께 정해야 하는 사인오프 사안이다.
