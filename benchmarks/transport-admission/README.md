# 암호화 TCP 연결 자원 하네스

DoH·DoT·DNSCrypt TCP가 공유하는 framing admission 자원 계약을 Windows에서 재현한다. 현재
하네스는 가장 단순한 DoT admission을 쓴다. 클라이언트 64개가 TLS record type 한 바이트만
보내고 멈춰, DNS 처리량이나 업스트림 상태와 무관하게 완전한 ClientHello 전의
스레드·핸들·메모리 수명만 측정한다.

```powershell
.\benchmarks\transport-admission\run-dot-windows.ps1 `
  -Binary target\codex-tcp-prefix-release\release\OnetDNS.exe `
  -ClientCount 64 -HoldSeconds 5
```

수신 주소를 늘렸을 때 admission이 곱해지지 않는지도 같은 하네스로 측정한다. `ClientCount`는
수신 주소 **하나당** 접속 수다.

```powershell
.\benchmarks\transport-admission\run-dot-windows.ps1 `
  -Binary target\codex-tcp-prefix-release\release\OnetDNS.exe `
  -ClientCount 64 -ListenerCount 2 -HoldSeconds 5
```

스크립트는 별도 DNS·DoT 포트와 `target/dot-admission/<UTC timestamp>` 아래의 자체 설정을
사용한다. 시작 전 TCP/UDP 포트와 설정을 검증하고, baseline/held/released의 CPU·thread·handle·
working set·private·virtual을 `summary.json`에 쓴다. 종료할 때는 자신이 시작한 PID만 멈춘다.
루프백 한 주소의 연결 상한이 64이므로 기본 클라이언트 수도 64다.

## 2026-08-09 단일 수신 주소 교대 결과

기준 SHA-256:
`3A42140BEDCAB7BF86A9A1083F05917964263C3307B92060C28007415E1F45D2`

최종 후보 SHA-256:
`C6238639C685F2026798A063AB2303699C35E3BD982ED6C2BF3E41E1F6F53110`

| 64개 연결 | 기준 R1 / R2 | 최종 후보 R1 / R2 |
|---|---:|---:|
| write / established | 64 / 64 | 64 / 64 |
| thread 증가 | +64 / +64 | +64 / +64 |
| virtual 증가 | 135,266,304 / 135,266,304 B | **34,603,008 / 34,603,008 B** |
| held handle 증가 | +256 / +256 | **+192 / +192** |
| released handle 증가 | +64 / +64 | **0 / 0** |

512KiB 명시적 스택으로 virtual 증가는 **74.4186%** 줄었다. `JoinHandle`을 즉시 detach하고
`ConnectionLimiter` 조건변수로 종료를 기다려, 실행 중 thread handle 하나씩과 완료 뒤 남던
64개 handle도 제거했다. working set은 줄지 않았으므로 이 결과를 RSS 개선으로 해석하지 않는다.

원자료:

- 기준: `target/dot-admission/20260809T045411Z`, `20260809T050055Z`
- 최종 후보: `target/dot-admission/20260809T050010Z`, `20260809T050043Z`

## 두 수신 주소의 프로세스 admission 교대 결과

직전 후보는 주소마다 별도 512/64 limiter를 만들었다. 최종 후보는 DoH·DoT·DNSCrypt TCP와
모든 수신 주소가 단일 512-total/64-per-IP limiter를 공유한다. 서로 다른 DoT 주소 두 개에
루프백 IP 하나가 주소당 64회 접속했으며, client write 성공과 서버가 5초 뒤 유지한
`Established` 연결 수를 따로 기록했다.

직전 후보 SHA-256:
`C6238639C685F2026798A063AB2303699C35E3BD982ED6C2BF3E41E1F6F53110`

최종 후보 SHA-256:
`F3AAA6C6EA0142DEBC867825EF8F865B6D4B329705D183BDF4345AED9C562D13`

| 두 DoT 주소·주소당 64회 | 직전 후보 R1 / R2 | 최종 후보 R1 / R2 |
|---|---:|---:|
| client write | 128 / 128 | 128 / 128 |
| server established | 128 / 128 | **64 / 64** |
| thread 증가 | +128 / +128 | **+64 / +64** |
| handle 증가 | +384 / +384 | **+192 / +192** |
| virtual 증가 | 70,254,592 / 70,254,592 B | **34,603,008 / 34,603,008 B** |
| released handle 증가 | 0 / 0 | 0 / 0 |

이 결과는 연결당 비용이 줄었다는 뜻이 아니라 공격자가 수신 주소나 전송 종류를 늘려 프로세스
상한을 곱하지 못한다는 뜻이다. tracker는 리스너별이므로 한 주소를 내릴 때 다른 주소의 활성
연결이 끝나기를 기다리지 않는다. IPv4-mapped IPv6는 원래 IPv4와 같은 per-IP 키를 쓴다.

원자료:

- 직전 후보: `target/dot-admission/20260809T053304Z`, `20260809T053630Z`
- 최종 후보: `target/dot-admission/20260809T054854Z`, `20260809T054912Z`

## 첫 frame 전 무스레드 admission 결과

위 두 단계 뒤에도 느린 연결 하나마다 512 KiB 스택의 처리 스레드가 하나씩 존재했다. 현행
DoH·DoT 리스너는 최대 64 KiB의 완전한 TLS ClientHello, DNSCrypt TCP 리스너는 최대 8 KiB의
완전한 길이 접두사 frame을 먼저 nonblocking으로 모은다. 완결 전에는 처리 스레드를 만들지
않고, 완결 뒤에는 먼저 읽은 바이트를 기존 TLS·DNSCrypt 파서에 그대로 재생한다. 프레이밍
admission은 프로토콜 의미를 대신 판정하지 않는다. 30초 절대 데드라인과 10→250 ms 적응형 확인,
accept 64개 batch 상한으로 느린 연결의 syscall과 새 연결 폭주가 종료 확인을 굶기지 않게 했다.

최종 후보 SHA-256:
`09694ADEB7061A9697AF9C155FE135F48EEE11C7091CF45AA61F4D179AE00375`

| 한 DoT 주소·64개 one-byte 연결 | R1 | R2 |
|---|---:|---:|
| client write / server established | 64 / 64 | 64 / 64 |
| thread 증가 | **0** | **0** |
| handle 증가 | **+65** | **+65** |
| working set 증가 | 73,728 B | 86,016 B |
| private 증가 | 40,960 B | 53,248 B |
| virtual 증가 | **0 B** | **0 B** |
| 5초 hold CPU | 0 ms | 0 ms |
| 해제 뒤 handle 증가 | **0** | **0** |

두 수신 주소에 주소당 64회 접속한 반복도 client write는 128/128이었지만 프로세스 동일-IP
상한에 따라 서버 연결은 64/64만 유지했다. 두 회차 모두 thread +0·virtual +0 B였고 handle은
+66, working set은 +86,016/+106,496 B, private는 +32,768/+61,440 B였다. 5초 CPU는
15.625/31.25 ms였고 해제 뒤 handle은 기준으로 돌아왔다. 따라서 이 결과는 연결을 거절해 얻은
무스레드 수치가 아니다. 64개 허용 연결은 그대로 유지됐다.

원자료:

- 단일 수신 주소: `target/dot-admission/20260809T062548Z`, `20260809T062605Z`
- 두 수신 주소: `target/dot-admission/20260809T062627Z`, `20260809T062648Z`
