# Current Implementation State

기준일: 2026-08-31

`scripts/` 아래의 로컬 테스트 helper, smoke runner, release evidence collector, memory
profile wrapper는 삭제되었다. 이 문서에 남아 있는 해당 script 이름은 과거 Phase evidence를
설명하는 추적 정보이며 현재 실행 가능한 명령으로 해석하지 않는다. 현재 코드 검증의 기본
출발점은 `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace -- --test-threads=1`,
`python3 tools/release/check_architecture.py --workspace .`, 실제 `edge-proxy` 실행과 필요한
`python3 tools/release/check_source_indexes.py --workspace .`, 실제 `edge-proxy` 실행과 필요한
수동/통합 검증이다. Build Binaries workflow의 read-only `Source quality` job은 fmt, clippy,
workspace test, architecture/source-index fitness와 pinned `cargo-audit`의 `cargo audit`을 모두
통과시킨 뒤에만 artifact build와 prerelease candidate publish를 시작한다. audit tool install
또는 advisory DB 접근 실패도 job 실패로 처리한다. A SemVer tag remains a candidate until
tracked clean-host evidence validates through `promote-release.yml`; this does not reopen certificate
automation.

The public `v0.0.4` prerelease remains immutable but is rejected from promotion: its image
manifest lacks the required OCI revision and version labels. It must not be retagged, amended,
or used as clean-host evidence. The public `v0.0.5` prerelease has a valid identity and C8
evidence, but its official Compose package has no primary-config mount and therefore cannot
complete the clean-host deployment matrix. The public `v0.0.6` prerelease adds the missing
read-only canonical primary-config mount and first-install preservation behavior, but its
operator documentation omits the required fixed `runtime.env` Compose input. The public `v0.0.7`
prerelease corrects that command, but its root-only Compose backup override lacks the minimum
capability required to open the edge-owned data lock after `cap_drop: ALL`. The current tree
carries `v0.0.10 candidate metadata`, but has no tag or published artifact. It retains only
`DAC_OVERRIDE` in the short-lived root override. The unpublished v0.0.9 source correctly
declared its closing responses but lost enough throughput to fail C8; v0.0.10 instead supports
one-at-a-time plaintext HTTP/1.1 client keep-alive after a fully flushed response, while still
honoring an explicit client `Connection: close` and preserving TLS close-notify behavior. Its
source-level contracts do not replace the required
same-identity clean-host matrix.
Before a candidate prerelease is assembled, the tag workflow anonymously pulls its exact GHCR
digest and fails closed unless the inspected OCI revision and version labels equal the tagged
commit and SemVer tag.

## Performance Test Environment

The separate `tests/performance/` Compose boundary now provides a production
`edge-perf` release image, deterministic Node upstream, Edge-only k6 profiles,
host-only CPU/memory samples, fail-closed summary/audit, and a 30-second smoke
CI gate. Baseline (three independent warmup/measurement runs), stress, and
30-minute soak remain manual characterization profiles. Their ignored artifacts
do not replace the canonical Phase 011 7,200-second/platform release gate.
For C8, new baseline artifacts must capture matching host identity and pass the
5% median-RPS, 10% p95/p99, and no-error-increase gate described in
[`release-gate.md`](release-gate.md#support-and-performance-evidence). Artifacts
created before that host-identity schema remain characterization-only.

이 문서는 Phase 001부터 Phase 011까지 완료된 구현의 현재 기준이다. 상세 과거 계획과 실행
기록은 `.tasks/phase001/`부터 `.tasks/phase012/`에 보관하며, Phase 010 완료 판정은
`artifacts/release-evidence/phase010-20260716-final-r2`와
`docs/mvp-completion-audit.md`를 기준으로 한다. Phase 011 정량 memory/resource safety의
완료 근거는 `.tasks/phase011/`과 이 문서에 보관한다. 활성 `.tasks/plan.md`는 이후 단일 노드
운영 제품화 계획이며 아직 완료된 기능을 주장하지 않는다. Task 001~023은 typed policy, global logical payload
ledger, exact release, restart-required desired/active 분리, resource metrics/logs와 live
Admin summary까지 완료했다. Task 024~038은 cross-platform harness foundation, canonical
evidence, HTTP small-load, macOS arm64 1,024-connection capacity/admission, slow header/body timeout과
cleanup smoke까지 완료했다. Task 039~043은 HTTPS/mTLS idle capacity, WebSocket backpressure,
50,000 HTTP connection churn plateau와 128 slow-response cleanup을 완료했다. 이후 fixed
12-scenario macOS arm64/native Linux x86_64 full profile, 7,200초 soak, macOS deep diagnostic과
final release binding까지 완료했다.
Production은 process-wide
`SharedFileAuditLedger`를 사용하며
재시작 보존, verified startup/reconciliation, authenticated `GET /api/v1/audit`와
Admin audit viewer를 지원한다. Phase 008에서 암호화 backup,
crash-recoverable offline restore/replace/recovery, 사설 PKI 인증 행렬과
backup→restore→fresh startup→Admin 재인증→trusted HTTPS recovery E2E가 구현됐다.
Phase 008 automatic release marker/snippet contract와 independent evidence validator까지
통과했다. 외부 Let's Encrypt는 이 완료 판정에 포함하지 않는다.
Phase 009의 managed private trust bundle CRUD/verified read, strict rustls client
factory/core transport, production startup preparation과 실제 rustls private-PKI mio
upstream HTTPS forwarding, strict HTTPS active health probe와 TLS WebSocket tunnel은
구현되었다. managed private client Root를 사용하는 required inbound mTLS도 listener별
factory로 구현되었다. config snapshot, health availability, listener별 inbound server factory,
outbound request/health TLS registry의 generation-atomic apply와 rollback compensation도
구현되었다. Task 019에서 trust bundle backup/restore schema v2, schema v1 read/restore
compatibility, trust CA/profile preflight와 fresh restore bidirectional TLS E2E도 구현되었다.

현재 활성 운영 제품화 작업은 fixed-path support bundle을 추가했다. authenticated/CSRF-protected
`POST /api/v1/support-bundles`와 Admin UI는 fixed allowlist, file/byte/log-age bounds,
no-follow path checks와 sensitive-content scan을 거친 private tar receipt만 제공한다. API/UI는
archive filesystem path, PEM, secret, header/cookie/body/query를 노출하지 않는다. Compose/systemd
offline upgrade helper는 fixed image digest manifest와 checksum-backed backup receipt를 사용하며,
실제 clean-host release evidence는 아직 완료 주장 근거가 아니다. Manual certificate/private PKI만
지원하며 external Let’s Encrypt/ACME issuance or renewal automation is explicitly deferred until
the user reopens that scope.

Phase 011 Task 001의 macOS arm64 release mini-run 2회에서 idle과 incomplete idle connection
100개 RSS는 9~10 MiB 범위였고 관측 증가는 1 MiB 미만이었다. 이는 owner
inventory와 sampler contract characterization일 뿐이며 Linux profile, HTTP/TLS peak,
churn/soak 완료를 의미하지 않는다. 권위 계약은
`docs/memory-resource-baseline.md`와 ADR 011이다.

Task 023 기준 Core는 active revision, logical payload used/limit, active connection count와
closed pressure state를 deduplicated latest snapshot으로 nonblocking 게시한다. Admin API/UI는
이 mirror만 읽으며 Core connection table/ledger를 직접 lock하지 않는다. 미게시 상태는
`null`/`unavailable`이고 값은 process RSS나 per-owner 상세가 아니다.

Task 024는 test/release-only memory harness에 platform-neutral lifecycle과 process/RSS/load/
clock port, fake-port orchestrator를 추가했다. 이는 실제 OS sampler나 release scenario
완료 증거가 아니라 Gate C를 위한 deterministic foundation이다.

Task 025는 macOS `ps`와 Linux `/proc` fixture를 checked bytes/start identity로 해석하는
test-tool adapter, explicit child command supervisor와 current-host child smoke를 추가했다.
실제 release proxy scenario와 cross-platform approval report는 아직 남아 있다.

Task 026은 source/config/scenario/process identity에 묶인 canonical memory report schema v2,
atomic writer, SHA-256 digest와 independent tamper/stale validator를 추가했다. Ceiling/plateau
평가와 release collector 승인은 아직 수행하지 않았다.

Task 027은 absolute ceiling, 5-cycle cooldown plateau와 process/request/connection/payload
correctness를 함께 판정하는 pure evaluator를 추가했다. 실제 release-process observation은
아직 이 evaluator에 공급되지 않는다.

Task 028은 release `edge-proxy` PID를 schema v2 evidence CLI로 직접 측정하고 별도 validator
invocation으로 source/config/scenario identity와 digest를 승인했다. macOS arm64 idle 3 sample은
모두 9,338,880 bytes였고 missing sample은 0이었다. 이는 short Gate C smoke이며 Linux/full
load/plateau 승인 결과가 아니다.

Task 029는 test-tool에 immutable loopback target/request bound를 받는 HTTP churn driver와
Admin live resource status projection parser를 추가했다. 정상 200/Content-Length/body,
malformed/length mismatch/response limit, request counter 보존과 잘못된 phase 전이를 loopback
테스트로 검증했다. 실제 release proxy의 HTTP 부하, cooldown cleanup과 RSS evaluator/report
조합은 다음 태스크에 남아 있다.

Task 030은 release proxy, loopback upstream, attached PID RSS sampler와 Admin status probe를
하나의 explicit scenario runner로 조합했다. macOS arm64 small smoke는 신규 연결 HTTP 요청
100개를 모두 성공했고 최종 검증 실행의 peak/5-cycle cooldown RSS는 9,830,400 bytes로 동일했으며 cooldown 뒤
active connection/logical payload가 모두 0, pressure가 normal이었다. 이는 256 MiB conservative
smoke ceiling 아래의 small observation이며 source-bound canonical full report, Linux,
1024/slow/control-plane 및 TLS 계열 합격은 아직 아니다.

Task 031은 기존 idle schema v2를 변경하지 않고 HTTP 전용 canonical evidence schema를
추가했다. `scripts/smoke_http_memory_scenario.sh`는 current source/config/scenario/process
identity, request 100/100, ordered RSS/ceiling/plateau, active revision/normal pressure와 cleanup
0을 report/digest에 atomic publish한 뒤 별도 process로 재검증한다. stale build와 digest를
다시 계산한 unknown-field report도 거부한다. exact current 값은
`artifacts/memory-evidence/task030-current/`가 권위 자료이며 이 역시 macOS small profile이다.

Task 032는 별도 test-tool process가 64/256/512/1,024 순서로 incomplete HTTP connection을
보유하고 정확히 해제하는 상태머신과 actual release smoke를 추가했다. 현재 macOS arm64
실행에서 holder와 Admin live aggregate가 1,024에서 일치했고 logical payload는 1,024 bytes였다.
proxy RSS는 hold 시 약 12.2 MiB, release 후 약 12.3 MiB였으며, 종료 뒤 active connection과
logical payload는 모두 0이고 pressure는 normal이었다. exact source/config-bound report와
digest는 `artifacts/memory-evidence/task032-current/`를 따른다. Linux, 1,025 admission 거부,
slow payload, TLS/mTLS와 장기 soak는 아직 완료되지 않았다.

Task 033은 1,024개 connection 유지 중 1,025번째 actual socket이 terminal close로 거부되고
기존 Admin active count 1,024가 보존되는 것을 검증했다. 같은 실행에서
`connection/connection_limit` metric 값 1과 bounded Product rejection event 1건을 확인했다.
기존 holder 해제 후 count/payload 0, 새 1개 connection 재입장, 최종 0/0 cleanup까지
통과했다. source-bound held report/digest와 요약은
`artifacts/memory-evidence/task033-current/`에 있다. payload pressure, Linux, TLS/mTLS와
long soak는 여전히 남아 있다.

Task 034는 현재 Python shim이 `python3 -` stdin code를 실행하지 않고 성공 종료하는 문제를
발견해 Task 028/031 memory smoke의 readiness와 unknown-field fixture 생성을 `python3 -c`로
교체했다. HTTP negative gate는 mutated JSON/digest 존재, `"unknown": true`, exact SHA-256
일치를 먼저 확인한 후 validator rejection을 요구한다. 수정 후 idle evidence와 HTTP 100/100
actual smoke가 통과했다. 이는 test evidence 신뢰성 수정이며 product 기능 추가는 아니다.

Task 035 actual release smoke는 incomplete header 64개를 production 기본 30초 timeout까지
유지했다. Hold 중 Admin은 connection 64, logical payload 2,624 bytes를 보고했고 별도 정상
request는 HTTP 200이었다. Timeout 뒤 slow client 64/64가 408로 종료되고 Admin은
connection/payload 0/0, normal pressure로 수렴했다. Held peak RSS는 10,043,392 bytes였으며
report/digest는 `artifacts/memory-evidence/task035-current/`에 있다. Slow body/response,
TLS/mTLS, Linux와 soak는 남아 있다.

Task 036 actual release smoke는 32개 POST에서 각각 Content-Length 65,536 bytes를
선언하고 body 32,768 bytes만 전송해 production 30초 timeout까지 유지했다.
Hold 중 Admin은 connection 32, logical payload 1,051,072 bytes를 보고했고 별도
정상 request는 HTTP 200이었다. Timeout 뒤 slow client 32/32가 408로 종료되고
Admin은 connection/payload 0/0, normal pressure로 수렴했다. Held peak RSS는 약 11 MiB였으며
report/digest는
`artifacts/memory-evidence/task036-current/`에 있다. Payload exhaustion, response
backpressure, TLS/mTLS, Linux와 soak는 남아 있다.

Task 037 actual release smoke는 max connection 64와 지원 최소 payload 예산 16 MiB를
사용했다. 13개 partial body가 logical payload 13,625,040 bytes를 charge해 80%
임계 13,421,773 bytes를 넘었고 Admin pressure는 `pressured`였다. 추가 connection은
terminal close로 거부되었고 metric과 bounded Product event는 모두
`payload/payload_pressure`로 분류했으며 기존 13개는 보존됐다. Holder 13/13이
408로 종료된 후 Admin은 0/0 normal, 새 request는 200으로 회복했다. Held
peak RSS는 약 23 MiB였고 증거는 `artifacts/memory-evidence/task037-current/`에
있다. Normal socket path는 80%에서 read/admission을 중지하며 100% exact-fit/max+1
hard exhaustion은 pure ledger test가 검증한다. Response/TLS/Linux/soak는 남아 있다.

Task 038은 외부 network/ACME 없이 temporary private Root와 localhost SAN leaf를
production managed certificate store에 bootstrap 전 배치했다. Production mio/rustls HTTPS는
trusted correct-SNI request 100/100을 forwarding했고 untrusted Root/wrong SNI 2/2를
거부했으며 negative 후 trusted request도 200이었다. 최종 Admin은 0/0 normal,
peak RSS는 약 10.7 MiB였고 증거는 `artifacts/memory-evidence/task038-current/`에
있다.

Task 039는 test-tool에만 존재하는 rustls client로 64/128/256/512 순서의 handshake를
완료하고 512개 TLS connection을 idle 상태로 보유했다. Hold 중 Admin은 connection 512,
logical payload 0, normal pressure를 보고했다. 완료된 TLS session 자체와 kernel socket
buffer는 byte-exact payload ledger 대상이 아니므로 이 비용은 process RSS 약 16.7 MiB로
별도 확인했다. 명시적 close-notify/socket shutdown 뒤 Admin은 0/0 normal로 수렴했고
trusted HTTPS recovery request는 200이었다. 증거는
`artifacts/memory-evidence/task039-current/`에 있다. mTLS, WebSocket, Linux/soak는 남아 있다.

Task 040은 별도 private client Root와 managed client trust bundle로 required-mTLS
handshake를 64/128/256 순서로 완료했다. Hold 중 Admin은 256/0 normal이었고 client
certificate가 없거나 다른 Root가 서명한 두 handshake는 모두 거부되면서 기존 256개는
보존됐다. exact release 뒤 0/0 normal, trusted client recovery 200, peak RSS 약 14.9 MiB를
확인했다. 증거는 `artifacts/memory-evidence/task040-current/`에 있으며 client identity,
certificate/key/path는 포함하지 않는다. Revocation, WebSocket, Linux/soak는 남아 있다.

Task 041은 production `101` WebSocket tunnel 128개에서 masked client frame과 server echo를
검증한 뒤 읽기를 멈춰 upstream-to-client backpressure를 만들었다. Hold 중 Admin은
128 connections, 8,504,064 logical payload bytes, normal pressure를 보고했고 peak RSS는 약
106 MiB였다. 첫 실행에서 pending client output이 있는 terminal tunnel이 cleanup되지 않는
결함을 발견해 Core cleanup 불변식과 회귀 테스트를 추가했다. 수정 후 exact release 128,
final 0/0 normal과 HTTP recovery 200을 확인했다. 증거는
`artifacts/memory-evidence/task041-current/`에 있다. Task 055는 동일 process에서 이
upgrade/echo/hold/release/cooldown을 한 번 warm-up한 뒤 5회 측정하고 first/last cooldown median plateau를
검증한다. TLS WebSocket capacity, fragmentation/extensions, Linux/soak는 남아 있다.

Task 056 adds a fail-closed readiness layer above the scenario-specific validators. Its fixed
12-scenario allowlist distinguishes single-run, three-run, and five-cycle evidence and reports
missing, stale-source, wrong-kind, and validator-failed blockers in deterministic scenario order.
It does not convert historical evidence into current-source evidence or replace the underlying
correctness, cleanup, ceiling, and plateau validators.

Task 057 upgrades slow-header from single-run capacity evidence to a same-process plateau contract.
`scripts/smoke_slow_header_memory.sh` performs one verified warm-up followed by exactly five measured
cycles of 256 partial headers. Every cycle requires 256 successful timeout terminals, at least
10,496 charged bytes, hold-time HTTP 200, final 0/0 normal cleanup, recovery 200, and a 384 MiB peak
ceiling. `edge-slow-header-cycles` independently validates the source-bound canonical report and the
`max(16 MiB, first cooldown median / 10)` plateau. This removes only the slow-header evidence-kind
gap; current-source reruns for the remaining scenarios, Linux, soak, and deep diagnostics remain.

Task 058 adds the fixed execution boundary for those reruns. Ten source-controlled jobs cover the
twelve readiness scenarios; the steady job supplies the HTTP, HTTPS, and required-mTLS entries from
one independently inspected three-run aggregate. The runner accepts only a new explicit output
root, checks every child exit, physical report/digest, SHA-256, and report build identity, then
atomically publishes the ordered inventory and ready report. Any failed, stale, missing, symlinked,
or tampered job stops before success publication. The runner contract does not itself satisfy the
macOS/Linux/soak gates until the full command is actually executed on those hosts.

Task 060 defines the missing long-soak evidence contract without changing the product. A valid
report contains baseline plus 120 exact 60-second windows over 7,200 seconds, alternating sixty
1,000-request churn windows and sixty 128-WebSocket lifecycle windows in one process. Every window
requires liveness, exact correctness, 0/0 normal cleanup, recovery 200, and RSS below 384 MiB. The
first/last five-window median plateau uses the fixed 16 MiB/10% rule. Unit/fake-clock reports cannot
be represented as actual two-hour evidence; a later task must run the wall-clock adapter.

Task 042는 10,000개의 신규 HTTP connect/request/response/close를 5회 반복했다. 50,000개
요청은 모두 200 correctness를 통과했고 각 cycle cooldown에서 Admin connection/payload는
0/0, pressure는 normal이었다. 반복 macOS arm64 run의 startup/cooldown RSS는 약 9.5 MiB였고
마지막 cooldown pair는 fixed 16 MiB plateau tolerance 안에 있었다. 정확한 수치는 실행별
canonical report를 권위로 한다. source/config-bound report와 digest는
`artifacts/memory-evidence/task042-current/`에 있다. 이 값은 cycle 종료 RSS이며 load 중
sub-cycle transient peak, throughput, Linux/long-soak를 증명하지 않는다.

Task 043은 receive buffer를 4 KiB로 제한한 128개 client가 response header만 읽고 멈추는
actual backpressure를 검증했다. Hold 중 Admin은 128 connections, 약 12~13 MiB response bytes와
normal pressure를 보고했고 RSS는 약 36.4 MiB였다. 첫 실행에서 response 상태의 완전한 client
close를 무시하는 cleanup 결함을 발견했다. Core는 정상 request-side half-close를 유지하면서
mio `write_closed`/error에서만 upstream과 connection charge를 terminal release한다. 수정 후
128 release, 0/0 normal과 recovery 200을 확인했다. 증거는
`artifacts/memory-evidence/task043-current/`에 있다. Task 054의 same-process five-cycle contract는
각 cycle의 held/released 128, 최소 8 MiB charge, final 0/0 normal, recovery 200과 first/last
cooldown median plateau를 요구한다. TLS/Linux/soak는 남아 있다.

Task 054 full regression은 payload-pressure listener test의 test-only readiness race도 드러냈다.
기존 test가 nonblocking connect 직후 accept를 한 번만 호출해 socket이 accept queue에 도달하기
전에 metric을 검사할 수 있었다. 제품 admission behavior는 바꾸지 않고 기존 bounded
10 ms/100-attempt pattern으로 rejection event를 기다리도록 test를 안정화했다.

Task 044는 product binary에 fixture mode를 넣지 않고 test-tool process가 production
`FileAuditLedger`와 `MetricRegistry`를 함께 소유하도록 구성한다. 준비 단계는 정상 durable append
경로로 audit 100,000건을 만든 뒤 segment digest manifest를 게시하고, resident 단계는 hash chain을
재검증한 뒤 metric 16,384 series와 cumulative 12,288 series를 채운다. max+1은
`series_limit`이어야 한다. 실제 Admin audit/metrics handler를 3회 호출해 audit page 100과 metric
kind별 500 cap, immutable response를 검증하고 512 MiB RSS ceiling을 적용한다. fixture 재사용은
manifest와 aggregate segment digest가 일치할 때만 허용한다. 이 결과는 collection/control query
characterization이며 `edge-proxy` 전체 composition, Linux/plateau/soak 완료 증거가 아니다.
승인된 macOS arm64 실행의 durable fixture 준비 시간은 537.75초, 디스크 크기는 약 52 MiB였고,
resident peak RSS는 46,727,168 bytes(약 44.6 MiB)였다. source/manifest/report digest 증거는
`artifacts/memory-evidence/task044-current/`에 있다.

Task 045는 plaintext HTTP 100 worker가 각각 1,000개의 새 connection을 사용해 정확히
100,000/100,000 response를 검증했다. 930회 Admin sample에서 max active 100, max logical charge
18,620 bytes를 관찰했고 종료 후 0/0 normal과 recovery 200이었다. 100-sample load RSS peak는
10,764,288 bytes로 384 MiB ceiling을 통과했다. 증거는
`artifacts/memory-evidence/task045-current/`에 있다. 이는 keep-alive/throughput/latency,
Linux, 3회 independent run이나 long soak 완료 증거가 아니다.

Task 046은 외부 Let's Encrypt 없이 ephemeral private Root/localhost leaf를 process 시작 전에
생성하고, root를 driver bootstrap에서 한 번 읽어 immutable rustls client config로 100 worker에
공유했다. exact 50,000/50,000 HTTPS response, wrong-root/wrong-SNI 2/2 rejection과 trusted upstream
forward 50,000건을 확인했다. 593회 Admin sample의 max active는 101, max logical charge는 27,041
bytes였고 final 0/0 normal, trusted recovery 200이었다. 100-sample peak RSS 13,320,192 bytes는
384 MiB ceiling 아래였다. 증거는 `artifacts/memory-evidence/task046-current/`에 있다. 이는
public CA, mTLS steady, keep-alive 성능, Linux/plateau/soak 완료 증거가 아니다.

Task 047은 별도 client Root와 complete clientAuth chain/key를 startup에서 한 번 읽어 required
mTLS concurrency 64로 exact 25,000/25,000 response를 처리했다. no-cert/untrusted-client는 2/2
거부됐고 upstream count는 negative 전후 25,000으로 유지됐다. 335회 Admin sample의 max active는
64, max charge는 14,069 bytes였으며 final 0/0 normal, authenticated recovery 200이었다. peak RSS
13,352,960 bytes는 384 MiB 아래였다. 증거는 `artifacts/memory-evidence/task047-current/`에 있다.
이는 CRL/OCSP, rotation, Linux/plateau/soak 완료 증거가 아니다.
2026-07-15 Phase 009 Task 001에서 현재 경계를 다시 characterization하고 ADR 009를
승인했으며, 이후 task 결과는 아래 capability별 상태를 기준으로 판단한다.

## Implemented Product Surface

- Rust/mio 단일 data plane에서 HTTP/1.1과 HTTPS를 처리한다.
- Host/path route, HTTP-to-HTTPS redirect, WebSocket `101` tunnel을 지원한다.
- rustls 기반 TLS termination, SNI certificate selection, file-backed manual
  certificate import와 신규 연결 대상 hot install을 지원한다.
- service별 deterministic round-robin, active health check, passive transport
  ejection, safe GET/HEAD one-shot retry, generation-fenced graceful drain을
  지원한다.
- config는 parse, normalize, validate, diff, plan, runtime acknowledge, revision
  commit, audit 순서로 적용하고 실패 시 기존 snapshot을 유지한다.
- process startup은 revision repository의 `config/current`를 authoritative
  config로 사용한다. 완전히 빈 repository에서만 `config/current.toml`을 최초
  seed로 import하며, dangling pointer는 seed fallback 없이 fail closed한다.
- process mode는 serve와 typed backup/restore maintenance command를 구분한다.
  serve는 listener 시작 전에 canonical data-directory exclusive advisory lock을
  획득한다. `backup create`는 offline exclusive lock 아래 실행되며 verify/restore는
  authenticated bounded maintenance path에서만 동작한다.
- schema v1/v2 logical manifest, fixed backup limits, zeroizing/redacted sensitive
  value, backup/restore/rollback/recovery state reducer는 pure domain contract로
  구현됐다. allowlisted filesystem inventory, canonical SHA-256 manifest/record
  encoding, age passphrase encryption, owner-only temp/fsync/atomic publish, safe
  receipt와 create Product log까지 구현됐다. bounded no-follow reader와 `backup verify`가
  envelope authentication, manifest/record relation, digest, path/order/count/size를 검증하고
  payload 없는 compatibility report를 출력한다.
- `backup restore`는 absent new target에 한해 owner-only sibling stage, config/certificate/
  secret preflight, directory fsync와 atomic rename으로 복원한다. restored startup은
  repository current를 authoritative source로 사용한다.
- existing target `--replace`는 owner-only operation journal을 fsync한 뒤 target→rollback,
  stage→target 순서로 교체하고 각 crash state를 persist한다. `restore-recover`는 journal
  enum과 실제 target/rollback 검증 결과로 commit cleanup/rollback/abort를 명시 수행한다.
- Admin API는 setup/login/logout, config lifecycle, Proxy Host CRUD,
  certificate issue/renew/import/status, upstream health, recent logs, metrics
  summary와 bounded audit query를 제공한다.
- Persistent config/proxy/certificate/trust/setup mutation은 durable intent 뒤 effect를
  실행하고 terminal을 기록한다. Login/logout/lockout은 인증 결과를 바꾸지 않는 bounded
  security observation이며, degraded audit는 새 persistent mutation만 fail closed한다.
- Audit segment는 owner-only, hash-linked, bounded storage이며 startup에서 trailing crash
  residue와 interior corruption을 구분한다. Backup schema v3는 segment를 인증하고 restore
  publication 뒤 operation/archive-linked provenance를 이어 쓴다.
- 선택형 static Admin Web UI는 같은 Admin API만 사용하며 Core나 config
  file을 직접 수정하지 않는다.
- Product, Field Debug, Development 로그 모드와 bounded nonblocking log/metric
  handoff를 제공한다.
- typed 18-family metrics registry, immutable snapshot, loopback-only Prometheus
  `GET /metrics`, 인증된 `GET /api/v1/metrics`를 제공한다.
- running core의 logical payload charge/active limit과 connection-limit,
  payload-pressure, failed-closed admission rejection을 bounded metric으로 제공한다.
  pending-restart desired limit은 active limit metric에 반영하지 않는다.
- resource policy startup, pressure 진입/회복, admission rejection을 Product/Field
  정책으로 분리하며 rejection은 60초 TTL과 8,192 key cap으로 제한한다. 로그 큐 full 또는
  disconnected는 ledger/admission/cleanup을 변경하지 않는다.
- headless, Admin TCP/static UI, local self-signed HTTPS, private Root→Intermediate→leaf
  trust/SNI/validity matrix, Docker Compose,
  architecture/docs/release smoke가 자동화되어 있다.

## Architecture Invariants

```text
bin -> adapters -> application -> domain
bin -> application -> domain
adapters -> ports
application -> ports
domain -> no outer dependency
```

- `edge-domain`은 mio, rustls, socket, filesystem, DB, HTTP framework, env,
  logger 구현을 알지 않는다.
- `edge-core` hot path는 mio readiness와 명시적 connection/TLS/attempt 상태를
  관리하고 blocking file, DNS, ACME, certificate 작업을 수행하지 않는다.
- Admin mutation은 application use case와 bounded acknowledged Core command를
  거친다.
- 환경 변수는 `apps/edge-proxy/src/bootstrap.rs`에서 시작 시 한 번 읽고
  typed config/dependency로 전달한다.
- runtime config, health, drain, metrics state는 숨은 파일이나 process env에
  기록하지 않는다.

## Verified Safety Properties

- malformed/ambiguous HTTP framing, oversized header/body, slow client/upstream,
  backend reset, timeout, chunked response와 backpressure 회귀를 검사한다.
- config/TLS/health activation과 rollback은 실패 시 이전 runtime truth를
  보존한다.
- stale health/passive/drain 결과는 revision/generation fence로 거부한다.
- metric/log/health queue 포화가 mio event loop를 block하지 않는다.
- metrics listener는 disabled by default, loopback-only, worker 2, queue 16,
  timeout 5초, request header 8 KiB, response 4 MiB, series 16,384 상한을 가진다.
- Admin session/CSRF, secret masking, private-key permission과 structured error
  contract를 검사한다.
- Admin password verifier는 atomic write되고 Unix에서 temp/final 모두 `0600`으로
  제한된다.
- private PKI client는 test Root만 명시적으로 신뢰하며 complete chain과 correct SNI에서
  mio HTTPS forwarding에 성공한다. unrelated Root, wrong SNI, missing Intermediate,
  reversed chain, expired/not-yet-valid leaf와 key mismatch는 실패한다.
- encrypted recovery drill은 source/restored authoritative revision과 certificate identity를
  비교하고 old session을 fresh context에서 거부한 뒤 새 Admin login 및 trusted HTTPS를
  검증한다. wrong passphrase는 absent target을 만들지 않는다.
- schema v2 recovery drill은 retained revision의 inbound/outbound trust ref와 모든 managed
  trust bundle을 암호화하고, 복구 게시 전 ref/digest/count/CA profile을 다시 검증한다.
  fresh startup 후 no-cert client는 차단되고 trusted client 요청만 restored Root/SNI로
  private HTTPS upstream에 전달된다. schema v1 archive는 v2 reader에서도 계속 복구된다.

## External And Infrastructure Deferred

- 외부 Let's Encrypt staging/production 증적과 자동 갱신 운영 검증
- DNS-01 provider 실연동
- remote metrics exposure, retention/history/chart, bundled Prometheus/Grafana
- audit export/remote signing, multi-user RBAC/OIDC
- weighted/least-connections/sticky balancing, upstream keep-alive pool
- Docker/Kubernetes discovery, plugin marketplace, multi-node control plane
- HTTP/2, HTTP/3, gRPC, TCP proxy, WAF, cache/static hosting

## Planned TLS Work Testable With Private PKI

다음 기능은 아직 구현되지 않았지만 외부 인증기관이나 공개 DNS가 필요하지 않다.
test-only Root/Intermediate와 server/client leaf를 생성하여 loopback에서 자동 검증할 수
있으므로 명시적 제외가 아니라 후속 개발 범위로 관리한다.

- optional mTLS와 client identity 기반 authorization/revocation policy
- upstream client certificate를 사용하는 outbound mTLS
- private wildcard certificate와 exact/wildcard SNI selection
- ClientHello SNI 기반 TLS passthrough
- private certificate 교체, 만료 경고, activation/rollback 상태 전이

각 항목은 관련 domain/application contract와 실제 mio/rustls integration test가
완료되기 전까지 `implemented`로 표시하지 않는다.

2026-07-15 Phase 009 Task 014 기준으로 managed trust CRUD/read, strict rustls
client factory, prepared core registry/transport/state contract와 production startup
preparation을 구현했다. startup은 active snapshot의 HTTPS upstream을 deterministic하게
계획하고 각 managed Root를 verified reader로 한 번만 읽어 immutable registry로 주입한다.
누락되거나 유효하지 않은 trust는 listener 시작 전에 fail closed한다. 실제 rustls
private-PKI mio E2E는 Root-only client trust와 complete server chain/correct SNI에서
200을 확인하며, unrelated Root와 wrong SNI는 HTTP request가 backend application에
도달하기 전에 502로 종료된다. active health도 같은 typed endpoint/TLS policy와
prepared managed Root를 사용하며 correct Root/SNI/Host에서 Healthy를 게시하고 wrong
Root/SNI에서는 plaintext 없이 bounded TLS failure를 게시한다. endpoint뿐 아니라
Root/SNI/Host 변경도 reconciliation identity를 바꾸어 health counter를 reset한다.
WebSocket upgrade response와 양방향 tunnel payload도 upstream transport를 통과하고,
양방향 pending byte 합계에 따라 readable interest를 중단/복구한다. retry request는 새로
선택된 TLS upstream의 HTTP Host로 다시 구성하면서 original forwarded Host와 upgrade
headers를 보존한다. Task 018부터 request/health registry는 config snapshot과 같은 acknowledged
generation에서 교체되며 rejected candidate는 old registry를 유지하고 rollback은 old Root
behavior를 복원한다.
required inbound mTLS는 listener의 explicit `client_auth=required`와 managed trust ref를
startup composition root에서 immutable rustls verifier factory로 준비한다. 동일 ref는 한 번만
verified-read하며 missing/invalid material은 listener 시작 전에 실패한다. adapter matrix는
trusted Root/complete clientAuth chain 성공과 no-cert, unrelated Root, missing Intermediate,
serverAuth-only, expired/not-yet-valid, malformed record 실패를 검증한다. 실제 mio E2E는 실패한
두 client가 HTTP parser/upstream에 도달하지 않고 trusted client만 forwarding하는 것을 확인한다.
기존 disabled HTTPS listener는 동일 no-client-auth 경로를 유지한다. listener policy 변경은 현재
restart-required지만, 정책이 동일한 hot route/upstream apply와 certificate install은 bind별
prepared server registry를 사용하므로 required mTLS를 no-client-auth로 낮추지 않는다. core
ack 이후 health activation이 실패하면 command 전에 준비한 previous snapshot/server/client/health
generation으로 보상하고 mirror/revision은 변경하지 않는다.
offline backup create는 schema v2를 쓰며 `trust-bundles/<ref>/roots.pem|metadata.toml`만
allowlist한다. manifest는 roots/metadata 완전 관계와 config trust reference 존재를 검증한다.
restore는 publication 전에 managed store verified-read와 CA-only validator를 다시 실행한다.
TLS handshake terminal failure는 core에서 bounded nonblocking observation queue로 전달되고,
application sampler가 listener/upstream/error key별 60초 첫 Product event만 허용한다. queue가
포화되어도 event loop는 block하지 않고 기존 drop counter만 증가한다. upstream certificate
validity는 adapter에 주입한 rustls `TimeProvider`의 고정 시각으로 유효기간 전 실패와 기간 내
성공을 결정적으로 검증한다. inbound prepared registry는 실제 listener socket lifecycle과
동일한 validated unique bind로 keying하고, config와 Product log identity는 `ListenerId`를 유지한다.

Let's Encrypt 관련 adapter와 HTTP-01/fake ACME 테스트는 남아 있지만 외부
인증기관 준비 완료를 의미하지 않는다. 재개 시 `docs/acme-staging.md`의
승인된 public domain evidence 절차를 별도 수행한다.

## Verification Commands

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --test-threads=1
```

동일한 source-level gate는 `docker-compose.test.yml`의 상시 `edge-test` 서비스에서도 실행할
수 있다. 컨테이너는 source를 `/workspace`에 mount하고 Cargo registry/git/target cache만 named
volume으로 유지하며 host port, 운영 data와 secret을 mount하지 않는다. 정확한 명령과 lifecycle은
`docs/testing.md`를 따른다. 컨테이너 통과는 Linux source-level 검증이며 실제 production image,
Admin API/UI, TLS, backup/restore와 platform별 memory evidence를 대체하지 않는다.

2026-07-15 Phase 009 시작 기준선에는 fmt, clippy warnings-as-errors, 551개 workspace tests,
architecture/docs gates, Admin Web, Docker Compose, health, encrypted recovery/private-PKI 및 MVP
smoke가 통과했다. 해당 script 기반 결과는 과거 evidence이며 새 release는 현재 source에서 위
Cargo 명령과 필요한 runtime 검증을 다시 실행하고 fresh evidence를 수집해야 한다.

## Phase 011 Task 048 Memory Manifest

The test-only `edge-memory-manifest` command collects the exact HTTP, HTTPS, and required-mTLS
steady profile into one canonical manifest. It accepts one explicit input directory and fixed typed
arguments. It neither discovers scenario files nor runs load scenarios. The directory must contain
exactly 12 named report, digest, driver-summary, and terminal-summary files; symlinks, unknown or
missing names, and noncanonical content fail closed.

Collection verifies current source identity, request arithmetic, 384 MiB candidate ceilings,
negative TLS counts, upstream forwarding, Admin resource maxima, 0/0 normal cleanup, and recovery
200 before atomic publication. A separate process revalidates every source file or inspects a copied
manifest/digest against its source identity. Current macOS arm64 one-run evidence is always
`partial`; Linux x86_64, three independent repetitions, and long-soak/deep-diagnostic evidence
remain blockers. No product runtime crate depends on this model.

The Task 048 validation run also exposed a pre-existing mio half-close regression: a client that
finished an HTTP request with TCP `shutdown(Write)` could still read the response, but a
`write_closed` readiness flag dropped its in-flight upstream. Client half-close is now preserved
after request completion; only an actual socket error aborts that upstream phase. The existing
upstream-read-timeout test is the regression contract and must return 504 rather than 502.

## Phase 011 Task 049 Three-Run Aggregate

The test-only `edge-memory-aggregate` command accepts exactly `run-001`, `run-002`, and `run-003`.
Each run must contain one exact steady profile and its independently validated Task 048 manifest.
All three runs bind the same source tree, platform, architecture, and fixed scenario contract, while
their hashed process-start identity sets must be distinct. Per-run config digests differ because
fresh ports and temporary paths are mandatory, and each remains child-manifest-bound. Missing,
extra, symlinked, mixed, or tampered paths fail before atomic output replacement.

For each scenario, the aggregate records peak and cooldown RSS ranges. Both ranges must fit
`max(16 MiB, minimum peak RSS / 10)`, and every child remains below the fixed 384 MiB ceiling with
zero correctness and cleanup failures. The aggregate status remains `partial`: Linux x86_64, the
full Phase 011 scenario profile, and long-soak/deep-diagnostic evidence remain blockers.

Run `scripts/run_three_steady_memory_profiles.sh <new-artifact-root>` only against an absent output
root. It reruns HTTP 100,000, private-PKI HTTPS 50,000, and required-mTLS 25,000 three times, checks
that source identity remains unchanged, then invokes separate collect, validate, and inspect
processes. Generated artifacts are evidence for that exact source identity only.

## Phase 011 Task 051 Canonical Slow Request Capacity

The earlier 64 slow-header and 32 slow-body runs remain historical characterization. The current
test-only typed contract fixes 256 partial-header connections and 128 partial-body connections with
65,536 declared and 32,768 transmitted bytes per body. The canonical scripts verify exact timeout
terminals, a healthy request during hold, source/config/process identity, RSS ceilings, and final
0 connection/0 payload/normal pressure.

This task is a capacity step, not the full slow-path plateau claim. Three slow-body cycles,
five-cycle slow-response/slow-path plateau, Linux, long soak, and deep diagnostics remain separate.

## Phase 011 Task 052/053 Slow-Body Same-Process Plateau

The slow-body script now keeps one release proxy alive across exactly three canonical 128-connection
load/timeout/cooldown cycles. Every cycle requires exact terminals, at least 4,194,304 charged bytes,
recovery 200, 0/0 normal cleanup, unchanged process identity, and a 512 MiB ceiling. That Task 052
run is repeatability evidence, not the formal plateau gate.

Task 053 extends the source-controlled contract to exactly five cycles. `edge-slow-body-cycles`
computes the median of cooldown cycles 1-2 and 4-5 and requires the latter to remain within
`max(16 MiB, first median / 10)`. It canonically publishes only after every cycle and the median
plateau pass. Slow-response/WebSocket cycles, soak, Linux, and deep diagnostics remain uncovered.

## Phase 011 Task 060/061 Long-Soak Boundary

The canonical long-soak contract requires one baseline plus 120 exact 60-second windows in one
process. Task 061 adds the test-tool-only one-window use case used by that future wall-clock runner.
It maps baseline/odd/even indices to fixed 0/1,000/128 workloads, calls explicit load, process, and
runtime ports, and returns an observation only after exact correctness, unchanged process identity,
positive RSS, 0/0 normal cleanup, and recovery 200. Concrete HTTP, WebSocket, attached-process, and
Admin adapters remain outside the pure state machine.

This is runner infrastructure, not two-hour evidence. The gate remains incomplete until a single
release proxy completes all 120 wall-clock windows and the final canonical report validates.

Task 062 adds the fixed wall-clock orchestration and executable composition. Its CLI accepts only
the attached process/proxy/Admin/identity/output boundary; duration, interval, counts, ceiling, and
plateau are not runtime options. `scripts/run_diagnostic_soak.sh NEW_OUTPUT_ROOT` starts one bounded
dual HTTP/WebSocket upstream and one release proxy, executes all deadlines, then invokes a separate
canonical validator. A completed run remains valid only while its recorded source identity matches
the source evaluated by the final binding below.

## Phase 011 Final Memory Release Binding

`edge-phase011-memory-release` is a test/release-only evaluator. It recomputes the 12-scenario full
profile readiness result from the copied inventory, requires `ready=true` with zero blockers, and
revalidates the canonical 7,200-second/121-observation diagnostic soak. Build identity, platform,
architecture, report digests, correctness, cleanup, RSS ceiling, and plateau must all agree.

```bash
./scripts/collect_phase011_memory_release.sh \
  <full-profile-root> <soak-report.json> <soak-report.sha256> <new-output-root>
./scripts/check_phase011_memory_release.sh <output-root>
```

The output root has exactly nine physical files: copied inventory/readiness/soak reports and their
digests, the bound release report and digest, and `phase011-memory.log`. Success requires the literal
`phase 011 quantitative memory and resource safety passed` marker. A prior-source result is
historical evidence and cannot be relabeled as current. The marker is platform-specific and does
not remove the separate Linux x86_64 or deep-diagnostic requirements.

## Phase 011 macOS Deep Diagnostic

Task 068 established a test-only macOS diagnostic path without modifying the shipped binary or host
security policy. A temporary copy of the current release proxy receives only the
`com.apple.security.get-task-allow` entitlement. `/usr/bin/leaks` then distinguishes a zero-leak
fixture from a deliberate positive-leak fixture; the signed copy is deleted and is never published.

Task 069 adds a strict pure parser/evaluator, canonical report, collector, independent validator,
fixture smoke, and actual proxy runner. The actual runner requires 1,000 successful loopback HTTP
requests, 0 connections, 0 charged payload bytes, normal pressure, recovery status 200, unchanged
process identity, tool exit 0, and exactly zero leaked allocations/bytes. Raw tool output is private
mode 0600 under a mode 0700 evidence directory. The public report and log contain hashes and verdicts,
not PID, addresses, stacks, temporary paths, or credentials. This closes the macOS reference deep
diagnostic only after an actual current-source artifact passes
`scripts/check_macos_leaks_diagnostic.sh`; Linux x86_64 remains a separate requirement.

## Phase 011 Cross-Platform Final Status

Phase 011 완료는 문구가 아니라 current-source artifact로 판정한다. macOS arm64와 native Linux
x86_64는 각각 fixed 10-job/12-scenario full profile에서 `ready=true`, blocker 0이어야 한다.
macOS reference는 추가로 7,200초/121-observation soak와 `/usr/bin/leaks` definite leak 0/0을
통과해야 하며, final collector/checker가 exact 9-file bundle을 byte-for-byte 재생성한다.

권위 artifact root는 `artifacts/memory-evidence/task073-*`이며 상세 경로는 `PROJECT.md` 32절을
따른다. RSS 결과는 process-level envelope이고 logical payload는 managed owners의 회계 값이다.
두 수치는 kernel socket memory, 모든 allocator 내부 상태 또는 모든 production workload에서의
절대 상한을 뜻하지 않는다. 외부 Let's Encrypt 실제 CA 발급은 계속 deferred다.

2026-07-20 accepted checkpoint의 source identity는
`source-tree-sha256:2c2bcbf580ed60fe18c330340236ecccf0936d7e5a2d18822e1c36f0fb970862`다.
Native Linux x86_64와 macOS arm64 full profile은 각각 jobs 10/10, scenarios 12/12,
`ready=true`, blocker 0을 통과했다. readiness digest는 Linux
`73cb85a4759b952969320651337106a854dc101c2c146e6f7f0468915a085f66`, macOS
`79162c859929ace3c7d82828639d0a71b3948624ba4c54fb108ee476409853d4`다.

같은 checkpoint의 macOS soak는 7,200초/121 observations, HTTP churn 60,000,
WebSocket lifecycle 7,680, correctness/cleanup failure 0, peak RSS 9,633,792 bytes와 plateau
통과를 기록했다. macOS deep diagnostic은 1,000/1,000 HTTP, cleanup 0/0/normal, recovery 200,
definite leak 0건/0 bytes다. Exact nine-file final binding digest는
`78d453e0568c069e68c5e563535f2f2497ab42b80d765845a5568bacb7cbcf09`이며 독립 checker가
승인했다.

최종 profile 과정에서 발견한 WebSocket consumed write history는 Task 074에서 수정했다.
Complete drain은 pending length를 0으로 만들면서 allocation capacity를 재사용하고, partial drain은
남은 tail을 유지한다. Task 075의 30초 loopback fixture timeout은 macOS endpoint security의 최초
연결 지연을 위한 test-only 상한이다. 제품 timeout과 release threshold는 바뀌지 않았다.

이 절은 승인된 checkpoint를 기록한다. 이후 tracked source 또는 문서 변경은 checkpoint artifact를
새 tree의 release evidence로 자동 승격하지 않으며, 정식 release 후보에는 해당 identity로 full
profile, soak, diagnostic과 binding을 다시 생성해야 한다.
