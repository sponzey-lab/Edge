# Project Definition

## Current Implemented State

Phase 001~009 are complete and archived under `.tasks/phase001/` through `.tasks/phase009/`.
Phase 010 is implemented and accepted by source-bound release evidence: a bounded file-backed
typed audit ledger, verified startup/reconciliation, audited control-plane mutations and
security observations, authenticated query/UI, and backup schema v3 restore provenance are
complete.
Phase 009 Tasks 001~021 implemented managed trust bundles, strict private upstream
HTTPS, required inbound mTLS, atomic TLS generation activation, and trust-aware
backup schema v2 while retaining schema v1 verify/restore compatibility. The final
completion work adds bounded 60-second TLS Product failure sampling, deterministic
rustls validity tests through an injected time provider, and explicit server-registry
collision coverage. Phase 008 implemented encrypted offline backup,
authenticated verify, fresh-target restore, crash-recoverable replace/recovery,
and a private Root/Intermediate/leaf disaster-recovery E2E. The existing product
also includes unified mio HTTP/HTTPS, failure-aware multi-upstream routing,
safe one-shot retry and drain, validated config apply/rollback, Admin API/Web UI,
and bounded local Prometheus/Admin metrics. Runtime health, drain, metric,
session, and CSRF state remains memory-only and is not restored. Phase 010
automatic release gates and independent evidence validation pass without
external Let's Encrypt. The accepted Phase 010 checkpoint evidence is
`artifacts/release-evidence/phase010-20260716-final-r2`, identified by
`source-tree-sha256:000b23c310bae98a40e7689139fab45e09300d83d4daee42bc51763d825c1a85`.

`docs/current-state.md` is the authoritative implemented/deferred scope.
External Let's Encrypt validation, remote backup storage/scheduling, remote
metrics retention, audit export/remote signing, RBAC, weighted balancing, and other broad
product roadmap items remain deferred. The detailed sections below describe the long-term product
vision and must not be read as claims that every listed feature exists today.

Phase 011 quantitative memory and resource safety is implemented and its 2026-07-20 acceptance
checkpoint passed. The fixed 12-scenario profile passed on macOS arm64 and native Linux x86_64,
the 7,200-second same-process soak passed, the authorized macOS deep diagnostic reported zero
definite leaks/bytes, and the exact nine-file binding passed independent validation. The accepted
checkpoint source identity is
`source-tree-sha256:2c2bcbf580ed60fe18c330340236ecccf0936d7e5a2d18822e1c36f0fb970862`.
Phase 010 completion remains authoritative through its accepted release evidence and
`docs/mvp-completion-audit.md`; Phase 011 extends that baseline without changing the deferred
external Let's Encrypt scope. A later tracked source or documentation change requires fresh
source-bound evidence before that changed tree is promoted as a release candidate.

As of 2026-07-21, local test helper scripts under `scripts/` have been removed from the working
tree. Script names that remain in historical evidence notes describe how earlier evidence was
collected; they are not current runnable release commands. Current verification starts from Cargo
workspace checks and explicit manual/integration procedures documented in the user-facing guides.

## Current Development Details And Verification

이 절은 간결한 제품 사용 문서인 `README.md`에서 분리한 개발 상세와 검증 기준을 기록한다.
현재 지원 여부의 최종 기준은 `docs/current-state.md`, Phase별 완료 근거는
`docs/mvp-completion-audit.md`, 실행 가능한 릴리스 절차는 `docs/release-gate.md`다.

### Data Plane And Runtime Safety

- 하나의 mio snapshot runtime이 HTTP/HTTPS listener, Host/path routing, TLS handshake,

  forwarding, timeout, backpressure, metrics와 WebSocket 상태를 처리한다.
- Host 기반 multi-route, path specificity, backend reset의 `502`, upstream connect/read

  timeout의 `504`, slow client header의 `408`, chunked response, rollback route 보존을
  integration/smoke test로 검증한다.
- 각 service는 eligible upstream에 deterministic round-robin을 적용한다. Active/passive

  health와 administrative drain을 합성하고 모든 upstream이 unavailable이면 `503`을 반환한다.
- 안전한 GET/HEAD만 upstream bytes와 response bytes가 전달되기 전에 한 번 재시도한다.

  POST와 이미 전달이 시작된 요청은 재시도하지 않는다.
- Config apply는 immutable snapshot, health availability, listener별 TLS server factory,

  outbound request/health trust registry를 하나의 acknowledged generation으로 교체한다.
  준비 또는 activation이 실패하면 이전 runtime truth와 revision을 보존한다.

### TLS And Private Trust

- 수동/file-backed certificate, local self-signed HTTPS, multi-certificate SNI selection,

  hot certificate install을 지원한다.
- 사설 PKI 검증은 test Root, issuing Intermediate, server/client leaf를 사용하며 complete

  chain, SNI, EKU와 validity를 검사한다. 인증서 시각 경계는 machine wall clock 대신 주입된
  rustls time provider로 결정적으로 테스트한다.
- Strict upstream HTTPS는 명시적으로 관리되는 Root, TLS server name, HTTP Host를 각각

  요구하며 OS native Root 또는 plaintext fallback을 사용하지 않는다. Active health와
  WebSocket tunnel도 동일한 trust policy를 사용한다.
- Required inbound mTLS는 HTTP parsing 전에 missing, unrelated Root, incomplete chain,

  wrong EKU, expired/not-yet-valid client certificate를 거부한다.
- TLS handshake 실패 observation은 bounded nonblocking queue를 통과하며

  listener/upstream/error key별 60초에 최대 한 번 Product Log로 출력된다.
- TLS passthrough, optional identity authorization, outbound client-certificate mTLS와

  revocation policy는 후속 범위다.
- 외부 Let's Encrypt 자동화는 Post-MVP다. 저장소의 fake ACME/HTTP-01 및 staging safety

  test는 경계 구현을 검증하지만 외부 CA 발급 완료 증거가 아니다.

자세한 설계와 검증 범위는 `docs/private-pki-testing.md`, `docs/tls-runtime-next.md`,
`docs/adr/009-private-pki-bidirectional-trust.md`를 따른다.

### Observability And Audit

- Product, Field Debug, Development의 세 로그 모드를 분리한다. Development 로그는

  production 기본 동작에 포함하지 않는다.
- Log, health observation, metric publication은 bounded nonblocking queue를 사용하며 포화가

  mio event loop를 block하지 않는다.
- 선택형 Prometheus endpoint는 loopback에만 bind하며 인증된 Admin metric summary와 동일한

  immutable registry snapshot을 읽는다. Remote unauthenticated exposure와 장기 retention은
  지원하지 않는다.
- Production audit는 process-wide file-backed typed ledger다. Persistent mutation은 durable

  intent 전에 effect를 시작하지 않고 같은 operation ID로 terminal을 기록한다.
- Ledger는 owner-only segment, bounded record/segment/total size, sequence와 SHA-256 chain,

  startup verification, trailing crash recovery와 interior corruption fail-closed를 제공한다.
- 인증된 `GET /api/v1/audit`와 Admin viewer는 max-100 exact filter, opaque cursor, metadata-only

  projection을 사용한다. Path, hash, secret, raw config와 payload를 노출하지 않는다.
- Local hash chain은 우발적 손상과 누락을 탐지하지만 hostile administrator에 대한

  non-repudiation을 보장하지 않는다. Remote export/signing은 후속 범위다.

### Backup And Recovery

- Offline backup은 allowlisted artifact를 age passphrase로 암호화하고 bounded manifest,

  digest와 relation을 검증한다.
- Fresh-target restore와 existing-target replace/recovery를 지원한다. 기존 target 교체는

  durable journal과 명시적 crash state를 사용하며 ambiguous state에서 경로를 임의 삭제하지
  않는다.
- Schema v3 backup은 config revision, certificate, secret, 모든 managed trust bundle과

  verified audit segment를 포함한다. Verify/restore는 schema v1/v2도 계속 허용한다.
- Recovery E2E는 authoritative revision과 certificate identity, old-session rejection,

  fresh Admin login, private-PKI trusted HTTPS, restored audit query와 next append를 검증한다.
- Runtime health, drain, metric, session, CSRF와 connection state는 ephemeral이며 backup에서

  복원하지 않는다.

자세한 절차는 `docs/backup-restore.md`, `docs/deployment.md`, `docs/troubleshooting.md`를
따른다.

### Resource Bounds And Memory Verification Status

- 기본 `max_connections`는 1,024이고 runtime connection table에서 강제한다.
- 기본 request header는 16 KiB, request body는 1 MiB, response buffer는 connection당

  64 KiB로 제한한다.
- Admin request는 512 KiB, metrics response는 4 MiB, metric series는 16,384,

  audit storage는 128 MiB와 32 segment 상한을 가진다.
- Backpressure, queue saturation, connection cleanup과 bounded recent log/metric behavior는

  자동 테스트한다.
- Admin status/UI는 running revision에 묶인 logical payload used/limit, pressure와 active

  connection aggregate를 표시한다. Core는 이를 nonblocking latest-only port로 게시하며
  Admin은 Core ledger/table을 직접 lock하지 않는다. 이 값은 process RSS가 아니다.
- Phase 011 Task 001~023은 typed policy, global logical payload ledger, exact release,

  restart-required desired/active 분리, resource metrics/logs와 live Admin summary를 완료했다.
  Task 024~043은 cross-platform harness foundation, canonical evidence, macOS arm64의
  1,024-connection capacity/admission, slow header/body, HTTPS/mTLS idle capacity, WebSocket
  backpressure, 50,000 HTTP connection churn plateau와 128 slow-response cleanup을 완료했다.
  이후 steady HTTP/HTTPS/mTLS, control-plane maximum, slow-path, WebSocket, macOS arm64와 native
  Linux x86_64 full profile, 2시간 soak와 macOS deep diagnostic까지 완료했다.
- Phase 011 Task 001 macOS arm64 release mini-run 2회에서 idle과 100개 incomplete idle

  connection RSS는 모두 9~10 MiB 범위였고 연결 100개의 관측 증가는 1 MiB
  미만이었다. 정확한 sample은 `artifacts/memory-baseline/task001/` report와
  `docs/adr/011-quantitative-memory-resource-safety.md`가 해당 build/profile을 기록한다.
- Task 028의 fresh schema v2 macOS arm64 release idle smoke는 proxy PID만 3회 측정해 모두

  9,338,880 bytes RSS, missing sample 0을 기록했고 source/config identity와 SHA-256을 별도
  validator invocation으로 확인했다. 이는 harness 신뢰성 smoke이지 full memory 합격이 아니다.
- Task 030의 macOS arm64 release HTTP small smoke는 신규 연결 요청 100개를 모두 정상

  응답으로 검증했고 최종 검증 실행의 peak와 5-cycle cooldown RSS가 모두 9,830,400 bytes였다. cooldown 뒤
  Admin live aggregate는 active connection과 logical payload가 모두 0이고 pressure는
  normal이었다. 이 결과는 아직 canonical full report나 Linux/고압력 합격 증거가 아니다.
- Task 031은 이 HTTP small observation을 current source/config/scenario/process identity에 묶은

  canonical report와 SHA-256 sidecar로 atomic publish하고 별도 validator에서 재검증한다.
  stale identity, tamper/unknown field, failed counter/evaluation과 nonzero cleanup은 승인되지
  않는다. exact current report는 `artifacts/memory-evidence/task030-current/`에 있으며
  cross-platform/full-pressure release marker는 아직 남아 있다.
- Task 032 actual release smoke는 64/256/512/1,024 순서로 incomplete connection을 올렸고,

  holder와 Admin live aggregate가 1,024에서 일치하는 것을 확인했다. logical payload는
  1,024 bytes였고 proxy RSS는 hold/release 관측에서 약 12.2~12.3 MiB였다. 모든 socket 해제 뒤
  active connection과 logical payload는 0, pressure는 normal이었다. exact current report와
  SHA-256 sidecar는 `artifacts/memory-evidence/task032-current/`에 있다. 이 결과는 macOS arm64
  plaintext profile이며 Linux, 1,025 admission 거부, slow/TLS/soak 완료 증거가 아니다.
- Task 033 actual max+1 smoke는 1,025번째 socket terminal close, 기존 active count 1,024

  보존, `connection/connection_limit` metric 증가와 bounded Product event를 함께 검증했다.
  원래 holder 해제 뒤 1개 connection 재입장과 최종 connection/payload 0/0도 통과했다.
  source-bound report/digest와 요약은 `artifacts/memory-evidence/task033-current/`에 있다.
  이 결과도 macOS arm64 plaintext profile이며 payload/TLS/Linux/soak 완료 증거가 아니다.
- Task 034는 local Python shim에서 stdin script가 실행되지 않는 evidence false-positive 위험을

  제거했다. Memory readiness와 HTTP unknown-field mutation은 explicit `python3 -c`로 실행되며,
  mutated file 존재, unknown field와 exact digest 일치를 validator 전에 확인한다. 수정 후 idle과
  HTTP 100/100 release smoke가 재통과했다. 제품 runtime behavior는 변경되지 않았다.
- Task 035는 actual release proxy에서 slow header 64개를 production 30초 timeout까지 유지했다.

  Hold 중 connection/payload는 64/2,624였고 별도 정상 요청은 200이었다. Slow client는 64/64
  408로 종료됐으며 final connection/payload는 0/0, held peak RSS는 10,043,392 bytes였다.
  이는 macOS arm64 slow-header profile이며 body/response/TLS/Linux/soak 증거가 아니다.
- Task 036은 actual release proxy에서 slow body 32개를 production 30초 timeout까지

  유지했다. 각 connection은 65,536 bytes를 선언하고 32,768 bytes만 전송했다.
  Hold 중 connection/payload는 32/1,051,072였고 별도 정상 request는 200이었다.
  Slow client는 32/32 408로 종료됐으며 final connection/payload는 0/0, held peak
  RSS는 약 11 MiB였다. 이는 macOS arm64 partial-body profile이며 payload
  exhaustion, response/TLS/Linux/soak 증거가 아니다.
- Task 037은 16 MiB payload 예산에서 13개 partial body로 13,625,040 bytes를

  charge해 80% proactive pressure에 진입했다. 추가 connection은 terminal close와
  `payload/payload_pressure` metric/Product event로 거부되었고 기존 13개는
  보존됐다. 13/13 408 cleanup 후 0/0 normal과 recovery request 200을 확인했다.
  Normal event loop는 80%에서 읽기와 admission을 중지하므로 100% hard exhaustion을
  socket으로 우회 유도하지 않고 exact-fit/max+1 pure ledger test로 검증한다.
  이 결과는 response/TLS/Linux/soak 완료 증거가 아니다.
- Task 038은 temporary private Root/localhost leaf를 production certificate store에 배치해

  mio/rustls HTTPS trusted request 100/100, untrusted Root/wrong SNI 2/2 거부, post-negative
  trusted 200과 final 0/0 normal을 검증했다. Peak RSS는 약 10.7 MiB였다.
  Let's Encrypt/외부 network는 사용하지 않았다.
- Task 039는 test-tool rustls client로 64/128/256/512 handshake를 완료해 TLS idle

  connection 512개를 실제 production listener에 보유했다. Admin은 hold 중
  `connections=512`, `payload=0`, `pressure=normal`을 보고했고, peak RSS는 약 16.7 MiB였다.
  완료된 TLS session과 kernel socket buffer는 logical payload ledger 밖에 있으므로 RSS로
  검증한다. close-notify/socket shutdown 뒤 0/0 normal과 trusted HTTPS 200 recovery를
  확인했다.
- Task 040은 별도 client Root를 managed trust bundle에 게시하고 required-mTLS

  64/128/256 handshake를 완료했다. Hold 중 256/0 normal, no-cert/untrusted-client 2/2
  거부와 기존 session 보존, release 후 0/0 normal, authenticated recovery 200을 확인했다.
  Peak RSS는 약 14.9 MiB였다. 이는 revocation, WebSocket, Linux/soak 완료 증거가 아니다.
- Task 041은 plaintext WebSocket 128개를 upgrade/echo 후 backpressure 상태로 유지해

  8,504,064 logical payload bytes, normal pressure와 peak RSS 약 106 MiB를 측정했다.
  최초 actual이 pending output을 가진 terminal tunnel cleanup 결함을 발견했고, Core는 이제
  drain 경로가 중단된 terminal WebSocket을 즉시 제거하면서 모든 directional charge를
  release한다. 수정 후 release 128, final 0/0 normal, HTTP recovery 200을 확인했다.
  Task 055는 동일 proxy/upstream에서 이 lifecycle을 5회 반복해 cooldown median plateau를
  검증한다. TLS WebSocket capacity, fragmentation/extensions, Linux/soak 완료 증거는 아니다.
- Task 042는 신규 HTTP connection 10,000개를 5 cycle로 반복해 50,000/50,000 성공과

  cycle별 final 0/0 normal을 확인했다. 반복 macOS arm64 run의 startup/cooldown RSS는 약
  9.5 MiB였고 fixed 16 MiB plateau tolerance를 통과했다. 정확한 값은 실행별 canonical
  report를 권위로 하며 source/config/digest와 각 cycle counter/runtime/RSS를 묶는다. 이 값은
  cycle 종료 표본이므로 sub-cycle transient peak, throughput, Linux/long-soak 완료 증거는 아니다.
- Task 043은 response header만 읽는 128개 slow client로 약 12~13 MiB logical response bytes와

  약 36.4 MiB RSS를 유지했다. 첫 actual에서 response 중 client full-close를 무시하는 결함을
  발견했고, Core는 request-side half-close는 정상 처리하되 mio `write_closed`/error에서
  upstream과 모든 charge를 즉시 정리하도록 수정했다. final 0/0 normal과 recovery 200을
  확인했다. Task 054는 동일 proxy/upstream에서 이 128 hold/release/cooldown을 5회 반복하고
  first/last cooldown median plateau를 검증한다. TLS slow client, Linux/soak 완료 증거는 아니다.
- Task 044는 production audit/metrics collection의 최대 resident 위험을 별도 test-tool

  composition으로 측정한다. 정상 durable append로 생성한 audit 100,000건을 hash-chain
  재검증하고 metric 16,384 series/12,288 cumulative series를 함께 유지한다. 실제 Admin
  handler query를 3회 실행해 audit page 100, metric kind별 500 cap과 immutable response를
  확인하며 512 MiB RSS ceiling을 적용한다. 재사용 fixture는 manifest와 전체 segment digest가
  일치해야 한다. 이는 `edge-proxy` 전체 composition, Linux/plateau/soak 완료 주장이 아니다.
  승인된 macOS arm64 실행은 fixture 준비 537.75초, 약 52 MiB disk와 resident peak RSS
  46,727,168 bytes(약 44.6 MiB)를 관찰했다. 정확한 identity/digest는
  `artifacts/memory-evidence/task044-current/`를 권위로 한다.
- Task 045는 plaintext HTTP concurrency 100에서 worker당 1,000개의 새 connection을 처리해

  100,000/100,000 response correctness를 확인했다. 930회 public Admin 관찰의 max active는
  100, max charge는 18,620 bytes였고 final 0/0 normal, recovery 200이었다. load RSS peak
  10,764,288 bytes는 384 MiB ceiling 아래다. connection-per-request profile이므로 keep-alive
  throughput/latency, Linux, 3회 independent run과 long soak 완료를 주장하지 않는다.
- Task 046은 private-PKI HTTPS concurrency 100에서 worker당 500개의 새 TLS connection을 처리해

  50,000/50,000 response correctness를 확인했다. wrong-root/wrong-SNI는 2/2 거부됐고 negative가
  trusted upstream forward 50,000건을 늘리지 않았다. 593회 Admin 관찰의 max active는 101,
  max charge는 27,041 bytes였으며 final 0/0 normal, trusted recovery 200이었다. load RSS peak
  13,320,192 bytes는 384 MiB ceiling 아래다. 이는 사설 인증서 기반 반복 full handshake
  profile이며 public CA, mTLS steady, keep-alive throughput/latency, Linux/plateau/soak 완료를
  주장하지 않는다.
- Task 047은 required-mTLS concurrency 64에서 quotient/remainder로 exact 25,000 request를

  분배해 25,000/25,000 response를 확인했다. no-cert/untrusted-client는 2/2 거부되고 upstream
  count는 25,000을 유지했다. max active 64, max charge 14,069 bytes, final 0/0 normal,
  authenticated recovery 200과 peak RSS 13,352,960 bytes를 확인했다. CRL/OCSP, rotation under
  load, keep-alive 성능, Linux/plateau/soak 완료 주장이 아니다.
- 이 mini-run은 측정 tool과 owner inventory의 초기 characterization이다. 최대 동시 연결,

  HTTP/HTTPS/mTLS steady payload peak, 장시간 allocation leak slope와 Linux
  reference profile의 합격 기준은 아직 없다. 현재 수치를 memory usage 완료
  증거로 과장하지 않는다.
- 후속 성능 단계는 HTTP/HTTPS/mTLS 각각 idle, steady load, max connection, slow-client,

  connection churn과 cooldown을 측정하고 macOS `time`, `ps`, `vmmap`, `leaks`, Instruments
  또는 대상 Linux의 동등한 profiler로 재현 가능한 report를 남겨야 한다.
- Config의 `max_connections`와 `max_inflight_payload_bytes`는 typed schema bound와 startup

  validation을 통과해야 하며 running process에서는 immutable active policy로 전달된다.

### Automatic Quality And Release Evidence

기본 품질 게이트는 현재 source tree에서 직접 실행 가능한 Cargo 명령을 기준으로 한다.

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --test-threads=1
```

반복 개발 검증은 `Dockerfile.test`와 `docker-compose.test.yml`의 상시 `edge-test` 서비스에서도
동일한 세 명령으로 실행할 수 있다. source bind mount와 Cargo registry/git/target named cache만
사용하고 host port, 운영 data와 secret은 mount하지 않는다. 상세 lifecycle과 경계는
`docs/testing.md`가 소유한다. 이 Linux container 결과는 실제 production image/runtime 및
platform별 memory evidence를 대체하지 않는다.

삭제된 `scripts/` 기반 smoke, release collector, evidence validator는 더 이상 현재 실행
경로가 아니다. Phase 010/011 승인 증적에 기록된 script transcript는 과거 checkpoint의
source-bound evidence로만 보존한다. 새로운 release candidate를 승인하려면 삭제된 helper를
복구해 재사용하지 말고, Cargo 테스트, 실제 `edge-proxy` 실행, Docker Compose 실행,
Admin API/Web UI 수동 또는 별도 통합 검증, platform별 메모리 측정 결과를 새 evidence
bundle로 명시적으로 기록해야 한다. 새 evidence bundle은 build/source identity, 실행 명령,
환경, 결과, 실패/성공 기준, 민감정보 제외 여부를 사람이 검토할 수 있게 포함해야 한다.

Post-MVP Let's Encrypt staging 증적은 공개 test domain, 실제 ACME staging adapter, 명시적
Admin API issue 요청, challenge 응답, HTTPS 확인, Product Log를 하나의 수동 evidence
bundle로 묶어야 한다. Certificate issue의 안정적인 `X-Request-Id`는 ACME `metadata.env`, Admin API 성공 응답,
구조화된 `certificate.issue.success` Product Log와 required statement에 동일하게 기록해야
한다. 상세 binding, overwrite, release/build identity 일치 규칙은 `docs/acme-staging.md`와
`docs/release-gate.md`를 기준으로 한다. Let's Encrypt가 보류된 동안 이 외부 증적은 현재
MVP 완료 조건이 아니다.

### Architecture Rules Applied To The Implementation

- Core data plane은 Tokio가 아니라 mio를 사용한다.
- 의존성은 `bin -> adapters -> application -> domain` 방향을 유지하고 domain은 외부 I/O와

  framework를 import하지 않는다.
- 환경 변수는 bootstrap에서 한 번 읽고 typed config/dependency로 전달한다. Runtime 중

  environment 재조회나 변경으로 policy를 바꾸지 않는다.
- Admin Web UI는 Admin API client이며 config file이나 Core 내부 상태를 직접 수정하지 않는다.
- Config 변경은 parse, normalize, validate, diff, plan, acknowledged apply, revision commit,

  audit 순서를 따른다.
- 복잡한 connection, TLS, health/drain, backup/recovery, audit 흐름은 boolean flag 조합이

  아니라 명시적 state machine과 transition test로 관리한다.

작성일: 2026-06-04  
프로젝트 임시명: Sponzey Edge Proxy  
목표: HAProxy, Traefik, NGINX, Caddy의 장점을 조합한 Rust 기반 리버스 프록시 및 선택형 웹 관리 콘솔

## Current MVP Scope Note

2026-07-16 기준 구현된 MVP는 HTTP/1.1 reverse proxy, unified mio
manual/file-backed HTTPS, failure-aware multi-upstream routing, Admin API/Web UI
기반 config lifecycle, local metrics, durable audit 검색/복구와 Docker Compose smoke를 포함한다. Let's Encrypt 자동 발급과
외부 staging 검증은 사용자가 명시적으로 재개하기 전까지 Post-MVP 보류다. 이 문서의 ACME/Let's
Encrypt 항목은 제품 비전 또는 보류 후보로 읽어야 하며 `docs/current-state.md`의 구현
완료 주장으로 해석하지 않는다. Phase 011 memory/resource evidence는 `.tasks/phase011/`에
보관된 완료 근거이고, 활성 `.tasks/plan.md`는 단일 노드 운영 제품화의 미완료 계획이다.

## 1. 프로젝트 개요

이 프로젝트는 Rust로 작성된 고성능, 안전한 reverse proxy core와 별도로 운영 가능한 Admin Web UI를 제공하는 self-hosted edge gateway 솔루션이다.

목표는 단순히 NGINX, HAProxy, Traefik, Caddy를 대체하는 또 하나의 프록시를 만드는 것이 아니다. 각 제품의 강점을 뽑아 다음 성격을 결합한 "종합 선물 세트형" 솔루션을 만드는 것이다.

- NGINX의 안정적인 HTTP reverse proxy, 정적 파일 서빙, 캐시, 운영 검증성
- HAProxy의 강력한 로드 밸런싱, 헬스체크, TCP/HTTP 트래픽 제어, 장애 대응
- Traefik의 동적 서비스 발견, 라우터/미들웨어/서비스 모델, Kubernetes/Docker 친화성
- Caddy의 자동 HTTPS, 쉬운 설정, 안전한 기본값, Admin API 중심 운영

프로젝트의 핵심 방향은 다음과 같다.

```text
Rust Core
  - reverse proxy data plane
  - TLS / ACME / routing / load balancing
  - config validation / hot reload / metrics
  - stable Admin API

Admin Web UI Plugin
  - 별도 프로세스 또는 선택형 번들
  - proxy host / upstream / certificate / policy 관리
  - config diff / rollback / audit / backup

Plugin System
  - DNS provider
  - auth provider
  - observability exporter
  - notification
  - optional request filter
```

기본 제품 철학은 `headless-first`다. Core proxy는 Admin Web UI 없이도 CLI/API/config file로 운영 가능해야 한다. Admin Web UI는 편의 기능이며, 보안상 분리 배포하거나 완전히 비활성화할 수 있어야 한다.

## 2. 제품 비전

### 2.1 한 줄 비전

Rust 기반의 안전한 reverse proxy core 위에 자동 HTTPS, 웹 관리 콘솔, 동적 서비스 발견, 로드 밸런싱, 보안 정책, 관측성을 통합한 self-hosted edge gateway.

### 2.2 핵심 사용자

초기 타깃 사용자는 다음 순서로 본다.

1. NGINX 설정을 직접 관리하기 부담스러운 소규모 웹서비스 운영자
2. Docker Compose 기반으로 여러 내부 서비스를 외부에 안전하게 노출하려는 팀
3. 여러 고객 도메인과 SSL 인증서를 관리하는 에이전시/호스팅 운영자
4. 홈랩/셀프호스팅 사용자
5. 추후 Kubernetes, multi-cluster, enterprise edge gateway 사용자

### 2.3 핵심 가치

- 설정이 쉽다: 웹 UI와 declarative config를 모두 지원한다.
- 기본값이 안전하다: HTTPS 우선, admin UI 보호, 검증된 timeout, 안전한 TLS 기본값.
- 장애에 강하다: config validation, dry-run, zero-downtime reload, rollback.
- 운영이 보인다: access log, metrics, health, certificate 상태를 한 곳에서 본다.
- 확장 가능하다: core와 admin UI, plugin을 분리한다.
- 메모리 안전성을 강조한다: core는 Rust로 작성한다.

## 3. 기존 제품에서 가져올 장점

### 3.1 NGINX에서 가져올 장점

NGINX는 가장 널리 쓰이는 reverse proxy와 web server 중 하나다. 이 프로젝트는 NGINX의 다음 장점을 흡수한다.

- 안정적인 HTTP/HTTPS reverse proxy
- server block / location 기반 라우팅 개념
- 정적 파일 서빙
- SPA fallback 지원
- proxy buffering
- gzip/brotli 압축
- upstream keep-alive
- disk cache 또는 memory cache 계층
- rewrite / redirect
- header manipulation
- rate limiting
- access log 기반 운영
- 낮은 리소스 사용량
- reload 중심 운영 모델

단, NGINX 설정 문법을 그대로 복제하지는 않는다. 목표는 NGINX의 운영 가치와 성능 특성을 가져오되, 더 안전하고 이해하기 쉬운 config model을 제공하는 것이다.

### 3.2 HAProxy에서 가져올 장점

HAProxy는 L4/L7 load balancing과 traffic control에 강하다. 이 프로젝트는 다음 장점을 가져온다.

- frontend/backend 모델
- 강력한 active health check
- passive failure detection
- weighted round-robin
- least connections
- hash 기반 sticky routing
- SNI 기반 TCP/TLS routing
- PROXY protocol 지원
- connection limit
- request rate limit
- slow client/upstream 방어
- runtime API 기반 서버 상태 변경
- 세밀한 timeout 모델
- 장애 서버 자동 제외
- graceful drain
- stats/metrics 중심 운영

초기 MVP에서는 HAProxy 수준의 모든 기능을 제공하지 않는다. 그러나 아키텍처는 이후 HAProxy식 고급 load balancing과 traffic control을 붙일 수 있게 설계한다.

### 3.3 Traefik에서 가져올 장점

Traefik은 cloud-native dynamic routing에 강하다. 이 프로젝트는 다음 장점을 가져온다.

- Router / Middleware / Service 모델
- Docker provider 기반 서비스 자동 발견
- Kubernetes provider 확장 가능성
- rule 기반 라우팅: Host, Path, Headers, Method
- middleware chain
- automatic certificate resolver
- dashboard 기반 운영 가시성
- dynamic config reload
- HTTP/TCP/UDP entrypoint 모델
- canary, mirror, weighted service 확장 가능성

Traefik식 모델은 웹 UI와 잘 맞는다. 사용자가 "도메인 -> 라우터 -> 미들웨어 -> 서비스 -> upstream" 흐름을 화면에서 이해할 수 있기 때문이다.

### 3.4 Caddy에서 가져올 장점

Caddy는 automatic HTTPS와 쉬운 설정이 가장 큰 장점이다. 이 프로젝트는 다음 장점을 가져온다.

- Let's Encrypt 자동 발급과 갱신
- HTTP-01 challenge
- DNS-01 challenge
- local HTTPS 개발 인증서 지원 가능성
- 안전한 TLS 기본값
- 간결한 config
- Admin API
- atomic config reload
- module/plugin 구조
- 단일 바이너리 배포 경험
- 사용자가 TLS를 신경 쓰지 않아도 되는 UX

특히 자동 HTTPS는 프로젝트의 핵심 기능이다. 사용자는 도메인과 upstream만 입력하면 HTTPS endpoint가 자동으로 준비되어야 한다.

## 4. 제품 형태

### 4.1 전체 구성

```text
Client
  -> Rust Core Proxy
       -> Listener
       -> TLS / ACME
       -> Router
       -> Middleware
       -> Load Balancer
       -> Upstream Pool
       -> Backend Service

Operator
  -> Admin Web UI Plugin
       -> Admin API
       -> Config Store
       -> Audit Log
       -> Certificate Status
       -> Metrics Viewer
```

### 4.2 배포 형태

지원해야 할 배포 형태는 다음과 같다.

1. 단일 바이너리 모드
   - core proxy만 실행
   - config file 기반 운영
   - 서버/임베디드/홈랩에 적합
2. core + admin web 모드
   - core proxy와 admin UI를 함께 실행
   - 초기 MVP의 기본 형태
   - 소규모 팀과 홈랩에 적합
3. core + external admin 모드
   - core proxy는 data plane
   - admin web은 별도 프로세스 또는 컨테이너
   - 보안상 admin UI를 내부망에만 노출 가능
4. cluster 모드
   - 여러 core proxy를 하나의 admin/control plane에서 관리
   - 추후 enterprise 기능
5. Kubernetes controller 모드
   - Gateway API 또는 CRD 기반 관리
   - 장기 목표

### 4.3 핵심 원칙

- Core는 Admin UI에 의존하지 않는다.
- Admin UI는 Core Admin API만 사용한다.
- Config는 사람이 읽고 쓸 수 있어야 한다.
- Config 변경은 반드시 validation을 통과해야 한다.
- 실패한 reload는 현재 동작 중인 config에 영향을 주면 안 된다.
- Certificate lifecycle은 자동화하되, 사용자가 상태를 명확히 볼 수 있어야 한다.
- Admin UI는 외부 공개가 기본값이면 안 된다.

## 5. 아키텍처 상세

### 5.1 Rust Core

Rust Core는 data plane이다. 실제 client traffic을 처리한다.

주요 책임:

- TCP listener 관리
- TLS termination
- HTTP/1.1 parser
- HTTP/2 parser
- reverse proxy
- upstream connection pool
- routing
- middleware execution
- load balancing
- health check
- ACME certificate lifecycle
- access log
- metrics
- config validation
- config reload
- Admin API

초기 Rust stack 후보:

- event loop: mio
- HTTP: 직접 구현 또는 mio 친화적 HTTP parser 조합 검토
- TLS: rustls 우선, 필요 시 OpenSSL/BoringSSL 옵션 검토
- ACME: acme-client 계열 crate 또는 직접 구현
- config: serde + TOML/YAML/JSON
- metrics: Prometheus exposition
- storage: SQLite 또는 file store
- web admin backend: core와 분리된 별도 UI service

중요한 판단:

- Core data plane은 Tokio가 아니라 mio 기반 event loop로 작성한다.
- MVP는 HTTP/1.1 reverse proxy 범위를 좁혀 mio 기반 네트워크 루프, parser, upstream connection pool을 직접 통제한다.
- Admin Web UI는 core hot path에 들어가지 않으므로 별도 프로세스에서 다른 웹 프레임워크를 사용할 수 있다.
- 장기적으로 Pingora 기반 data plane을 직접 채택하는 방향은 기본 전략에서 제외한다. Pingora의 설계와 아이디어는 참고하되 core event loop는 mio 중심으로 유지한다.
- TLS는 가능하면 rustls를 기본으로 한다. 메모리 안전성과 배포 단순성을 얻기 위해서다.

### 5.2 Admin API

Admin API는 Core의 안정적인 관리 인터페이스다.

역할:

- config 조회
- config draft 생성
- config validation
- config diff
- config apply
- rollback
- certificate 상태 조회
- proxy route 상태 조회
- upstream health 상태 조회
- metrics 조회
- audit event 조회
- backup/restore

원칙:

- Admin API는 loopback 또는 unix socket 바인딩이 기본이다.
- 외부 노출은 명시적으로 켜야 한다.
- 인증 없는 Admin API 외부 노출은 허용하지 않는다.
- 모든 config 변경은 audit log에 남긴다.
- API는 versioning한다.

예상 endpoint:

```text
GET    /api/v1/status
GET    /api/v1/config
POST   /api/v1/config/validate
POST   /api/v1/config/diff
POST   /api/v1/config/apply
POST   /api/v1/config/rollback

GET    /api/v1/listeners
GET    /api/v1/routes
POST   /api/v1/routes
PATCH  /api/v1/routes/{id}
DELETE /api/v1/routes/{id}

GET    /api/v1/upstreams
POST   /api/v1/upstreams
PATCH  /api/v1/upstreams/{id}
DELETE /api/v1/upstreams/{id}

GET    /api/v1/certificates
POST   /api/v1/certificates/issue
POST   /api/v1/certificates/renew

GET    /api/v1/health/upstreams
GET    /api/v1/metrics
GET    /api/v1/audit
```

### 5.3 Admin Web UI Plugin

Admin Web UI는 core의 필수 구성 요소가 아니라 선택형 관리 플러그인이다.

권장 형태:

- 별도 프로세스
- Core Admin API와 통신
- 자체 인증/세션 관리
- 내부망/VPN/localhost 배포 권장
- core와 같은 컨테이너로 번들 배포 가능

초기 UI 기능:

- 로그인
- 대시보드
- Proxy Host 목록
- Proxy Host 생성/수정/삭제
- upstream 서버 목록
- 인증서 상태
- Let's Encrypt 발급/갱신 상태
- access log 간단 조회
- config validation 결과 표시
- apply 전 diff 표시
- rollback 버튼

장기 UI 기능:

- 라우팅 그래프
- middleware chain editor
- service discovery 상태
- audit log 검색
- RBAC
- 팀/프로젝트 분리
- multi-node 관리
- Prometheus/Grafana 연동
- backup/restore
- notification 설정

### 5.4 Plugin System

플러그인은 두 종류로 나눈다.

#### Management Plugin

관리 plane에서 동작한다. hot path에 직접 들어가지 않는다.

예:

- Admin Web UI
- DNS provider
- notification: Slack, Discord, email, webhook
- backup storage: S3, local, Git
- auth provider: OIDC, LDAP
- observability exporter

권장 구현:

- 별도 프로세스
- gRPC 또는 HTTP API
- core process crash와 격리

#### Data Plane Plugin

요청 처리 경로에 들어간다. 성능과 안전성이 중요하다.

예:

- request auth filter
- header rewrite
- rate limit decision
- custom routing decision
- WAF rule
- body transform

권장 구현:

- 초기에는 first-party built-in middleware만 제공
- 외부 data plane plugin은 나중에 제한적으로 지원
- WASM 기반 sandbox를 우선 검토
- native dynamic library plugin은 피한다

native plugin을 피하는 이유:

- Rust ABI 안정성 문제가 있다.
- plugin crash가 core process crash로 이어질 수 있다.
- memory safety 경계가 약해진다.
- hot reload가 복잡해진다.

## 6. Config Model

### 6.1 기본 개념

Config는 다음 객체로 구성한다.

- Listener
- Certificate Resolver
- Route
- Middleware
- Service
- Upstream
- Health Check
- Access Policy
- Log Policy

### 6.2 예시 config

```toml
[admin]
bind = "127.0.0.1:9443"
enabled = true

[[listeners]]
name = "https"
bind = "0.0.0.0:443"
protocol = "https"
certificate_resolver = "letsencrypt"

[[listeners]]
name = "http"
bind = "0.0.0.0:80"
protocol = "http"
redirect_to_https = true

[[certificate_resolvers]]
name = "letsencrypt"
provider = "acme"
email = "admin@example.com"
challenge = "http-01"

[[services]]
name = "app"
load_balancer = "round_robin"

[[services.upstreams]]
url = "http://127.0.0.1:3000"
weight = 1

[[routes]]
name = "app-example"
listener = "https"
hosts = ["app.example.com"]
paths = ["/"]
service = "app"
middlewares = ["secure-headers", "gzip"]
```

### 6.3 Config lifecycle

```text
edit draft
  -> validate syntax
  -> validate references
  -> validate ports/domains/certificates
  -> dry-run bind/listener check
  -> diff current vs draft
  -> apply
  -> start new config
  -> drain old config
  -> commit revision
```

필수 조건:

- validation 실패 시 적용하지 않는다.
- apply 도중 실패하면 이전 config로 유지한다.
- 모든 revision은 저장한다.
- rollback은 클릭 한 번으로 가능해야 한다.

## 7. 지원 프로토콜

### 7.1 MVP 지원 프로토콜

MVP에서 반드시 지원할 프로토콜:

| 프로토콜          | 방향                                 | 목표               |
| ------------- | ---------------------------------- | ---------------- |
| HTTP/1.1      | client -> proxy, proxy -> upstream | 기본 reverse proxy |
| HTTPS         | client -> proxy                    | TLS termination  |
| HTTP upstream | proxy -> upstream                  | 일반 backend 연결    |
| WebSocket     | client -> upstream                 | 기본 upgrade proxy |
| ACME HTTP-01  | proxy -> Let's Encrypt             | 자동 인증서 발급        |

MVP에서 선택 지원:

| 프로토콜                             | 설명                |
| -------------------------------- | ----------------- |
| HTTP/2 client-side               | 브라우저 HTTPS 연결 최적화 |
| Prometheus metrics HTTP endpoint | 운영 지표 노출          |

### 7.2 Phase 2 이후 지원

| 프로토콜                 | 목표                                        |
| -------------------- | ----------------------------------------- |
| HTTP/2 upstream      | gRPC와 modern backend 지원                   |
| gRPC                 | HTTP/2 기반 gRPC proxy                      |
| ACME DNS-01          | wildcard certificate와 private network 도메인 |
| PROXY protocol v1/v2 | 앞단 LB와 client IP 전달                       |
| TCP proxy            | database, SSH, custom TCP service         |
| TLS passthrough      | SNI 기반 backend 전달                         |

### 7.3 장기 지원

| 프로토콜                   | 목표                           |
| ---------------------- | ---------------------------- |
| HTTP/3 / QUIC          | modern edge protocol         |
| UDP proxy              | gaming, DNS, custom UDP      |
| MQTT                   | IoT gateway                  |
| MCP gateway            | AI agent tool access gateway |
| OpenTelemetry Protocol | trace/metrics/log 연동         |

### 7.4 명시적으로 초기 제외할 기능

MVP에서 제외:

- full WAF
- Kubernetes controller
- advanced TCP proxy
- HTTP/3
- multi-node cluster
- enterprise RBAC
- billing
- plugin marketplace
- service mesh 기능

제외 이유:

- MVP 목표는 간단한 NGINX 대체다.
- traffic critical path 제품은 초기 범위를 줄여 안정성을 먼저 확보해야 한다.
- 프로토콜과 기능을 많이 넣으면 correctness test 범위가 급격히 커진다.

## 8. 전체 기능 리스트

### 8.1 Reverse Proxy

필수:

- Host 기반 라우팅
- Path prefix 기반 라우팅
- HTTP/HTTPS proxy
- upstream keep-alive
- WebSocket upgrade
- request header 추가/삭제/수정
- response header 추가/삭제/수정
- X-Forwarded-For
- X-Forwarded-Proto
- X-Forwarded-Host
- request body size 제한
- timeout 설정
- access log

확장:

- regex path match
- method match
- header match
- query match
- priority 기반 route
- route shadowing
- traffic mirror
- canary routing

### 8.2 TLS / Certificate

필수:

- TLS termination
- SNI
- Let's Encrypt 자동 발급
- 자동 갱신
- HTTP-01 challenge
- 인증서 만료 상태 표시
- 인증서 저장소
- 수동 인증서 등록
- HTTP to HTTPS redirect

확장:

- DNS-01 challenge
- wildcard certificate
- staging/production ACME 전환
- EAB 지원
- custom ACME server
- upstream TLS
- mTLS client certificate 검증
- OCSP stapling
- certificate pinning 정보 표시

### 8.3 Load Balancing

MVP:

- 단일 upstream
- round-robin
- upstream failure 시 basic retry

Phase 2:

- weighted round-robin
- least connections
- random
- IP hash
- header hash
- cookie sticky session
- active health check
- passive health check
- server drain

장기:

- EWMA latency 기반 선택
- circuit breaker
- outlier detection
- locality-aware routing
- per-route retry budget

### 8.4 Health Check

필수:

- HTTP health check
- status code match
- interval
- timeout
- failure threshold
- recovery threshold

확장:

- TCP health check
- TLS health check
- gRPC health check
- custom header
- body match
- passive error rate detection

### 8.5 Static File Serving

MVP 또는 Phase 2:

- directory root
- index file
- SPA fallback
- cache-control header
- gzip/brotli precompressed file

확장:

- directory listing 옵션
- range request
- ETag
- last-modified
- sendfile 또는 zero-copy 최적화

### 8.6 Cache

초기 제외 또는 Phase 3:

- response cache
- cache key 설정
- cache-control respect
- stale-while-revalidate
- purge API
- size limit
- TTL
- disk cache
- memory cache

주의:

- 캐시는 correctness가 어렵다.
- 인증 사용자 응답과 cookie 처리에서 보안 문제가 생길 수 있다.
- MVP에서는 넣지 않는 것을 권장한다.

### 8.7 Middleware

MVP:

- HTTPS redirect
- secure headers
- gzip compression
- request/response header edit
- basic auth

Phase 2:

- rate limit
- IP allow/deny
- forward auth
- OIDC login
- path rewrite
- redirect
- CORS
- request body limit

장기:

- WAF-lite
- JWT validation
- OAuth2 proxy mode
- bot protection
- geo/IP reputation
- WASM filter

### 8.8 Service Discovery

MVP:

- 수동 upstream 등록

Phase 2:

- Docker container label discovery
- Docker Compose project discovery
- file provider watch

Phase 3:

- Consul provider
- Kubernetes Ingress/Gateway API provider
- DNS SRV discovery

### 8.9 Observability

MVP:

- structured access log
- error log
- request count
- response status count
- latency histogram
- upstream health status
- certificate expiry status

Phase 2:

- Prometheus metrics
- dashboard charts
- per-route metrics
- per-upstream metrics
- log search

장기:

- OpenTelemetry traces
- distributed tracing propagation
- anomaly alert
- SLO dashboard
- cost/egress tracking

### 8.10 Admin Web UI

MVP:

- 로그인
- 대시보드
- proxy host CRUD
- upstream CRUD
- certificate status
- Let's Encrypt 발급 버튼
- config validation 결과
- apply/rollback
- 간단한 access log

Phase 2:

- middleware editor
- service discovery viewer
- health check editor
- route priority editor
- audit log
- backup/restore

Phase 3:

- RBAC
- team/project
- SSO/OIDC
- multi-node 관리
- notification 설정

### 8.11 Security

MVP:

- admin bind 기본값 localhost
- admin password 초기 설정 강제
- session cookie secure/httpOnly/sameSite
- CSRF protection
- config secret masking
- TLS 기본 보안 설정

Phase 2:

- RBAC
- audit log
- OIDC
- IP allowlist for admin
- mTLS for Admin API
- encrypted secret store

장기:

- policy as code
- compliance report
- signed config bundle
- supply chain attestation

## 9. 장점

### 9.1 사용자 관점 장점

- NGINX 설정 문법을 몰라도 reverse proxy를 만들 수 있다.
- 도메인만 연결하면 Let's Encrypt 인증서가 자동 발급된다.
- config 변경 전에 validation과 diff를 볼 수 있다.
- 실패한 설정이 운영 중인 proxy를 깨뜨리지 않는다.
- 웹 UI 없이 headless 운영도 가능하다.
- Docker Compose 기반 서비스 노출이 쉬워진다.
- 여러 도메인과 upstream을 한 화면에서 관리할 수 있다.
- 인증서 만료와 upstream 장애를 UI에서 확인할 수 있다.

### 9.2 운영 관점 장점

- zero-downtime reload를 기본 설계로 가져간다.
- rollback 가능한 config revision을 제공한다.
- access log, metrics, certificate 상태가 통합된다.
- admin UI를 별도 배포할 수 있어 공격면을 줄일 수 있다.
- core data plane은 작고 안정적으로 유지할 수 있다.
- plugin을 통해 DNS provider, auth provider, notification을 확장할 수 있다.

### 9.3 기술 관점 장점

- Rust core로 memory safety를 확보한다.
- TLS stack을 rustls 중심으로 구성하면 배포와 보안 관리가 단순해질 수 있다.
- mio 기반 non-blocking I/O로 많은 연결을 명시적으로 제어할 수 있다.
- config model을 처음부터 API-friendly하게 설계할 수 있다.
- C 기반 프록시보다 extension boundary를 더 명확히 잡을 수 있다.

### 9.4 시장 관점 장점

- NGINX Proxy Manager류 수요가 이미 존재한다.
- Caddy의 자동 HTTPS 경험은 검증된 사용자 가치다.
- Traefik의 dynamic routing 모델은 cloud-native 사용자에게 익숙하다.
- HAProxy식 load balancing은 SMB/호스팅/내부 서비스 운영에 필요하다.
- Rust 기반 보안/안전성 메시지는 차별화에 도움이 된다.

## 10. 단점과 리스크

### 10.1 경쟁 리스크

이미 강한 경쟁자가 많다.

- NGINX: 사실상 표준 reverse proxy
- HAProxy: 고성능 load balancer 표준
- Caddy: automatic HTTPS와 쉬운 설정
- Traefik: Docker/Kubernetes dynamic routing
- NGINX Proxy Manager: 웹 UI 기반 self-hosted proxy manager
- Pangolin: identity-aware reverse proxy와 tunnel
- Kong/Envoy: API Gateway와 enterprise gateway

따라서 단순히 "웹 UI + Let's Encrypt"만으로는 부족하다. 차별화는 다음에서 나와야 한다.

- 안전한 config lifecycle
- rollback과 audit
- admin UI 분리
- Rust core
- Docker/service discovery UX
- access policy
- 보안 기본값

### 10.2 기술 리스크

프록시는 critical path에 있다. 작은 버그도 전체 서비스 장애가 된다.

주요 리스크:

- HTTP parser edge case
- request smuggling
- chunked encoding 처리
- HTTP/2 stream handling
- WebSocket upgrade
- slowloris 방어
- timeout/retry 폭발
- upstream connection leak
- TLS certificate reload
- ACME rate limit
- config reload race condition
- log/metrics cardinality 폭발

대응:

- MVP 범위를 좁힌다.
- correctness test suite를 먼저 만든다.
- fuzzing을 장기적으로 도입한다.
- shadow traffic 테스트를 지원한다.
- rollback을 core 기능으로 만든다.

### 10.3 제품 리스크

- 홈랩 사용자는 많지만 유료 전환이 낮을 수 있다.
- SMB는 편의성을 원하지만 설치/운영 지원 비용이 높을 수 있다.
- enterprise는 기능 요구가 많고 sales cycle이 길다.
- proxy 제품은 신뢰를 얻는 데 시간이 오래 걸린다.

대응:

- open-source core로 adoption을 만든다.
- paid feature는 team/RBAC/audit/multi-node/SSO에 둔다.
- 초기에는 self-hosted 단일 노드에 집중한다.
- 문서와 migration guide를 강하게 만든다.

### 10.4 자체 엔진 개발 리스크

Rust core는 차별점이지만, 동시에 부담이다.

단점:

- NGINX/HAProxy 수준 안정성까지 시간이 걸린다.
- HTTP/2/3, TLS, proxy buffering 등 구현 범위가 크다.
- 벤치마크에서 기존 프록시를 이기기 어렵다.
- 라이브러리 선택에 따라 장기 유지보수 리스크가 있다.

완화:

- HTTP parser와 connection state machine은 검증된 crate를 신중히 조합하되, event loop와 backpressure는 core가 직접 제어한다.
- 초기에는 HTTP/1.1 reverse proxy에 집중한다.
- 고급 기능은 단계적으로 붙인다.
- "가장 빠른 proxy"가 아니라 "가장 안전하고 운영하기 쉬운 proxy"로 포지셔닝한다.

## 11. Historical MVP Proposal (Not Current Execution Scope)

이 절은 초기 제품 제안과 장기 roadmap을 보존한다. 현재 구현·지원 범위의 권위는
`docs/current-state.md`, 실행·release 절차의 권위는 `docs/release-gate.md`다. 특히 아래의
ACME, Let's Encrypt, HTTP-01, DNS-01, 자동 갱신 언급은 현재 기능 또는 작업 지시가 아니다.
사용자가 명시적으로 범위를 재개하기 전까지 단일 노드 제품은 manual/file-backed certificate와
private PKI만 지원한다.

### 11.1 MVP 목표

최초 MVP는 "간단한 웹 UI를 포함한 아주 간단한 NGINX 대체"다.

MVP는 아래 사용자가 바로 쓸 수 있어야 한다.

> 사용자가 `app.example.com -> http://127.0.0.1:3000` proxy host를 웹 UI에서 추가하고
> manual/file-backed certificate 또는 private PKI certificate를 등록·선택하면 HTTPS reverse
> proxy가 동작한다.

### 11.2 MVP에 반드시 포함할 기능

Core:

- Rust 기반 reverse proxy daemon
- HTTP listener
- HTTPS listener
- HTTP to HTTPS redirect
- Host 기반 routing
- Path prefix routing
- 단일 upstream reverse proxy
- WebSocket upgrade
- X-Forwarded-* header
- request/response timeout
- structured access log
- config file 저장
- config validation
- zero-downtime에 가까운 reload
- previous config rollback

TLS/certificate:

- manual/file-backed certificate 등록과 저장
- private PKI chain 검증과 SNI 선택
- 새 connection에 대한 certificate hot install
- 인증서 만료일 표시
- 자동 ACME 발급·갱신은 명시 재개 전 Post-MVP 보류

Admin API:

- local Admin API
- proxy host CRUD
- upstream CRUD
- certificate status
- config validate/apply/rollback

Admin Web UI:

- 로그인
- 대시보드
- proxy host 목록
- proxy host 생성/수정/삭제
- upstream URL 입력
- manual certificate 선택·상태 표시
- HTTPS redirect 체크박스
- 설정 적용 전 validation 표시
- 최근 access log 표시
- certificate 상태 표시

배포:

- macOS/Linux 단일 바이너리
- Docker image
- Docker Compose 예제
- 기본 포트: 80, 443, admin 9443

### 11.3 MVP에서 제외할 기능

- Kubernetes
- Docker discovery
- Let's Encrypt/ACME 자동 발급과 갱신
- HTTP-01 challenge
- DNS-01
- wildcard certificate
- multi-user RBAC
- OIDC
- TCP proxy
- HTTP/3
- cache
- WAF
- advanced load balancing
- plugin marketplace
- multi-node cluster

### 11.4 MVP 성공 기준

기능 기준:

- 웹 UI에서 proxy host를 만들 수 있다.
- manual/file-backed certificate 또는 private PKI certificate로 HTTPS route를 구성할 수 있다.
- HTTPS로 backend 서비스에 접근할 수 있다.
- 잘못된 upstream/config는 적용 전에 차단된다.
- config apply 실패 시 기존 proxy가 계속 동작한다.
- WebSocket echo service가 proxy 뒤에서 동작한다.

운영 기준:

- 기본 설치 후 10분 안에 첫 proxy host 생성 가능
- config file을 사람이 읽을 수 있음
- admin UI를 끄고 core만 실행 가능
- access log로 요청 상태를 확인 가능

비기능 기준:

- 단일 노드에서 일반 소규모 서비스 트래픽 처리
- idle connection 누수 없음
- certificate import/validation failure가 기존 route를 깨뜨리지 않음
- 기본 보안 스캔 통과

## 12. 개발 단계

### Phase 0. Foundation

목표:

1. Rust workspace 구성
2. core daemon skeleton
3. config model 초안
4. local reverse proxy proof of concept

상세 작업:

- `core` crate 생성
- `admin-api` crate 생성
- `config` crate 생성
- `web-admin` app 디렉터리 생성
- mio event loop 구성
- connection state machine skeleton 작성
- 기본 CLI 구현
- TOML config load
- HTTP listener 생성
- 단일 upstream proxy POC
- structured logging 도입

완료 기준:

- config file로 `localhost:8080 -> localhost:3000` proxy 가능
- core daemon 시작/종료 가능
- 기본 access log 출력

### Phase 1. Original MVP Proposal (Historical)

이 원래 제안의 ACME account, HTTP-01, renewal scheduler 항목은 현재 실행 계획에 포함되지
않는다. 현재 제품화 범위는 위의 manual/file-backed certificate 및 private PKI 운영 계약을
따른다.

목표:

1. 웹 UI로 proxy host 관리
2. HTTP/HTTPS reverse proxy
3. Let's Encrypt HTTP-01 자동 인증서
4. config validation/apply/rollback

상세 작업:

- Host 기반 route
- Path prefix route
- upstream CRUD
- HTTP to HTTPS redirect
- TLS termination
- ACME account 생성
- HTTP-01 challenge responder
- certificate store
- renewal scheduler
- Admin API v1
- Admin Web UI login
- Proxy Host CRUD 화면
- certificate status 화면
- config diff/validation 화면
- rollback 기능
- Docker image
- Docker Compose 예제

완료 기준:

- 사용자가 UI에서 `domain -> upstream`을 만들면 HTTPS proxy가 동작
- WebSocket proxy 성공
- 잘못된 config 적용 차단
- rollback 성공
- admin UI 비활성화 모드 동작

### Phase 2. Production Hardening

목표:

1. load balancing과 health check
2. 운영 관측성 강화
3. 보안 기본값 강화
4. 백업/복원

상세 작업:

- multiple upstream
- round-robin
- weighted round-robin
- active HTTP health check
- passive failure detection
- upstream drain
- request timeout 세분화
- retry policy
- Prometheus metrics
- per-route latency/status metrics
- access log search
- audit log
- admin session hardening
- admin IP allowlist
- config secret masking
- backup/restore
- notification webhook

완료 기준:

- upstream 장애 시 자동 제외
- Prometheus에서 route/upstream metrics 확인 가능
- audit log에 모든 config 변경 기록
- backup 파일로 복구 가능

### Phase 3. Dynamic Discovery And Middleware

목표:

1. Docker service discovery
2. middleware chain
3. 인증/접근 제어
4. DNS-01과 wildcard certificate

상세 작업:

- Docker provider
- Docker Compose label rule
- file provider watch
- middleware model 정식화
- secure headers
- gzip/brotli compression
- path rewrite
- redirect
- CORS
- basic auth
- forward auth
- IP allow/deny
- rate limit
- DNS provider plugin interface
- Cloudflare DNS plugin
- Route53 DNS plugin
- wildcard certificate

완료 기준:

- Docker label만으로 route 자동 생성
- middleware chain을 UI에서 편집 가능
- wildcard certificate 발급 가능
- rate limit과 access control 동작

### Phase 4. Advanced Proxy Features

목표:

1. TCP/TLS passthrough
2. gRPC/HTTP2 upstream
3. 고급 load balancing
4. cache/static serving

상세 작업:

- TCP listener
- SNI 기반 TLS passthrough
- PROXY protocol v1/v2
- HTTP/2 upstream
- gRPC proxy
- least connections
- hash load balancing
- sticky session
- circuit breaker
- outlier detection
- static file serving
- SPA fallback
- response cache POC
- cache purge API

완료 기준:

- TCP service proxy 가능
- gRPC service proxy 가능
- sticky session 동작
- static site hosting 가능
- cache hit/miss metrics 확인 가능

### Phase 5. Team And Enterprise Features

목표:

1. multi-user/RBAC
2. SSO/OIDC
3. multi-node management
4. policy/audit/compliance

상세 작업:

- user/team/project model
- role-based access control
- OIDC login
- LDAP option 검토
- mTLS Admin API
- signed config revision
- multi-node inventory
- remote agent registration
- central control plane
- per-node config sync
- compliance report
- policy template
- approval workflow

완료 기준:

- 팀별 route 권한 분리
- SSO 로그인 가능
- 여러 proxy node를 하나의 UI에서 관리
- audit/compliance export 가능

### Phase 6. Cloud Native And Gateway API

목표:

1. Kubernetes Gateway API 지원
2. Ingress migration path
3. multi-cluster traffic management
4. GitOps workflow

상세 작업:

- Kubernetes controller
- GatewayClass
- Gateway
- HTTPRoute
- TLSRoute 검토
- ReferenceGrant
- policy CRD
- Gateway API status reporting
- cert-manager 연동
- Argo CD/Flux friendly manifests
- route conflict detection
- multi-cluster inventory

완료 기준:

- Gateway API 리소스로 route 생성
- status condition이 정확히 보고됨
- route conflict가 UI에 표시됨
- GitOps로 config 변경 가능

### Phase 7. Plugin Ecosystem

목표:

1. management plugin SDK
2. DNS/auth/notification plugin 확대
3. data plane WASM filter 검토
4. plugin registry 또는 marketplace 기초

상세 작업:

- plugin manifest
- plugin lifecycle
- plugin permission model
- plugin sandbox policy
- gRPC plugin protocol
- WASM filter POC
- plugin signing
- plugin install/update
- first-party plugin catalog

완료 기준:

- 외부 DNS provider plugin 추가 가능
- notification plugin 추가 가능
- plugin 권한을 UI에서 확인 가능
- data plane plugin은 제한적 POC 수준으로 검증

## 13. 권장 개발 우선순위

최우선:

1. Core reverse proxy correctness
2. TLS/ACME 안정성
3. config validation/apply/rollback
4. Admin UI 최소 기능

다음:

1. health check
2. multiple upstream
3. metrics
4. Docker 배포

그 다음:

1. Docker discovery
2. middleware
3. DNS-01
4. access policy

장기:

1. TCP/gRPC
2. Kubernetes Gateway API
3. multi-node
4. plugin ecosystem

## 14. 초기 기술 의사결정

### 14.1 Core는 Rust

이유:

- memory safety
- mio 기반 non-blocking event loop를 직접 제어할 수 있음
- request/connection state machine을 제품 요구에 맞게 설계 가능
- single binary 배포 가능
- 보안 제품 메시지에 유리
- TLS, config, storage, metrics 등 주변 생태계를 Rust로 통합 가능

주의:

- 기존 C proxy만큼 검증되려면 시간이 필요하다.
- Tokio/hyper 기반 생태계를 그대로 활용하기 어렵다.
- HTTP parser, connection lifecycle, backpressure, timeout을 직접 설계해야 한다.
- 성능보다 correctness와 안정성을 먼저 잡아야 한다.

### 14.2 Core event loop는 mio

이유:

- Tokio 같은 범용 async runtime에 의존하지 않는다.
- proxy hot path의 event registration, readiness, buffering, backpressure를 직접 제어한다.
- HAProxy/NGINX처럼 명시적인 connection state machine을 만들기 좋다.
- 런타임 추상화 비용과 예측 불가능성을 줄이는 방향으로 설계할 수 있다.

주의:

- 개발 난도가 올라간다.
- async/await 기반 라이브러리 재사용성이 떨어진다.
- TLS handshake, HTTP parsing, upstream 연결, timeout wheel을 직접 통합해야 한다.
- Windows/macOS/Linux 이벤트 모델 차이를 테스트해야 한다.

권장:

- MVP는 HTTP/1.1 reverse proxy에 집중한다.
- 처음부터 HTTP/2/gRPC/HTTP/3를 넣지 않는다.
- connection state machine과 timer, buffer pool을 독립 모듈로 둔다.
- Admin Web UI는 core event loop 밖의 별도 프로세스로 유지한다.

### 14.3 Admin UI는 분리 가능한 plugin

이유:

- admin UI 공격면을 core와 분리할 수 있다.
- headless 운영이 가능하다.
- enterprise에서 내부망 전용 UI 배포가 쉽다.
- UI 기술 스택을 core와 독립적으로 바꿀 수 있다.

권장:

- MVP에서는 같은 repo에 포함하되 프로세스는 분리 가능하게 설계
- Admin API는 안정적인 계약으로 유지
- UI는 API client일 뿐이라는 원칙 유지

### 14.4 Config는 declarative

이유:

- GitOps와 백업에 유리
- diff/rollback이 쉽다.
- UI 없이도 운영 가능하다.
- 장애 시 사람이 직접 수정할 수 있다.

권장:

- 내부 canonical format은 JSON-compatible struct
- 외부 파일은 TOML 또는 YAML
- UI 변경도 결국 config revision으로 저장

### 14.5 Plugin은 단계적으로

MVP에서 plugin system을 과하게 만들지 않는다.

순서:

1. Admin Web UI를 optional component로 분리
2. DNS provider를 trait/interface로 분리
3. notification plugin 추가
4. auth provider plugin 추가
5. WASM data plane filter 검토

## 15. 유료화 전략과 비용 제도

### 15.1 결론

이 프로젝트는 core reverse proxy 기능을 유료로 잠그는 방식보다, `open-core + paid control plane/plugin + support/managed` 모델이 가장 적합하다.

가장 중요한 원칙은 다음이다.

- 기본 reverse proxy 기능은 무료여야 한다.
- 자동 HTTPS의 기본 흐름은 무료여야 한다.
- 설정 validation과 rollback은 무료여야 한다.
- 단일 노드 Admin Web UI는 무료여야 한다.
- 보안 기본값을 유료로 잠그면 안 된다.
- 유료화는 팀 운영, 감사, 자동화, 멀티노드, 고급 보안, 지원, 관리형 서비스에 둔다.

이유는 명확하다. 이 제품은 트래픽의 critical path에 들어간다. 사용자는 core가 투명하고 신뢰 가능해야 도입한다. NGINX, Caddy, Traefik, HAProxy, Nginx Proxy Manager 같은 무료/오픈소스 대안이 이미 있기 때문에, 기본 proxy와 Let's Encrypt만 유료로 묶으면 adoption이 매우 어렵다.

반대로 기업과 팀이 돈을 내는 지점은 "프록시가 동작하는 것" 자체가 아니라 "여러 사람이 안전하게 운영하고, 변경 이력을 남기고, 여러 노드를 관리하고, 장애가 났을 때 지원받는 것"이다.

### 15.2 경쟁 제품의 가격 흐름

2026년 기준 경쟁 제품의 패키징 흐름은 다음과 같다.

- Kong Konnect는 30일 무료 trial을 제공하고, Plus는 Gateway 단위 월 과금과 API analytics 사용량 과금이 섞여 있다. Enterprise는 custom pricing이며 SSO, audit logs, self-hosted gateway, 높은 SLA와 지원이 enterprise 영역이다. [Kong Pricing](https://konghq.com/pricing)
- Tyk은 Core/Professional/Enterprise 형태로 usage-based, flat-rate, custom enterprise 모델을 모두 제공하며, Cloud/Hybrid/Self-managed를 지원한다. [Tyk Pricing](https://tyk.io/pricing/)
- Traefik은 OSS 프록시를 기반으로 Hub/API Gateway 제품에서 AI Gateway, MCP Gateway, Native WAF, advanced access control, distributed Let's Encrypt, distributed rate limiting, cluster dashboard, multi-cluster management 같은 기능을 상위 제품에 둔다. [Traefik Pricing](https://traefik.io/pricing)
- F5 NGINX One은 NGINX 제품군을 enterprise subscription으로 묶고, deployment size, 환경, 필요한 기능에 따라 가격이 달라진다고 설명한다. [NGINX One FAQ](https://www.f5.com/go/faq/nginx-faq)
- Cloudflare는 개인/소규모 사용자를 무료 또는 낮은 가격으로 흡수하고, Business/Contract/Zero Trust/SASE 쪽에서 과금한다. Zero Trust도 무료 tier와 사용자 단위 paid tier가 있다. [Cloudflare Plans](https://www.cloudflare.com/plans/)
- Pangolin 계열은 self-hosted reverse proxy/access 제품에서 open-source adoption을 만들고, managed hosting 또는 supporter/enterprise 성격으로 수익화를 시도한다. [Pangolin Supporter Program](https://docs.pangolin.net/self-host/supporter-program)

시사점:

- 시장은 free/open-source entry를 기대한다.
- self-hosted 사용자는 요청 수 기반 과금을 싫어한다.
- 기업은 SSO, RBAC, audit, policy, support, multi-node에는 돈을 낸다.
- 가격을 공개하지 않는 enterprise custom pricing은 흔하지만, 초기 제품은 투명한 self-serve 가격이 adoption에 유리하다.

### 15.3 유료화 원칙

유료화 원칙:

1. 기본 안전성은 무료다.
2. 개인/홈랩/소규모 단일 서버는 무료로 충분히 쓸 수 있어야 한다.
3. 팀 협업부터 유료화한다.
4. 여러 노드, 여러 환경, 여러 팀을 관리하는 순간 유료화한다.
5. 규제/감사/SSO/지원은 유료화한다.
6. self-hosted 제품은 트래픽 과금보다 노드/팀/기능 과금이 낫다.
7. managed SaaS 또는 managed hosting에서는 사용량 과금이 가능하다.

유료로 잠그면 안 되는 것:

- HTTP reverse proxy
- HTTPS reverse proxy
- Let's Encrypt HTTP-01
- 기본 certificate renewal
- config validation
- config rollback
- 단일 관리자 로그인
- 단일 노드 Admin Web UI
- access log 기본 조회
- 보안 헤더 기본값
- basic health status

이 기능들은 제품 신뢰의 기본이다. 여기를 잠그면 사용자는 그냥 Caddy, NGINX Proxy Manager, Traefik으로 간다.

유료화하기 좋은 것:

- multi-user
- RBAC
- SSO/OIDC/SAML
- audit log 장기 보관
- approval workflow
- team/project 분리
- multi-node management
- cluster dashboard
- GitOps integration
- backup automation
- advanced notification
- advanced metrics retention
- distributed Let's Encrypt
- distributed rate limiting
- advanced access policy
- private support
- air-gapped/offline license
- compliance report
- managed control plane
- managed hosting

### 15.4 권장 제품 에디션

#### 15.4.1 Community Edition

가격:

- 무료
- open source
- self-hosted

대상:

- 개인
- 홈랩
- 소규모 단일 서버
- 개발/테스트 환경
- 초기 adoption 사용자

포함 기능:

- Rust/mio core proxy
- HTTP/HTTPS reverse proxy
- HTTP/1.1
- WebSocket
- 단일 노드 Admin Web UI
- 단일 관리자 계정
- Let's Encrypt HTTP-01
- 수동 인증서 등록
- config validation
- config diff
- config apply
- config rollback
- proxy host CRUD
- 단일 upstream
- round-robin 기본
- basic health status
- product/field/dev 로그 모드
- 최근 access log
- Docker Compose 배포

제한:

- 공식 SLA 없음
- 커뮤니티 지원
- multi-user 없음
- RBAC 없음
- SSO 없음
- multi-node 없음
- audit log 장기 보관 없음
- 고급 정책 없음

중요:

- proxy host 수, domain 수, request 수를 인위적으로 제한하지 않는 것을 권장한다.
- 무료 사용자가 많아야 프로젝트 신뢰와 생태계가 생긴다.
- 제한은 규모보다 운영 조직 기능에 둔다.

#### 15.4.2 Pro Edition

권장 가격:

- self-hosted: 노드당 월 12-19달러
- 연간 결제: 노드당 연 120-190달러
- 또는 개인/소규모 팀용 flat license: 월 15-29달러

대상:

- 소규모 SaaS
- 에이전시
- 프리랜서 운영자
- 여러 고객 도메인을 관리하는 팀
- 홈랩보다 진지한 self-hosted 사용자

포함 기능:

- Community 전체
- DNS-01 challenge
- wildcard certificate
- 주요 DNS provider plugins
- automated backup
- restore UI
- notification: Slack, Discord, email, webhook
- log retention 설정
- access log 검색
- advanced health check
- multiple upstream
- weighted round-robin
- basic rate limit
- IP allow/deny
- basic auth
- forward auth
- Docker discovery
- config scheduled backup
- config export/import

왜 이 구성이 맞는가:

- Pro 사용자는 wildcard certificate, DNS provider, backup, notification에 명확한 가치를 느낀다.
- 그래도 core proxy와 기본 HTTPS는 무료라 adoption 장벽이 낮다.
- node 단위 과금은 self-hosted 인프라 비용과 연결되어 이해하기 쉽다.

주의:

- DNS-01을 Pro로 둘지 Community로 둘지는 민감하다.
- wildcard certificate를 많이 쓰는 홈랩 사용자는 반발할 수 있다.
- 초기 adoption이 중요하면 DNS-01 기본 provider 1-2개는 Community에 열고, enterprise DNS provider와 관리 기능을 Pro로 두는 절충도 가능하다.

#### 15.4.3 Team Edition

권장 가격:

- 팀당 월 49-99달러
- 포함 노드 3개
- 추가 노드 월 10-20달러
- 포함 사용자 5명
- 추가 사용자 월 5-10달러

대상:

- 소규모 회사
- 내부 도구를 여러 사람이 운영하는 팀
- 에이전시
- DevOps가 1-3명 있는 조직

포함 기능:

- Pro 전체
- multi-user
- RBAC
- team/project 분리
- audit log
- approval workflow
- config change comment
- change history 검색
- rollback 권한 분리
- admin activity log
- SSO/OIDC
- GitOps sync
- Git backup
- staging/production environment 분리
- route ownership
- support: email, 2-3 business days

왜 이 구성이 맞는가:

- 팀이 생기는 순간 "누가 무엇을 바꿨는가"가 돈을 낼 이유가 된다.
- RBAC, SSO, audit은 기업 구매자가 명확히 이해하는 유료 가치다.
- 기능이 core data plane보다 control plane에 있으므로 open-core 반발이 적다.

#### 15.4.4 Business Edition

권장 가격:

- 월 199-499달러
- 포함 노드 10개
- 추가 노드 월 15-30달러
- 연간 계약 권장

대상:

- 운영 중인 SaaS 회사
- 호스팅/에이전시
- 여러 환경을 가진 SMB
- 내부 서비스가 많은 회사

포함 기능:

- Team 전체
- multi-node dashboard
- centralized control plane
- node inventory
- node health
- distributed config sync
- distributed Let's Encrypt
- distributed rate limiting
- advanced metrics
- metrics retention
- alert rule
- Slack/PagerDuty webhook
- backup policy
- disaster recovery runbook
- private plugin registry
- priority email support

왜 이 구성이 맞는가:

- Business부터는 "서버 하나 편하게 관리"가 아니라 "운영 체계"를 구매한다.
- multi-node와 중앙 관리 기능은 명확히 유료화 가능하다.
- 이 단계부터 self-hosted control plane과 data plane의 분리가 중요해진다.

#### 15.4.5 Enterprise Edition

권장 가격:

- custom annual contract
- 시작 기준: 연 10,000-25,000달러 이상
- 대규모/규제 산업: 연 50,000달러 이상 가능

대상:

- regulated industry
- 대기업
- 금융/의료/공공
- air-gapped 환경
- mission-critical edge gateway

포함 기능:

- Business 전체
- SAML SSO
- SCIM
- advanced RBAC
- policy as code
- signed config bundle
- approval chain
- compliance report
- long-term audit retention
- air-gapped/offline license
- private build
- FIPS 검토 또는 FIPS-ready build 옵션
- custom plugin support
- private Slack/Teams support
- SLA
- security advisory
- migration support
- dedicated solution engineering

왜 이 구성이 맞는가:

- Enterprise 고객은 기능보다 책임과 지원을 산다.
- custom pricing은 deployment size, node 수, support level, compliance 요구에 따라 달라져야 한다.
- 공개 가격보다 sales-assisted pricing이 자연스럽다.

### 15.5 권장 과금 축

#### 15.5.1 self-hosted는 노드 기반 과금이 가장 단순하다

권장:

```text
billable unit = active proxy node
```

노드 기반 과금의 장점:

- 이해하기 쉽다.
- 인프라 규모와 가격이 대체로 비례한다.
- request 수를 수집하지 않아도 된다.
- privacy 우려가 작다.
- self-hosted 고객이 받아들이기 쉽다.

노드 정의:

- active data plane process
- 일정 기간 heartbeat 또는 license check-in을 보내는 core proxy
- standby node는 할인 또는 무료로 처리 가능

정책 예:

- Community: 1개 이상의 노드도 무료 가능
- Pro: 노드당 과금
- Team: 포함 노드 + 추가 노드
- Business: 포함 노드 + 추가 노드
- Enterprise: 계약 기준

#### 15.5.2 사용자 기반 과금은 Team 이상에서만 적용한다

사용자 기반 과금은 개인/홈랩에는 맞지 않는다. Team 이상에서 RBAC/SSO/audit과 묶을 때만 자연스럽다.

권장:

```text
Community: 1 admin user
Pro: 1-2 admin users
Team: included 5 users, extra user paid
Business: included 20 users, extra user paid
Enterprise: custom
```

#### 15.5.3 request 기반 과금은 self-hosted에서는 피한다

self-hosted에서 request 기반 과금은 권장하지 않는다.

이유:

- 사용자가 트래픽 측정을 불신할 수 있다.
- telemetry/privacy 논란이 생긴다.
- 고트래픽 단순 reverse proxy 고객에게 비용 예측성이 나빠진다.
- NGINX/Caddy/HAProxy 무료 대안과 비교해 불리하다.

request 기반 과금이 가능한 경우:

- managed control plane analytics
- hosted/managed gateway
- API monetization 기능
- AI Gateway token/cost analytics

즉, self-hosted proxy 자체는 node/user/feature로 과금하고, SaaS 부가 기능은 usage-based를 선택적으로 붙인다.

#### 15.5.4 기능 기반 add-on

Add-on으로 둘 수 있는 것:

- Advanced Security Pack
- AI Gateway Pack
- Compliance Pack
- Managed Backup Pack
- Premium DNS Provider Pack
- Request Debugger Pack
- Long-term Analytics Pack

단, 초기에는 add-on을 너무 많이 만들지 않는다. 가격표가 복잡하면 구매가 늦어진다.

### 15.6 어떤 기능을 무료로 둘지

무료 기능은 adoption을 만든다. 다음은 무료로 두는 것을 강하게 권장한다.

#### Core proxy

- HTTP reverse proxy
- HTTPS reverse proxy
- WebSocket
- Host/path route
- single upstream
- basic round-robin
- HTTP to HTTPS redirect

이유:

- 제품의 기본 가치다.
- 무료 대안이 너무 강하다.
- 여기서 제한하면 사용자가 테스트조차 하지 않는다.

#### Automatic HTTPS 기본

- Let's Encrypt HTTP-01
- certificate renewal
- certificate status

이유:

- Caddy가 이미 automatic HTTPS를 무료로 제공한다.
- 이 프로젝트의 기본 약속이다.
- HTTPS를 유료로 잠그면 시장 포지션이 약해진다.

#### Safe config lifecycle

- validation
- diff
- apply
- rollback
- revision 기본 저장

이유:

- 제품 차별화의 핵심이다.
- 안전 기능을 유료화하면 무료 사용자가 위험해진다.
- 오픈소스 평판에 좋지 않다.

#### 단일 노드 Admin Web UI

- proxy host CRUD
- certificate 상태
- logs 기본 조회
- settings 기본

이유:

- 이 프로젝트는 웹 콘솔이 중요한 제품이다.
- UI를 유료화하면 NGINX Proxy Manager와 경쟁하기 어렵다.

### 15.7 어떤 기능을 유료로 둘지

#### Team operations

유료화 우선순위가 가장 높다.

- multi-user
- RBAC
- SSO/OIDC/SAML
- audit log
- approval workflow
- team/project separation
- change request
- config review

구매 이유:

- 회사는 협업과 책임 추적에 돈을 낸다.
- 보안팀/감사팀이 요구한다.
- 개인 사용자는 없어도 된다.

#### Multi-node operations

유료화 가치가 높다.

- node inventory
- cluster dashboard
- remote node registration
- centralized config push
- distributed certificate state
- distributed rate limit
- blue/green config rollout
- canary config rollout

구매 이유:

- 단일 서버를 넘어서면 운영 복잡도가 급격히 증가한다.
- 기존 무료 도구만으로는 통합 관리가 어렵다.

#### Advanced observability

유료화 가능:

- long-term metrics retention
- log search
- request debugger
- per-route latency heatmap
- anomaly detection
- alert rules
- external sink integrations

무료로 둘 것:

- 기본 access log
- 기본 metrics
- 최근 로그

구매 이유:

- 장애 분석과 운영 시간을 줄인다.

#### Advanced security

유료화 가능:

- OIDC access policy
- SAML
- SCIM
- mTLS client auth management
- policy as code
- signed config
- compliance report
- advanced rate limiting
- bot/abuse protection

무료로 둘 것:

- secure headers
- basic auth
- IP allow/deny 기본
- admin secure defaults

주의:

- 기본 보안을 유료로 잠그면 안 된다.
- 규제/조직/고급 통합이 필요한 기능을 유료화한다.

#### Managed service

유료화 강함:

- hosted control plane
- managed backup
- managed updates
- managed monitoring
- managed Pangolin-like tunnel/edge node
- support SLA

구매 이유:

- 운영 부담을 줄인다.
- self-hosted 제품의 낮은 ARPU를 보완한다.

### 15.8 권장 가격표 초안

초기 공개 가격표 예시:

| Plan       | 가격                               | 대상            | 포함                                                                          |
| ---------- | -------------------------------- | ------------- | --------------------------------------------------------------------------- |
| Community  | $0                               | 개인, 홈랩, 단일 서버 | core proxy, Admin UI, HTTP-01, validation, rollback                         |
| Pro        | $15/node/month 또는 $150/node/year | 소규모 운영자, 에이전시 | DNS-01, wildcard, backup, notifications, Docker discovery, basic rate limit |
| Team       | $79/month 포함 3 nodes, 5 users    | 소규모 회사        | Pro + multi-user, RBAC, OIDC, audit, approval workflow                      |
| Business   | $299/month 포함 10 nodes, 20 users | 운영팀, SMB      | Team + multi-node, central dashboard, advanced metrics, alerting            |
| Enterprise | Custom, 연 $10k+                  | 대기업, 규제 산업    | Business + SAML/SCIM, compliance, air-gap, SLA, private support             |

가격은 초기에는 낮게 시작하는 편이 낫다. 이유는 제품 신뢰와 reference가 아직 없기 때문이다. 대신 Business/Enterprise에서 지원과 운영 기능으로 ARPU를 올린다.

초기 1년 권장:

- Community를 강하게 밀어 adoption을 만든다.
- Pro는 낮은 가격으로 early supporter 역할을 하게 한다.
- Team부터 본격적인 수익 모델로 본다.
- Enterprise는 기능이 충분해지기 전까지 "design partner" 또는 "private beta"로 받는다.

### 15.9 라이선스 전략

권장 라이선스:

- Core: Apache-2.0 또는 MPL-2.0
- Community Admin UI: Apache-2.0 또는 MPL-2.0
- Pro/Team/Business plugins: commercial license
- Enterprise control plane: commercial license

라이선스 선택 판단:

- Apache-2.0은 adoption과 기업 사용에 유리하다.
- MPL-2.0은 수정 공개 의무가 파일 단위라 open-core 보호에 조금 더 유리하다.
- AGPL은 SaaS 우회를 막는 데 유리하지만, 기업 adoption을 막을 수 있다.
- BSL은 상업적 보호에 유리하지만 초기 커뮤니티 신뢰를 떨어뜨릴 수 있다.

이 프로젝트의 초기 목표가 adoption이라면 Apache-2.0 또는 MPL-2.0을 권장한다. 단, 유료 플러그인과 control plane은 별도 commercial license로 둔다.

### 15.10 가격 정책에서 피해야 할 것

피해야 할 정책:

- proxy host 수 제한
- domain 수 제한
- request 수 제한
- Let's Encrypt 기본 기능 유료화
- rollback 유료화
- 단일 노드 UI 유료화
- local backup 완전 유료화
- 보안 기본값 유료화

이런 제한은 사용자가 제품을 "신뢰 가능한 인프라 도구"가 아니라 "제약 많은 SaaS"로 보게 만든다.

특히 request 수 제한은 self-hosted reverse proxy와 맞지 않는다. 사용자는 자기 서버에서 자기 트래픽을 처리하는데 왜 요청 수로 돈을 내야 하는지 납득하기 어렵다.

### 15.11 추천 go-to-market

#### 1단계: 무료 Community로 신뢰 확보

목표:

- GitHub stars
- Docker pulls
- 홈랩/개발자 adoption
- NGINX Proxy Manager/Caddy 대체 사용 사례

핵심 메시지:

- Rust로 만든 안전한 reverse proxy manager
- NGINX 설정 없이 자동 HTTPS
- 잘못된 설정도 rollback 가능

#### 2단계: Pro로 early revenue

목표:

- wildcard certificate
- DNS-01
- backup
- notification
- Docker discovery
- 소규모 운영자 과금

핵심 메시지:

- 운영 시간을 줄이는 self-hosted proxy manager
- 도메인과 인증서 관리 자동화

#### 3단계: Team/Business로 B2B 전환

목표:

- RBAC
- SSO
- audit
- approval
- multi-node

핵심 메시지:

- 팀이 안전하게 변경할 수 있는 edge gateway control plane
- 누가 무엇을 바꿨는지 추적 가능한 proxy 운영

#### 4단계: Enterprise

목표:

- compliance
- air-gap
- SAML/SCIM
- SLA
- private support

핵심 메시지:

- self-hosted, auditable, memory-safe edge gateway
- 기업 내부망과 규제 환경에 맞는 NGINX/Traefik 대체 운영 플랫폼

### 15.12 최종 추천

최종 추천은 다음이다.

```text
무료:
  Rust core
  단일 노드 Admin Web UI
  기본 reverse proxy
  Let's Encrypt HTTP-01
  config validation/diff/apply/rollback

저가 유료:
  DNS-01
  wildcard certificate
  backup/restore 자동화
  notification
  Docker discovery

팀 유료:
  multi-user
  RBAC
  OIDC/SSO
  audit log
  approval workflow

고가 유료:
  multi-node
  centralized control plane
  distributed certificate/rate limit
  advanced observability
  compliance
  enterprise support
```

가장 좋은 초기 가격 구조:

```text
Community: Free
Pro: $15/node/month
Team: $79/month, includes 3 nodes and 5 users
Business: $299/month, includes 10 nodes and 20 users
Enterprise: Custom annual, starts around $10k/year
```

이 구조는 무료 대안과 경쟁하면서도, 실제 돈을 내는 조직의 구매 이유를 분명히 만든다. 핵심은 기능을 인질로 잡는 것이 아니라, 운영 규모와 조직 복잡도가 커질수록 자연스럽게 유료 플랜이 필요해지도록 만드는 것이다.

## 16. 제품 차별화 문장

초기 마케팅 문장 후보:

- Rust-native reverse proxy manager with automatic HTTPS.
- Headless-first Caddy and Traefik alternative for self-hosted teams.
- A memory-safe edge gateway with optional web admin, safe config reloads, and Let's Encrypt automation.
- NGINX simplicity for operators, HAProxy-style health checks, Traefik-style dynamic routing, Caddy-style HTTPS automation.

한국어 문장 후보:

- Rust로 만든 안전한 리버스 프록시 관리 솔루션.
- NGINX 설정 없이 도메인, SSL, upstream을 웹 UI에서 안전하게 관리한다.
- Caddy처럼 HTTPS는 자동으로, Traefik처럼 서비스는 동적으로, HAProxy처럼 장애에는 강하게.

## 17. 최종 정리

이 프로젝트는 시장에 이미 존재하는 reverse proxy들을 정면으로 대체하려고 하면 어렵다. 하지만 다음 조합으로 접근하면 충분히 가능성이 있다.

- Rust core로 안전성과 현대성을 제공한다.
- Admin Web UI는 선택형 plugin/control plane으로 분리한다.
- 초기 MVP는 간단한 NGINX 대체에 집중한다.
- 자동 HTTPS와 config validation/rollback을 핵심 가치로 둔다.
- 이후 HAProxy식 load balancing, Traefik식 discovery, Caddy식 HTTPS 자동화, NGINX식 static/proxy/cache 기능을 단계적으로 붙인다.

가장 중요한 성공 조건은 기능 개수가 아니다.

1. 설정을 잘못해도 운영 트래픽이 깨지지 않아야 한다.
2. 인증서 발급/갱신이 조용히 안정적으로 동작해야 한다.
3. 웹 UI가 편해야 하지만 core는 UI 없이도 신뢰성 있게 운영되어야 한다.
4. 초기에는 작게 시작하되, config model과 Admin API는 장기 확장을 버틸 수 있어야 한다.

## 18. Phase 011 메모리 증거 매니페스트 상태

Task 048은 제품 data plane을 변경하지 않고 `edge-memory-harness` 바깥 어댑터에
`phase011-steady-v1` 매니페스트 계약을 추가했다. 고정 프로필은 plaintext HTTP 100,000건,
private-PKI HTTPS 50,000건, required-mTLS 25,000건의 세 시나리오다. 각 항목은 canonical RSS
보고서와 다이제스트, driver summary, terminal summary를 결합하며 요청/실패/worker 수, TLS
negative 수, upstream 전달 수, peak RSS, Admin 최대 resource 값, 종료 시 0 connection/0
payload/normal pressure와 recovery 200을 교차 검증한다.

`scripts/collect_memory_evidence_manifest.sh`는 정확한 12개 일반 파일만 읽는다. unknown path,
symlink, stale source identity, report 또는 summary 변조, 384 MiB 초과, cleanup 실패는 게시 전에
거부된다. 별도 `validate` process가 원본 파일을 다시 대조한다. 릴리스 수집기는 두 매니페스트
파일을 명시적으로 함께 제공한 경우에만 `memory_manifest_status=partial`로 결합한다.

현재 계약은 의도적으로 `approved`를 허용하지 않는다. macOS arm64 한 번의 steady 결과는
`partial`이며 Linux x86_64, 세 번의 독립 반복, long-soak/deep-diagnostic가 차단 사유다. 이는
불완전한 증거를 완료로 표시하지 않게 만들었을 뿐 Phase 011 전체 승인을 의미하지 않는다.

steady test upstream은 요청마다 thread를 생성하지 않고 고정 128 worker가 공용 accept socket을
처리한다. 기존 fixture에서 100,000건 중 51건과 23건이 유실된 재현 결과를 근거로 테스트
인프라만 bounded하게 변경했으며 제품 proxy의 요청 수, 동시성, 임계값은 완화하지 않았다.

## 19. Phase 011 3회 반복 메모리 집계 계약

Task 049는 `phase011-steady-v1` 단일 실행을 정확히 세 번 독립 수행한 결과를
`phase011-steady-3run-v1` canonical aggregate로 결합한다. 각 실행은 `run-001`부터
`run-003`까지 고정된 디렉터리와 새 proxy/config/certificate/process를 사용한다. 집계기는 세
child manifest를 원본 12개 파일과 다시 대조하고, source/build/profile/platform/architecture가
모두 같은지 검사한다. 새 포트와 임시 경로를 쓰는 각 실행의 config digest는 서로 다른 것이
정상이며 각 child manifest 안에서 원본 config-bound report와 검증한다. 보고서의 원시 process
identity는 게시하지 않고 run별 SHA-256 fingerprint만 보존하며 세 fingerprint의 중복을 거부한다.

scenario별 peak RSS와 cooldown RSS의 최솟값과 최댓값은 고정 384 MiB ceiling을 다시 통과해야
한다. 임시 재현성 허용 폭은 `max(16 MiB, 최소 peak의 10%)`이며 peak와 cooldown 모두 이 범위
안에 있어야 한다. correctness 실패, cleanup 실패, duplicate/missing/mixed/tampered input,
symlink, unknown path는 output 교체 전에 실패한다. `collect`, 원본 재대조 `validate`, canonical
bundle `inspect`는 별도 process로 실행된다.

`scripts/run_three_steady_memory_profiles.sh`가 세 실행과 child manifest, aggregate를 닫힌 순서로
생성한다. 실행 중 source identity 변경은 허용되지 않는다. 이 결과도 `partial`이다. 세 번의
macOS 반복 차단 사유는 제거하지만 Linux x86_64, 전체 Phase 011 scenario profile,
long-soak/deep-diagnostic가 남으므로 메모리 전체 승인이나 누수 부재를 주장하지 않는다.

## 20. Phase 011 canonical slow request capacity

Task 035/036의 slow-header 64와 slow-body 32 결과는 초기 characterization으로 보존한다. 현재
canonical capacity contract `phase011-slow-request-capacity-v1`은 partial header 256 connection과
partial body 128 connection을 고정한다. slow body는 connection마다 65,536 bytes를 선언하고
32,768 bytes를 전송하므로 hold 중 최소 logical payload는 4,194,304 bytes다.

`scripts/smoke_slow_header_memory.sh`와 `scripts/smoke_slow_body_memory.sh`는 이 count를 낮추는 CLI
override 없이 release proxy에 실행한다. hold 중 정상 요청 200, source/config/process identity,
RSS ceiling, exact timeout terminal, final active/payload 0을 모두 검증한다. 이 capacity 결과는
slow-body 5-cycle plateau, slow-response cycle, Linux, long soak 또는 deep diagnostic 완료를
의미하지 않는다.

## 21. Phase 011 slow-body same-process plateau

Task 052는 한 release proxy process에서 canonical slow-body 128 load, timeout cleanup과 cooldown을
세 번 반복해 same-process repeatability와 cycle별 cleanup을 먼저 검증했다. Task 053의 canonical
contract는 동일 load/cooldown을 정확히 다섯 번 반복한다. cycle마다 128/128 terminal, 최소
4,194,304-byte held payload, recovery 200, final 0 connection/0 payload/normal pressure와 512 MiB
ceiling을 요구한다.

plateau 기준은 첫 2개 cooldown RSS의 median과 마지막 2개 cooldown RSS의 median을 비교한다.
마지막 median은 첫 median보다 `max(16 MiB, 첫 median의 10%)`를 초과해 증가할 수 없다. process
identity가 cycle 사이에 바뀌거나 한 cycle이라도 실패하면 canonical report를 게시하지 않는다.
이 five-cycle 결과도 slow-response/WebSocket cycle, 2-hour soak, Linux 또는 deep diagnostic을
대신하지 않는다.

## 22. Phase 011 slow-response same-process plateau

Task 054는 한 release proxy와 threaded test upstream을 유지한 채 response header만 읽는
128개 client의 hold/release/cooldown을 정확히 다섯 번 반복한다. 각 cycle은 held/released
128/128, failed 0, 최소 8,388,608-byte logical payload, final 0/0/normal과 recovery 200을
요구한다. 모든 peak는 512 MiB 이하여야 한다.

plateau는 cooldown cycle 1~2 median과 4~5 median을 비교하며 허용 증가는
`max(16 MiB, first median의 10%)`다. count, minimum payload, ceiling과 tolerance는 test source에
고정하고 runtime/CLI override를 제공하지 않는다. report는 process identity를 hash로만 포함하며
PID, temporary path, request content와 secret을 게시하지 않는다.

Task 054 전체 회귀 중 payload-pressure listener test가 nonblocking client connect 직후 accept를
한 번만 호출해 간헐적으로 rejection metric을 관찰하지 못하는 테스트 레이스가 재현됐다. 제품
admission 동작은 바꾸지 않고 테스트가 최대 1초 동안 accept readiness와 metric을 기다리게 했으며,
동일 test 10회 반복으로 안정성을 확인한다.

## 23. Phase 011 WebSocket same-process plateau

Task 055는 한 release proxy와 bounded flood WebSocket upstream을 유지한 채 128 tunnel의
upgrade/echo/hold/release/cooldown warm-up 1회 후 측정 cycle을 정확히 다섯 번 반복한다. warm-up을
포함한 각 cycle은 upgraded/echoed/held/
released 128, failed 0, 최소 8,388,608-byte logical tunnel payload, final 0/0/normal과 recovery
200을 요구한다. 모든 peak는 384 MiB 이하여야 한다.

plateau는 cooldown cycle 1~2 median과 4~5 median을 비교하고 허용 증가는
`max(16 MiB, first median의 10%)`다. count, payload floor, ceiling과 tolerance는 source에
고정한다. canonical report는 process identity hash만 게시하며 PID, temp path, frame/request
content와 secret을 포함하지 않는다.

## 24. Phase 011 full-profile readiness gate

Task 056은 `idle`, `http-steady`, `http-idle-1024`, `slow-header`, `slow-body`, `slow-response`,
`connection-churn`, `https-steady`, `https-idle-512`, `mtls-steady`, `websocket-128`, `control-max`
12개를 canonical allowlist로 고정한다. steady는 three-run, slow/churn/WebSocket은 warm-up 이후
five-cycle, 나머지는 single-run evidence kind를 요구한다.

각 entry는 explicit source identity, evidence kind, report digest와 기존 validator 통과 결과를
가져야 한다. 누락은 `missing`, source 불일치는 `stale`, kind/validator 실패는 `failed` blocker다.
모든 entry가 current source에서 verified일 때만 readiness가 true다. 이 gate는 과거 report의 source
identity를 바꾸거나 validator를 대신하지 않으며, Linux, long soak와 deep diagnostic은 별도 최종
승인 조건으로 유지한다.

## 25. Phase 011 slow-header same-process plateau

Task 057은 한 release proxy와 upstream process를 유지하면서 partial-header 256 connection을
warm-up 1회 실행한 후 measured cycle을 정확히 다섯 번 반복한다. warm-up과 각 measured cycle은
expected/succeeded 256, failed 0, 최소 10,496-byte logical payload, hold 중 healthy request 200,
timeout terminal, final 0 connection/0 payload/normal pressure와 recovery 200을 요구한다. 모든
measured peak는 macOS candidate ceiling 384 MiB 이하여야 한다.

plateau는 measured cooldown cycle 1~2 median과 4~5 median을 비교하며 허용 증가는
`max(16 MiB, first median의 10%)`다. cycle 수, count, payload floor, ceiling과 tolerance는
test source에 고정하고 runtime override를 제공하지 않는다. canonical aggregate는 같은
source/config/process identity와 모든 cycle invariant가 통과한 뒤에만 atomic publish한다. 이
증적은 full-profile의 slow-header evidence-kind 요구만 충족하며 다른 stale scenario, Linux,
2-hour soak 또는 deep diagnostic을 대신하지 않는다.

## 26. Phase 011 full-profile execution runner

Task 058은 수동으로 작성한 `validation_passed=true`를 최종 승인 근거로 사용하지 않도록
full-profile 실행 경계를 고정한다. typed registry는 임의 command가 아니라 source-controlled
10개 job만 허용한다. steady job 하나가 HTTP/HTTPS/required-mTLS 세 scenario를 제공하므로 총
12개 scenario를 정확히 한 번 덮는다. registry test는 누락, 중복과 unknown scenario를 거부한다.

`scripts/run_full_memory_profile.sh <new-output-root>`는 source identity를 시작 시 한 번 계산하고
`edge-full-profile-runner`에 명시적으로 전달한다. runner는 각 fixed smoke를 별도 process로 실행해
exit 0을 확인한 뒤, 고정 상대 경로의 physical report/digest, SHA-256과 report build identity를
다시 검사한다. 한 job이라도 실패, stale, missing, symlink 또는 tampered이면 즉시 terminal
failure이며 inventory/readiness를 게시하지 않는다. 모든 job 검증 후에만 ordered 12-entry
inventory와 `ready=true` readiness report/digest를 atomic publish한다. wrapper는 종료 전 source
identity가 바뀌지 않았는지 다시 검사한다.

runner 통과는 현재 host의 full macOS 또는 Linux scenario profile 증거다. 한 platform 결과를 다른
platform 결과로 해석하지 않으며 2-hour soak와 deep diagnostic도 별도 승인 조건이다.

## 27. Phase 011 two-hour diagnostic soak contract

Task 060은 long-soak 결과를 단순 경과 시간이나 process 생존 여부만으로 판정하지 않는다.
`phase011-diagnostic-soak-2h-v1`은 baseline 0초와 60초 간격 120개 workload window, 총 121개
observation과 exact 7,200초를 요구한다. odd window는 HTTP churn 1,000/1,000/0, even window는
WebSocket lifecycle 128/128/0이며 각각 60회다. 모든 window는 같은 source/config/process identity,
process alive, cleanup 0/0/normal과 recovery 200을 가져야 한다.

각 RSS는 양수이고 macOS candidate 384 MiB 이하여야 한다. 첫 5개와 마지막 5개 RSS median의
허용 증가는 `max(16 MiB, first median의 10%)`다. report는 raw process identity를 SHA-256으로만
게시하며 strict `edge-diagnostic-soak collect|validate`가 exact duration/order/workload,
correctness, cleanup, ceiling, plateau, canonical encoding, digest와 source identity를 검증한다.
fake clock과 short fixture test는 evaluator 검증일 뿐 실제 wall-clock 2-hour evidence가 아니다.

## 28. Phase 011 same-process soak window boundary

Task 061은 long-soak orchestration이 product core나 shell 내부 상태를 직접 조작하지 않도록 한
window의 실행 경계를 분리한다. pure `SoakWindowRunner`는 index/elapsed와 시작 시 받은 immutable
source/config/process identity를 입력으로 받고, load/process/runtime port만 호출한다. index 0은
baseline, odd index는 churn 1,000, even index는 WebSocket 128로만 변환된다. 공개 production
adapter의 수량은 runtime argument로 완화할 수 없다.

window는 `Created -> Loading -> Verifying -> Completed|Failed` 상태로 진행한다. load exact count,
실행 전후 process liveness/identity, 양수 RSS, Admin active connection 0, charged payload 0, normal
pressure와 recovery 200 중 하나라도 실패하면 observation을 만들지 않는다. HTTP adapter는 기존
`HttpLoadDriver`의 warm/load/cool을 사용하고 WebSocket adapter는 upgrade와 frame echo를 검증한
session을 명시적으로 닫는다. process/Admin/network 접근은 `soak_window_adapters`에만 있다.

fake port test와 기존 current-source WebSocket product smoke는 경계 동작을 검증할 뿐 실제 proxy를
7,200초 유지한 evidence가 아니다. 다음 orchestration은 하나의 release
proxy/config/process identity를 유지하고 이 경계를 정확히 120회 호출한 뒤 Task 060 canonical
collector에 전달해야 한다.

## 29. Phase 011 fixed wall-clock soak orchestration

Task 062는 one-window 경계를 `Created -> Baseline -> Running(1..120) -> Analyzing ->
Published|Failed` orchestration으로 연결한다. pure runner는 schedule port가 각 target deadline까지
기다린 뒤 반환한 monotonic elapsed가 target보다 이르지 않고 5초보다 늦지 않은지 확인한다.
baseline 0부터 7,200초까지 121개 target은 source에 고정되며 missed, duplicate, child failure 또는
runner 재사용은 terminal failure다. `Instant`와 sleep은 system adapter에만 있다.

`edge-diagnostic-soak-runner`는 PID, proxy/Admin address, host, expected revision,
source/config identity와 새 output pair만 받는다. duration, interval, window count, churn count,
WebSocket count, ceiling과 tolerance option은 없다. attached process와 config identity는 시작 시 한
번 고정하고, 모든 window 통과 후 Task 060 evaluator가 승인한 canonical report/digest만 atomic
publish한다.

`scripts/run_diagnostic_soak.sh NEW_OUTPUT_ROOT`는 하나의 bounded dual HTTP/WebSocket test
upstream과 하나의 release proxy를 시작해 fixed runner를 실행하고 별도 `edge-diagnostic-soak
validate` process로 결과를 재검증한다. output root는 실행 전에 없어야 하고 source identity 변경,
child failure와 민감 field scan 실패는 success를 게시하지 않는다. 이 task는 실행기를 구현한
범위를 기록한다. 이후 실제 실행의 유효성은 문서의 고정 문구가 아니라 아래 최종 결합기가 현재
source identity와 report digest를 다시 검증해 판정한다.

## 30. Phase 011 최종 메모리 릴리스 결합

Task 065는 full-profile inventory/readiness와 실제 2시간 diagnostic soak를 하나의
`phase011-memory-release-v1` 보고서로 결합한다. `edge-phase011-memory-release`의 pure evaluator는
full profile 12개 scenario를 원본 inventory에서 다시 평가하고 `ready=true`, blocker 0을 요구한다.
soak는 canonical validator를 다시 통과해야 하며 정확히 7,200초, 121개 observation, correctness와
cleanup 실패 0, RSS ceiling 및 plateau 통과를 요구한다. 두 증적의 source identity, platform,
architecture가 실행 시 현재 값과 다르면 게시하지 않는다.

상태 전이는 `Created -> InputsVerified -> ReportsValidated -> Bound -> Published|Failed`다. CLI와
shell은 filesystem, digest, process 실행을 담당하는 test/release adapter이고 제품 domain,
application, core 및 mio event loop는 이 결합기를 import하지 않는다. profile 수량과 threshold는
source-controlled이며 환경 변수나 실행 인자로 완화할 수 없다. 모든 입력이 검증된 뒤에만 다음
마커가 canonical report와 transcript에 포함된다.

```text
phase 011 quantitative memory and resource safety passed
```

`scripts/collect_phase011_memory_release.sh`는 명시적으로 지정된 full-profile root와 soak
report/digest를 새 output root에 정확히 9개 파일로 복사한다. 독립
`scripts/check_phase011_memory_release.sh`는 unknown path와 symlink를 거부하고 세 입력 digest를
다시 계산하며 결합 report를 원본에서 재생성해 byte-for-byte 비교한다. stale source, 다른
platform/architecture, non-ready 또는 tampered report, 짧은 soak, marker 누락, raw PID, 임시 경로,
credential 관련 field는 모두 실패다. `.tasks`, `artifacts`, 모든 `target`과 `node_modules`
디렉터리는 source identity에서 제외되어 계획 문서와 생성 산출물이 증거 대상을 순환 변경하지
않는다.

이 마커는 해당 platform/architecture의 정량 profile과 soak가 current source에서 통과했다는
뜻이다. Linux x86_64 지원 증적이나 platform deep diagnostic을 자동으로 대신하지 않으며, 두
항목의 완료 여부는 별도 릴리스 blocker로 유지한다.

## 31. Phase 011 macOS 심층 누수 진단

Task 068은 macOS `/usr/bin/leaks`가 일반 ad-hoc release process에 attach할 수 없던 원인을
제품 결함과 분리했다. 제품 release binary는 그대로 두고 진단용 임시 사본에만
`com.apple.security.get-task-allow=true` entitlement를 부여하면 현재 사용자 세션에서 live PID
attach가 가능하다. 이 방식은 SIP, sudo, 시스템 보안 정책 또는 배포 artifact를 변경하지 않는다.
fixture 검증에서 누수 없음은 exit 0과 `0 leaks for 0 total leaked bytes`, 의도적 누수는 exit 1과
양수 leak count/bytes로 구분됐다.

Task 069의 `edge-macos-leaks-evidence`는 bounded raw output에서 summary 한 줄만 strict parse한다.
missing, duplicate, malformed, overflow, task-port/권한 실패, nonzero leak, workload/cleanup 실패,
source 또는 digest 불일치는 모두 승인 전에 거부한다. 상태는 `Created -> InputsVerified -> Parsed
-> Validated -> Published|Failed`이고 제품 domain/application/core는 이 test/release model을
import하지 않는다.

실제 실행은 새 output root를 사용한다.

```bash
./scripts/run_macos_leaks_diagnostic.sh \
  artifacts/memory-evidence/phase011-macos-leaks-arm64
./scripts/check_macos_leaks_diagnostic.sh \
  artifacts/memory-evidence/phase011-macos-leaks-arm64
```

runner는 현재 release proxy digest를 고정한 뒤 임시 사본만 서명하고, loopback HTTP 1,000건,
Admin cleanup 0 connection/0 payload/normal pressure와 recovery 200을 확인한 동일 process에
`leaks --quiet --nostacks --noContent`를 실행한다. 공개 report는 source, 원본/서명 사본/config/
process identity의 SHA-256과 판정값만 보존한다. PID, 주소, stack, 임시 경로를 포함할 수 있는
`macos-leaks.raw`는 mode 0600, evidence root는 0700이며 공개 요약과 분리한다. checker는 정확히
5개 파일 allowlist, 현재 source와 원본 release binary digest, raw/report digest와 canonical report,
0 leak/0 bytes 및 성공 marker를 독립 재검증한다.

이 증거는 해당 macOS architecture와 정확한 source에서 definite leak가 검출되지 않았다는
reference diagnostic이다. 모든 heap leak 부재의 수학적 증명, Linux 결과, Instruments 결과 또는
RSS ceiling/plateau를 대신하지 않는다. 진단 코드가 변경되면 기존 Phase 011 정량 evidence도 stale이
되므로 같은 최종 source에서 full profile, 2시간 soak와 final binding을 다시 생성해야 한다.

## 32. Phase 011 Cross-Platform Completion

Phase 011의 최종 source는 다음 고정 검증을 모두 통과해야 완료다.

- macOS arm64와 native Linux x86_64에서 각각 full-profile jobs 10/10, scenarios 12/12,

  `ready=true`, blocker 0
- HTTP/HTTPS/mTLS steady, 1,024 HTTP idle, 512 private HTTPS idle, slow header/body/response,

  50,000 connection churn, 128 WebSocket와 control-plane maximum의 correctness/cleanup/ceiling
- 한 macOS arm64 release process에서 7,200초, 121 observations, HTTP churn 60,000,

  WebSocket lifecycle 7,680, correctness/cleanup failure 0과 RSS plateau
- macOS `/usr/bin/leaks` reference diagnostic에서 1,000/1,000 HTTP, cleanup 0/0/normal,

  recovery 200과 definite leak 0건/0 bytes
- exact 9-file final memory bundle, canonical digest, current source identity와 독립 checker marker

최종 증거는 `artifacts/memory-evidence/task073-full-linux-x86_64-r1`,
`artifacts/memory-evidence/task073-full-macos-arm64-r1`,
`artifacts/memory-evidence/task073-diagnostic-soak-macos-arm64-r1`,
`artifacts/memory-evidence/task073-macos-leaks-arm64-r1`과
`artifacts/memory-evidence/task073-phase011-memory-release-macos-arm64-r1`에 생성한다.

### 32.1 Accepted 2026-07-20 Checkpoint

| 검증 항목                            | 승인 결과                                                                                                                            |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Source identity                  | `source-tree-sha256:2c2bcbf580ed60fe18c330340236ecccf0936d7e5a2d18822e1c36f0fb970862`                                            |
| Native Linux x86_64 full profile | jobs 10/10, scenarios 12/12, ready=true, blocker 0, readiness `73cb85a4759b952969320651337106a854dc101c2c146e6f7f0468915a085f66` |
| macOS arm64 full profile         | jobs 10/10, scenarios 12/12, ready=true, blocker 0, readiness `79162c859929ace3c7d82828639d0a71b3948624ba4c54fb108ee476409853d4` |
| macOS fixed soak                 | 7,200초, 121 observations, HTTP churn 60,000, WebSocket lifecycle 7,680, correctness/cleanup failure 0                            |
| Soak RSS                         | peak 9,633,792 bytes, first/last median 9,043,968/9,011,200 bytes, plateau pass                                                  |
| macOS deep diagnostic            | HTTP 1,000/1,000/0, cleanup 0/0/normal, recovery 200, definite leak 0건/0 bytes                                                   |
| Final binding                    | exact 9 files, 12 scenarios, 121 soak observations, digest `78d453e0568c069e68c5e563535f2f2497ab42b80d765845a5568bacb7cbcf09`    |

Task 074는 이 최종 검증 중 발견된 WebSocket write buffer의 consumed history 보유를
`advance_and_clear_if_complete` 전이로 제거했다. Complete drain은 길이를 0으로 되돌리고 기존
capacity를 재사용하며, partial drain은 전송되지 않은 tail과 byte order를 보존한다. Task 075는
macOS endpoint security가 새 test binary의 최초 loopback 연결을 약 15초 지연하는 환경을
test fixture의 30초 상한으로만 흡수했다. 제품 timeout, memory ceiling, plateau tolerance와
allocator 설정은 변경하지 않았다.

위 값은 해당 checkpoint source와 명시된 OS/architecture/workload에 결합된 승인 결과다. 이
문서를 포함한 tracked file이 이후 변경되면 과거 artifact는 이력을 설명하는 증거로는 유효하지만,
변경된 tree의 신규 release 승인을 대신하지 않는다.

이 승인은 process RSS와 명시적으로 관리되는 logical owner의 고정 workload envelope를 의미한다.
모든 입력/트래픽/allocator에 대한 메모리 상한의 수학적 증명, 모든 종류의 heap leak 부재,
kernel socket memory 또는 장기 production traffic의 완전한 대체를 주장하지 않는다. 외부 Let's
Encrypt 검증은 여전히 Post-MVP이며 Phase 011 완료 범위에 포함하지 않는다.
