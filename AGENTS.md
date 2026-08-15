# AGENTS.md

프로젝트: Sponzey Edge Proxy  
목적: Rust/mio 기반 reverse proxy core와 선택형 Admin Web UI를 개발할 때 모든 사람과 자동화 에이전트가 따라야 하는 기본 작업 규칙

이 문서는 단순 코딩 스타일 문서가 아니다. 이 프로젝트의 설계, 구현, 테스트, 설정, 로그, 운영 안정성에 대한 최상위 규칙이다. 모든 코드 변경은 이 문서의 원칙을 먼저 만족해야 한다.

## 1. 절대 원칙

다음 규칙은 프로젝트 전체를 관통한다. 편의를 위해 우회하지 않는다.

### 1.1 Layered Architecture, Clean Architecture, Tidy First, TDD는 필수다

모든 기능은 다음 기준을 만족해야 한다.

- Layered Architecture를 따른다.
- Clean Architecture의 의존성 방향을 지킨다.
- Tidy First 원칙에 따라 구조 정리와 행동 변경을 분리한다.
- TDD를 기본 개발 방식으로 삼는다.

실제 의미:

- 도메인 모델은 외부 프레임워크, 네트워크, 파일 시스템, 데이터베이스, UI에 의존하면 안 된다.
- core business rule과 proxy policy는 테스트 가능한 순수 코드로 유지한다.
- mio event loop, socket, TLS, file store, Admin API, Web UI는 바깥 adapter다.
- 큰 기능을 만들기 전에 작게 실패하는 테스트를 먼저 만든다.
- 구조 개선과 기능 변경을 같은 커밋/변경 단위에 섞지 않는다.

### 1.2 외부 파일 설정은 최소화한다

외부 파일은 운영 편의와 복구 가능성을 위해 필요하지만, 설정이 파일에 과도하게 흩어져서는 안 된다.

원칙:

- canonical configuration은 하나의 명확한 config model로 관리한다.
- config file은 사람이 읽을 수 있는 선언적 표현일 뿐이다.
- 런타임 내부 상태는 여러 파일에 임의로 분산하지 않는다.
- 플러그인별 임의 설정 파일을 남발하지 않는다.
- UI에서 변경한 설정도 동일한 config revision model로 저장한다.

허용되는 외부 파일:

- primary config file
- config revision store
- certificate store
- key/secret store
- access/error/audit log
- backup archive

금지되는 패턴:

- 기능마다 별도 설정 파일을 자동 생성해 숨겨두는 방식
- core가 모르는 plugin private config에 운영 핵심 정책을 저장하는 방식
- 환경별 동작을 여러 파일명 convention으로 암묵 결정하는 방식
- 코드가 파일 존재 여부로 정책을 추론하는 방식

### 1.3 프로세스 중간에 환경 설정을 삽입해 변경하는 방법은 거부한다

실행 중인 프로세스의 환경 변수를 바꾸거나, 외부 환경 설정을 주입해서 동작을 바꾸는 방식은 허용하지 않는다.

금지:

- running process에 environment variable을 주입해 동작 변경
- signal handler에서 environment를 다시 읽어 config 변경
- plugin이 process environment를 수정하거나 의존
- request 처리 중 environment를 읽어 routing/policy 결정
- 테스트에서 global environment를 바꿔 병렬 테스트를 불안정하게 만드는 방식

허용:

- 프로세스 시작 시 environment를 한 번 읽는 bootstrap
- bootstrap 값을 명시적 argument/config object로 변환
- 이후 모든 계층에는 argument, typed config, dependency object로 전달
- 설정 변경은 Admin API 또는 config revision apply 경로만 사용

### 1.4 외부 환경 상수는 최초에만 받아들이고 이후에는 인자로만 전달한다

외부 환경 값은 프로그램 시작 시점에만 받아들인다. 그 이후에는 전역 상수처럼 읽지 않는다.

규칙:

- environment variable은 `main` 또는 bootstrap boundary에서만 읽는다.
- 읽은 값은 typed `BootstrapConfig` 또는 `RuntimeOptions`로 변환한다.
- 내부 모듈은 environment variable API를 직접 호출하지 않는다.
- 내부 모듈은 global mutable config를 읽지 않는다.
- 필요한 값은 함수 인자, 생성자 인자, trait object, immutable config snapshot으로 전달한다.

예:

```text
허용:
main
  -> read env once
  -> build BootstrapConfig
  -> build AppContext
  -> run(core, config_snapshot)

금지:
router.rs
  -> std::env::var("ROUTE_MODE")

금지:
tls.rs
  -> request마다 CERT_MODE env 읽기
```

### 1.5 로그는 3가지 수준으로 나눈다

로그는 목적에 따라 세 가지 모드로 분리한다.

1. 프로덕트용 최소 로그
2. 현장 확인용 디버그 로그
3. 개발 및 테스트용 개발 로그

이 세 모드는 단순한 log level 이름이 아니라 운영 모드다. 각 모드에서 남기는 정보, 비용, 민감정보 노출 수준이 달라야 한다.

## 2. 프로젝트 아키텍처 규칙

### 2.1 계층 구조

권장 계층:

```text
domain
  - routing model
  - proxy policy
  - config model
  - certificate lifecycle policy
  - load balancing policy
  - health decision

application
  - use cases
  - config validation
  - config apply planning
  - certificate issue/renew orchestration
  - route CRUD
  - upstream CRUD
  - health check orchestration

ports
  - repository traits
  - clock
  - DNS provider
  - ACME client
  - certificate store
  - metrics sink
  - audit sink
  - admin auth

adapters
  - mio network adapter
  - TLS adapter
  - HTTP parser adapter
  - file store adapter
  - SQLite store adapter
  - Admin API adapter
  - Web UI adapter
  - DNS provider plugins

bin
  - process bootstrap
  - env parsing
  - CLI
  - dependency wiring
```

의존성 방향:

```text
bin -> adapters -> application -> domain
bin -> application -> domain
adapters -> ports
application -> ports
domain -> no outer dependency
```

도메인 계층은 다음을 import하면 안 된다.

- mio
- rustls
- file system API
- database driver
- HTTP server framework
- Admin API framework
- Web UI framework
- environment variable API
- system time direct API
- logger implementation

### 2.2 Rust Core와 Admin Web UI 분리

Rust Core는 data plane이다. Admin Web UI는 control plane UI다.

규칙:

- Core는 Admin UI 없이 실행 가능해야 한다.
- Admin UI는 Core Admin API의 client로 동작해야 한다.
- Admin UI가 Core 내부 module을 직접 호출하면 안 된다.
- Admin UI가 config file을 직접 수정하면 안 된다.
- Admin UI 변경은 Admin API의 validation/apply 경로를 통과해야 한다.
- Core hot path는 UI framework, template engine, frontend build artifact에 의존하면 안 된다.

허용 배포:

- core only
- core + bundled admin UI
- core + external admin UI
- future central control plane + multiple core nodes

### 2.3 mio event loop 규칙

Core network data plane은 Tokio가 아니라 mio를 사용한다.

규칙:

- client connection, upstream connection, readiness, interest 변경은 명시적 state machine으로 관리한다.
- connection state는 테스트 가능한 구조체로 분리한다.
- event loop는 policy decision을 직접 품지 않는다.
- event loop는 domain/application service를 호출하되, 비즈니스 규칙을 자체 구현하지 않는다.
- blocking I/O는 event loop thread에서 금지한다.
- DNS, file, certificate operation 등 blocking 가능 작업은 별도 worker 경계로 분리한다.

event loop가 직접 하면 안 되는 일:

- config file parsing
- certificate renewal business decision
- route validation
- audit policy 결정
- access policy 판단 로직의 세부 구현
- UI/API request 처리

event loop가 해야 하는 일:

- socket readiness 처리
- read/write buffer 진행
- connection timeout 반영
- upstream connection lifecycle 처리
- backpressure 적용
- graceful drain

### 2.4 Core command boundary 규칙

Core event loop와 control plane은 명확한 command boundary로만 통신한다.

규칙:

- Admin API handler가 event loop 내부 상태를 직접 잠그거나 수정하면 안 된다.
- Admin API handler가 connection table, listener registry, TLS state를 직접 참조하면 안 된다.
- runtime 변경은 application use case에서 검증된 command로 변환한 뒤 Core command queue로 전달한다.
- command queue는 bounded queue여야 한다.
- command 처리 결과는 명시적 acknowledgement로 반환한다.
- event loop는 command를 짧게 처리해야 하며, file I/O, DNS, ACME, certificate parsing 같은 blocking 작업을 수행하면 안 된다.
- long-running 작업은 worker boundary에서 수행하고, event loop에는 완료 이벤트만 전달한다.
- config snapshot 교체는 원자적이어야 하며 실패 시 이전 snapshot을 유지해야 한다.

허용 command 예:

```text
ApplyConfigSnapshot
RollbackConfigSnapshot
InstallCertificate
DrainListener
Shutdown
RefreshRouteTable
```

금지:

```text
Admin API handler -> ConnectionTable 직접 변경
Admin API handler -> ListenerRegistry 직접 bind/unbind
ACME worker -> TLS state 직접 교체
Plugin -> ConfigSnapshot 직접 mutate
```

### 2.5 Runtime and dependency boundary 규칙

Core data plane은 mio 기반이다. 다른 런타임이나 프레임워크를 쓸 수 있는 영역은 명시적으로 분리한다.

규칙:

- `edge-core` hot path는 Tokio, async web framework, UI framework에 의존하지 않는다.
- Admin API adapter는 별도 thread/process에서 동작할 수 있지만 Core event loop를 오염시키면 안 된다.
- Admin Web UI는 완전히 별도 process 또는 static asset + separate service로 취급한다.
- dependency 추가 시 어느 계층에서 쓰이는지 명시해야 한다.
- dependency가 domain/application 계층으로 새어 들어가면 안 된다.
- HTTP parser, TLS, crypto dependency는 선택 근거와 대체 가능성을 문서화한다.

권장:

- dependency graph를 자동 검사하는 architecture fitness test를 둔다.
- core hot path dependency 목록을 작게 유지한다.
- adapter에서만 필요한 dependency는 adapter crate에만 둔다.

### 2.6 Clean Architecture 포트 규칙

외부 시스템은 반드시 port trait 뒤에 둔다.

예:

```text
AcmeClient
CertificateStore
ConfigRepository
ConfigRevisionRepository
AuditSink
MetricsSink
Clock
DnsProvider
SecretStore
HealthProbeTransport
```

application layer는 concrete file store나 HTTP client를 직접 알면 안 된다.

나쁜 예:

```text
IssueCertificateUseCase
  -> directly reads /etc/sponzey/certs
  -> directly calls reqwest
  -> directly logs to file
```

좋은 예:

```text
IssueCertificateUseCase
  -> AcmeClient
  -> CertificateStore
  -> Clock
  -> AuditSink
```

## 3. Tidy First 규칙

Tidy First는 구조 변경과 행동 변경을 분리하는 원칙이다.

### 3.1 변경 유형

모든 변경은 먼저 유형을 구분한다.

1. Tidy change
   - 이름 변경
   - 파일 이동
   - 함수 추출
   - 중복 제거
   - interface 정리
   - 테스트 helper 정리
2. Behavior change
   - 기능 추가
   - 버그 수정
   - 정책 변경
   - 프로토콜 처리 변경
   - 설정 model 변경

규칙:

- Tidy change와 behavior change를 가능한 한 분리한다.
- behavior change 전 필요한 작은 tidy를 먼저 한다.
- 불필요한 대형 리팩터링을 기능 변경에 끼워 넣지 않는다.
- 테스트가 없는 상태에서 큰 tidy를 하지 않는다.

### 3.2 커밋/작업 단위 원칙

이 저장소가 git 저장소인지 여부와 관계없이 작업 단위는 아래처럼 생각한다.

- 작은 단위
- 설명 가능한 단위
- 되돌릴 수 있는 단위
- 테스트로 검증 가능한 단위

좋은 작업 단위:

- `RouteMatch` 도메인 객체 추가
- route host/path match 테스트 추가
- Admin API route create endpoint 추가
- config validation에 duplicate route 검사 추가

나쁜 작업 단위:

- proxy core, UI, ACME, Docker discovery를 한 번에 추가
- 테스트 없이 전체 config model 재작성
- UI 요구 때문에 domain model이 framework type을 import

## 4. TDD 규칙

### 4.1 기본 루프

기능 개발은 다음 루프를 따른다.

```text
Red
  -> 실패하는 테스트 작성

Green
  -> 가장 작은 구현으로 통과

Refactor
  -> 구조 정리
  -> 테스트 유지
```

TDD를 생략할 수 있는 경우는 극히 제한한다.

예외 허용:

- 문서만 수정
- spike/prototype 디렉터리의 명시적 실험 코드
- 단순 build script 변경

예외도 가능하면 smoke check를 둔다.

### 4.2 테스트 종류

필수 테스트 계층:

1. Domain unit test
   - route match
   - config validation rule
   - load balancing decision
   - certificate renewal decision
   - access policy decision
2. Application use case test
   - create route
   - apply config
   - rollback config
   - issue certificate
   - renew certificate
   - mark upstream unhealthy
3. Adapter test
   - file config repository
   - certificate store
   - Admin API handler
   - DNS provider plugin
4. Integration test
   - core proxy to test upstream
   - HTTP reverse proxy
   - WebSocket proxy
   - TLS termination
   - ACME staging or fake ACME
5. Contract test
   - Admin API request/response schema
   - plugin protocol
   - config file schema

### 4.3 Proxy correctness test

프록시는 correctness가 가장 중요하다. 다음 테스트는 장기적으로 반드시 필요하다.

- Host match
- Path prefix match
- Path exact match
- route priority
- header preservation
- X-Forwarded-* 생성
- hop-by-hop header 제거
- chunked request/response
- content-length mismatch 방어
- request body size limit
- upstream timeout
- client timeout
- slow client
- slow upstream
- backend connection reset
- WebSocket upgrade
- TLS SNI
- certificate selection
- HTTP to HTTPS redirect
- config reload 중 요청 처리
- rollback 후 이전 route 유지

### 4.4 Test dependency rule

테스트도 architecture를 깨면 안 된다.

규칙:

- domain test는 file system, network, env에 의존하지 않는다.
- application test는 fake port를 사용한다.
- adapter test만 실제 file/network boundary를 사용할 수 있다.
- environment variable을 바꾸는 테스트는 병렬 실행에 안전해야 한다.
- 가능한 한 env 대신 explicit test config를 사용한다.

## 5. 설정 관리 규칙

### 5.1 설정의 단일 흐름

설정 변경은 반드시 아래 흐름을 따른다.

```text
draft
  -> parse
  -> normalize
  -> validate
  -> diff
  -> plan
  -> apply
  -> commit revision
  -> audit
```

중간 단계 생략 금지:

- UI가 파일을 직접 수정하고 reload signal만 보내는 방식 금지
- plugin이 config fragment를 몰래 삽입하는 방식 금지
- environment variable로 runtime policy를 바꾸는 방식 금지
- request path에서 config를 직접 mutate하는 방식 금지

### 5.2 Config snapshot

Core는 mutable global config를 읽지 않는다.

규칙:

- 적용된 설정은 immutable snapshot으로 본다.
- 새 설정은 새 snapshot으로 생성한다.
- event loop는 snapshot reference를 원자적으로 교체한다.
- 기존 connection은 정책에 따라 old snapshot으로 drain하거나 safe migration한다.
- snapshot은 revision id를 가진다.

### 5.3 외부 파일 최소화

파일 구조는 단순해야 한다.

권장:

```text
data/
  config/
    current.toml
    revisions/
  certs/
  secrets/
  logs/
  backups/
```

금지:

```text
plugins/
  plugin-a/custom-runtime-policy.json
  plugin-b/secret-copy.env
  plugin-c/routes.override
```

플러그인이 설정이 필요하면 core config model에 typed extension으로 등록하거나 Admin API를 통해 저장한다.

### 5.4 환경 변수 규칙

환경 변수는 bootstrap only다.

허용 예:

```text
SPONZEY_DATA_DIR
SPONZEY_CONFIG_FILE
SPONZEY_ADMIN_BIND
SPONZEY_LOG_MODE
SPONZEY_BOOTSTRAP_ADMIN_PASSWORD_FILE
```

금지 예:

```text
SPONZEY_ROUTE_MODE
SPONZEY_ENABLE_AUTH_FOR_THIS_REQUEST
SPONZEY_UPSTREAM_URL_DYNAMIC
SPONZEY_TLS_CERT_RELOAD_NOW
```

규칙:

- env 값은 process start에서만 읽는다.
- env 값은 typed bootstrap config로 변환한다.
- bootstrap 이후 내부 코드는 env를 읽지 않는다.
- 테스트도 env 대신 explicit config를 우선한다.
- env 변경으로 runtime behavior를 바꾸려는 요구는 거부한다.

### 5.5 Secret handling

secret은 일반 config와 구분한다.

규칙:

- secret은 log에 남기지 않는다.
- UI/API response에서 masking한다.
- config diff에서도 masking한다.
- secret store는 추상화한다.
- plugin에 secret을 전달할 때 최소 권한 원칙을 지킨다.

## 6. 로그 규칙

로그는 세 가지 운영 모드로 나눈다.

### 6.1 Product Minimal Log

목적:

- 프로덕션에서 상시 켜둘 수 있는 최소 로그
- 장애 이후 원인 파악의 출발점
- 낮은 비용과 낮은 민감정보 노출

포함:

- process start/stop
- config revision apply success/failure
- certificate issue/renew success/failure
- upstream health state change
- listener bind failure
- critical error
- access log는 sampling 또는 최소 필드

필드:

```text
timestamp
level
component
event
revision_id
route_id
upstream_id
status_code
duration_ms
error_code
```

금지:

- request body
- response body
- authorization header
- cookie
- full query string
- secret value
- private key path 이상 상세

### 6.2 Field Debug Log

목적:

- 현장 장애 확인
- 운영자가 재현 없이 상태를 파악
- product minimal보다 상세하지만 프로덕션에서 제한적으로 사용 가능

포함:

- route match 결과
- selected upstream
- retry decision
- timeout reason
- health check detail
- certificate challenge state
- config validation detail
- Admin API request id

주의:

- 민감정보 masking은 유지한다.
- request/response body는 기본적으로 남기지 않는다.
- 고카디널리티 label을 metrics/log에 남발하지 않는다.
- TTL 또는 sampling이 있어야 한다.

### 6.3 Development/Test Log

목적:

- 개발 중 state machine, parser, protocol 문제 확인
- 테스트 실패 원인 추적
- fuzz/integration test 분석

포함 가능:

- connection state transition
- mio readiness event
- buffer size
- parser state
- timer wheel event
- test fixture id
- fake ACME interaction

주의:

- 개발 로그는 production build에서 기본 비활성화한다.
- 민감정보는 개발 모드에서도 masking한다.
- 로그 때문에 테스트가 flaky해지면 안 된다.

### 6.4 로그 구현 규칙

규칙:

- structured logging을 사용한다.
- 문자열 조합 로그보다 key-value 필드를 우선한다.
- request id를 전파한다.
- config revision id를 포함한다.
- route id와 upstream id를 포함한다.
- error는 사람이 읽는 message와 기계가 읽는 code를 모두 가진다.
- log mode는 bootstrap에서 결정하고 runtime env 변경으로 바꾸지 않는다.
- 임시 디버그 로그를 남긴 채 merge하지 않는다.

## 7. Error Handling 규칙

### 7.1 에러 분류

에러는 최소한 다음으로 분류한다.

- config error
- validation error
- runtime I/O error
- upstream error
- TLS error
- ACME error
- certificate store error
- admin auth error
- plugin error
- internal bug

### 7.2 사용자에게 보여줄 에러

Admin UI/API에 보여줄 에러는 다음을 가져야 한다.

```text
code
message
details
hint
request_id
```

예:

```text
code: CONFIG_ROUTE_DUPLICATE_HOST
message: Duplicate host/path route.
hint: Remove one route or increase route specificity.
```

### 7.3 Panic 규칙

Core data plane에서 panic은 버그다.

허용되는 panic:

- test helper
- impossible invariant를 방어하는 debug assertion
- process bootstrap에서 필수 invariant 위반

금지:

- request 처리 중 panic
- config parse 실패 panic
- certificate renew 실패 panic
- plugin 실패 panic

## 8. Admin API 규칙

### 8.1 Admin API는 유일한 runtime 변경 경로다

runtime config 변경은 Admin API 또는 동일 application use case를 호출하는 CLI 경로만 허용한다.

금지:

- UI가 config 파일 직접 수정
- plugin이 process memory의 config 직접 수정
- environment variable로 runtime 변경
- 임의 unix signal로 policy 변경

허용:

- Admin API `validate`
- Admin API `apply`
- Admin API `rollback`
- CLI가 application use case 호출

### 8.2 API contract

규칙:

- Admin API는 versioning한다.
- breaking change는 명시한다.
- request/response schema test를 둔다.
- UI는 내부 Rust type에 의존하지 않고 API schema에 의존한다.
- error code는 안정적으로 유지한다.

### 8.3 Admin 보안

기본값:

- admin bind는 localhost 또는 unix socket
- 외부 노출은 명시 설정 필요
- 초기 admin password 설정 강제
- session cookie는 secure/httpOnly/sameSite
- CSRF 보호
- brute force 방어
- audit log

## 9. Plugin 규칙

### 9.1 Plugin의 기본 원칙

plugin은 core 안정성을 깨면 안 된다.

규칙:

- management plugin과 data plane plugin을 구분한다.
- 초기에는 management plugin 위주로 지원한다.
- data plane plugin은 WASM 또는 제한된 sandbox를 우선 검토한다.
- native dynamic library plugin은 기본적으로 금지한다.
- plugin은 core config를 직접 mutate하지 않는다.
- plugin은 명시적 permission을 가져야 한다.

### 9.2 Admin Web UI plugin

Admin Web UI는 plugin/control plane component다.

규칙:

- Core 없이 단독으로 meaningful traffic 처리를 하면 안 된다.
- Core Admin API를 통해서만 변경한다.
- 인증/세션은 자체적으로 관리하되 Core Admin API 인증도 통과해야 한다.
- UI 설정 변경은 config revision으로 남아야 한다.

### 9.3 DNS Provider plugin

DNS plugin은 ACME DNS-01을 위해 필요하다.

규칙:

- DNS credential은 secret store에서 가져온다.
- credential은 log/API response/diff에 노출하지 않는다.
- DNS provider plugin 실패는 certificate workflow error로 수렴한다.
- provider별 retry/backoff 정책을 명시한다.

## 10. Security 규칙

### 10.1 기본 보안

기본값은 안전해야 한다.

- HTTPS 우선
- admin localhost bind
- secret masking
- secure headers
- request body size limit
- timeout 기본값
- unsafe feature opt-in
- debug/admin endpoint 외부 노출 금지

### 10.2 Proxy 보안

주의할 공격:

- HTTP request smuggling
- header injection
- CRLF injection
- slowloris
- oversized header/body
- upstream response splitting
- open proxy 오용
- SSRF via dynamic upstream
- certificate private key 노출

규칙:

- hop-by-hop header를 명확히 처리한다.
- header normalization 정책을 문서화한다.
- upstream URL은 validation한다.
- admin이 아닌 사용자가 upstream을 임의 지정할 수 없게 한다.
- proxy는 기본적으로 forward proxy가 아니다.

### 10.3 Dependency 보안

규칙:

- dependency 추가는 이유가 있어야 한다.
- core hot path dependency는 특히 신중히 추가한다.
- crypto/TLS/HTTP parser dependency는 유지보수 상태를 확인한다.
- known vulnerability 대응 절차를 둔다.

## 11. Coding 규칙

### 11.1 Rust 규칙

권장:

- small module
- explicit type
- clear ownership
- immutable by default
- trait boundary at ports
- domain model에 framework type 금지
- error type은 분류 가능하게 설계
- `unsafe`는 기본 금지

`unsafe` 규칙:

- 사용 전 설계 문서 필요
- safety invariant 주석 필수
- 테스트 필수
- 대체 수단이 없을 때만 허용

### 11.2 State machine 규칙

mio 기반 core는 state machine 품질이 핵심이다.

규칙:

- connection state enum을 명확히 둔다.
- state transition은 테스트한다.
- read/write interest 변경을 테스트한다.
- timeout transition을 테스트한다.
- buffer ownership을 명확히 한다.
- backpressure 정책을 명시한다.

### 11.3 Naming

권장 용어:

- Listener
- Route
- Middleware
- Service
- Upstream
- CertificateResolver
- ConfigRevision
- ConfigSnapshot
- AdminApi
- Plugin

같은 개념에 여러 이름을 쓰지 않는다.

## 12. Documentation 규칙

문서는 코드와 함께 유지한다.

필수 문서:

- architecture overview
- config schema
- Admin API contract
- plugin contract
- logging modes
- security model
- deployment guide
- migration guide from NGINX basic config

규칙:

- 기능 추가 시 사용자 문서도 갱신한다.
- config 변경 시 schema 문서와 예제를 갱신한다.
- 보안 관련 변경은 threat model 문서에 반영한다.

## 13. 작업 절차

새 기능 작업 전:

1. 요구를 작은 use case로 쪼갠다.
2. domain/application 영향을 먼저 확인한다.
3. 실패하는 테스트를 작성한다.
4. 최소 구현한다.
5. 리팩터링한다.
6. adapter/UI를 붙인다.
7. integration test를 추가한다.
8. 문서를 갱신한다.

버그 수정 전:

1. 재현 테스트를 만든다.
2. 실패를 확인한다.
3. 원인을 domain/application/adapter 중 어디인지 분류한다.
4. 가장 좁은 범위로 수정한다.
5. regression test를 남긴다.

설정 변경 관련 작업 전:

1. config schema 영향을 확인한다.
2. validation rule을 먼저 정의한다.
3. migration 필요성을 판단한다.
4. diff/rollback 영향을 확인한다.
5. Admin API와 UI 표현을 맞춘다.

## 14. 명시적 거부 사항

다음 요구는 기본적으로 거부하거나 설계를 다시 요구한다.

- 실행 중 env를 바꿔 동작을 바꾸자는 요구
- UI가 config file을 직접 수정하자는 요구
- plugin이 core config를 직접 mutate하자는 요구
- domain layer가 mio/rustls/Admin API framework에 의존하게 만드는 변경
- 테스트 없이 proxy parser/routing/TLS 동작을 바꾸는 변경
- production minimal log에 secret/request body를 남기는 변경
- native dynamic plugin을 core process에 바로 로드하는 변경
- admin UI를 기본값으로 0.0.0.0에 인증 없이 노출하는 변경
- MVP에 HTTP/3, Kubernetes, WAF, service mesh 기능을 한 번에 넣자는 요구

## 15. MVP 작업 시 특별 규칙

MVP 목표는 "간단한 웹 UI를 포함한 아주 간단한 NGINX 대체"다.

현재 단일 노드 운영 제품화 단계에서는 수동/file-backed certificate와 사설 PKI를
유지한다. Let's Encrypt, ACME, HTTP-01/DNS-01, 자동 갱신을 포함한 신규 인증서 자동화
작업은 사용자가 명시적으로 재개하기 전까지 시작하거나 확장하지 않는다.

MVP에서 집중할 것:

- HTTP/1.1 reverse proxy
- Host/path route
- HTTPS termination
- manual/file-backed certificate와 private PKI 운영
- Admin Web UI proxy host CRUD
- config validation
- config apply/rollback
- access log

MVP에서 하지 않을 것:

- Kubernetes
- HTTP/3
- full WAF
- advanced load balancing
- TCP proxy
- plugin marketplace
- multi-node cluster

MVP 품질 기준:

- 작지만 신뢰할 수 있어야 한다.
- 기능이 적어도 설정 실패로 운영 proxy를 깨뜨리면 안 된다.
- 테스트 없는 기능은 완료로 보지 않는다.
- UI가 있어도 core는 headless로 동작해야 한다.

## 16. 최종 원칙

이 프로젝트의 경쟁력은 기능을 많이 넣는 데서 나오지 않는다.

경쟁력은 다음에서 나온다.

- Rust/mio 기반의 예측 가능한 core
- Clean Architecture로 유지되는 낮은 결합도
- TDD로 검증된 proxy correctness
- 외부 환경과 설정을 통제하는 안전한 config lifecycle
- product/field/development로 분리된 로그 전략
- Admin Web UI가 편하지만 core를 오염시키지 않는 구조
- 잘못된 설정이 운영 트래픽을 깨뜨리지 않는 apply/rollback 모델

항상 이 순서를 우선한다.

```text
correctness
  -> safety
  -> operability
  -> simplicity
  -> performance
  -> feature count
```
