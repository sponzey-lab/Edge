# Sponzey Edge Proxy

[English](README.md)

Sponzey Edge Proxy는 선택형 Admin Web UI를 제공하는 Rust/mio 기반 self-hosted 리버스
프록시입니다.

## 최종 목표

다음 요소를 결합한 예측 가능하고 메모리 안전한 edge gateway를 개발합니다.

- HTTP, HTTPS, routing, health, backpressure를 처리하는 작은 Rust/mio data plane
- 안전한 config 검증, 적용 승인, revision 이력과 rollback
- 안정적인 Admin API만 사용하는 선택형 Admin Web UI
- 안전한 사설 PKI 운영, 관측 가능한 장애, 암호화 복구와 영속 audit
- 향후 discovery, identity, protocol, multi-node 기능을 proxy hot path와 결합하지 않고

  추가할 수 있는 명확한 경계

기능 수보다 correctness, safety, operability, simplicity, performance를 우선합니다.

## 현재 지원 기능

### 리버스 프록시와 Routing

- 통합 mio runtime 기반 HTTP/1.1 및 HTTPS 리버스 프록시
- Host, exact path, path-prefix routing
- HTTP에서 HTTPS로 redirect
- `X-Forwarded-*`와 hop-by-hop header 처리
- chunked response, request/response timeout, slow client 처리와 backpressure
- WebSocket upgrade와 양방향 tunnel

### Upstream과 가용성

- service별 단일 또는 다중 upstream
- deterministic round-robin 선택
- active HTTP/HTTPS health check와 passive transport failure ejection
- generation fence가 적용된 administrative drain
- 조건을 만족하는 GET/HEAD 요청의 안전한 1회 retry
- 명시적인 `502`, `503`, `504`와 timeout 처리

### TLS와 사설 신뢰

- rustls TLS termination과 SNI 인증서 선택
- 수동/file-backed 인증서와 신규 연결 대상 certificate hot install
- self-signed 및 Root/Intermediate 사설 PKI 검증
- 관리형 Root trust, 검증된 SNI, 명시적 HTTP Host를 사용하는 엄격한 private upstream HTTPS
- 관리형 client Root trust를 사용하는 required inbound mTLS
- rollback 보상을 포함한 config, TLS, health의 generation 단위 원자적 활성화

외부 Let's Encrypt staging/production 발급과 실제 자동 갱신 검증은 Post-MVP 작업으로
보류되어 있습니다. 현재 TLS 운영에는 수동 인증서 또는 사설 PKI 인증서를 사용합니다.

## Support bundle

인증된 Admin 사용자는 CSRF 보호가 적용된 Admin UI 또는
`POST /api/v1/support-bundles`로 제한된 진단 bundle을 생성할 수 있습니다. 요청은 경로나
artifact 선택을 받지 않으며 고정 경로의 private tar archive를 만듭니다. API/UI에는 archive ID,
digest, artifact 요약, 누락 항목, 크기만 표시되고 private key, secret, header/cookie/body/query,
filesystem path는 표시되지 않습니다. 이는 backup을 대체하지 않습니다.

### 설정과 관리

- 선언형 TOML config
- parse, normalize, validate, diff, plan, apply, revision commit, audit 흐름
- 실패 시 이전 runtime 상태를 보존하는 안전한 apply와 rollback
- 선택형 same-origin Admin Web UI
- setup, login/logout, CSRF 보호, Proxy Host CRUD, config lifecycle, certificate/trust 관리,

  health, metrics, log, audit 검색을 제공하는 인증된 Admin API
- Admin Web UI가 없는 headless 운영

### 운영과 복구

- Product, Field Debug, Development 로그 모드
- 명시적 pressure/cleanup 회계를 사용하는 process-wide connection 및 in-flight payload admission
- 선택형 loopback 전용 Prometheus metrics와 인증된 Admin metric summary
- 인증된 Admin 검색을 제공하는 bounded, restart-safe, file-backed audit ledger
- 암호화 offline backup, 인증된 verify, fresh restore, replace, rollback과 crash recovery
- backup schema v1/v2 호환과 schema v3 trust/audit 보존
- Docker 및 Docker Compose 패키징

구현 및 보류 범위의 최종 기준은 [`docs/current-state.md`](docs/current-state.md)입니다.
제품 방향과 개발 증적의 상세 내용은 [`PROJECT.md`](PROJECT.md)에 있습니다.

## 설치

### 소스에서 빌드

필요 조건:

- Cargo가 포함된 Rust toolchain
- macOS 또는 Linux

Release binary를 빌드합니다.

```bash
cargo build --release -p edge-proxy
```

Binary는 다음 경로에 생성됩니다.

```text
target/release/edge-proxy
```

### Docker Compose

필요 조건:

- Docker
- Docker Compose

공식 release는 SemVer tag와 immutable manifest digest가 함께 지정된 published Linux
image를 사용합니다. 압축을 푼 release package에서 다음을 실행합니다.

```bash
sudo ./compose/install.sh \
  --image-tag vX.Y.Z \
  --image-digest RELEASE_MANIFEST_IMAGE_SHA256_WITHOUT_PREFIX
sudo docker compose --project-directory /etc/sponzey-edge/compose \
  --file /etc/sponzey-edge/compose/docker-compose.yml up -d --wait
```

로컬 source 개발에서만 명시적 override를 사용합니다.

```bash
docker compose -f docker-compose.yml -f docker-compose.local.yml --profile local-build up --build
```

Runtime 경로, 권한, backup, 지원 platform 경계, 배포에 관한 자세한 내용은
[`docs/install.md`](docs/install.md)와 [`docs/deployment.md`](docs/deployment.md)를 참고하십시오.

### 재사용 가능한 테스트 컨테이너

테스트 컨테이너를 한 번 시작한 뒤 Cargo dependency와 target cache를 유지하며 반복 사용합니다.

```bash
docker compose -f docker-compose.test.yml up -d --build
docker compose -f docker-compose.test.yml exec edge-test \
  bash -c 'cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace -- --test-threads=1'
```

테스트 컨테이너는 host port를 공개하지 않고 운영 data나 secret을 mount하지 않습니다. 집중
테스트, 중지·재시작 및 cache 초기화 방법은 [`docs/testing.md`](docs/testing.md)를 참고하십시오.

### Release 성능 테스트 환경

지속 Compose 성능 경계는 `edge-test`와 분리됩니다. production `edge-perf` 이미지를 빌드하고,
결정론적 Node.js upstream까지의 경로로 k6 트래픽을 전송합니다. 먼저 기능 gate를 실행합니다.

```bash
node tests/performance/bin/run.mjs smoke
```

runner는 성능 서비스만 재생성하고 ignored test PKI를 만들며 raw 결과를
`artifacts/performance/<run-id>/`에 게시합니다. host에는 읽기 전용 Node dashboard만
`127.0.0.1:3000`으로 공개합니다. Edge Admin은 host port가 없고 컨테이너에 Docker socket을
mount하지 않습니다. 긴 baseline/stress/soak profile은
[`docs/testing.md`](docs/testing.md#release-performance-test-environment)를 먼저 확인하십시오.

## 사용법

### 1. Upstream 준비

샘플 config는 다음 주소에서 HTTP service가 실행 중이라고 가정합니다.

```text
http://127.0.0.1:3000
```

### 2. 샘플 Config 확인

[`examples/minimal.toml`](examples/minimal.toml)은 `0.0.0.0:8080`에서 요청을 받고,
`localhost` Host를 선택해 `3000`번 port의 upstream으로 전달합니다.

```toml
schema_version = 1

[admin]
bind = "127.0.0.1:9443"
enabled = true

[logging]
mode = "product"

[storage]
data_dir = ".sponzey"

[runtime]
max_connections = 1024
max_inflight_payload_bytes = 134217728
upstream_read_timeout_ms = 30000

[[listeners]]
name = "http"
bind = "0.0.0.0:8080"
protocol = "http"

[[services]]
name = "example"

[[services.upstreams]]
url = "http://127.0.0.1:3000"

[[routes]]
name = "example"
hosts = ["localhost"]
paths = ["/"]
service = "example"
```

### 3. 프록시 시작

소스에서 실행합니다.

```bash
SPONZEY_DATA_DIR=.sponzey \
SPONZEY_CONFIG_FILE=examples/minimal.toml \
SPONZEY_ADMIN_BIND=127.0.0.1:9443 \
SPONZEY_LOG_MODE=product \
cargo run -p edge-proxy
```

또는 release binary를 실행합니다.

```bash
SPONZEY_DATA_DIR=.sponzey \
SPONZEY_CONFIG_FILE=examples/minimal.toml \
SPONZEY_ADMIN_BIND=127.0.0.1:9443 \
SPONZEY_LOG_MODE=product \
target/release/edge-proxy
```

환경 변수는 bootstrap 시점에만 읽습니다. 시작 이후에는 Admin Web UI 또는 검증된 Admin API
config lifecycle을 통해 runtime config를 변경합니다.

### 4. Proxy Routing 확인

```bash
curl -i -H 'Host: localhost' http://127.0.0.1:8080/
```

### 5. Admin Web UI 열기

다음 주소를 엽니다.

```text
http://127.0.0.1:9443/
```

새 data directory에서는 최초 Admin setup을 완료하고 로그인합니다. Proxy Hosts 화면에서
domain, path, upstream, health check와 HTTPS policy를 생성하거나 변경합니다. UI는
`/api/v1`을 통해 변경을 적용합니다. `apps/admin-web/index.html`을 직접 열면 프록시를 실제로
제어하지 않습니다.

### 6. Headless Config 적용

Primary config 파일은 비어 있는 revision repository를 위한 최초 seed입니다. Current revision이
생성된 뒤에는 seed 파일을 수정하거나 process 환경 변수를 변경하지 말고 Admin API의 validate,
diff, apply, rollback endpoint를 사용합니다.

Config field와 API 예제는 다음 문서에 있습니다.

- [`docs/config-schema.md`](docs/config-schema.md)
- [`docs/admin-curl.md`](docs/admin-curl.md)
- [`docs/admin-api.md`](docs/admin-api.md)
- [`docs/nginx-migration.md`](docs/nginx-migration.md)
