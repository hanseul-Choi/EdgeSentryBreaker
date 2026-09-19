# EdgeSentryBreaker

**EdgeSentryBreaker**는 로그인 이상탐지(Anomaly Detection) 시스템의 방어력을 외부 공격자의 블랙박스(Blackbox) 관점에서 검증하고, 탐지 사각지대(False Negative)와 신호 커버리지 갭을 체계적으로 도출하기 위한 모듈형 레드팀 테스트 자동화 프레임워크입니다.

기획서 문서: [`docs/blackbox-login-detection-redteam-plan.md`](docs/blackbox-login-detection-redteam-plan.md)

---

## 주요 기능

1. **블랙박스 테스트 시나리오 (T1 ~ T7)**
   - **T1**: 단발성 정상 요청 (정상 트래픽 기준선 및 오탐/False Positive 검증)
   - **T2**: 데이터센터 IP 대역 (AWS, GCP, Azure, DigitalOcean, Tor 출구 노드 등 IP 평판 S1 검증)
   - **T3**: 고빈도 버스트 요청 (초당 N회 연속 요청으로 Velocity/Rate-limit S3 검증)
   - **T4**: 저속·분산 요청 (Low & Slow: 요청 간격 지연 및 소수 IP 로테이션으로 S3 속도 우회 검증)
   - **T5**: 지리적 불일치 (원거리 해외 공인 IP 연속 요청으로 Impossible Travel S2 검증)
   - **T6**: `login_result` 조작 (반복 실패 후 success 조작 및 비표준 입력으로 API Trust Boundary 검증)
   - **T7**: 계정 순회 vs 계정 고정 (Password Spraying S7 vs 단일 계정 집중 Brute-force S3 비교)

2. **업계 표준 탐지 신호 커버리지 분석 (S1 ~ S7)**
   - S1 (IP 평판), S2 (지리 일관성), S3 (빈도·속도), S4 (계정-자산 연관성), S5 (시간대), S6 (성공/실패 비율), S7 (분산도) 반응 여부 추적 및 사각지대 매트릭스 도출

3. **엄격한 안전 가드레일 (Safety Guardrails)**
   - **타겟 제한**: 로컬/스테이징(`127.0.0.1`, `localhost`, 사설 IP) 환경만 기본 허용 (`--force-unsafe-target` 없이는 외부 프로덕션 호스트 접근 차단)
   - **계정 제한**: `test_*`, `*@example.com` 등 테스트 전용 패턴 계정만 사용 허용

4. **구조화된 리포팅**
   - 실행 시마다 `results/<run_id>/`에 3종 아티팩트 자동 생성:
     - `results.json`: 전체 요청/응답/지연시간/판정 계층 데이터
     - `results.csv`: 시계열 플랫 데이터
     - `summary.md`: 방어팀 공유용 사각지대 분석 마크다운 리포트

5. **내장 모의 탐지 서버 (Mock Server & Mock Protocol)**
   - 외부 서버 없이도 즉시 전체 시나리오를 시뮬레이션하고 테스트할 수 있는 `mock_server` 및 `mock://` 인프로세스 프로토콜 내장

---

## 설치 방법

```bash
# 가상환경 권장
pip install -r requirements.txt
# 또는 패키지 설치
pip install -e .
```

---

## 사용법 (CLI)

### 1. 시나리오 목록 확인
```bash
python3 -m edgesentry_breaker.cli list
```

### 2. 모의 서버를 이용한 자체 테스트
```bash
# 내장 Mock 환경으로 전체 시나리오 즉시 실행
python3 -m edgesentry_breaker.cli run --target mock --scenarios all
```

### 3. 로컬 탐지 서버(`http://127.0.0.1:8080/v1/detect`) 대상 실행
```bash
# 전체 시나리오 실행
python3 -m edgesentry_breaker.cli run --target http://127.0.0.1:8080/v1/detect

# 특정 시나리오만 선택 실행 (예: T1, T3, T6)
python3 -m edgesentry_breaker.cli run --target http://127.0.0.1:8080/v1/detect --scenarios t1,t3,t6

# 요청 딜레이 조절 (예: 빠른 검증을 위한 0.1배속)
python3 -m edgesentry_breaker.cli run --target http://127.0.0.1:8080/v1/detect --delay-scale 0.1
```

### 4. 내장 모의 서버 직접 구동 (독립 프로세스)
```bash
python3 -m edgesentry_breaker.cli serve-mock --port 8080
```

### 5. 최근 테스트 결과 리포트 확인
```bash
python3 -m edgesentry_breaker.cli inspect
```

---

## 테스트 실행

```bash
python3 -m unittest discover -s tests -v
```

---

## 디렉터리 구조

```text
EdgeSentryBreaker/
├── docs/
│   └── blackbox-login-detection-redteam-plan.md  # 레드팀 테스트 기획서
├── edgesentry_breaker/
│   ├── __init__.py
│   ├── cli.py               # CLI 인터페이스
│   ├── client.py            # 안전한 HTTP 클라이언트 & 판정 분류기
│   ├── config.py            # 설정 및 안전 가드레일
│   ├── mock_server.py       # 내장 모의 탐지 서버 & 인프로세스 어댑터
│   ├── models.py            # 데이터 모델 (요청, 응답, 판정, 지표)
│   ├── reporter.py          # JSON, CSV, MD 리포트 생성기
│   ├── runner.py            # 시나리오 실행 오케스트레이터
│   └── scenarios/           # 개별 시나리오 모듈
│       ├── base.py
│       ├── registry.py
│       ├── t1_baseline.py
│       ├── t2_datacenter.py
│       ├── t3_high_velocity.py
│       ├── t4_low_and_slow.py
│       ├── t5_geo_mismatch.py
│       ├── t6_result_tamper.py
│       └── t7_account_spray.py
├── tests/
│   ├── test_guardrails.py   # 안전 가드레일 단위 테스트
│   ├── test_scenarios.py    # 시나리오 생성 및 평가 테스트
│   └── test_e2e.py          # 모의 엔진 연동 E2E 통합 테스트
├── results/                 # 결과 파일 저장소 (.gitignore 처리)
├── pyproject.toml
├── requirements.txt
└── README.md
```
