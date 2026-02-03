# depsolve_ext v0.4.0

통합 의존성 분석기 - 하이브리드 프로젝트 지원, Phantom 탐지 개선

## v0.4.0 주요 개선

| 문제 | 원인 | 해결 |
|:-----|:-----|:-----|
| backend/ manifest 미탐지 | 루트만 검색 | 서브디렉토리 전체 검색 |
| pyproject.toml 파싱 불완전 | 기본 파싱만 | PEP 621 + Poetry 완전 지원 |
| pydantic-settings 오탐 | 패키지명 불일치 | 정규화 + 별칭 매칭 |
| 내부 모듈 오탐 | 필터 부재 | .claude/skills/ 등 제외 |
| requirements-dev.txt 미지원 | 무시됨 | dev 의존성으로 처리 |

## v0.3.0 주요 개선

| 문제 | 원인 | 해결 |
|:-----|:-----|:-----|
| Node.js stdlib 오탐 | 불완전한 목록 | 40+ 모듈 완전 필터링 |
| Python stdlib 오탐 | 필터 부재 | 200+ 모듈 필터 추가 |
| Cross-ecosystem 오탐 | 단일 manifest | 생태계별 격리 검증 |
| 하이브리드 미지원 | 하나만 감지 | 모든 manifest 동시 로드 |

## 기능

| 기능 | 설명 | 심각도 |
|:-----|:-----|:------:|
| **순환 의존성** | A → B → C → A 탐지 | HIGH |
| **다이아몬드** | 버전 충돌 있는 다이아몬드 탐지 | MEDIUM |
| **Phantom (JS)** | package.json에 없는 import | HIGH |
| **Phantom (Python)** | requirements.txt에 없는 import | HIGH |
| **다중 버전** | 같은 패키지 여러 버전 설치 | MEDIUM |

## 설치

```bash
# 압축 해제
unzip depsolve_ext.zip
cd depsolve_ext

# 테스트 실행
python -m depsolve_ext.tests
```

## CLI 사용법

```bash
# 전체 분석 (권장)
python -m depsolve_ext analyze ./my-project

# 런타임 검증 + 상세 출력
python -m depsolve_ext analyze . --verify --verbose

# JSON/Markdown 출력
python -m depsolve_ext analyze . --format json
python -m depsolve_ext analyze . --format markdown

# Phantom만 탐지
python -m depsolve_ext phantoms .

# 그래프 분석 + Mermaid
python -m depsolve_ext graph . --mermaid

# 파일 import 추출
python -m depsolve_ext imports ./src/App.tsx


```

## Python API

```python
from depsolve_ext import analyze, DependencyGraph, Severity

# 전체 분석
result = analyze("./my-project", verify=True)

# 결과 확인
print(f"Ecosystem: {result.ecosystem}")
print(f"Packages: {result.summary.total_packages}")
print(f"Issues: {len(result.issues)}")

for issue in result.issues:
    if issue.severity == Severity.HIGH:
        print(f"[{issue.severity.value}] {issue.title}")

# Mermaid 다이어그램
print(result.mermaid_diagram)
```

## 생태계 인식

### 파일 확장자 → 생태계 매핑

| 확장자 | 생태계 | 표준 라이브러리 필터 |
|:-------|:-------|:---------------------|
| `.js`, `.ts`, `.jsx`, `.tsx` | JavaScript | Node.js 40+ 모듈 |
| `.py`, `.pyx` | Python | Python 200+ 모듈 |
| `.go` | Go | Go stdlib |
| `.rs` | Rust | - |

### 격리 검증

```
JS import  → package.json + node_modules 검증
Python import → requirements.txt + site-packages 검증
```

## 하이브리드 프로젝트

JS + Python이 공존하는 프로젝트에서:

```
project/
├── package.json      # JS deps: express, react
├── requirements.txt  # Python deps: flask, requests
├── src/
│   ├── server.js     # import express → JS manifest로 검증
│   └── app.py        # import flask → Python manifest로 검증
```

## Phantom 탐지 개선

### Before (v0.2.0)
```
[HIGH] Phantom: https    ← Node.js stdlib 오탐
[HIGH] Phantom: os       ← Python stdlib 오탐
[HIGH] Phantom: openai   ← Cross-ecosystem 오탐
```

### After (v0.3.0)
```
✓ No phantom dependencies detected!

--- Detected Ecosystems ---
  JavaScript: 12 deps
  Python: 8 deps
```

## 파일 구조

```
depsolve_ext/
├── __init__.py      # 패키지 초기화, 공개 API
├── __main__.py      # CLI 진입점
├── models.py        # 데이터 모델 (Ecosystem, Issue, ...)
├── graph.py         # 의존성 그래프 (순환, 다이아몬드)
├── extensions.py    # 생태계 인식 Import, Phantom, 검증
├── analyzer.py      # 통합 분석기
├── reporters.py     # 리포터 (Console, Markdown, JSON)
├── cli.py           # CLI 구현
├── tests.py         # 테스트 (35개)
└── README.md
```

## 테스트

```bash
python -m depsolve_ext.tests
# Ran 35 tests in X.XXXs - OK
```

## 요구사항

- Python 3.8+
- Node.js (선택적, JS 런타임 검증용)
- npm (선택적, 다중 버전 탐지용)

## 지원 생태계

| 생태계 | Manifest | 완전 지원 |
|:-------|:---------|:---------:|
| npm | package.json | ✅ |
| pip | requirements.txt, pyproject.toml | ✅ |
| Go | go.mod | ⚠️ (파싱만) |
| Rust | Cargo.toml | ⚠️ (파싱만) |

## 변경 이력

### v0.4.0
- 하이브리드 프로젝트 서브디렉토리 manifest 탐지 개선 (backend/ 등)
- pyproject.toml PEP 621 및 Poetry 포맷 완전 지원
- 패키지명 정규화 및 별칭 매칭을 통한 오탐 수정 (pydantic-settings 등)
- 내부 특수 모듈 필터링 (.claude/skills/ 등)
- 개발용 의존성 파일 지원 (requirements-dev.txt)

### v0.3.0
- 생태계 인식 Import 추출
- Python 표준 라이브러리 필터 (200+ 모듈)
- Node.js 내장 모듈 완전 필터 (40+ 모듈)
- 하이브리드 프로젝트 지원
- 생태계별 격리 Phantom 탐지
- Cross-ecosystem 오탐 수정

### v0.2.0
- 기본 Phantom 탐지
- 순환/다이아몬드 탐지
- Mermaid 시각화
