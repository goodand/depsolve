"""
depsolve_ext - 통합 의존성 분석기
=================================

기능:
1. 구조 분석: 순환 의존성, 다이아몬드 의존성
2. Phantom 탐지: 생태계 인식, 표준 라이브러리 필터링, 런타임 검증
3. 시각화: Mermaid, DOT 다이어그램
4. 다중 생태계: npm, pip, Go, Rust
5. 하이브리드 프로젝트: JS + Python 공존 지원

사용법:
    # CLI
    python -m depsolve_ext analyze ./my-project
    python -m depsolve_ext analyze . --verify --verbose
    python -m depsolve_ext graph . --mermaid
    
    # Python API
    from depsolve_ext import analyze, DependencyGraph
    
    result = analyze("./my-project", verify=True)
    for issue in result.issues:
        print(f"[{issue.severity.value}] {issue.title}")
    
    print(result.mermaid_diagram)
"""

__version__ = "0.3.0"

# 모델
from .models import (
    # Enums
    Ecosystem, IssueType, Severity, DependencyType,
    ImportType, FileContext, VerifyStatus,
    
    # Data classes
    Location, Evidence, Issue, Summary, AnalysisResult,
    PackageNode, DependencyEdge, CycleInfo, DiamondInfo,
    ImportInfo, ResolveResult, PhantomResult, MultiVersionPkg, 
    PackageInfo, HybridManifest,
)

# 그래프
from .graph import DependencyGraph

# 확장
from .extensions import (
    ImportExtractor, RuntimeVerifier, PhantomDetector,
    GoAdapter, CargoAdapter, EcosystemDetector,
    load_hybrid_manifest, get_file_ecosystem, is_stdlib,
    NODE_BUILTINS, PYTHON_STDLIB, GO_STDLIB,
)

# 분석기
from .analyzer import DependencyAnalyzer, analyze

# 리포터
from .reporters import (
    ConsoleReporter, MarkdownReporter, JsonReporter,
)

# CLI
from .cli import main as cli_main

# Override Layer (신규)
from .override_engine import (
    OverrideType, OverrideEntry, OverrideConfig, OverrideApplicator,
    get_known_alias, create_initial_overrides,
    KNOWN_PYTHON_ALIASES, KNOWN_JS_ALIASES,
)
from .override_verifier import (
    VerificationMethod, VerificationResult, OverrideVerifier,
    update_overrides_with_verification, generate_verification_report,
)

__all__ = [
    # Version
    '__version__',
    
    # Enums
    'Ecosystem', 'IssueType', 'Severity', 'DependencyType',
    'ImportType', 'FileContext', 'VerifyStatus',
    
    # Models
    'Location', 'Evidence', 'Issue', 'Summary', 'AnalysisResult',
    'PackageNode', 'DependencyEdge', 'CycleInfo', 'DiamondInfo',
    'ImportInfo', 'ResolveResult', 'PhantomResult', 'MultiVersionPkg', 
    'PackageInfo', 'HybridManifest',
    
    # Graph
    'DependencyGraph',
    
    # Extensions
    'ImportExtractor', 'RuntimeVerifier', 'PhantomDetector',
    'GoAdapter', 'CargoAdapter', 'EcosystemDetector',
    'load_hybrid_manifest', 'get_file_ecosystem', 'is_stdlib',
    'NODE_BUILTINS', 'PYTHON_STDLIB', 'GO_STDLIB',
    
    # Analyzer
    'DependencyAnalyzer', 'analyze',
    
    # Reporters
    'ConsoleReporter', 'MarkdownReporter', 'JsonReporter',
    
    # CLI
    'cli_main',
    
    # Override Layer
    'OverrideType', 'OverrideEntry', 'OverrideConfig', 'OverrideApplicator',
    'get_known_alias', 'create_initial_overrides',
    'KNOWN_PYTHON_ALIASES', 'KNOWN_JS_ALIASES',
    'VerificationMethod', 'VerificationResult', 'OverrideVerifier',
    'update_overrides_with_verification', 'generate_verification_report',
]
