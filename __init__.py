"""
depsolve_ext - 통합 의존성 분석기 (v2)
=====================================

개선 사항:
1. 하이브리드 프로젝트 지원 (JS + Python 공존)
2. AST 기반 정밀 분석 (오탐 방지)
3. 생태계별 격리 검증

사용법:
    # CLI
    python -m depsolve_ext analyze . --verify --verbose
"""

__version__ = "0.4.0"

# 모델 (기존 모델 유지 및 신규 모델 import)
from .models import (
    Ecosystem, IssueType, Severity, DependencyType,
    ImportType, FileContext, VerifyStatus,
    Location, Evidence, Issue, Summary, AnalysisResult,
    PackageNode, DependencyEdge, CycleInfo, DiamondInfo,
    ImportInfo, ResolveResult, MultiVersionPkg, 
    PackageInfo, HybridManifest,
)

# 확장 (v2 기반)
from .extensions import (
    EcosystemAwareExtractor, EcosystemAwarePhantomDetector,
    load_hybrid_manifest, get_file_ecosystem, is_stdlib,
    NODE_BUILTINS, PYTHON_STDLIB, GO_STDLIB,
    EcosystemImportInfo, EcosystemPhantomResult
)

# 분석기 (v2 기반)
from .analyzer import ImprovedAnalyzer, analyze_improved as analyze, ImprovedAnalysisResult

# CLI
from .cli import main as cli_main

__all__ = [
    '__version__',
    'Ecosystem',
    'ImprovedAnalyzer',
    'analyze',
    'EcosystemAwareExtractor',
    'EcosystemAwarePhantomDetector',
    'cli_main',
]