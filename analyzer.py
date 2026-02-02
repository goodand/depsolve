"""
depsolve_ext/analyzer.py
========================
통합 의존성 분석기 (v2 + Graph 통합 버전)

기능:
1. 하이브리드 프로젝트 지원 (JS + Python 공존)
2. 생태계별 격리 검증 (Phantom 탐지)
3. 의존성 그래프 구조 분석 (순환, 다이아몬드 탐지)
4. Mermaid 시각화
"""

import json
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field

from .extensions import (
    Ecosystem,
    EcosystemAwarePhantomDetector,
    EcosystemPhantomResult,
    load_hybrid_manifest,
    HybridManifest,
)
from .graph import DependencyGraph
from .models import (
    DependencyEdge, DependencyType, Issue, IssueType, Severity,
    Location, Evidence, CycleInfo, DiamondInfo
)


# =============================================================================
# Phantom 분석 결과 (v2)
# =============================================================================

@dataclass
class ImprovedAnalysisResult:
    """개선된 분석 결과"""
    project_path: str
    detected_ecosystems: List[str]
    
    # 생태계별 Phantom 결과
    js_phantoms: List[EcosystemPhantomResult] = field(default_factory=list)
    py_phantoms: List[EcosystemPhantomResult] = field(default_factory=list)
    
    # 통계
    total_phantoms: int = 0
    confirmed_phantoms: int = 0
    transitive_deps: int = 0
    
    # 디버그 정보
    manifest_summary: Dict = field(default_factory=dict)
    
    # 그래프 정보 (필요시 추가)
    mermaid_diagram: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "project_path": self.project_path,
            "detected_ecosystems": self.detected_ecosystems,
            "js_phantoms": [
                {
                    "package": p.package,
                    "is_phantom": p.is_phantom,
                    "version": p.installed_version,
                    "reason": p.reason,
                    "import_count": len(p.imports),
                }
                for p in self.js_phantoms
            ],
            "py_phantoms": [
                {
                    "package": p.package,
                    "is_phantom": p.is_phantom,
                    "version": p.installed_version,
                    "reason": p.reason,
                    "import_count": len(p.imports),
                }
                for p in self.py_phantoms
            ],
            "summary": {
                "total_phantoms": self.total_phantoms,
                "confirmed_phantoms": self.confirmed_phantoms,
                "transitive_deps": self.transitive_deps,
            },
            "manifest_summary": self.manifest_summary,
        }


# =============================================================================
# Phantom 분석기 (v2)
# =============================================================================

class ImprovedAnalyzer:
    """
    개선된 통합 의존성 분석기 (Phantom 탐지 중심)
    """
    
    def __init__(
        self,
        project_path: Path,
        verify_runtime: bool = True,
    ):
        self.project = Path(project_path)
        self.verify_runtime = verify_runtime
        self.manifest: Optional[HybridManifest] = None
    
    def analyze(
        self,
        source_dirs: Optional[List[str]] = None,
        max_nodes: int = 50
    ) -> ImprovedAnalysisResult:
        """프로젝트 분석 실행"""
        # 1. 모든 manifest 로드
        self.manifest = load_hybrid_manifest(self.project)
        
        # 2. Phantom 탐지기 설정
        detector = EcosystemAwarePhantomDetector(
            project_path=self.project,
            js_deps=self.manifest.js_deps,
            js_dev_deps=self.manifest.js_dev_deps,
            py_deps=self.manifest.py_deps,
            py_dev_deps=self.manifest.py_dev_deps,
            verify=self.verify_runtime,
        )
        
        # 3. Phantom 탐지
        all_phantoms = detector.detect(source_dirs)
        
        # 4. 생태계별 분류
        js_phantoms = [p for p in all_phantoms if p.ecosystem == Ecosystem.JAVASCRIPT]
        py_phantoms = [p for p in all_phantoms if p.ecosystem == Ecosystem.PYTHON]
        
        # 5. 통계 계산
        confirmed = sum(1 for p in all_phantoms if p.is_phantom)
        transitive = sum(1 for p in all_phantoms if not p.is_phantom)
        
        # 6. 결과 생성
        result = ImprovedAnalysisResult(
            project_path=str(self.project),
            detected_ecosystems=[e.value for e in self.manifest.detected_ecosystems],
            js_phantoms=js_phantoms,
            py_phantoms=py_phantoms,
            total_phantoms=len(all_phantoms),
            confirmed_phantoms=confirmed,
            transitive_deps=transitive,
            manifest_summary={
                "js_deps": len(self.manifest.js_deps),
                "js_dev_deps": len(self.manifest.js_dev_deps),
                "py_deps": len(self.manifest.py_deps),
                "py_dev_deps": len(self.manifest.py_dev_deps),
            }
        )
        
        return result


# =============================================================================
# 의존성 그래프 분석기 (복원됨)
# =============================================================================

class DependencyAnalyzer:
    """
    의존성 그래프 구조 분석기
    """
    
    def __init__(
        self,
        project_path: Path,
        verify_runtime: bool = False,
        include_dev: bool = True
    ):
        self.project = Path(project_path)
        self.verify_runtime = verify_runtime
        self.include_dev = include_dev
        
        self.graph = DependencyGraph()
        self.ecosystem = "unknown"
        
        self.deps: Set[str] = set()
        self.dev_deps: Set[str] = set()
        self.all_deps: Dict[str, str] = {}
    
    def _detect_ecosystem(self):
        """생태계 감지"""
        if (self.project / "package.json").exists():
            self.ecosystem = "npm"
        elif (self.project / "requirements.txt").exists():
            self.ecosystem = "pip"
    
    def _load_manifest(self):
        """존재하는 모든 manifest 로드 (하이브리드/서브디렉토리 지원)"""
        # load_hybrid_manifest를 재사용하여 모든 의존성 수집
        manifest = load_hybrid_manifest(self.project)
        
        self.deps.update(manifest.js_deps)
        self.deps.update(manifest.py_deps)
        self.dev_deps.update(manifest.js_dev_deps)
        self.dev_deps.update(manifest.py_dev_deps)
        
        # all_deps (버전 정보 포함) 업데이트
        for d in manifest.js_deps: self.all_deps[d] = "*"
        for d in manifest.py_deps: self.all_deps[d] = "*"
        
        # 실제 버전 정보를 알기 위해 루트의 package.json은 한 번 더 읽음
        pkg_json = self.project / "package.json"
        if pkg_json.exists():
            try:
                with open(pkg_json) as f:
                    data = json.load(f)
                self.all_deps.update(data.get("dependencies", {}))
                if self.include_dev:
                    self.all_deps.update(data.get("devDependencies", {}))
            except Exception: pass
    
    def _load_npm_manifest(self):
        pkg_json = self.project / "package.json"
        try:
            with open(pkg_json) as f:
                data = json.load(f)
            self.deps = set(data.get("dependencies", {}).keys())
            self.dev_deps = set(data.get("devDependencies", {}).keys())
            self.all_deps.update(data.get("dependencies", {}))
            if self.include_dev:
                self.all_deps.update(data.get("devDependencies", {}))
        except Exception: pass

    def _load_pip_manifest(self):
        req_txt = self.project / "requirements.txt"
        try:
            content = req_txt.read_text()
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'): continue
                for sep in ['==', '>=', '<=', '~=', '!=']:
                    if sep in line:
                        parts = line.split(sep)
                        name, ver = parts[0].strip(), parts[1].strip()
                        self.deps.add(name)
                        self.all_deps[name] = ver
                        break
                else:
                    self.deps.add(line)
                    self.all_deps[line] = "*"
        except Exception: pass

    def _build_graph(self):
        """그래프 구축"""
        root_name = self.project.name
        self.graph.add_node(root_name)
        
        for dep, version in self.all_deps.items():
            self.graph.add_edge(DependencyEdge(
                source=root_name,
                target=dep,
                version_range=version,
                dep_type=DependencyType.DEV if dep in self.dev_deps else DependencyType.RUNTIME
            ))
        
        if self.ecosystem == "npm":
            self._load_npm_lockfile()
    
    def _load_npm_lockfile(self):
        lock_file = self.project / "package-lock.json"
        if not lock_file.exists(): return
        try:
            with open(lock_file) as f:
                data = json.load(f)
            packages = data.get("packages", {})
            for path, info in packages.items():
                if not path: continue
                name = path.split("node_modules/")[-1]
                version = info.get("version")
                self.graph.add_node(name, version)
                for dep, ver in info.get("dependencies", {}).items():
                    self.graph.add_edge(DependencyEdge(source=name, target=dep, version_range=ver))
        except Exception: pass


# =============================================================================
# 편의 함수 및 리포터
# =============================================================================

def analyze_improved(
    project_path: str,
    verify: bool = True,
    source_dirs: Optional[List[str]] = None,
) -> ImprovedAnalysisResult:
    analyzer = ImprovedAnalyzer(Path(project_path), verify_runtime=verify)
    return analyzer.analyze(source_dirs)

def print_improved_report(result: ImprovedAnalysisResult, verbose: bool = False):
    print(f"\n{'=' * 60}")
    print("  depsolve v2 Analysis Report (Ecosystem-Aware)")
    print(f"{'=' * 60}")
    print(f"  Project: {result.project_path}")
    print(f"  Detected Ecosystems: {', '.join(result.detected_ecosystems)}\n")
    
    print("--- Manifest Summary ---")
    for k, v in result.manifest_summary.items(): print(f"  {k}: {v}")
    
    print(f"\n--- Phantom Summary ---")
    print(f"  Total candidates: {result.total_phantoms}")
    print(f"  Confirmed phantoms: {result.confirmed_phantoms}")
    print(f"  Transitive deps (OK): {result.transitive_deps}\n")
    
    for eco, phantoms in [("JavaScript", result.js_phantoms), ("Python", result.py_phantoms)]:
        if phantoms:
            confirmed = [p for p in phantoms if p.is_phantom]
            print(f"--- {eco} Phantoms ({len(confirmed)} confirmed) ---")
            if confirmed:
                print("\n  ✗ Confirmed Phantoms:")
                for p in confirmed[:10]:
                    print(f"    • {p.package} ({len(set(i.file for i in p.imports))} files)")
                    if verbose:
                        for i in p.imports[:3]: print(f"      - {i.file}:{i.line}")
            print()

__all__ = [
    'ImprovedAnalysisResult',
    'ImprovedAnalyzer',
    'DependencyAnalyzer',
    'analyze_improved',
    'print_improved_report',
]