"""
depsolve_ext/analyzer.py
========================
통합 의존성 분석기

기능:
- npm/pip/Go/Rust 생태계 분석
- 하이브리드 프로젝트 지원 (JS + Python 공존)
- 그래프 구조 분석 (순환, 다이아몬드)
- 생태계별 격리 Phantom 탐지
- 다중 버전 탐지
- Mermaid 시각화

v0.4.0 개선사항:
- 서브디렉토리 manifest 검색
- 패키지명 정규화 개선
- Ignore 규칙 지원
"""

import json
from pathlib import Path
from typing import Dict, List, Set, Optional

from .models import (
    AnalysisResult, Summary, Issue, Location, Evidence,
    Severity, IssueType, DependencyType, DependencyEdge,
    DiamondInfo, CycleInfo, PhantomResult, MultiVersionPkg,
    Ecosystem, HybridManifest
)
from .graph import DependencyGraph
from .extensions import (
    PhantomDetector, RuntimeVerifier, ImportExtractor, 
    EcosystemDetector, load_hybrid_manifest, IgnoreConfig,
    normalize_package_name, get_package_aliases
)
from .override_engine import OverrideConfig, OverrideApplicator


class DependencyAnalyzer:
    """
    통합 의존성 분석기
    
    분석 항목:
    1. 그래프 구조 (순환, 다이아몬드)
    2. 생태계별 Phantom 의존성
    3. 다중 버전 설치
    4. 버전 충돌
    """
    
    def __init__(
        self,
        project_path: Path,
        verify_runtime: bool = False,
        include_dev: bool = True,
        ignore_config: Optional[IgnoreConfig] = None
    ):
        self.project = Path(project_path)
        self.verify_runtime = verify_runtime
        self.include_dev = include_dev
        self.ignore_config = ignore_config
        
        self.graph = DependencyGraph()
        self.ecosystem = "unknown"
        self.manifest: Optional[HybridManifest] = None
        
        # 레거시 호환
        self.deps: Set[str] = set()
        self.dev_deps: Set[str] = set()
        self.all_deps: Dict[str, str] = {}
    
    def analyze(self, max_nodes: int = 50) -> AnalysisResult:
        """전체 분석 실행"""
        issues: List[Issue] = []
        
        # 1. 하이브리드 manifest 로드
        self.manifest = load_hybrid_manifest(self.project)
        self._detect_ecosystem()
        self._load_manifest()
        
        # 2. 그래프 구축
        self._build_graph()
        
        # 3. 구조 분석
        cycles = self.graph.find_cycles()
        diamonds = self.graph.find_diamonds()
        
        # 4. 순환 이슈 생성
        for cycle in cycles:
            issues.append(self._create_cycle_issue(cycle))
        
        # 5. 다이아몬드 이슈 생성 (버전 충돌만)
        for diamond in diamonds:
            if diamond.has_version_conflict:
                issues.append(self._create_diamond_issue(diamond))
        
        # 6. 생태계별 Phantom 탐지
        phantoms = self._detect_phantoms()
        for phantom in phantoms:
            if phantom.is_phantom:
                issues.append(self._create_phantom_issue(phantom))
        
        # 7. 다중 버전 탐지
        if self.verify_runtime:
            verifier = RuntimeVerifier(self.project)
            multi_versions = verifier.get_multi_versions()
            for mv in multi_versions:
                issues.append(self._create_multi_version_issue(mv))
        
        # 8. 요약 생성
        summary = self._create_summary(issues)
        
        # 9. Mermaid 다이어그램
        mermaid = self.graph.to_mermaid(max_nodes=max_nodes)
        
        # 생태계 문자열 생성
        eco_str = self.ecosystem
        if self.manifest and len(self.manifest.detected_ecosystems) > 1:
            eco_str = "+".join(e.value for e in self.manifest.detected_ecosystems)
        
        return AnalysisResult(
            project_path=str(self.project),
            ecosystem=eco_str,
            issues=issues,
            summary=summary,
            mermaid_diagram=mermaid
        )
    
    def _detect_ecosystem(self):
        """생태계 감지"""
        if self.manifest and self.manifest.detected_ecosystems:
            # 첫 번째 생태계를 기본으로
            eco = self.manifest.detected_ecosystems[0]
            if eco == Ecosystem.JAVASCRIPT:
                self.ecosystem = "npm"
            elif eco == Ecosystem.PYTHON:
                self.ecosystem = "pip"
            else:
                self.ecosystem = eco.value
        elif (self.project / "package.json").exists():
            self.ecosystem = "npm"
        elif (self.project / "requirements.txt").exists() or (self.project / "pyproject.toml").exists():
            self.ecosystem = "pip"
        elif (self.project / "go.mod").exists():
            self.ecosystem = "go"
        elif (self.project / "Cargo.toml").exists():
            self.ecosystem = "cargo"
    
    def _load_manifest(self):
        """manifest 파일 로드"""
        if self.manifest:
            # HybridManifest에서 레거시 필드 채우기
            self.deps = self.manifest.js_deps | self.manifest.py_deps
            self.dev_deps = self.manifest.js_dev_deps | self.manifest.py_dev_deps
            
            for dep in self.manifest.js_deps:
                self.all_deps[dep] = "*"
            for dep in self.manifest.py_deps:
                self.all_deps[dep] = "*"
            if self.include_dev:
                for dep in self.manifest.js_dev_deps:
                    self.all_deps[dep] = "*"
                for dep in self.manifest.py_dev_deps:
                    self.all_deps[dep] = "*"
        
        # 상세 버전 정보 로드
        if self.ecosystem == "npm":
            self._load_npm_manifest()
        elif self.ecosystem == "pip":
            self._load_pip_manifest()
    
    def _load_npm_manifest(self):
        """package.json 로드"""
        pkg_json = self.project / "package.json"
        if not pkg_json.exists():
            return
        
        try:
            with open(pkg_json) as f:
                data = json.load(f)
            
            self.deps = set(data.get("dependencies", {}).keys())
            self.dev_deps = set(data.get("devDependencies", {}).keys())
            
            self.all_deps.update(data.get("dependencies", {}))
            if self.include_dev:
                self.all_deps.update(data.get("devDependencies", {}))
        except Exception:
            pass
    
    def _load_pip_manifest(self):
        """requirements.txt 로드"""
        req_txt = self.project / "requirements.txt"
        if not req_txt.exists():
            return
        
        try:
            content = req_txt.read_text()
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                match = None
                for sep in ['==', '>=', '<=', '~=', '!=', '>', '<']:
                    if sep in line:
                        parts = line.split(sep)
                        name = parts[0].strip()
                        version = parts[1].strip() if len(parts) > 1 else "*"
                        self.deps.add(name)
                        self.all_deps[name] = version
                        match = True
                        break
                
                if not match:
                    self.deps.add(line)
                    self.all_deps[line] = "*"
        except Exception:
            pass
    
    def _build_graph(self):
        """의존성 그래프 구축"""
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
        """package-lock.json 로드"""
        lock_file = self.project / "package-lock.json"
        if not lock_file.exists():
            return
        
        try:
            with open(lock_file) as f:
                data = json.load(f)
            
            packages = data.get("packages", {})
            for path, info in packages.items():
                if not path:
                    continue
                
                name = path.split("node_modules/")[-1]
                version = info.get("version")
                deps = info.get("dependencies", {})
                
                self.graph.add_node(name, version)
                
                for dep, ver in deps.items():
                    self.graph.add_edge(DependencyEdge(
                        source=name,
                        target=dep,
                        version_range=ver
                    ))
        except Exception:
            pass
    
    def _detect_phantoms(self) -> List[PhantomResult]:
        """생태계별 Phantom 탐지"""
        detector = PhantomDetector(
            project_path=self.project,
            js_deps=self.manifest.js_deps if self.manifest else self.deps,
            js_dev_deps=self.manifest.js_dev_deps if self.manifest else self.dev_deps,
            py_deps=self.manifest.py_deps if self.manifest else set(),
            py_dev_deps=self.manifest.py_dev_deps if self.manifest else set(),
            verify=self.verify_runtime,
            ignore_config=self.ignore_config
        )
        phantoms = detector.detect()
        
        # Override 적용
        config = OverrideConfig.load(self.project)
        applicator = OverrideApplicator(config)
        return applicator.apply(phantoms)
    
    def _create_cycle_issue(self, cycle: CycleInfo) -> Issue:
        """순환 이슈 생성"""
        return Issue(
            type=IssueType.CIRCULAR,
            severity=Severity.HIGH,
            title=f"Circular dependency detected: {' → '.join(cycle.path[:4])}{'...' if len(cycle.path) > 4 else ''}",
            locations=[Location(package=p) for p in cycle.path[:-1]],
            evidence=Evidence(
                type="cycle",
                data=cycle.to_dict(),
                visualization=self.graph.to_mermaid_cycle(cycle)
            ),
            suggestion="Break the cycle by extracting shared code into a separate package"
        )
    
    def _create_diamond_issue(self, diamond: DiamondInfo) -> Issue:
        """다이아몬드 이슈 생성"""
        return Issue(
            type=IssueType.DIAMOND,
            severity=Severity.MEDIUM if diamond.has_version_conflict else Severity.LOW,
            title=f"Diamond dependency: {diamond.bottom} required by {diamond.left} and {diamond.right}",
            locations=[
                Location(package=diamond.left, version=diamond.left_version),
                Location(package=diamond.right, version=diamond.right_version),
                Location(package=diamond.bottom)
            ],
            evidence=Evidence(
                type="diamond",
                data=diamond.to_dict(),
                visualization=self.graph.to_mermaid_diamond(diamond)
            ),
            suggestion=f"Align versions: {diamond.left_version} vs {diamond.right_version}"
        )
    
    def _create_phantom_issue(self, phantom: PhantomResult) -> Issue:
        """Phantom 이슈 생성"""
        eco_hint = f" ({phantom.ecosystem.value})" if phantom.ecosystem != Ecosystem.UNKNOWN else ""
        
        if phantom.ecosystem == Ecosystem.PYTHON:
            suggestion = f"Add '{phantom.package}' to requirements.txt or pyproject.toml"
        else:
            suggestion = f"Add '{phantom.package}' to dependencies in package.json"
        
        return Issue(
            type=IssueType.PHANTOM,
            severity=Severity.HIGH,
            title=f"Phantom dependency{eco_hint}: {phantom.package}",
            locations=[
                Location(
                    package=phantom.package,
                    file=imp.file,
                    line=imp.line
                )
                for imp in phantom.imports[:5]
            ],
            evidence=Evidence(
                type="phantom",
                data={
                    "package": phantom.package,
                    "ecosystem": phantom.ecosystem.value,
                    "import_count": len(phantom.imports),
                    "files": list(set(i.file for i in phantom.imports))
                }
            ),
            suggestion=suggestion
        )
    
    def _create_multi_version_issue(self, mv: MultiVersionPkg) -> Issue:
        """다중 버전 이슈 생성"""
        return Issue(
            type=IssueType.MULTI_VERSION,
            severity=Severity.MEDIUM,
            title=f"Multiple versions of {mv.package}: {', '.join(mv.versions)}",
            locations=[Location(package=mv.package, version=v) for v in mv.versions],
            evidence=Evidence(
                type="multi_version",
                data={
                    "package": mv.package,
                    "versions": mv.versions,
                    "paths": mv.paths[:5]
                }
            ),
            suggestion="Consider deduplicating with 'npm dedupe'"
        )
    
    def _create_summary(self, issues: List[Issue]) -> Summary:
        """요약 생성"""
        by_severity: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        
        for issue in issues:
            sev = issue.severity.value
            typ = issue.type.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_type[typ] = by_type.get(typ, 0) + 1
        
        return Summary(
            total_packages=self.graph.node_count,
            total_dependencies=self.graph.edge_count,
            issues_by_severity=by_severity,
            issues_by_type=by_type
        )


def analyze(
    project_path: str,
    verify: bool = False,
    include_dev: bool = True,
    max_nodes: int = 50,
    ignore_config: Optional[IgnoreConfig] = None
) -> AnalysisResult:
    """
    프로젝트 분석 편의 함수
    
    Args:
        project_path: 프로젝트 경로
        verify: 런타임 검증 활성화
        include_dev: devDependencies 포함
        max_nodes: Mermaid 다이어그램 최대 노드 수
        ignore_config: 무시 규칙 설정
        
    Returns:
        AnalysisResult
    """
    analyzer = DependencyAnalyzer(
        project_path=Path(project_path),
        verify_runtime=verify,
        include_dev=include_dev,
        ignore_config=ignore_config
    )
    return analyzer.analyze(max_nodes=max_nodes)


__all__ = [
    'DependencyAnalyzer',
    'analyze',
]
