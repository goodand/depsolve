"""
depsolve_ext/models.py
======================
공통 타입 정의

설계 원칙:
- 외부 의존성 없음 (순수 Python 표준 라이브러리만)
- 순환 import 방지 (이 모듈은 다른 모듈을 import하지 않음)
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Set
import uuid


# =============================================================================
# 열거형 (Enums)
# =============================================================================

class Ecosystem(Enum):
    """파일/패키지의 생태계"""
    JAVASCRIPT = "javascript"
    PYTHON = "python"
    GO = "go"
    RUST = "rust"
    NPM = "npm"  # 레거시 호환
    PIP = "pip"  # 레거시 호환
    UNKNOWN = "unknown"


class IssueType(Enum):
    """의존성 이슈 타입"""
    CIRCULAR = "circular"
    DIAMOND = "diamond"
    DUPLICATE = "duplicate"
    PHANTOM = "phantom"
    VERSION_CONFLICT = "version_conflict"
    MULTI_VERSION = "multi_version"


class Severity(Enum):
    """이슈 심각도"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DependencyType(Enum):
    """의존성 종류"""
    RUNTIME = "runtime"
    DEV = "dev"
    PEER = "peer"
    OPTIONAL = "optional"


class ImportType(Enum):
    """Import 유형"""
    STATIC = "import"
    REQUIRE = "require"
    DYNAMIC = "dynamic_import"
    RE_EXPORT = "re_export"
    TYPE_ONLY = "type_import"
    SIDE_EFFECT = "side_effect"
    JEST_MOCK = "jest_mock"
    VITE_GLOB = "vite_glob"
    WEBPACK = "webpack_lazy"
    # Python 전용
    FROM_IMPORT = "from_import"
    DUNDER_IMPORT = "dunder_import"
    IMPORTLIB = "importlib"


class FileContext(Enum):
    """파일 컨텍스트"""
    SOURCE = "source"
    CONFIG = "config"
    TEST = "test"
    SCRIPT = "script"


class VerifyStatus(Enum):
    """런타임 검증 상태"""
    VERIFIED = "verified"
    NOT_FOUND = "not_found"
    MULTIPLE = "multiple"
    ERROR = "error"
    SKIPPED = "skipped"


# =============================================================================
# 기본 데이터 클래스
# =============================================================================

@dataclass
class Location:
    """이슈 발생 위치"""
    package: str
    version: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None
    
    def __str__(self) -> str:
        result = self.package
        if self.version:
            result += f"@{self.version}"
        if self.file:
            result += f" ({self.file}"
            if self.line:
                result += f":{self.line}"
            result += ")"
        return result


@dataclass
class Evidence:
    """탐지 근거"""
    type: str
    data: Dict[str, Any] = field(default_factory=dict)
    visualization: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "data": self.data,
            "visualization": self.visualization
        }


@dataclass
class Issue:
    """탐지된 이슈"""
    type: IssueType
    severity: Severity
    title: str
    locations: List[Location]
    evidence: Evidence
    suggestion: str = ""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "severity": self.severity.value,
            "title": self.title,
            "locations": [str(loc) for loc in self.locations],
            "evidence": self.evidence.to_dict(),
            "suggestion": self.suggestion
        }


@dataclass
class Summary:
    """분석 요약"""
    total_packages: int = 0
    total_dependencies: int = 0
    issues_by_severity: Dict[str, int] = field(default_factory=dict)
    issues_by_type: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_packages": self.total_packages,
            "total_dependencies": self.total_dependencies,
            "issues_by_severity": self.issues_by_severity,
            "issues_by_type": self.issues_by_type
        }


@dataclass
class AnalysisResult:
    """분석 결과"""
    project_path: str
    ecosystem: str
    issues: List[Issue] = field(default_factory=list)
    summary: Summary = field(default_factory=Summary)
    mermaid_diagram: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "project_path": self.project_path,
            "ecosystem": self.ecosystem,
            "issues": [i.to_dict() for i in self.issues],
            "summary": self.summary.to_dict(),
            "mermaid_diagram": self.mermaid_diagram
        }


# =============================================================================
# 그래프 관련 데이터 클래스
# =============================================================================

@dataclass
class PackageNode:
    """패키지 노드"""
    name: str
    version: Optional[str] = None


@dataclass
class DependencyEdge:
    """의존성 엣지"""
    source: str
    target: str
    version_range: str = "*"
    dep_type: DependencyType = DependencyType.RUNTIME
    resolved_version: Optional[str] = None


@dataclass
class CycleInfo:
    """순환 의존성 정보"""
    path: List[str]
    length: int = 0
    
    def __post_init__(self):
        if self.length == 0:
            self.length = len(set(self.path))
    
    def to_dict(self) -> Dict:
        return {"path": self.path, "length": self.length}
    
    def __str__(self) -> str:
        return " → ".join(self.path)


@dataclass
class DiamondInfo:
    """다이아몬드 의존성 정보"""
    top: str
    left: str
    right: str
    bottom: str
    left_version: str = "*"
    right_version: str = "*"
    
    @property
    def has_version_conflict(self) -> bool:
        if self.left_version == self.right_version:
            return False
        if self.left_version == "*" or self.right_version == "*":
            return False
        return True
    
    def to_dict(self) -> Dict:
        return {
            "top": self.top, "left": self.left,
            "right": self.right, "bottom": self.bottom,
            "left_version": self.left_version,
            "right_version": self.right_version,
            "has_conflict": self.has_version_conflict
        }
    
    def __str__(self) -> str:
        return (f"{self.top} → {self.left} → {self.bottom}@{self.left_version}\n"
                f"{self.top} → {self.right} → {self.bottom}@{self.right_version}")


# =============================================================================
# Import/Phantom 관련 데이터 클래스
# =============================================================================

@dataclass
class ImportInfo:
    """Import 정보"""
    module: str
    package: str
    file: str
    line: int
    import_type: ImportType
    file_context: FileContext = FileContext.SOURCE
    is_type_only: bool = False
    ecosystem: Ecosystem = Ecosystem.UNKNOWN
    
    def __str__(self):
        return f"{self.package} ({self.import_type.value}) at {self.file}:{self.line}"


@dataclass
class ResolveResult:
    """require.resolve 결과"""
    package: str
    status: VerifyStatus
    version: Optional[str] = None
    error: Optional[str] = None


@dataclass
class PhantomResult:
    """Phantom 탐지 결과"""
    package: str
    imports: List[ImportInfo] = field(default_factory=list)
    is_phantom: bool = True
    installed_version: Optional[str] = None
    reason: str = ""
    ecosystem: Ecosystem = Ecosystem.UNKNOWN


@dataclass
class MultiVersionPkg:
    """다중 버전 패키지"""
    package: str
    versions: List[str] = field(default_factory=list)
    paths: List[List[str]] = field(default_factory=list)


@dataclass
class PackageInfo:
    """패키지 정보 (다중 생태계)"""
    name: str
    version: str
    dependencies: Dict[str, str] = field(default_factory=dict)
    dev_dependencies: Dict[str, str] = field(default_factory=dict)


# =============================================================================
# 하이브리드 프로젝트 지원
# =============================================================================

@dataclass
class HybridManifest:
    """하이브리드 프로젝트의 통합 Manifest"""
    js_deps: Set[str] = field(default_factory=set)
    js_dev_deps: Set[str] = field(default_factory=set)
    py_deps: Set[str] = field(default_factory=set)
    py_dev_deps: Set[str] = field(default_factory=set)
    go_deps: Set[str] = field(default_factory=set)
    rust_deps: Set[str] = field(default_factory=set)
    detected_ecosystems: List[Ecosystem] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "js_deps": list(self.js_deps),
            "js_dev_deps": list(self.js_dev_deps),
            "py_deps": list(self.py_deps),
            "py_dev_deps": list(self.py_dev_deps),
            "detected_ecosystems": [e.value for e in self.detected_ecosystems]
        }
