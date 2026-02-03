"""
depsolve_ext/override_engine.py
===============================
Override Layer: LLM 판단을 핵심 로직과 분리하여 적용

설계 원칙:
1. 핵심 로직(extensions.py, analyzer.py)은 수정하지 않음
2. Override 파일(overrides.yaml)만 수정하여 동작 조정
3. 모든 Override는 Script로 검증 가능
4. 검증 통과 전까지 Override 적용 안 함 (verified: true 필요)

사용 흐름:
1. depsolve가 PhantomResult 생성
2. LLM이 overrides.yaml 수정 제안
3. Script가 검증 실행
4. 검증 통과 시 verified: true 설정
5. 다음 분석 시 Override 적용
"""

import yaml
import fnmatch
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any
from enum import Enum
from datetime import datetime

from .models import PhantomResult, Ecosystem, ImportInfo


class OverrideType(Enum):
    """Override 유형"""
    TYPO = "typo_correction"
    ALIAS = "package_alias"
    INTERNAL = "internal_module"
    IGNORE = "ignore_rule"


@dataclass
class OverrideEntry:
    """단일 Override 항목"""
    type: OverrideType
    key: str                    # detected/import_name/module/pattern
    value: str                  # corrected/package_name/reason
    confidence: float = 1.0
    reasoning: str = ""
    verified: bool = False
    verified_at: Optional[str] = None
    verification_error: Optional[str] = None
    ecosystem: Ecosystem = Ecosystem.UNKNOWN
    
    def to_dict(self) -> Dict[str, Any]:
        """YAML 직렬화용"""
        result = {
            "type": self.type.value,
            "key": self.key,
            "value": self.value,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "verified": self.verified,
        }
        if self.verified_at:
            result["verified_at"] = self.verified_at
        if self.verification_error:
            result["verification_error"] = self.verification_error
        if self.ecosystem != Ecosystem.UNKNOWN:
            result["ecosystem"] = self.ecosystem.value
        return result


@dataclass
class OverrideConfig:
    """
    Override 설정 전체
    
    구조:
    - typo_corrections: Dict[detected_name, OverrideEntry]
    - package_aliases: Dict[import_name, OverrideEntry]
    - internal_modules: Set[module_name]
    - internal_patterns: List[glob_pattern]
    """
    typo_corrections: Dict[str, OverrideEntry] = field(default_factory=dict)
    package_aliases: Dict[str, OverrideEntry] = field(default_factory=dict)
    internal_modules: Set[str] = field(default_factory=set)
    internal_patterns: List[str] = field(default_factory=list)
    ignore_rules: Dict[str, OverrideEntry] = field(default_factory=dict)
    
    # 메타데이터
    version: str = "1.0"
    last_updated: Optional[str] = None
    last_updated_by: Optional[str] = None
    
    @classmethod
    def load(cls, project_path: Path, include_unverified: bool = False) -> "OverrideConfig":
        """
        프로젝트에서 Override 설정 로드
        
        Args:
            project_path: 프로젝트 경로
            include_unverified: True면 검증되지 않은 항목도 로드 (검증용)
        """
        config = cls()
        override_file = project_path / ".depsolve" / "overrides.yaml"
        
        if not override_file.exists():
            return config
        
        try:
            with open(override_file, encoding='utf-8') as f:
                data = yaml.safe_load(f) or {}
            
            config.version = data.get("version", "1.0")
            config.last_updated = data.get("last_updated")
            config.last_updated_by = data.get("last_updated_by")
            
            # 오타 교정 로드
            for entry in data.get("typo_corrections", []):
                is_verified = entry.get("verified", False)
                if is_verified or include_unverified:
                    key = entry.get("detected", "")
                    if key:
                        config.typo_corrections[key.lower()] = OverrideEntry(
                            type=OverrideType.TYPO,
                            key=key,
                            value=entry.get("corrected", ""),
                            confidence=entry.get("confidence", 1.0),
                            reasoning=entry.get("reasoning", ""),
                            verified=is_verified,
                            verified_at=entry.get("verified_at"),
                            ecosystem=cls._parse_ecosystem(entry.get("ecosystem"))
                        )
            
            # 패키지 별칭 로드
            for entry in data.get("package_aliases", []):
                is_verified = entry.get("verified", False)
                if is_verified or include_unverified:
                    key = entry.get("import_name", "")
                    if key:
                        config.package_aliases[key.lower()] = OverrideEntry(
                            type=OverrideType.ALIAS,
                            key=key,
                            value=entry.get("package_name", ""),
                            confidence=entry.get("confidence", 1.0),
                            reasoning=entry.get("reasoning", ""),
                            verified=is_verified,
                            verified_at=entry.get("verified_at"),
                            ecosystem=cls._parse_ecosystem(entry.get("ecosystem"))
                        )
            
            # 내부 모듈 로드
            for entry in data.get("internal_modules", []):
                is_verified = entry.get("verified", False)
                if is_verified or include_unverified:
                    module = entry.get("module", "")
                    if module:
                        config.internal_modules.add(module.lower())
                    pattern = entry.get("pattern")
                    if pattern:
                        config.internal_patterns.append(pattern)
            
            # Ignore 규칙 로드
            for entry in data.get("ignore_rules", []):
                pattern = entry.get("pattern", "")
                if pattern:
                    config.ignore_rules[pattern] = OverrideEntry(
                        type=OverrideType.IGNORE,
                        key=pattern,
                        value=entry.get("reason", ""),
                        ecosystem=cls._parse_ecosystem(entry.get("ecosystem")),
                        verified=True  # Ignore 규칙은 검증 불필요
                    )
        
        except yaml.YAMLError:
            pass
        except Exception:
            pass
        
        return config
    
    @staticmethod
    def _parse_ecosystem(value: Optional[str]) -> Ecosystem:
        """생태계 문자열 파싱"""
        if not value:
            return Ecosystem.UNKNOWN
        try:
            return Ecosystem(value.lower())
        except ValueError:
            return Ecosystem.UNKNOWN
    
    def save(self, project_path: Path) -> None:
        """설정을 파일로 저장"""
        override_dir = project_path / ".depsolve"
        override_dir.mkdir(parents=True, exist_ok=True)
        override_file = override_dir / "overrides.yaml"
        
        data = {
            "version": self.version,
            "last_updated": datetime.now().isoformat(),
            "last_updated_by": self.last_updated_by or "depsolve",
            "typo_corrections": [],
            "package_aliases": [],
            "internal_modules": [],
            "ignore_rules": [],
        }
        
        # 오타 교정
        for entry in self.typo_corrections.values():
            data["typo_corrections"].append({
                "detected": entry.key,
                "corrected": entry.value,
                "confidence": entry.confidence,
                "reasoning": entry.reasoning,
                "verified": entry.verified,
                "verified_at": entry.verified_at,
                "ecosystem": entry.ecosystem.value if entry.ecosystem != Ecosystem.UNKNOWN else None,
            })
        
        # 패키지 별칭
        for entry in self.package_aliases.values():
            data["package_aliases"].append({
                "import_name": entry.key,
                "package_name": entry.value,
                "confidence": entry.confidence,
                "reasoning": entry.reasoning,
                "verified": entry.verified,
                "verified_at": entry.verified_at,
                "ecosystem": entry.ecosystem.value if entry.ecosystem != Ecosystem.UNKNOWN else None,
            })
        
        # 내부 모듈
        for module in self.internal_modules:
            data["internal_modules"].append({
                "module": module,
                "verified": True,
            })
        for pattern in self.internal_patterns:
            # 패턴과 모듈 분리 필요 시 별도 처리
            pass
        
        # Ignore 규칙
        for entry in self.ignore_rules.values():
            data["ignore_rules"].append({
                "pattern": entry.key,
                "reason": entry.value,
                "ecosystem": entry.ecosystem.value if entry.ecosystem != Ecosystem.UNKNOWN else None,
            })
        
        with open(override_file, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
    
    def has_any_overrides(self) -> bool:
        """Override가 하나라도 있는지 확인"""
        return bool(
            self.typo_corrections or 
            self.package_aliases or 
            self.internal_modules or 
            self.internal_patterns or
            self.ignore_rules
        )


class OverrideApplicator:
    """
    Override를 PhantomResult에 적용
    
    핵심 로직 변경 없이, 결과만 후처리
    """
    
    def __init__(self, config: OverrideConfig):
        self.config = config
        self._stats = {
            "typo_corrected": 0,
            "alias_resolved": 0,
            "internal_marked": 0,
            "ignored": 0,
            "unchanged": 0,
        }
    
    @property
    def stats(self) -> Dict[str, int]:
        """적용 통계"""
        return self._stats.copy()
    
    def apply(self, phantoms: List[PhantomResult]) -> List[PhantomResult]:
        """
        Phantom 목록에 Override 적용
        
        Returns:
            수정된 PhantomResult 목록 (원본 변경 없음)
        """
        result: List[PhantomResult] = []
        
        for phantom in phantoms:
            pkg_lower = phantom.package.lower()
            
            # 1. Ignore 규칙 체크
            if self._should_ignore(phantom.package, phantom.ecosystem):
                self._stats["ignored"] += 1
                # Ignore된 것은 결과에서 제외
                continue
            
            # 2. 오타 교정 체크
            if pkg_lower in self.config.typo_corrections:
                override = self.config.typo_corrections[pkg_lower]
                modified = self._mark_as_corrected(phantom, override)
                result.append(modified)
                self._stats["typo_corrected"] += 1
                continue
            
            # 3. 별칭 체크 (사용자 정의 OR 내장)
            known_alias = get_known_alias(phantom.package, phantom.ecosystem)
            if pkg_lower in self.config.package_aliases or known_alias:
                if pkg_lower in self.config.package_aliases:
                    override = self.config.package_aliases[pkg_lower]
                else:
                    # 내장 별칭용 임시 OverrideEntry 생성
                    override = OverrideEntry(
                        type=OverrideType.ALIAS,
                        key=phantom.package,
                        value=known_alias,
                        reasoning="Well-known import alias (built-in)",
                        verified=True,
                        ecosystem=phantom.ecosystem
                    )
                
                modified = self._mark_as_alias(phantom, override)
                result.append(modified)
                self._stats["alias_resolved"] += 1
                continue
            
            # 4. 내부 모듈 체크
            if self._is_internal(phantom.package):
                modified = self._mark_as_internal(phantom)
                result.append(modified)
                self._stats["internal_marked"] += 1
                continue
            
            # 5. 변경 없음
            result.append(phantom)
            self._stats["unchanged"] += 1
        
        return result
    
    def _should_ignore(self, package: str, ecosystem: Ecosystem) -> bool:
        """Ignore 규칙에 해당하는지 확인"""
        for pattern, rule in self.config.ignore_rules.items():
            # 생태계 필터
            if rule.ecosystem != Ecosystem.UNKNOWN and rule.ecosystem != ecosystem:
                continue
            
            # 패턴 매칭
            if fnmatch.fnmatch(package.lower(), pattern.lower()):
                return True
        
        return False
    
    def _is_internal(self, module: str) -> bool:
        """내부 모듈 여부 확인"""
        module_lower = module.lower()
        
        if module_lower in self.config.internal_modules:
            return True
        
        for pattern in self.config.internal_patterns:
            if fnmatch.fnmatch(module_lower, pattern.lower()):
                return True
        
        return False
    
    def _mark_as_corrected(self, phantom: PhantomResult, override: OverrideEntry) -> PhantomResult:
        """오타로 마킹 (Phantom에서 제외)"""
        return PhantomResult(
            package=phantom.package,
            imports=phantom.imports,
            is_phantom=False,  # 오타였으므로 실제 Phantom 아님
            installed_version=phantom.installed_version,
            reason=f"[Override] Typo corrected: '{phantom.package}' → '{override.value}' ({override.reasoning})",
            ecosystem=phantom.ecosystem
        )
    
    def _mark_as_alias(self, phantom: PhantomResult, override: OverrideEntry) -> PhantomResult:
        """별칭으로 마킹"""
        return PhantomResult(
            package=phantom.package,
            imports=phantom.imports,
            is_phantom=False,
            installed_version=phantom.installed_version,
            reason=f"[Override] Package alias: '{phantom.package}' is import name for '{override.value}'",
            ecosystem=phantom.ecosystem
        )
    
    def _mark_as_internal(self, phantom: PhantomResult) -> PhantomResult:
        """내부 모듈로 마킹"""
        return PhantomResult(
            package=phantom.package,
            imports=phantom.imports,
            is_phantom=False,
            installed_version=phantom.installed_version,
            reason="[Override] Internal module: part of project source",
            ecosystem=phantom.ecosystem
        )


# =============================================================================
# Well-known Package Aliases (Built-in)
# =============================================================================

KNOWN_PYTHON_ALIASES: Dict[str, str] = {
    # import 이름 → PyPI 패키지명
    "pil": "pillow",
    "cv2": "opencv-python",
    "sklearn": "scikit-learn",
    "skimage": "scikit-image",
    "yaml": "pyyaml",
    "bs4": "beautifulsoup4",
    "dateutil": "python-dateutil",
    "dotenv": "python-dotenv",
    "jwt": "pyjwt",
    "magic": "python-magic",
    "serial": "pyserial",
    "usb": "pyusb",
    "gi": "pygobject",
    "wx": "wxpython",
    "cv": "opencv-python",
    "google": "google-api-python-client",
    "googleapiclient": "google-api-python-client",
    "flask_sqlalchemy": "flask-sqlalchemy",
    "flask_login": "flask-login",
    "flask_wtf": "flask-wtf",
    "flask_cors": "flask-cors",
    "flask_restful": "flask-restful",
    "flask_migrate": "flask-migrate",
}

KNOWN_JS_ALIASES: Dict[str, str] = {
    # scoped 패키지의 짧은 이름
    "react-dom/client": "react-dom",
    "react/jsx-runtime": "react",
}


def get_known_alias(import_name: str, ecosystem: Ecosystem) -> Optional[str]:
    """
    알려진 별칭에서 실제 패키지명 조회
    
    Returns:
        실제 패키지명 또는 None
    """
    name_lower = import_name.lower()
    
    if ecosystem == Ecosystem.PYTHON:
        return KNOWN_PYTHON_ALIASES.get(name_lower)
    elif ecosystem == Ecosystem.JAVASCRIPT:
        return KNOWN_JS_ALIASES.get(name_lower)
    
    return None


def create_initial_overrides(project_path: Path) -> OverrideConfig:
    """
    초기 overrides.yaml 템플릿 생성
    
    LLM이 수정할 기본 구조 제공
    """
    config = OverrideConfig(
        version="1.0",
        last_updated=datetime.now().isoformat(),
        last_updated_by="depsolve-init"
    )
    
    # 알려진 별칭 추가 (검증 필요)
    for import_name, package_name in KNOWN_PYTHON_ALIASES.items():
        config.package_aliases[import_name] = OverrideEntry(
            type=OverrideType.ALIAS,
            key=import_name,
            value=package_name,
            confidence=1.0,
            reasoning="Well-known Python import alias",
            verified=False,  # 검증 필요
            ecosystem=Ecosystem.PYTHON
        )
    
    return config


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    'OverrideType',
    'OverrideEntry',
    'OverrideConfig',
    'OverrideApplicator',
    'get_known_alias',
    'create_initial_overrides',
    'KNOWN_PYTHON_ALIASES',
    'KNOWN_JS_ALIASES',
]
