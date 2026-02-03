"""
depsolve_ext/override_verifier.py
=================================
Override 검증기: LLM의 수정이 실제로 유효한지 검증

검증 방법:
1. 오타 교정: 교정된 패키지가 실제로 존재하는지 (PyPI/npm 조회)
2. 별칭: import alias가 실제 패키지로 resolve 되는지
3. 내부 모듈: 해당 경로에 파일이 존재하는지

검증 루프:
1. LLM이 overrides.yaml 수정 제안
2. Script가 검증 실행 (이 모듈)
3. 검증 통과 시 verified: true 설정
4. 검증 실패 시 verification_error 기록
5. 다음 LLM 분석 시 실패 원인 참고
"""

import subprocess
import sys
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set, Tuple
from datetime import datetime
from enum import Enum

from .override_engine import (
    OverrideConfig, OverrideEntry, OverrideType,
    KNOWN_PYTHON_ALIASES
)
from .models import Ecosystem
from .extensions import normalize_package_name, get_package_aliases


class VerificationMethod(Enum):
    """검증 방법"""
    PYPI_LOOKUP = "pypi_lookup"
    NPM_LOOKUP = "npm_lookup"
    IMPORT_TEST = "import_test"
    FILE_EXISTS = "file_exists"
    METADATA_CHECK = "metadata_check"


@dataclass
class VerificationResult:
    """검증 결과"""
    entry: OverrideEntry
    success: bool
    method: VerificationMethod
    error: Optional[str] = None
    details: Dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict:
        return {
            "type": self.entry.type.value,
            "key": self.entry.key,
            "value": self.entry.value,
            "success": self.success,
            "method": self.method.value,
            "error": self.error,
            "details": self.details,
            "timestamp": self.timestamp,
        }


class OverrideVerifier:
    """
    Override 항목 검증
    
    검증 실패 시 overrides.yaml의 verified 필드를 false로 유지
    """
    
    def __init__(self, project_path: Path, timeout: int = 30):
        self.project = Path(project_path)
        self.timeout = timeout
        self._pip_available: Optional[bool] = None
        self._npm_available: Optional[bool] = None
    
    @property
    def pip_available(self) -> bool:
        """pip 사용 가능 여부"""
        if self._pip_available is None:
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "--version"],
                    capture_output=True,
                    timeout=5
                )
                self._pip_available = result.returncode == 0
            except Exception:
                self._pip_available = False
        return self._pip_available
    
    @property
    def npm_available(self) -> bool:
        """npm 사용 가능 여부"""
        if self._npm_available is None:
            try:
                result = subprocess.run(
                    ["npm", "--version"],
                    capture_output=True,
                    timeout=5
                )
                self._npm_available = result.returncode == 0
            except Exception:
                self._npm_available = False
        return self._npm_available
    
    def verify_all(self, config: OverrideConfig) -> List[VerificationResult]:
        """모든 Override 검증"""
        results: List[VerificationResult] = []
        
        # 오타 교정 검증
        for key, entry in config.typo_corrections.items():
            result = self.verify_typo(entry)
            results.append(result)
        
        # 별칭 검증
        for key, entry in config.package_aliases.items():
            result = self.verify_alias(entry)
            results.append(result)
        
        # 내부 모듈 검증
        for module in config.internal_modules:
            entry = OverrideEntry(
                type=OverrideType.INTERNAL,
                key=module,
                value=""
            )
            result = self.verify_internal(entry)
            results.append(result)
        
        return results
    
    def verify_typo(self, entry: OverrideEntry) -> VerificationResult:
        """
        오타 교정 검증
        
        방법: 교정된 패키지가 PyPI/npm에 존재하는지 확인
        """
        corrected = entry.value
        ecosystem = entry.ecosystem
        
        if ecosystem == Ecosystem.PYTHON or ecosystem == Ecosystem.UNKNOWN:
            return self._verify_python_package(entry, corrected)
        elif ecosystem == Ecosystem.JAVASCRIPT:
            return self._verify_js_package(entry, corrected)
        
        return VerificationResult(
            entry=entry,
            success=False,
            method=VerificationMethod.METADATA_CHECK,
            error=f"Unknown ecosystem: {ecosystem}"
        )
    
    def verify_alias(self, entry: OverrideEntry) -> VerificationResult:
        """
        별칭 검증
        
        방법: 
        1. 패키지가 설치되어 있으면 import 테스트
        2. 설치 안 되어 있으면 PyPI 메타데이터에서 top-level 확인
        """
        import_name = entry.key
        package_name = entry.value
        ecosystem = entry.ecosystem
        
        if ecosystem == Ecosystem.PYTHON or ecosystem == Ecosystem.UNKNOWN:
            # 1. 먼저 설치 여부 확인
            installed = self._check_installed_python(package_name)
            
            if installed:
                # 2. import 테스트
                return self._verify_python_import(entry, import_name, package_name)
            else:
                # 3. 설치 안 되어 있으면 패키지 존재만 확인
                result = self._verify_python_package(entry, package_name)
                if result.success:
                    result.details["note"] = "Package exists but not installed; import test skipped"
                return result
        
        elif ecosystem == Ecosystem.JAVASCRIPT:
            return self._verify_js_package(entry, package_name)
        
        return VerificationResult(
            entry=entry,
            success=False,
            method=VerificationMethod.METADATA_CHECK,
            error=f"Unknown ecosystem: {ecosystem}"
        )
    
    def verify_internal(self, entry: OverrideEntry) -> VerificationResult:
        """
        내부 모듈 검증
        
        방법: 프로젝트 내에 해당 경로/파일이 존재하는지
        """
        module = entry.key
        
        # 모듈명을 경로로 변환
        module_path = module.replace(".", "/")
        
        candidates = [
            self.project / f"{module_path}.py",
            self.project / module_path / "__init__.py",
            self.project / "src" / f"{module_path}.py",
            self.project / "src" / module_path / "__init__.py",
            self.project / "lib" / f"{module_path}.py",
            self.project / "app" / f"{module_path}.py",
        ]
        
        for candidate in candidates:
            if candidate.exists():
                return VerificationResult(
                    entry=entry,
                    success=True,
                    method=VerificationMethod.FILE_EXISTS,
                    details={"found_at": str(candidate.relative_to(self.project))}
                )
        
        # 패턴 매칭 (generated/* 등)
        if self._matches_project_structure(module):
            return VerificationResult(
                entry=entry,
                success=True,
                method=VerificationMethod.FILE_EXISTS,
                details={"note": "Matched by project structure pattern"}
            )
        
        return VerificationResult(
            entry=entry,
            success=False,
            method=VerificationMethod.FILE_EXISTS,
            error=f"Module path not found in project: {module}",
            details={"searched_paths": [str(c.relative_to(self.project)) for c in candidates if c.exists() == False]}
        )
    
    def _verify_python_package(self, entry: OverrideEntry, package: str) -> VerificationResult:
        """Python 패키지 존재 검증"""
        
        # pip index 시도
        if self.pip_available:
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "index", "versions", package],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout
                )
                
                if result.returncode == 0 or "Available versions" in result.stdout:
                    return VerificationResult(
                        entry=entry,
                        success=True,
                        method=VerificationMethod.PYPI_LOOKUP,
                        details={"package": package, "source": "pip index"}
                    )
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass
            
            # pip show 폴백 (이미 설치된 경우)
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "show", package],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    return VerificationResult(
                        entry=entry,
                        success=True,
                        method=VerificationMethod.PYPI_LOOKUP,
                        details={"package": package, "source": "pip show (installed)"}
                    )
            except Exception:
                pass
        
        # importlib.metadata 폴백
        try:
            import importlib.metadata as metadata
            
            # 정규화된 이름들로 시도
            aliases = get_package_aliases(package, Ecosystem.PYTHON)
            for alias in aliases:
                try:
                    dist = metadata.distribution(alias)
                    return VerificationResult(
                        entry=entry,
                        success=True,
                        method=VerificationMethod.METADATA_CHECK,
                        details={
                            "package": package,
                            "found_as": alias,
                            "version": dist.version
                        }
                    )
                except metadata.PackageNotFoundError:
                    continue
        except ImportError:
            pass
        
        return VerificationResult(
            entry=entry,
            success=False,
            method=VerificationMethod.PYPI_LOOKUP,
            error=f"Package '{package}' not found in PyPI or not installed"
        )
    
    def _verify_js_package(self, entry: OverrideEntry, package: str) -> VerificationResult:
        """JavaScript 패키지 존재 검증"""
        
        # node_modules 확인
        nm = self.project / "node_modules"
        if nm.exists():
            if package.startswith("@"):
                parts = package.split("/")
                pkg_path = nm / parts[0] / parts[1] if len(parts) >= 2 else None
            else:
                pkg_path = nm / package
            
            if pkg_path and pkg_path.exists():
                pkg_json = pkg_path / "package.json"
                if pkg_json.exists():
                    try:
                        with open(pkg_json) as f:
                            data = json.load(f)
                        return VerificationResult(
                            entry=entry,
                            success=True,
                            method=VerificationMethod.FILE_EXISTS,
                            details={
                                "package": package,
                                "version": data.get("version"),
                                "source": "node_modules"
                            }
                        )
                    except Exception:
                        pass
        
        # npm 레지스트리 조회 (설치 안 된 경우)
        if self.npm_available:
            try:
                result = subprocess.run(
                    ["npm", "view", package, "version"],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    return VerificationResult(
                        entry=entry,
                        success=True,
                        method=VerificationMethod.NPM_LOOKUP,
                        details={
                            "package": package,
                            "version": result.stdout.strip(),
                            "source": "npm registry"
                        }
                    )
            except Exception:
                pass
        
        return VerificationResult(
            entry=entry,
            success=False,
            method=VerificationMethod.NPM_LOOKUP,
            error=f"Package '{package}' not found in npm or node_modules"
        )
    
    def _verify_python_import(
        self, entry: OverrideEntry, import_name: str, package_name: str
    ) -> VerificationResult:
        """Python import 테스트"""
        
        test_script = f"""
import sys
try:
    import {import_name}
    print("SUCCESS")
except ImportError as e:
    print(f"FAIL: {{e}}")
"""
        
        try:
            result = subprocess.run(
                [sys.executable, "-c", test_script],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=self.project
            )
            
            output = result.stdout.strip()
            
            if "SUCCESS" in output:
                return VerificationResult(
                    entry=entry,
                    success=True,
                    method=VerificationMethod.IMPORT_TEST,
                    details={
                        "import_name": import_name,
                        "package_name": package_name
                    }
                )
            
            return VerificationResult(
                entry=entry,
                success=False,
                method=VerificationMethod.IMPORT_TEST,
                error=output or result.stderr.strip()
            )
        
        except subprocess.TimeoutExpired:
            return VerificationResult(
                entry=entry,
                success=False,
                method=VerificationMethod.IMPORT_TEST,
                error="Import test timeout"
            )
        except Exception as e:
            return VerificationResult(
                entry=entry,
                success=False,
                method=VerificationMethod.IMPORT_TEST,
                error=str(e)
            )
    
    def _check_installed_python(self, package: str) -> bool:
        """Python 패키지 설치 여부 확인"""
        try:
            import importlib.metadata as metadata
            
            aliases = get_package_aliases(package, Ecosystem.PYTHON)
            for alias in aliases:
                try:
                    metadata.distribution(alias)
                    return True
                except metadata.PackageNotFoundError:
                    continue
        except ImportError:
            pass
        
        return False
    
    def _matches_project_structure(self, module: str) -> bool:
        """프로젝트 구조 패턴 매칭"""
        # generated, _internal 등 특수 패턴
        special_prefixes = ['generated', '_internal', '__', 'build', 'dist']
        
        base = module.split('.')[0]
        return any(base.startswith(prefix) for prefix in special_prefixes)


def update_overrides_with_verification(
    project_path: Path,
    results: List[VerificationResult]
) -> Tuple[int, int]:
    """
    검증 결과를 overrides.yaml에 반영
    
    검증 통과: verified=true
    검증 실패: verified=false, verification_error 추가
    
    Returns:
        (성공 개수, 실패 개수)
    """
    import yaml
    
    override_file = project_path / ".depsolve" / "overrides.yaml"
    
    if not override_file.exists():
        return 0, 0
    
    try:
        with open(override_file, encoding='utf-8') as f:
            data = yaml.safe_load(f) or {}
    except Exception:
        return 0, 0
    
    success_count = 0
    fail_count = 0
    
    # 결과를 타입별로 그룹화
    result_map: Dict[str, Dict[str, VerificationResult]] = {
        "typo": {},
        "alias": {},
        "internal": {}
    }
    
    for result in results:
        key = result.entry.key.lower()
        if result.entry.type == OverrideType.TYPO:
            result_map["typo"][key] = result
        elif result.entry.type == OverrideType.ALIAS:
            result_map["alias"][key] = result
        elif result.entry.type == OverrideType.INTERNAL:
            result_map["internal"][key] = result
    
    # 오타 교정 업데이트
    for item in data.get("typo_corrections", []):
        key = item.get("detected", "").lower()
        if key in result_map["typo"]:
            result = result_map["typo"][key]
            item["verified"] = result.success
            item["verified_at"] = result.timestamp
            if not result.success:
                item["verification_error"] = result.error
                fail_count += 1
            else:
                item.pop("verification_error", None)
                success_count += 1
    
    # 별칭 업데이트
    for item in data.get("package_aliases", []):
        key = item.get("import_name", "").lower()
        if key in result_map["alias"]:
            result = result_map["alias"][key]
            item["verified"] = result.success
            item["verified_at"] = result.timestamp
            if not result.success:
                item["verification_error"] = result.error
                fail_count += 1
            else:
                item.pop("verification_error", None)
                success_count += 1
    
    # 내부 모듈 업데이트
    for item in data.get("internal_modules", []):
        key = item.get("module", "").lower()
        if key in result_map["internal"]:
            result = result_map["internal"][key]
            item["verified"] = result.success
            item["verified_at"] = result.timestamp
            if not result.success:
                item["verification_error"] = result.error
                fail_count += 1
            else:
                item.pop("verification_error", None)
                success_count += 1
    
    # 검증 실패 기록 추가/업데이트
    failures = [r for r in results if not r.success]
    if failures:
        if "verification_failures" not in data:
            data["verification_failures"] = []
        
        existing_keys = {
            (f.get("entry_type"), f.get("key"))
            for f in data["verification_failures"]
        }
        
        for failure in failures:
            key = (failure.entry.type.value, failure.entry.key)
            if key not in existing_keys:
                data["verification_failures"].append({
                    "entry_type": failure.entry.type.value,
                    "key": failure.entry.key,
                    "value": failure.entry.value,
                    "error": failure.error,
                    "method": failure.method.value,
                    "timestamp": failure.timestamp,
                    "resolution": "pending"
                })
    
    # 메타데이터 업데이트
    data["last_updated"] = datetime.now().isoformat()
    data["last_verified"] = datetime.now().isoformat()
    
    # 저장
    try:
        with open(override_file, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
    except Exception:
        pass
    
    return success_count, fail_count


def generate_verification_report(results: List[VerificationResult]) -> str:
    """검증 결과 보고서 생성"""
    lines = ["# Override Verification Report", ""]
    
    success = [r for r in results if r.success]
    failed = [r for r in results if not r.success]
    
    lines.append(f"**Total:** {len(results)} entries")
    lines.append(f"**Passed:** {len(success)}")
    lines.append(f"**Failed:** {len(failed)}")
    lines.append("")
    
    if success:
        lines.append("## ✅ Verified")
        lines.append("")
        for r in success:
            lines.append(f"- `{r.entry.key}` → `{r.entry.value}` ({r.entry.type.value})")
            if r.details:
                lines.append(f"  - Method: {r.method.value}")
                for k, v in r.details.items():
                    lines.append(f"  - {k}: {v}")
        lines.append("")
    
    if failed:
        lines.append("## ❌ Failed")
        lines.append("")
        for r in failed:
            lines.append(f"- `{r.entry.key}` ({r.entry.type.value})")
            lines.append(f"  - Error: {r.error}")
            lines.append(f"  - Method: {r.method.value}")
        lines.append("")
    
    return "\n".join(lines)


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    'VerificationMethod',
    'VerificationResult',
    'OverrideVerifier',
    'update_overrides_with_verification',
    'generate_verification_report',
]
