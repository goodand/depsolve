"""
depsolve_ext/extensions_v2.py
=============================
개선된 확장 기능: 생태계 인식 Import 패턴, 격리된 런타임 검증

핵심 개선:
1. 파일 확장자 기반 생태계 분류 (JS/TS vs Python)
2. 각 생태계별 표준 라이브러리 필터
3. 격리된 검증: JS→node_modules, Python→site-packages
4. 하이브리드 프로젝트 지원
"""

import subprocess
import json
import re
import sys
import ast
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict
from enum import Enum
from dataclasses import dataclass, field


# =============================================================================
# 생태계 정의
# =============================================================================

class Ecosystem(Enum):
    """파일/패키지의 생태계"""
    JAVASCRIPT = "javascript"  # JS/TS/JSX/TSX
    PYTHON = "python"
    GO = "go"
    RUST = "rust"
    UNKNOWN = "unknown"


# =============================================================================
# 표준 라이브러리 (Built-in) 목록
# =============================================================================

NODE_BUILTINS = {
    # Node.js core modules
    'assert', 'async_hooks', 'buffer', 'child_process', 'cluster', 'console',
    'constants', 'crypto', 'dgram', 'diagnostics_channel', 'dns', 'domain',
    'events', 'fs', 'http', 'http2', 'https', 'inspector', 'module', 'net',
    'os', 'path', 'perf_hooks', 'process', 'punycode', 'querystring', 'readline',
    'repl', 'stream', 'string_decoder', 'sys', 'timers', 'tls', 'trace_events',
    'tty', 'url', 'util', 'v8', 'vm', 'wasi', 'worker_threads', 'zlib',
    # node: prefix variants are handled separately
}

# Python 3.8+ 표준 라이브러리 (주요 모듈)
PYTHON_STDLIB = {
    # Built-in
    'abc', 'aifc', 'argparse', 'array', 'ast', 'asynchat', 'asyncio', 'asyncore',
    'atexit', 'audioop', 'base64', 'bdb', 'binascii', 'binhex', 'bisect',
    'builtins', 'bz2', 'calendar', 'cgi', 'cgitb', 'chunk', 'cmath', 'cmd',
    'code', 'codecs', 'codeop', 'collections', 'colorsys', 'compileall',
    'concurrent', 'configparser', 'contextlib', 'contextvars', 'copy', 'copyreg',
    'cProfile', 'crypt', 'csv', 'ctypes', 'curses', 'dataclasses', 'datetime',
    'dbm', 'decimal', 'difflib', 'dis', 'distutils', 'doctest', 'email',
    'encodings', 'enum', 'errno', 'faulthandler', 'fcntl', 'filecmp', 'fileinput',
    'fnmatch', 'formatter', 'fractions', 'ftplib', 'functools', 'gc', 'getopt',
    'getpass', 'gettext', 'glob', 'graphlib', 'grp', 'gzip', 'hashlib', 'heapq',
    'hmac', 'html', 'http', 'idlelib', 'imaplib', 'imghdr', 'imp', 'importlib',
    'inspect', 'io', 'ipaddress', 'itertools', 'json', 'keyword', 'lib2to3',
    'linecache', 'locale', 'logging', 'lzma', 'mailbox', 'mailcap', 'marshal',
    'math', 'mimetypes', 'mmap', 'modulefinder', 'multiprocessing', 'netrc',
    'nis', 'nntplib', 'numbers', 'operator', 'optparse', 'os', 'ossaudiodev',
    'parser', 'pathlib', 'pdb', 'pickle', 'pickletools', 'pipes', 'pkgutil',
    'platform', 'plistlib', 'poplib', 'posix', 'posixpath', 'pprint', 'profile',
    'pstats', 'pty', 'pwd', 'py_compile', 'pyclbr', 'pydoc', 'queue', 'quopri',
    'random', 're', 'readline', 'reprlib', 'resource', 'rlcompleter', 'runpy',
    'sched', 'secrets', 'select', 'selectors', 'shelve', 'shlex', 'shutil',
    'signal', 'site', 'smtpd', 'smtplib', 'sndhdr', 'socket', 'socketserver',
    'spwd', 'sqlite3', 'ssl', 'stat', 'statistics', 'string', 'stringprep',
    'struct', 'subprocess', 'sunau', 'symbol', 'symtable', 'sys', 'sysconfig',
    'syslog', 'tabnanny', 'tarfile', 'telnetlib', 'tempfile', 'termios', 'test',
    'textwrap', 'threading', 'time', 'timeit', 'tkinter', 'token', 'tokenize',
    'trace', 'traceback', 'tracemalloc', 'tty', 'turtle', 'turtledemo', 'types',
    'typing', 'typing_extensions', 'unicodedata', 'unittest', 'urllib', 'uu',
    'uuid', 'venv', 'warnings', 'wave', 'weakref', 'webbrowser', 'winreg',
    'winsound', 'wsgiref', 'xdrlib', 'xml', 'xmlrpc', 'zipapp', 'zipfile',
    'zipimport', 'zlib', 'zoneinfo',
    # 자주 오탐되는 내장 모듈
    '_thread', '__future__', '_collections_abc',
}

GO_STDLIB = {
    'fmt', 'os', 'io', 'net', 'http', 'json', 'encoding', 'strings',
    'strconv', 'time', 'sync', 'context', 'errors', 'log', 'testing',
    'runtime', 'reflect', 'sort', 'math', 'crypto', 'regexp', 'path', 'bufio',
    'bytes', 'archive', 'compress', 'container', 'database', 'debug', 'embed',
    'flag', 'go', 'hash', 'html', 'image', 'index', 'mime', 'plugin', 'text',
    'unicode', 'unsafe',
}


# =============================================================================
# 확장자 → 생태계 매핑
# =============================================================================

EXTENSION_ECOSYSTEM_MAP = {
    # JavaScript/TypeScript
    '.js': Ecosystem.JAVASCRIPT,
    '.jsx': Ecosystem.JAVASCRIPT,
    '.ts': Ecosystem.JAVASCRIPT,
    '.tsx': Ecosystem.JAVASCRIPT,
    '.mjs': Ecosystem.JAVASCRIPT,
    '.cjs': Ecosystem.JAVASCRIPT,
    '.vue': Ecosystem.JAVASCRIPT,
    '.svelte': Ecosystem.JAVASCRIPT,
    # Python
    '.py': Ecosystem.PYTHON,
    '.pyx': Ecosystem.PYTHON,  # Cython
    '.pxd': Ecosystem.PYTHON,
    # Go
    '.go': Ecosystem.GO,
    # Rust
    '.rs': Ecosystem.RUST,
}


def get_file_ecosystem(filepath: str) -> Ecosystem:
    """파일 경로에서 생태계 추론"""
    path = Path(filepath)
    ext = path.suffix.lower()
    return EXTENSION_ECOSYSTEM_MAP.get(ext, Ecosystem.UNKNOWN)


def is_stdlib(package: str, ecosystem: Ecosystem) -> bool:
    """해당 생태계의 표준 라이브러리인지 확인"""
    base = package.split('.')[0].split('/')[0]
    
    if ecosystem == Ecosystem.JAVASCRIPT:
        # node: prefix 처리
        if package.startswith('node:'):
            return True
        return base in NODE_BUILTINS
    elif ecosystem == Ecosystem.PYTHON:
        return base in PYTHON_STDLIB
    elif ecosystem == Ecosystem.GO:
        return base in GO_STDLIB
    
    return False


# =============================================================================
# Import 패턴 (생태계별)
# =============================================================================

class JsPatterns:
    """JavaScript/TypeScript Import 패턴"""
    TYPE_IMPORT = re.compile(r'''import\s+type\s+[{}\w\s,*]+\s+from\s+['"]([^'"]+)['"]''')
    EXPORT_FROM = re.compile(r'''export\s+(?:\*|{[^}]*})\s+from\s+['"]([^'"]+)['"]''')
    JEST_MOCK = re.compile(r'''jest\.(?:mock|doMock|requireActual)\s*\(\s*['"]([^'"]+)['"]''')
    VITE_GLOB = re.compile(r'''import\.meta\.glob(?:Eager)?\s*\(\s*['"]([^'"]+)['"]''')
    WEBPACK = re.compile(r'''import\s*\(\s*/\*[^*]*\*/\s*['"]([^'"]+)['"]''')
    STATIC = re.compile(r'''import\s+(?:[\w{}\s,*]+\s+from\s+)?['"]([^'"]+)['"]''')
    DYNAMIC = re.compile(r'''import\s*\(\s*['"]([^'"]+)['"]\s*\)''')
    REQUIRE = re.compile(r'''require\s*\(\s*['"]([^'"]+)['"]\s*\)''')


class PyPatterns:
    """Python Import 패턴"""
    # import module, from module import x
    IMPORT = re.compile(r'''^\s*import\s+([\w.]+)''', re.MULTILINE)
    FROM_IMPORT = re.compile(r'''^\s*from\s+([\w.]+)\s+import''', re.MULTILINE)
    # __import__('module')
    DUNDER_IMPORT = re.compile(r'''__import__\s*\(\s*['"]([^'"]+)['"]''')
    # importlib.import_module('module')
    IMPORTLIB = re.compile(r'''import_module\s*\(\s*['"]([^'"]+)['"]''')


# =============================================================================
# 생태계 인식 Import 정보
# =============================================================================

@dataclass
class EcosystemImportInfo:
    """생태계 인식 Import 정보"""
    module: str
    package: str  # 최상위 패키지명
    file: str
    line: int
    ecosystem: Ecosystem
    import_type: str  # 'static', 'dynamic', 'require', 'type_only' 등
    is_type_only: bool = False
    
    def __str__(self):
        return f"{self.package} ({self.ecosystem.value}) at {self.file}:{self.line}"


# =============================================================================
# 생태계 인식 Import 추출기
# =============================================================================

class EcosystemAwareExtractor:
    """
    생태계 인식 Import 추출기
    
    핵심 개선:
    - 파일 확장자에 따라 다른 패턴 적용
    - 각 생태계의 표준 라이브러리 자동 필터링
    - 상대 경로 import 무시
    """
    
    def __init__(self, filter_stdlib: bool = True):
        """
        Args:
            filter_stdlib: 표준 라이브러리 필터링 여부
        """
        self.filter_stdlib = filter_stdlib
    
    def extract_file(self, path: Path) -> List[EcosystemImportInfo]:
        """파일에서 import 추출 (생태계 자동 감지)"""
        ecosystem = get_file_ecosystem(str(path))
        
        if ecosystem == Ecosystem.UNKNOWN:
            return []
        
        try:
            content = path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return []
        
        if ecosystem == Ecosystem.JAVASCRIPT:
            return self._extract_js(content, str(path))
        elif ecosystem == Ecosystem.PYTHON:
            return self._extract_python(content, str(path))
        
        return []
    
    def _extract_js(self, content: str, filepath: str) -> List[EcosystemImportInfo]:
        """JavaScript/TypeScript import 추출"""
        imports: List[EcosystemImportInfo] = []
        seen: Set[str] = set()  # 패키지명 기준 중복 제거
        
        patterns = [
            (JsPatterns.TYPE_IMPORT, 'type_only', True),
            (JsPatterns.EXPORT_FROM, 're_export', False),
            (JsPatterns.JEST_MOCK, 'jest_mock', False),
            (JsPatterns.VITE_GLOB, 'vite_glob', False),
            (JsPatterns.WEBPACK, 'webpack', False),
            (JsPatterns.STATIC, 'static', False),
            (JsPatterns.DYNAMIC, 'dynamic', False),
            (JsPatterns.REQUIRE, 'require', False),
        ]
        
        for line_num, line in enumerate(content.split('\n'), 1):
            if line.strip().startswith('//'):
                continue
            
            for pattern, imp_type, is_type in patterns:
                for match in pattern.finditer(line):
                    module = match.group(1)
                    package = self._get_js_package(module)
                    
                    if not package:
                        continue
                    
                    # 표준 라이브러리 필터링
                    if self.filter_stdlib and is_stdlib(package, Ecosystem.JAVASCRIPT):
                        continue
                    
                    # 패키지 기준 중복 체크
                    if package in seen:
                        continue
                    seen.add(package)
                    
                    imports.append(EcosystemImportInfo(
                        module=module,
                        package=package,
                        file=filepath,
                        line=line_num,
                        ecosystem=Ecosystem.JAVASCRIPT,
                        import_type=imp_type,
                        is_type_only=is_type
                    ))
        
        return imports
    
    def _extract_python(self, content: str, filepath: str) -> List[EcosystemImportInfo]:
        """Python import 추출 (AST 기반)"""
        imports: List[EcosystemImportInfo] = []
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        seen: Set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self._add_python_import(imports, seen, alias.name, filepath, 
                                          content, node.lineno, 'import')
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    # from . import x 등 상대 경로는 level > 0
                    if node.level > 0:
                        continue
                    self._add_python_import(imports, seen, node.module, filepath,
                                          content, node.lineno, 'from_import')
        
        return imports
    
    def _add_python_import(
        self,
        imports: List[EcosystemImportInfo],
        seen: Set[str],
        module: str,
        filepath: str,
        content: str, # unused but kept for signature compatibility if needed
        line_num: int,
        import_type: str
    ):
        """Python import 추가 (중복/상대경로/stdlib 필터링)"""
        # 상대 경로 무시
        if module.startswith('.'):
            return
        
        # 최상위 패키지명 추출
        package = module.split('.')[0]
        
        # 표준 라이브러리 필터링
        if self.filter_stdlib and is_stdlib(package, Ecosystem.PYTHON):
            return
        
        # 중복 체크
        if package in seen:
            return
        seen.add(package)
        
        imports.append(EcosystemImportInfo(
            module=module,
            package=package,
            file=filepath,
            line=line_num,
            ecosystem=Ecosystem.PYTHON,
            import_type=import_type,
        ))
    
    def _get_js_package(self, module: str) -> Optional[str]:
        """JS 모듈에서 패키지명 추출"""
        if not module:
            return None
        
        # 상대 경로, 절대 경로 무시
        if module.startswith('.') or module.startswith('/'):
            return None
        
        # node: prefix (내장 모듈)
        if module.startswith('node:'):
            return None
        
        # scoped package (@org/pkg)
        if module.startswith('@'):
            parts = module.split('/')
            return f"{parts[0]}/{parts[1]}" if len(parts) >= 2 else None
        
        # 일반 패키지
        return module.split('/')[0]


# =============================================================================
# 생태계 인식 Phantom 탐지기
# =============================================================================

@dataclass
class EcosystemPhantomResult:
    """생태계 인식 Phantom 탐지 결과"""
    package: str
    ecosystem: Ecosystem
    imports: List[EcosystemImportInfo] = field(default_factory=list)
    is_phantom: bool = True
    installed_version: Optional[str] = None
    reason: str = ""


class EcosystemAwarePhantomDetector:
    """
    생태계 인식 Phantom 탐지기
    
    핵심 개선:
    - JS import → npm/node_modules에서 검증
    - Python import → pip/site-packages에서 검증
    - 생태계 혼재 프로젝트에서 cross-ecosystem 오탐 방지
    """
    
    SKIP_DIRS = [
        'node_modules', '__pycache__', '.git', 'dist', 'build',
        '.history', '.vscode', '.idea', '.cache', '.next', '.nuxt',
        'coverage', '.tox', '.eggs', '*.egg-info', 'venv', '.venv',
        'env', '.env', 'site-packages',  # pip 설치 경로도 스킵
    ]
    
    def __init__(
        self,
        project_path: Path,
        js_deps: Optional[Set[str]] = None,
        js_dev_deps: Optional[Set[str]] = None,
        py_deps: Optional[Set[str]] = None,
        py_dev_deps: Optional[Set[str]] = None,
        verify: bool = False
    ):
        """
        Args:
            project_path: 프로젝트 경로
            js_deps: package.json의 dependencies
            js_dev_deps: package.json의 devDependencies
            py_deps: requirements.txt/pyproject.toml의 dependencies
            py_dev_deps: dev dependencies (optional-dependencies, extras)
            verify: 런타임 검증 활성화
        """
        self.project = Path(project_path)
        
        # 소문자로 정규화
        self.js_deps = {d.lower() for d in (js_deps or set())}
        self.js_dev_deps = {d.lower() for d in (js_dev_deps or set())}
        self.py_deps = {d.lower().replace('-', '_').replace('.', '_') 
                       for d in (py_deps or set())}
        self.py_dev_deps = {d.lower().replace('-', '_').replace('.', '_') 
                          for d in (py_dev_deps or set())}
        
        self.verify = verify
        self.extractor = EcosystemAwareExtractor(filter_stdlib=True)
        self.local_modules = self._get_local_modules()
    
    def _get_local_modules(self) -> Set[str]:
        """프로젝트 내의 모든 로컬 모듈/패키지 이름 수집"""
        local = {"depsolve_ext", "depsolve", "backend", "app", "src", "tests"}
        try:
            for p in self.project.iterdir():
                if p.name.startswith(('.', '__')) or p.name in self.SKIP_DIRS: continue
                local.add((p.stem if p.is_file() else p.name).lower().replace('-', '_'))
            for sub in ["backend", "app", "src", "scripts"]:
                sub_path = self.project / sub
                if sub_path.exists() and sub_path.is_dir():
                    for p in sub_path.iterdir():
                        if p.name.startswith(('.', '__')): continue
                        local.add((p.stem if p.is_file() else p.name).lower().replace('-', '_'))
        except Exception: pass
        return local

    def detect(
        self,
        source_dirs: Optional[List[str]] = None
    ) -> List[EcosystemPhantomResult]:
        """
        Phantom 의존성 탐지 (생태계별 격리)
        
        Args:
            source_dirs: 검색할 소스 디렉토리
            
        Returns:
            EcosystemPhantomResult 목록
        """
        source_dirs = source_dirs or ['.', 'src', 'lib', 'app']
        
        # 1. Import 수집
        all_imports = self._collect_imports(source_dirs)
        
        # 2. 생태계별 그룹화
        js_imports: Dict[str, List[EcosystemImportInfo]] = defaultdict(list)
        py_imports: Dict[str, List[EcosystemImportInfo]] = defaultdict(list)
        
        for imp in all_imports:
            if imp.ecosystem == Ecosystem.JAVASCRIPT:
                js_imports[imp.package.lower()].append(imp)
            elif imp.ecosystem == Ecosystem.PYTHON:
                # Python 패키지명 정규화 (- → _, . → _)
                normalized = imp.package.lower().replace('-', '_').replace('.', '_')
                py_imports[normalized].append(imp)
        
        # 3. 생태계별 Phantom 후보 필터링
        candidates: List[EcosystemPhantomResult] = []
        
        # JS Phantoms
        for pkg, imports in js_imports.items():
            if pkg in self.js_deps or pkg in self.js_dev_deps or pkg in self.local_modules:
                continue
            candidates.append(EcosystemPhantomResult(
                package=pkg,
                ecosystem=Ecosystem.JAVASCRIPT,
                imports=imports,
                reason="Not in package.json dependencies"
            ))
        
        # Python Phantoms
        for pkg, imports in py_imports.items():
            if pkg in self.py_deps or pkg in self.py_dev_deps or pkg in self.local_modules:
                continue
            candidates.append(EcosystemPhantomResult(
                package=pkg,
                ecosystem=Ecosystem.PYTHON,
                imports=imports,
                reason="Not in Python dependencies"
            ))
        
        # 4. 런타임 검증 (선택적)
        if self.verify:
            self._verify_candidates(candidates)
        
        return candidates
    
    def _collect_imports(self, dirs: List[str]) -> List[EcosystemImportInfo]:
        """소스 디렉토리에서 import 수집"""
        imports: List[EcosystemImportInfo] = []
        
        # 지원하는 확장자
        extensions = list(EXTENSION_ECOSYSTEM_MAP.keys())
        
        for d in dirs:
            path = self.project / d
            if not path.exists():
                continue
            
            for ext in extensions:
                pattern = f'*{ext}'
                for f in path.rglob(pattern):
                    if self._should_skip(f):
                        continue
                    imports.extend(self.extractor.extract_file(f))
        
        return imports
    
    def _should_skip(self, path: Path) -> bool:
        """스킵 여부 (node_modules, __pycache__ 등)"""
        path_str = str(path)
        return any(
            skip_dir in path_str.split('/')
            for skip_dir in self.SKIP_DIRS
        )
    
    def _verify_candidates(self, candidates: List[EcosystemPhantomResult]):
        """런타임 검증 (생태계별 격리)"""
        js_candidates = [c for c in candidates if c.ecosystem == Ecosystem.JAVASCRIPT]
        py_candidates = [c for c in candidates if c.ecosystem == Ecosystem.PYTHON]
        
        # JS: node_modules 검증
        if js_candidates:
            self._verify_js(js_candidates)
        
        # Python: site-packages 검증
        if py_candidates:
            self._verify_python(py_candidates)
    
    def _verify_js(self, candidates: List[EcosystemPhantomResult]):
        """JS 패키지 런타임 검증 (node_modules)"""
        nm = self.project / "node_modules"
        if not nm.exists():
            return
        
        for c in candidates:
            pkg = c.package
            
            # scoped package
            if pkg.startswith('@'):
                parts = pkg.split('/')
                pkg_path = nm / parts[0] / parts[1] if len(parts) >= 2 else None
            else:
                pkg_path = nm / pkg
            
            if pkg_path and pkg_path.exists():
                pkg_json = pkg_path / "package.json"
                if pkg_json.exists():
                    try:
                        with open(pkg_json) as f:
                            data = json.load(f)
                        c.is_phantom = False
                        c.installed_version = data.get("version")
                        c.reason = f"Installed as transitive (v{c.installed_version})"
                    except Exception:
                        pass
    
    def _verify_python(self, candidates: List[EcosystemPhantomResult]):
        """Python 패키지 런타임 검증 (importlib)"""
        try:
            import importlib.metadata as metadata
        except ImportError:
            return
        
        for c in candidates:
            try:
                # 패키지명 변환 (litellm → litellm, torch → torch)
                # pip 패키지명과 import 이름이 다를 수 있음
                dist = metadata.distribution(c.package)
                c.is_phantom = False
                c.installed_version = dist.version
                c.reason = f"Installed (v{c.installed_version})"
            except metadata.PackageNotFoundError:
                # 대체 이름 시도 (언더스코어 ↔ 하이픈)
                alt_name = c.package.replace('_', '-')
                try:
                    dist = metadata.distribution(alt_name)
                    c.is_phantom = False
                    c.installed_version = dist.version
                    c.reason = f"Installed as '{alt_name}' (v{c.installed_version})"
                except metadata.PackageNotFoundError:
                    pass
            except Exception:
                pass


# =============================================================================
# 하이브리드 프로젝트 Manifest 로더
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


def load_hybrid_manifest(project_path: Path) -> HybridManifest:
    """
    하이브리드 프로젝트의 모든 manifest 로드
    루트 및 주요 서브디렉토리(backend/ 등)를 검색합니다.
    """
    manifest = HybridManifest()
    project = Path(project_path)
    
    # 검색할 후보 디렉토리
    search_dirs = [project, project / "backend", project / "server", project / "api"]
    
    for d in search_dirs:
        if not d.exists():
            continue
            
        # npm (package.json)
        pkg_json = d / "package.json"
        if pkg_json.exists():
            try:
                with open(pkg_json) as f:
                    data = json.load(f)
                manifest.js_deps.update(data.get("dependencies", {}).keys())
                manifest.js_dev_deps.update(data.get("devDependencies", {}).keys())
                if Ecosystem.JAVASCRIPT not in manifest.detected_ecosystems:
                    manifest.detected_ecosystems.append(Ecosystem.JAVASCRIPT)
            except Exception:
                pass
        
        # pip (requirements.txt)
        req_txt = d / "requirements.txt"
        if req_txt.exists():
            try:
                content = req_txt.read_text()
                for line in content.split('\n'):
                    line = line.strip()
                    if not line or line.startswith(('#', '-')):
                        continue
                    for sep in ['==', '>=', '<=', '~=', '!=', '>', '<', '[']:
                        if sep in line:
                            line = line.split(sep)[0]
                            break
                    manifest.py_deps.add(line.strip())
                if Ecosystem.PYTHON not in manifest.detected_ecosystems:
                    manifest.detected_ecosystems.append(Ecosystem.PYTHON)
            except Exception:
                pass
        
        # pip (pyproject.toml)
        pyproj = d / "pyproject.toml"
        if pyproj.exists():
            try:
                content = pyproj.read_text()
                import re
                
                # 1. PEP 621 스타일 (dependencies = [...])
                in_pep621_deps = False
                for line in content.split('\n'):
                    l = line.strip()
                    if re.match(r'^dependencies\s*=', l):
                        in_pep621_deps = True
                        continue
                    if in_pep621_deps:
                        if l.startswith(']'):
                            in_pep621_deps = False
                            continue
                        m = re.search(r'["\']([^">=<~! ]+)', l)
                        if m:
                            manifest.py_deps.add(m.group(1).strip())
                
                # 2. Poetry 스타일 ([tool.poetry.dependencies])
                in_poetry_deps = False
                for line in content.split('\n'):
                    l = line.strip()
                    if l.startswith('[tool.poetry.dependencies]') or l.startswith('[tool.poetry.group.dev.dependencies]'):
                        in_poetry_deps = True
                        continue
                    if in_poetry_deps:
                        if l.startswith('['):
                            in_poetry_deps = False
                            continue
                        if '=' in l:
                            pkg = l.split('=')[0].strip()
                            if pkg and pkg.lower() != 'python':
                                manifest.py_deps.add(pkg)
                
                if Ecosystem.PYTHON not in manifest.detected_ecosystems:
                    manifest.detected_ecosystems.append(Ecosystem.PYTHON)
            except Exception:
                pass
    
    return manifest


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    'Ecosystem',
    'NODE_BUILTINS',
    'PYTHON_STDLIB',
    'GO_STDLIB',
    'get_file_ecosystem',
    'is_stdlib',
    'EcosystemImportInfo',
    'EcosystemAwareExtractor',
    'EcosystemPhantomResult',
    'EcosystemAwarePhantomDetector',
    'HybridManifest',
    'load_hybrid_manifest',
]
