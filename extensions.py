"""
depsolve_ext/extensions.py
==========================
í™•ìž¥ ê¸°ëŠ¥: ìƒíƒœê³„ ì¸ì‹ Import íŒ¨í„´, ëŸ°íƒ€ìž„ ê²€ì¦, ë‹¤ì¤‘ ìƒíƒœê³„ ì§€ì›

í•µì‹¬ ê¸°ëŠ¥:
1. ìƒíƒœê³„ ì¸ì‹ Import ì¶”ì¶œ (JS/TS, Python ë¶„ë¦¬)
2. ì™„ì „í•œ í‘œì¤€ ë¼ì´ë¸ŒëŸ¬ë¦¬ í•„í„°ë§ (Node.js, Python)
3. ê²©ë¦¬ëœ ëŸ°íƒ€ìž„ ê²€ì¦ (node_modules, site-packages)
4. í•˜ì´ë¸Œë¦¬ë“œ í”„ë¡œì íŠ¸ ì§€ì› (ì„œë¸Œë””ë ‰í† ë¦¬ ê²€ìƒ‰)
5. Ignore ê·œì¹™ ì§€ì› (ì •ê·œì‹ ê¸°ë°˜)

v0.4.0 ê°œì„ ì‚¬í•­:
- ì„œë¸Œë””ë ‰í† ë¦¬ manifest ê²€ìƒ‰ (backend/, server/, api/, ...)
- pyproject.toml ì™„ì „ íŒŒì‹± (PEP 621, Poetry, Flit)
- requirements-dev.txt ì§€ì›
- Ignore ê·œì¹™ ì‹œìŠ¤í…œ
- íŒ¨í‚¤ì§€ëª… ì •ê·œí™” ê°œì„  (pydantic-settings â†” pydantic_settings)
"""

import subprocess
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Pattern
from collections import defaultdict
from dataclasses import dataclass, field

from .models import (
    Ecosystem, ImportType, FileContext, VerifyStatus,
    ImportInfo, ResolveResult, PhantomResult, MultiVersionPkg, 
    PackageInfo, HybridManifest
)


# =============================================================================
# í‘œì¤€ ë¼ì´ë¸ŒëŸ¬ë¦¬ (Built-in) ëª©ë¡
# =============================================================================

NODE_BUILTINS = {
    # Node.js core modules (ì™„ì „í•œ ëª©ë¡)
    'assert', 'async_hooks', 'buffer', 'child_process', 'cluster', 'console',
    'constants', 'crypto', 'dgram', 'diagnostics_channel', 'dns', 'domain',
    'events', 'fs', 'http', 'http2', 'https', 'inspector', 'module', 'net',
    'os', 'path', 'perf_hooks', 'process', 'punycode', 'querystring', 'readline',
    'repl', 'stream', 'string_decoder', 'sys', 'timers', 'tls', 'trace_events',
    'tty', 'url', 'util', 'v8', 'vm', 'wasi', 'worker_threads', 'zlib',
}

# Python 3.8+ í‘œì¤€ ë¼ì´ë¸ŒëŸ¬ë¦¬ (ì£¼ìš” ëª¨ë“ˆ)
PYTHON_STDLIB = {
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
# í™•ìž¥ìž â†’ ìƒíƒœê³„ ë§¤í•‘
# =============================================================================

EXTENSION_ECOSYSTEM_MAP = {
    '.js': Ecosystem.JAVASCRIPT,
    '.jsx': Ecosystem.JAVASCRIPT,
    '.ts': Ecosystem.JAVASCRIPT,
    '.tsx': Ecosystem.JAVASCRIPT,
    '.mjs': Ecosystem.JAVASCRIPT,
    '.cjs': Ecosystem.JAVASCRIPT,
    '.vue': Ecosystem.JAVASCRIPT,
    '.svelte': Ecosystem.JAVASCRIPT,
    '.py': Ecosystem.PYTHON,
    '.pyx': Ecosystem.PYTHON,
    '.pxd': Ecosystem.PYTHON,
    '.go': Ecosystem.GO,
    '.rs': Ecosystem.RUST,
}


def get_file_ecosystem(filepath: str) -> Ecosystem:
    """íŒŒì¼ ê²½ë¡œì—ì„œ ìƒíƒœê³„ ì¶”ë¡ """
    path = Path(filepath)
    ext = path.suffix.lower()
    return EXTENSION_ECOSYSTEM_MAP.get(ext, Ecosystem.UNKNOWN)


def is_stdlib(package: str, ecosystem: Ecosystem) -> bool:
    """í•´ë‹¹ ìƒíƒœê³„ì˜ í‘œì¤€ ë¼ì´ë¸ŒëŸ¬ë¦¬ì¸ì§€ í™•ì¸"""
    base = package.split('.')[0].split('/')[0]
    
    if ecosystem == Ecosystem.JAVASCRIPT:
        if package.startswith('node:'):
            return True
        return base in NODE_BUILTINS
    elif ecosystem == Ecosystem.PYTHON:
        return base in PYTHON_STDLIB
    elif ecosystem == Ecosystem.GO:
        return base in GO_STDLIB
    
    return False


def normalize_package_name(name: str, ecosystem: Ecosystem = Ecosystem.PYTHON) -> str:
    """
    íŒ¨í‚¤ì§€ëª… ì •ê·œí™”
    
    Python: pydantic-settings â†’ pydantic_settings (PEP 503)
    """
    if ecosystem == Ecosystem.PYTHON:
        return name.lower().replace('-', '_').replace('.', '_')
    return name.lower()


def get_package_aliases(name: str, ecosystem: Ecosystem = Ecosystem.PYTHON) -> Set[str]:
    """
    íŒ¨í‚¤ì§€ì˜ ê°€ëŠ¥í•œ ëª¨ë“  ì´ë¦„ ë³€í˜• ë°˜í™˜
    
    ì˜ˆ: pydantic-settings â†’ {pydantic_settings, pydantic-settings, pydanticSettings}
    """
    aliases = {name.lower()}
    
    if ecosystem == Ecosystem.PYTHON:
        # í•˜ì´í”ˆ â†” ì–¸ë”ìŠ¤ì½”ì–´ ë³€í™˜
        aliases.add(name.lower().replace('-', '_'))
        aliases.add(name.lower().replace('_', '-'))
        # ì  ì²˜ë¦¬
        aliases.add(name.lower().replace('.', '_'))
        aliases.add(name.lower().replace('.', '-'))
    
    return aliases


# =============================================================================
# Ignore ê·œì¹™ ì‹œìŠ¤í…œ
# =============================================================================

@dataclass
class IgnoreRule:
    """ë¬´ì‹œ ê·œì¹™"""
    pattern: str
    regex: Optional[Pattern] = None
    ecosystem: Optional[Ecosystem] = None  # Noneì´ë©´ ëª¨ë“  ìƒíƒœê³„ì— ì ìš©
    reason: str = ""
    
    def __post_init__(self):
        if self.regex is None:
            try:
                self.regex = re.compile(self.pattern)
            except re.error:
                # ì •ê·œì‹ì´ ì•„ë‹ˆë©´ ê¸€ë¡œë¸Œ íŒ¨í„´ìœ¼ë¡œ ë³€í™˜
                escaped = re.escape(self.pattern)
                escaped = escaped.replace(r'\*', '.*').replace(r'\?', '.')
                self.regex = re.compile(f'^{escaped}$')
    
    def matches(self, package: str, pkg_ecosystem: Ecosystem) -> bool:
        """íŒ¨í‚¤ì§€ê°€ ì´ ê·œì¹™ì— ë§¤ì¹˜ë˜ëŠ”ì§€ í™•ì¸"""
        if self.ecosystem is not None and self.ecosystem != pkg_ecosystem:
            return False
        return bool(self.regex and self.regex.match(package))


@dataclass
class IgnoreConfig:
    """ë¬´ì‹œ ê·œì¹™ ì„¤ì •"""
    rules: List[IgnoreRule] = field(default_factory=list)
    
    # ê¸°ë³¸ ë¬´ì‹œ íŒ¨í„´ (ìŠ¤í‚µí•  ë””ë ‰í† ë¦¬)
    skip_dirs: Set[str] = field(default_factory=lambda: {
        'node_modules', '__pycache__', '.git', 'dist', 'build',
        '.history', '.vscode', '.idea', '.cache', '.next', '.nuxt',
        'coverage', '.tox', '.eggs', 'venv', '.venv', 'env', '.env',
        'site-packages', '.claude', '.cursor', '.github', '.gitlab',
    })
    
    # ê¸°ë³¸ ë¬´ì‹œ íŒ¨í„´ (íŒŒì¼)
    skip_file_patterns: List[str] = field(default_factory=lambda: [
        r'.*\.min\.js$',
        r'.*\.bundle\.js$',
        r'.*\.d\.ts$',  # TypeScript ì„ ì–¸ íŒŒì¼
    ])
    
    def add_rule(self, pattern: str, ecosystem: Optional[Ecosystem] = None, reason: str = ""):
        """ê·œì¹™ ì¶”ê°€"""
        self.rules.append(IgnoreRule(pattern=pattern, ecosystem=ecosystem, reason=reason))
    
    def add_skip_dir(self, dir_name: str):
        """ìŠ¤í‚µ ë””ë ‰í† ë¦¬ ì¶”ê°€"""
        self.skip_dirs.add(dir_name)
    
    def should_ignore_package(self, package: str, ecosystem: Ecosystem) -> Tuple[bool, str]:
        """íŒ¨í‚¤ì§€ë¥¼ ë¬´ì‹œí•´ì•¼ í•˜ëŠ”ì§€ í™•ì¸"""
        for rule in self.rules:
            if rule.matches(package, ecosystem):
                return True, rule.reason or f"Matched ignore rule: {rule.pattern}"
        return False, ""
    
    def should_skip_path(self, path: Path) -> bool:
        """ê²½ë¡œë¥¼ ìŠ¤í‚µí•´ì•¼ í•˜ëŠ”ì§€ í™•ì¸"""
        path_parts = set(path.parts)
        if path_parts & self.skip_dirs:
            return True
        
        path_str = str(path)
        for pattern in self.skip_file_patterns:
            if re.match(pattern, path_str):
                return True
        
        return False
    
    @classmethod
    def load_from_file(cls, config_path: Path) -> "IgnoreConfig":
        """ì„¤ì • íŒŒì¼ì—ì„œ ë¡œë“œ (.depsolve-ignore ë˜ëŠ” depsolve.config.json)"""
        config = cls()
        
        if not config_path.exists():
            return config
        
        try:
            if config_path.suffix == '.json':
                with open(config_path) as f:
                    data = json.load(f)
                
                for rule in data.get('ignore_packages', []):
                    if isinstance(rule, str):
                        config.add_rule(rule)
                    elif isinstance(rule, dict):
                        eco = None
                        if 'ecosystem' in rule:
                            eco = Ecosystem(rule['ecosystem'])
                        config.add_rule(
                            rule.get('pattern', ''),
                            ecosystem=eco,
                            reason=rule.get('reason', '')
                        )
                
                for dir_name in data.get('skip_dirs', []):
                    config.add_skip_dir(dir_name)
            
            else:
                # .depsolve-ignore í˜•ì‹ (gitignore ìŠ¤íƒ€ì¼)
                content = config_path.read_text()
                for line in content.split('\n'):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # [python] ë˜ëŠ” [javascript] ì ‘ë‘ì‚¬ ì²˜ë¦¬
                    eco = None
                    if line.startswith('[') and ']' in line:
                        eco_str, line = line[1:].split(']', 1)
                        eco_str = eco_str.strip().lower()
                        if eco_str in ('python', 'py'):
                            eco = Ecosystem.PYTHON
                        elif eco_str in ('javascript', 'js', 'node'):
                            eco = Ecosystem.JAVASCRIPT
                        line = line.strip()
                    
                    if line:
                        config.add_rule(line, ecosystem=eco)
        
        except Exception:
            pass
        
        return config


# =============================================================================
# Import íŒ¨í„´
# =============================================================================

class Patterns:
    """Import íŒ¨í„´ ì •ê·œì‹"""
    # JavaScript/TypeScript
    TYPE_IMPORT = re.compile(r'''import\s+type\s+[{}\w\s,*]+\s+from\s+['"]([^'"]+)['"]''')
    EXPORT_FROM = re.compile(r'''export\s+(?:\*|{[^}]*})\s+from\s+['"]([^'"]+)['"]''')
    JEST_MOCK = re.compile(r'''jest\.(?:mock|doMock|requireActual)\s*\(\s*['"]([^'"]+)['"]''')
    VITE_GLOB = re.compile(r'''import\.meta\.glob(?:Eager)?\s*\(\s*['"]([^'"]+)['"]''')
    WEBPACK = re.compile(r'''import\s*\(\s*/\*[^*]*\*/\s*['"]([^'"]+)['"]''')
    STATIC = re.compile(r'''import\s+(?:[\w{}\s,*]+\s+from\s+)?['"]([^'"]+)['"]''')
    DYNAMIC = re.compile(r'''import\s*\(\s*['"]([^'"]+)['"]\s*\)''')
    REQUIRE = re.compile(r'''require\s*\(\s*['"]([^'"]+)['"]\s*\)''')
    
    # Python
    PY_IMPORT = re.compile(r'''^\s*import\s+([\w.]+)''', re.MULTILINE)
    PY_FROM_IMPORT = re.compile(r'''^\s*from\s+([\w.]+)\s+import''', re.MULTILINE)
    PY_DUNDER_IMPORT = re.compile(r'''__import__\s*\(\s*['"]([^'"]+)['"]''')
    PY_IMPORTLIB = re.compile(r'''import_module\s*\(\s*['"]([^'"]+)['"]''')
    
    # íŒŒì¼ ì»¨í…ìŠ¤íŠ¸ íŒ¨í„´
    CONFIG_FILES = [
        r".*\.config\.(js|ts|mjs|cjs)$",
        r"(vite|webpack|tailwind|jest|babel)\.config\..*$",
        r"\.eslintrc.*$", r"\.prettierrc.*$",
    ]
    TEST_FILES = [r".*\.(test|spec)\.(js|ts|jsx|tsx|py)$", r"__tests__/.*$", r"test_.*\.py$"]
    SCRIPT_FILES = [r"scripts?/.*\.(js|ts|py)$"]


# =============================================================================
# ìƒíƒœê³„ ì¸ì‹ Import ì¶”ì¶œê¸°
# =============================================================================

class ImportExtractor:
    """
    ìƒíƒœê³„ ì¸ì‹ Import ì¶”ì¶œê¸°
    
    íŠ¹ì§•:
    - íŒŒì¼ í™•ìž¥ìžì— ë”°ë¼ ë‹¤ë¥¸ íŒ¨í„´ ì ìš©
    - ê° ìƒíƒœê³„ì˜ í‘œì¤€ ë¼ì´ë¸ŒëŸ¬ë¦¬ ìžë™ í•„í„°ë§
    - ìƒëŒ€ ê²½ë¡œ import ë¬´ì‹œ
    """
    
    def __init__(self, include_types: bool = True, filter_stdlib: bool = True,
                 ignore_config: Optional[IgnoreConfig] = None):
        self.include_types = include_types
        self.filter_stdlib = filter_stdlib
        self.ignore_config = ignore_config or IgnoreConfig()
        
        self._config_re = [re.compile(p) for p in Patterns.CONFIG_FILES]
        self._test_re = [re.compile(p) for p in Patterns.TEST_FILES]
        self._script_re = [re.compile(p) for p in Patterns.SCRIPT_FILES]
        
        # JS íŒ¨í„´ ìš°ì„ ìˆœìœ„
        self.js_patterns = [
            (Patterns.TYPE_IMPORT, ImportType.TYPE_ONLY, True),
            (Patterns.EXPORT_FROM, ImportType.RE_EXPORT, False),
            (Patterns.JEST_MOCK, ImportType.JEST_MOCK, False),
            (Patterns.VITE_GLOB, ImportType.VITE_GLOB, False),
            (Patterns.WEBPACK, ImportType.WEBPACK, False),
            (Patterns.STATIC, ImportType.STATIC, False),
            (Patterns.DYNAMIC, ImportType.DYNAMIC, False),
            (Patterns.REQUIRE, ImportType.REQUIRE, False),
        ]
    
    def extract_file(self, path: Path) -> List[ImportInfo]:
        """íŒŒì¼ì—ì„œ import ì¶”ì¶œ (ìƒíƒœê³„ ìžë™ ê°ì§€)"""
        if self.ignore_config.should_skip_path(path):
            return []
        
        ecosystem = get_file_ecosystem(str(path))
        
        if ecosystem == Ecosystem.UNKNOWN:
            return []
        
        try:
            content = path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return []
        
        ctx = self._detect_context(str(path))
        
        if ecosystem == Ecosystem.JAVASCRIPT:
            return self._extract_js(content, str(path), ctx)
        elif ecosystem == Ecosystem.PYTHON:
            return self._extract_python(content, str(path), ctx)
        
        return []
    
    def extract_content(self, content: str, filepath: str = "") -> List[ImportInfo]:
        """ë¬¸ìžì—´ì—ì„œ import ì¶”ì¶œ (ë ˆê±°ì‹œ í˜¸í™˜ - JSë§Œ)"""
        ctx = self._detect_context(filepath)
        return self._extract_js(content, filepath, ctx)
    
    def _extract_js(self, content: str, filepath: str, ctx: FileContext) -> List[ImportInfo]:
        """JavaScript/TypeScript import ì¶”ì¶œ"""
        imports: List[ImportInfo] = []
        seen: Set[str] = set()
        
        for line_num, line in enumerate(content.split('\n'), 1):
            if line.strip().startswith('//'):
                continue
            
            for pattern, imp_type, is_type in self.js_patterns:
                for match in pattern.finditer(line):
                    module = match.group(1)
                    package = self._get_js_package(module)
                    
                    if not package:
                        continue
                    if is_type and not self.include_types:
                        continue
                    if self.filter_stdlib and is_stdlib(package, Ecosystem.JAVASCRIPT):
                        continue
                    
                    # Ignore ê·œì¹™ ì²´í¬
                    should_ignore, _ = self.ignore_config.should_ignore_package(
                        package, Ecosystem.JAVASCRIPT
                    )
                    if should_ignore:
                        continue
                    
                    if package in seen:
                        continue
                    seen.add(package)
                    
                    imports.append(ImportInfo(
                        module=module,
                        package=package,
                        file=filepath,
                        line=line_num,
                        import_type=imp_type,
                        file_context=ctx,
                        is_type_only=is_type,
                        ecosystem=Ecosystem.JAVASCRIPT
                    ))
        
        return imports
    
    def _extract_python(self, content: str, filepath: str, ctx: FileContext) -> List[ImportInfo]:
        """Python import ì¶”ì¶œ (AST ê¸°ë°˜ - ë¬¸ìžì—´/ì£¼ì„ ì•ˆì˜ import ë¬´ì‹œ)"""
        imports: List[ImportInfo] = []
        seen: Set[str] = set()
        
        try:
            import ast
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                # import module, import module as alias
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        module = alias.name
                        self._add_python_import_ast(
                            imports, seen, module, filepath, 
                            node.lineno, ImportType.STATIC, ctx
                        )
                
                # from module import x
                elif isinstance(node, ast.ImportFrom):
                    if node.module:  # from . import xëŠ” moduleì´ None
                        self._add_python_import_ast(
                            imports, seen, node.module, filepath,
                            node.lineno, ImportType.FROM_IMPORT, ctx
                        )
        except SyntaxError:
            # AST íŒŒì‹± ì‹¤íŒ¨ ì‹œ ì •ê·œì‹ í´ë°± (ë¹„í‘œì¤€ Python íŒŒì¼)
            pass
        
        return imports
    
    def _add_python_import_ast(self, imports: List[ImportInfo], seen: Set[str],
                               module: str, filepath: str, line_num: int,
                               import_type: ImportType, ctx: FileContext):
        """Python import ì¶”ê°€ (ASTìš©)"""
        if module.startswith('.'):
            return
        
        package = module.split('.')[0]
        
        if self.filter_stdlib and is_stdlib(package, Ecosystem.PYTHON):
            return
        
        # Ignore ê·œì¹™ ì²´í¬
        should_ignore, _ = self.ignore_config.should_ignore_package(
            package, Ecosystem.PYTHON
        )
        if should_ignore:
            return
        
        if package in seen:
            return
        seen.add(package)
        
        imports.append(ImportInfo(
            module=module,
            package=package,
            file=filepath,
            line=line_num,
            import_type=import_type,
            file_context=ctx,
            ecosystem=Ecosystem.PYTHON
        ))
    
    def _get_js_package(self, module: str) -> Optional[str]:
        """JS ëª¨ë“ˆì—ì„œ íŒ¨í‚¤ì§€ëª… ì¶”ì¶œ"""
        if not module or module.startswith('.') or module.startswith('/'):
            return None
        if module.startswith('node:'):
            return None
        
        base = module.split('/')[0]
        if base in NODE_BUILTINS:
            return None
        
        if module.startswith('@'):
            parts = module.split('/')
            return f"{parts[0]}/{parts[1]}" if len(parts) >= 2 else None
        
        return base
    
    def _detect_context(self, filepath: str) -> FileContext:
        """íŒŒì¼ ì»¨í…ìŠ¤íŠ¸ ê°ì§€"""
        fp = filepath.replace('\\', '/')
        fn = fp.split('/')[-1]
        
        for p in self._config_re:
            if p.match(fn) or p.match(fp):
                return FileContext.CONFIG
        for p in self._test_re:
            if p.match(fn) or p.match(fp):
                return FileContext.TEST
        for p in self._script_re:
            if p.match(fp):
                return FileContext.SCRIPT
        
        return FileContext.SOURCE


# =============================================================================
# ëŸ°íƒ€ìž„ ê²€ì¦ê¸°
# =============================================================================

class RuntimeVerifier:
    """
    ëŸ°íƒ€ìž„ ê²€ì¦ê¸° (ìƒíƒœê³„ë³„ ê²©ë¦¬)
    
    JS: node_modules ê²€ì¦
    Python: importlib.metadata ê²€ì¦
    """
    
    def __init__(self, project_path: Path, timeout: int = 30):
        self.project = Path(project_path)
        self.timeout = timeout
        self._node: Optional[bool] = None
        self._npm: Optional[bool] = None
        self._cache: Dict[str, ResolveResult] = {}
    
    @property
    def node_available(self) -> bool:
        if self._node is None:
            try:
                r = subprocess.run(["node", "-v"], capture_output=True, timeout=5)
                self._node = r.returncode == 0
            except Exception:
                self._node = False
        return self._node
    
    @property
    def npm_available(self) -> bool:
        if self._npm is None:
            try:
                r = subprocess.run(["npm", "-v"], capture_output=True, timeout=5)
                self._npm = r.returncode == 0
            except Exception:
                self._npm = False
        return self._npm
    
    def verify(self, packages: List[str]) -> Dict[str, ResolveResult]:
        """íŒ¨í‚¤ì§€ ëª©ë¡ ê²€ì¦ (ë ˆê±°ì‹œ í˜¸í™˜ - JS)"""
        return self.verify_js(packages)
    
    def verify_js(self, packages: List[str]) -> Dict[str, ResolveResult]:
        """JS íŒ¨í‚¤ì§€ ê²€ì¦"""
        if not packages:
            return {}
        
        results = {p: self._cache[p] for p in packages if p in self._cache}
        to_check = [p for p in packages if p not in self._cache]
        
        if not to_check:
            return results
        
        # Node.jsë¡œ ë°°ì¹˜ ê²€ì¦
        if self.node_available:
            script = """
            const pkgs = %s;
            const r = {};
            for (const p of pkgs) {
                try {
                    require.resolve(p);
                    let v = null;
                    try { v = require(p + '/package.json').version; } catch {}
                    r[p] = {s: 'verified', v};
                } catch (e) {
                    r[p] = {s: 'not_found', e: e.message};
                }
            }
            console.log(JSON.stringify(r));
            """ % json.dumps(to_check)
            
            try:
                res = subprocess.run(
                    ["node", "-e", script],
                    cwd=self.project,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout
                )
                if res.returncode == 0 and res.stdout.strip():
                    data = json.loads(res.stdout.strip())
                    for p, info in data.items():
                        status = VerifyStatus.VERIFIED if info['s'] == 'verified' else VerifyStatus.NOT_FOUND
                        r = ResolveResult(p, status, info.get('v'), info.get('e'))
                        self._cache[p] = r
                        results[p] = r
                    return results
            except Exception:
                pass
        
        # í´ë°±: node_modules ìŠ¤ìº”
        for p in to_check:
            if p in results:
                continue
            version = self._scan_node_modules(p)
            if version:
                r = ResolveResult(p, VerifyStatus.VERIFIED, version)
            else:
                r = ResolveResult(p, VerifyStatus.NOT_FOUND)
            self._cache[p] = r
            results[p] = r
        
        return results
    
    def verify_python(self, packages: List[str]) -> Dict[str, ResolveResult]:
        """Python íŒ¨í‚¤ì§€ ê²€ì¦ (ë³„ì¹­ ì§€ì›)"""
        results: Dict[str, ResolveResult] = {}
        
        try:
            import importlib.metadata as metadata
        except ImportError:
            for p in packages:
                results[p] = ResolveResult(p, VerifyStatus.SKIPPED)
            return results
        
        for pkg in packages:
            found = False
            
            # ê°€ëŠ¥í•œ ëª¨ë“  íŒ¨í‚¤ì§€ëª… ë³€í˜• ì‹œë„
            aliases = get_package_aliases(pkg, Ecosystem.PYTHON)
            
            for alias in aliases:
                try:
                    dist = metadata.distribution(alias)
                    results[pkg] = ResolveResult(pkg, VerifyStatus.VERIFIED, dist.version)
                    found = True
                    break
                except metadata.PackageNotFoundError:
                    continue
                except Exception:
                    continue
            
            if not found:
                results[pkg] = ResolveResult(pkg, VerifyStatus.NOT_FOUND)
        
        return results
    
    def _scan_node_modules(self, package: str) -> Optional[str]:
        """node_modulesì—ì„œ íŒ¨í‚¤ì§€ ë²„ì „ í™•ì¸"""
        nm = self.project / "node_modules"
        if not nm.exists():
            return None
        
        if package.startswith('@'):
            parts = package.split('/')
            pkg_path = nm / parts[0] / parts[1] if len(parts) >= 2 else None
        else:
            pkg_path = nm / package
        
        if not pkg_path or not pkg_path.exists():
            return None
        
        pkg_json = pkg_path / "package.json"
        if pkg_json.exists():
            try:
                with open(pkg_json) as f:
                    return json.load(f).get("version")
            except Exception:
                pass
        
        return None
    
    def get_multi_versions(self) -> List[MultiVersionPkg]:
        """ë‹¤ì¤‘ ë²„ì „ ì„¤ì¹˜ëœ íŒ¨í‚¤ì§€ íƒì§€"""
        if not self.npm_available:
            return []
        
        try:
            res = subprocess.run(
                ["npm", "ls", "--json", "--all"],
                cwd=self.project,
                capture_output=True,
                text=True,
                timeout=60
            )
            if not res.stdout.strip():
                return []
            
            tree = json.loads(res.stdout)
            pkg_versions: Dict[str, Dict[str, List[List[str]]]] = {}
            
            def collect(node: Dict, path: List[str]):
                for name, info in node.get("dependencies", {}).items():
                    if info.get("deduped"):
                        continue
                    ver = info.get("version")
                    if ver:
                        if name not in pkg_versions:
                            pkg_versions[name] = {}
                        if ver not in pkg_versions[name]:
                            pkg_versions[name][ver] = []
                        pkg_versions[name][ver].append(path + [name])
                        collect(info, path + [name])
            
            collect(tree, [tree.get("name", "root")])
            
            return [
                MultiVersionPkg(
                    package=pkg,
                    versions=sorted(vers.keys()),
                    paths=[p for paths in vers.values() for p in paths]
                )
                for pkg, vers in pkg_versions.items()
                if len(vers) > 1
            ]
        except Exception:
            return []


# =============================================================================
# Phantom íƒì§€ê¸°
# =============================================================================

class PhantomDetector:
    """
    ìƒíƒœê³„ ì¸ì‹ Phantom íƒì§€ê¸°
    
    í•µì‹¬ ê°œì„ :
    - JS import â†’ package.json + node_modules ê²€ì¦
    - Python import â†’ requirements.txt + site-packages ê²€ì¦
    - ìƒíƒœê³„ í˜¼ìž¬ í”„ë¡œì íŠ¸ì—ì„œ cross-ecosystem ì˜¤íƒ ë°©ì§€
    - Ignore ê·œì¹™ ì§€ì›
    """
    
    SKIP_DIRS = [
        'node_modules', '__pycache__', '.git', 'dist', 'build',
        '.history', '.vscode', '.idea', '.cache', '.next', '.nuxt',
        'coverage', '.tox', '.eggs', '*.egg-info', 'venv', '.venv',
        'env', '.env', 'site-packages', '.claude', '.cursor',
    ]
    
    def __init__(
        self,
        project_path: Path,
        deps: Optional[Set[str]] = None,
        dev_deps: Optional[Set[str]] = None,
        js_deps: Optional[Set[str]] = None,
        js_dev_deps: Optional[Set[str]] = None,
        py_deps: Optional[Set[str]] = None,
        py_dev_deps: Optional[Set[str]] = None,
        verify: bool = False,
        ignore_config: Optional[IgnoreConfig] = None
    ):
        self.project = Path(project_path)
        
        # ë ˆê±°ì‹œ í˜¸í™˜: depsë¥¼ js_depsë¡œ ì‚¬ìš©
        if deps is not None and js_deps is None:
            js_deps = deps
        if dev_deps is not None and js_dev_deps is None:
            js_dev_deps = dev_deps
        
        # íŒ¨í‚¤ì§€ëª… ì •ê·œí™” (ëª¨ë“  ë³€í˜• í¬í•¨)
        self.js_deps = self._normalize_deps(js_deps or set(), Ecosystem.JAVASCRIPT)
        self.js_dev_deps = self._normalize_deps(js_dev_deps or set(), Ecosystem.JAVASCRIPT)
        self.py_deps = self._normalize_deps(py_deps or set(), Ecosystem.PYTHON)
        self.py_dev_deps = self._normalize_deps(py_dev_deps or set(), Ecosystem.PYTHON)
        
        self.verify = verify
        self.ignore_config = ignore_config or self._load_default_ignore_config()
        self.extractor = ImportExtractor(filter_stdlib=True, ignore_config=self.ignore_config)
        self.verifier = RuntimeVerifier(project_path) if verify else None
        
        # ë‚´ë¶€ ëª¨ë“ˆ ìŠ¤ìº” (í”„ë¡œì íŠ¸ ë‚´ .py íŒŒì¼ëª…)
        self._local_py_modules = self._scan_local_modules()
        self._local_js_modules = self._scan_local_js_modules()
    
    def _normalize_deps(self, deps: Set[str], ecosystem: Ecosystem) -> Set[str]:
        """ì˜ì¡´ì„± ëª©ë¡ ì •ê·œí™” (ëª¨ë“  ë³€í˜• í¬í•¨)"""
        normalized = set()
        for dep in deps:
            normalized.update(get_package_aliases(dep, ecosystem))
        return normalized
    
    def _load_default_ignore_config(self) -> IgnoreConfig:
        """ê¸°ë³¸ ignore ì„¤ì • ë¡œë“œ"""
        # í”„ë¡œì íŠ¸ ë£¨íŠ¸ì—ì„œ ì„¤ì • íŒŒì¼ ì°¾ê¸°
        for config_name in ['.depsolve-ignore', 'depsolve.config.json', '.depsolverc']:
            config_path = self.project / config_name
            if config_path.exists():
                return IgnoreConfig.load_from_file(config_path)
        
        return IgnoreConfig()
    
    def _scan_local_modules(self) -> Set[str]:
        """í”„ë¡œì íŠ¸ ë‚´ë¶€ Python ëª¨ë“ˆ ìŠ¤ìº”"""
        local_modules: Set[str] = set()
        
        for py_file in self.project.rglob('*.py'):
            if self._should_skip(py_file):
                continue
            # íŒŒì¼ëª…ì—ì„œ .py ì œê±°
            module_name = py_file.stem
            if module_name != '__init__':
                local_modules.add(module_name.lower())
            
            # ë””ë ‰í† ë¦¬ëª…ë„ íŒ¨í‚¤ì§€ë¡œ ê°„ì£¼ (__init__.pyê°€ ìžˆìœ¼ë©´)
            if py_file.name == '__init__.py':
                local_modules.add(py_file.parent.name.lower())
        
        return local_modules
    
    def _scan_local_js_modules(self) -> Set[str]:
        """í”„ë¡œì íŠ¸ ë‚´ë¶€ JS ëª¨ë“ˆ ìŠ¤ìº”"""
        local_modules: Set[str] = set()
        js_exts = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']
        
        for ext in js_exts:
            for js_file in self.project.rglob(f'*{ext}'):
                if self._should_skip(js_file):
                    continue
                module_name = js_file.stem
                local_modules.add(module_name.lower())
        
        return local_modules
    
    def detect(self, source_dirs: Optional[List[str]] = None) -> List[PhantomResult]:
        """Phantom ì˜ì¡´ì„± íƒì§€"""
        source_dirs = source_dirs or ['.', 'src', 'lib', 'app', 'backend', 'server']
        
        # 1. Import ìˆ˜ì§‘
        all_imports = self._collect_imports(source_dirs)
        
        # 2. ìƒíƒœê³„ë³„ ê·¸ë£¹í™”
        js_imports: Dict[str, List[ImportInfo]] = defaultdict(list)
        py_imports: Dict[str, List[ImportInfo]] = defaultdict(list)
        
        for imp in all_imports:
            if imp.ecosystem == Ecosystem.JAVASCRIPT:
                js_imports[imp.package.lower()].append(imp)
            elif imp.ecosystem == Ecosystem.PYTHON:
                normalized = normalize_package_name(imp.package, Ecosystem.PYTHON)
                py_imports[normalized].append(imp)
        
        # 3. ìƒíƒœê³„ë³„ Phantom í›„ë³´ í•„í„°ë§
        candidates: List[PhantomResult] = []
        
        # JS Phantoms
        for pkg, imports in js_imports.items():
            # ë‚´ë¶€ JS ëª¨ë“ˆì´ë©´ ìŠ¤í‚µ
            if pkg in self._local_js_modules:
                continue
            
            # ì˜ì¡´ì„±ì— ìžˆìœ¼ë©´ ìŠ¤í‚µ (ì •ê·œí™”ëœ ì´ë¦„ìœ¼ë¡œ ë¹„êµ)
            if pkg in self.js_deps or pkg in self.js_dev_deps:
                continue
            
            all_non_source = all(
                imp.file_context in (FileContext.CONFIG, FileContext.TEST, FileContext.SCRIPT)
                for imp in imports
            )
            if all_non_source and pkg in self.js_dev_deps:
                continue
            
            candidates.append(PhantomResult(
                package=pkg,
                imports=imports,
                reason="Not in package.json dependencies",
                ecosystem=Ecosystem.JAVASCRIPT
            ))
        
        # Python Phantoms
        for pkg, imports in py_imports.items():
            # ë‚´ë¶€ Python ëª¨ë“ˆì´ë©´ ìŠ¤í‚µ
            if pkg in self._local_py_modules:
                continue
            
            # ì˜ì¡´ì„±ì— ìžˆìœ¼ë©´ ìŠ¤í‚µ (ì •ê·œí™”ëœ ì´ë¦„ìœ¼ë¡œ ë¹„êµ)
            if pkg in self.py_deps or pkg in self.py_dev_deps:
                continue
            
            candidates.append(PhantomResult(
                package=pkg,
                imports=imports,
                reason="Not in Python dependencies",
                ecosystem=Ecosystem.PYTHON
            ))
        
        # 4. ëŸ°íƒ€ìž„ ê²€ì¦
        if self.verify and self.verifier:
            self._verify_candidates(candidates)
        
        return candidates
    
    def _collect_imports(self, dirs: List[str]) -> List[ImportInfo]:
        """ì†ŒìŠ¤ ë””ë ‰í† ë¦¬ì—ì„œ import ìˆ˜ì§‘"""
        imports: List[ImportInfo] = []
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
        """ìŠ¤í‚µ ì—¬ë¶€"""
        # Ignore config ì²´í¬
        if self.ignore_config.should_skip_path(path):
            return True
        
        # ê¸°ë³¸ ìŠ¤í‚µ ë””ë ‰í† ë¦¬ ì²´í¬
        path_str = str(path)
        return any(skip_dir in path_str.split('/') for skip_dir in self.SKIP_DIRS)
    
    def _verify_candidates(self, candidates: List[PhantomResult]):
        """ëŸ°íƒ€ìž„ ê²€ì¦"""
        js_candidates = [c for c in candidates if c.ecosystem == Ecosystem.JAVASCRIPT]
        py_candidates = [c for c in candidates if c.ecosystem == Ecosystem.PYTHON]
        
        # JS ê²€ì¦
        if js_candidates and self.verifier:
            js_results = self.verifier.verify_js([c.package for c in js_candidates])
            for c in js_candidates:
                r = js_results.get(c.package)
                if r and r.status == VerifyStatus.VERIFIED:
                    c.is_phantom = False
                    c.installed_version = r.version
                    c.reason = f"Installed as transitive (v{r.version})"
        
        # Python ê²€ì¦
        if py_candidates and self.verifier:
            py_results = self.verifier.verify_python([c.package for c in py_candidates])
            for c in py_candidates:
                r = py_results.get(c.package)
                if r and r.status == VerifyStatus.VERIFIED:
                    c.is_phantom = False
                    c.installed_version = r.version
                    c.reason = f"Installed (v{r.version})"


# =============================================================================
# Manifest ë¡œë” (ê°œì„ ë¨)
# =============================================================================

def load_hybrid_manifest(project_path: Path) -> HybridManifest:
    """
    í•˜ì´ë¸Œë¦¬ë“œ í”„ë¡œì íŠ¸ì˜ ëª¨ë“  manifest ë¡œë“œ
    
    ê°œì„ ì‚¬í•­:
    - ì„œë¸Œë””ë ‰í† ë¦¬ ê²€ìƒ‰ (backend/, server/, api/, ...)
    - requirements-dev.txt ì§€ì›
    - pyproject.toml ì™„ì „ íŒŒì‹± (PEP 621, Poetry, Flit)
    - íŒ¨í‚¤ì§€ëª… ì •ê·œí™”
    """
    manifest = HybridManifest()
    project = Path(project_path)
    
    # ê²€ìƒ‰í•  í›„ë³´ ë””ë ‰í† ë¦¬ (ë£¨íŠ¸ + ì„œë¸Œë””ë ‰í† ë¦¬)
    search_dirs = [project]
    for subdir in ['backend', 'server', 'api', 'src', 'app', 'lib', 'packages']:
        candidate = project / subdir
        if candidate.exists() and candidate.is_dir():
            search_dirs.append(candidate)
    
    for d in search_dirs:
        _load_npm_manifest(d, manifest)
        _load_pip_manifest(d, manifest)
        _load_pyproject_toml(d, manifest)
        _load_go_manifest(d, manifest)
        _load_cargo_manifest(d, manifest)
    
    return manifest


def _load_npm_manifest(directory: Path, manifest: HybridManifest):
    """package.json ë¡œë“œ"""
    pkg_json = directory / "package.json"
    if not pkg_json.exists():
        return
    
    try:
        with open(pkg_json) as f:
            data = json.load(f)
        manifest.js_deps.update(data.get("dependencies", {}).keys())
        manifest.js_dev_deps.update(data.get("devDependencies", {}).keys())
        if Ecosystem.JAVASCRIPT not in manifest.detected_ecosystems:
            manifest.detected_ecosystems.append(Ecosystem.JAVASCRIPT)
    except Exception:
        pass


def _load_pip_manifest(directory: Path, manifest: HybridManifest):
    """requirements.txt ë° requirements-dev.txt ë¡œë“œ"""
    # ë©”ì¸ requirements
    for req_file in ['requirements.txt', 'requirements.in']:
        req_path = directory / req_file
        if req_path.exists():
            _parse_requirements_txt(req_path, manifest.py_deps)
            if Ecosystem.PYTHON not in manifest.detected_ecosystems:
                manifest.detected_ecosystems.append(Ecosystem.PYTHON)
    
    # Dev requirements
    for req_file in ['requirements-dev.txt', 'requirements_dev.txt', 
                     'dev-requirements.txt', 'requirements-test.txt']:
        req_path = directory / req_file
        if req_path.exists():
            _parse_requirements_txt(req_path, manifest.py_dev_deps)
            if Ecosystem.PYTHON not in manifest.detected_ecosystems:
                manifest.detected_ecosystems.append(Ecosystem.PYTHON)


def _parse_requirements_txt(path: Path, deps_set: Set[str]):
    """requirements.txt íŒŒì‹±"""
    try:
        content = path.read_text()
        for line in content.split('\n'):
            line = line.strip()
            
            # ë¹ˆ ì¤„, ì£¼ì„, ì˜µì…˜ ë¬´ì‹œ
            if not line or line.startswith('#') or line.startswith('-'):
                continue
            
            # URL í˜•ì‹ ë¬´ì‹œ (git+https://... ë“±)
            if '://' in line or line.startswith('git+'):
                continue
            
            # ë²„ì „ ëª…ì‹œìž ë¶„ë¦¬
            for sep in ['==', '>=', '<=', '~=', '!=', '>', '<', '[', '@', ';']:
                if sep in line:
                    line = line.split(sep)[0]
                    break
            
            pkg_name = line.strip()
            if pkg_name:
                deps_set.add(pkg_name)
    except Exception:
        pass


def _load_pyproject_toml(directory: Path, manifest: HybridManifest):
    """
    pyproject.toml ì™„ì „ íŒŒì‹±
    
    ì§€ì› í˜•ì‹:
    - PEP 621 (project.dependencies)
    - Poetry ([tool.poetry.dependencies])
    - Flit ([tool.flit.metadata])
    - PDM ([tool.pdm.dependencies])
    """
    pyproject = directory / "pyproject.toml"
    if not pyproject.exists():
        return
    
    try:
        content = pyproject.read_text()
        
        # 1. PEP 621 ìŠ¤íƒ€ì¼: [project] dependencies = [...]
        _parse_pep621_deps(content, manifest)
        
        # 2. Poetry ìŠ¤íƒ€ì¼: [tool.poetry.dependencies]
        _parse_poetry_deps(content, manifest)
        
        if Ecosystem.PYTHON not in manifest.detected_ecosystems:
            manifest.detected_ecosystems.append(Ecosystem.PYTHON)
    
    except Exception:
        pass


def _parse_pep621_deps(content: str, manifest: HybridManifest):
    """PEP 621 í˜•ì‹ íŒŒì‹±"""
    # dependencies = ["pkg1", "pkg2>=1.0"]
    deps_match = re.search(
        r'\[project\].*?dependencies\s*=\s*\[(.*?)\]',
        content, re.DOTALL
    )
    
    if deps_match:
        deps_str = deps_match.group(1)
        for match in re.finditer(r'["\']([^"\'>=<~!\[\];\s]+)', deps_str):
            pkg = match.group(1).strip()
            if pkg and not pkg.startswith('#'):
                manifest.py_deps.add(pkg)
    
    # optional-dependencies (dev deps)
    opt_deps_match = re.search(
        r'\[project\.optional-dependencies\](.*?)(?=\n\[|\Z)',
        content, re.DOTALL
    )
    
    if opt_deps_match:
        opt_section = opt_deps_match.group(1)
        for match in re.finditer(r'["\']([^"\'>=<~!\[\];\s]+)', opt_section):
            pkg = match.group(1).strip()
            if pkg and not pkg.startswith('#'):
                manifest.py_dev_deps.add(pkg)


def _parse_poetry_deps(content: str, manifest: HybridManifest):
    """Poetry í˜•ì‹ íŒŒì‹±"""
    # [tool.poetry.dependencies]
    poetry_deps_match = re.search(
        r'\[tool\.poetry\.dependencies\](.*?)(?=\n\[|\Z)',
        content, re.DOTALL
    )
    
    if poetry_deps_match:
        deps_section = poetry_deps_match.group(1)
        for line in deps_section.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('['):
                continue
            if '=' in line:
                pkg = line.split('=')[0].strip()
                if pkg and pkg.lower() != 'python':
                    manifest.py_deps.add(pkg)
    
    # [tool.poetry.group.dev.dependencies] ë˜ëŠ” [tool.poetry.dev-dependencies]
    for pattern in [
        r'\[tool\.poetry\.group\.dev\.dependencies\](.*?)(?=\n\[|\Z)',
        r'\[tool\.poetry\.dev-dependencies\](.*?)(?=\n\[|\Z)',
    ]:
        dev_deps_match = re.search(pattern, content, re.DOTALL)
        if dev_deps_match:
            dev_section = dev_deps_match.group(1)
            for line in dev_section.split('\n'):
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('['):
                    continue
                if '=' in line:
                    pkg = line.split('=')[0].strip()
                    if pkg:
                        manifest.py_dev_deps.add(pkg)


def _load_go_manifest(directory: Path, manifest: HybridManifest):
    """go.mod ë¡œë“œ"""
    go_mod = directory / "go.mod"
    if not go_mod.exists():
        return
    
    try:
        content = go_mod.read_text()
        
        # require block
        for block in re.finditer(r'require\s*\((.*?)\)', content, re.DOTALL):
            for line in block.group(1).split('\n'):
                line = line.strip()
                if line and not line.startswith('//'):
                    parts = line.split()
                    if parts:
                        manifest.go_deps.add(parts[0])
        
        # single require
        for match in re.finditer(r'^require\s+(\S+)', content, re.MULTILINE):
            manifest.go_deps.add(match.group(1))
        
        if Ecosystem.GO not in manifest.detected_ecosystems:
            manifest.detected_ecosystems.append(Ecosystem.GO)
    except Exception:
        pass


def _load_cargo_manifest(directory: Path, manifest: HybridManifest):
    """Cargo.toml ë¡œë“œ"""
    cargo_toml = directory / "Cargo.toml"
    if not cargo_toml.exists():
        return
    
    try:
        content = cargo_toml.read_text()
        
        # [dependencies] ì„¹ì…˜
        deps_match = re.search(
            r'\[dependencies\](.*?)(?=\n\[|\Z)',
            content, re.DOTALL
        )
        
        if deps_match:
            deps_section = deps_match.group(1)
            for line in deps_section.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    pkg = line.split('=')[0].strip()
                    if pkg:
                        manifest.rust_deps.add(pkg)
        
        if Ecosystem.RUST not in manifest.detected_ecosystems:
            manifest.detected_ecosystems.append(Ecosystem.RUST)
    except Exception:
        pass


# =============================================================================
# ë‹¤ì¤‘ ìƒíƒœê³„ ì–´ëŒ‘í„° (ë ˆê±°ì‹œ í˜¸í™˜)
# =============================================================================

class GoAdapter:
    """Go ìƒíƒœê³„ ì–´ëŒ‘í„°"""
    
    def __init__(self, project_path: Path):
        self.project = Path(project_path)
    
    def detect(self) -> bool:
        return (self.project / "go.mod").exists()
    
    def get_info(self) -> PackageInfo:
        content = (self.project / "go.mod").read_text()
        
        m = re.search(r'^module\s+(\S+)', content, re.MULTILINE)
        name = m.group(1) if m else "unknown"
        
        m = re.search(r'^go\s+(\d+\.\d+)', content, re.MULTILINE)
        version = m.group(1) if m else "1.0"
        
        deps: Dict[str, str] = {}
        for block in re.finditer(r'require\s*\((.*?)\)', content, re.DOTALL):
            for line in block.group(1).split('\n'):
                line = line.strip()
                if line and not line.startswith('//'):
                    parts = line.split()
                    if len(parts) >= 2:
                        deps[parts[0]] = parts[1]
        
        for m in re.finditer(r'^require\s+(\S+)\s+(\S+)', content, re.MULTILINE):
            deps[m.group(1)] = m.group(2)
        
        return PackageInfo(name=name, version=version, dependencies=deps)


class CargoAdapter:
    """Rust/Cargo ìƒíƒœê³„ ì–´ëŒ‘í„°"""
    
    def __init__(self, project_path: Path):
        self.project = Path(project_path)
    
    def detect(self) -> bool:
        return (self.project / "Cargo.toml").exists()
    
    def get_info(self) -> PackageInfo:
        content = (self.project / "Cargo.toml").read_text()
        parsed = self._parse_toml(content)
        
        pkg = parsed.get('package', {})
        
        deps: Dict[str, str] = {}
        for k, v in parsed.get('dependencies', {}).items():
            deps[k] = v.get('version', '*') if isinstance(v, dict) else str(v)
        
        dev_deps: Dict[str, str] = {}
        for k, v in parsed.get('dev-dependencies', {}).items():
            dev_deps[k] = v.get('version', '*') if isinstance(v, dict) else str(v)
        
        return PackageInfo(
            name=pkg.get('name', 'unknown'),
            version=pkg.get('version', '0.0.0'),
            dependencies=deps,
            dev_dependencies=dev_deps
        )
    
    def _parse_toml(self, content: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        section: List[str] = []
        
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if line.startswith('['):
                m = re.match(r'\[+([^\]]+)\]+', line)
                if m:
                    section = m.group(1).split('.')
                continue
            
            if '=' in line:
                k, _, v = line.partition('=')
                k, v = k.strip(), v.strip().strip('"\'')
                
                if v.startswith('{'):
                    v = {
                        kk.strip(): vv.strip().strip('"\'')
                        for item in v[1:-1].split(',') if '=' in item
                        for kk, _, vv in [item.partition('=')]
                    }
                
                target = result
                for s in section:
                    target = target.setdefault(s, {})
                target[k] = v
        
        return result


class EcosystemDetector:
    """ìƒíƒœê³„ ìžë™ ê°ì§€ê¸°"""
    
    ADAPTERS = [GoAdapter, CargoAdapter]
    
    @classmethod
    def detect(cls, path: Path) -> List[Tuple[str, Any]]:
        results: List[Tuple[str, Any]] = []
        for adapter_cls in cls.ADAPTERS:
            try:
                adapter = adapter_cls(path)
                if adapter.detect():
                    name = adapter_cls.__name__.replace('Adapter', '').lower()
                    results.append((name, adapter))
            except Exception:
                pass
        return results


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    'Patterns',
    'ImportExtractor',
    'RuntimeVerifier',
    'PhantomDetector',
    'GoAdapter',
    'CargoAdapter',
    'EcosystemDetector',
    'IgnoreRule',
    'IgnoreConfig',
    'load_hybrid_manifest',
    'get_file_ecosystem',
    'is_stdlib',
    'normalize_package_name',
    'get_package_aliases',
    'NODE_BUILTINS',
    'PYTHON_STDLIB',
    'GO_STDLIB',
    'EXTENSION_ECOSYSTEM_MAP',
]
