#!/usr/bin/env python3
"""
depsolve_ext/tests.py
=====================
í†µí•© í…ŒìŠ¤íŠ¸

ì‹¤í–‰:
    python -m pytest tests.py -v
    python tests.py
"""

import unittest
import tempfile
import json
from pathlib import Path

from .models import (
    IssueType, Severity, ImportType, FileContext, VerifyStatus,
    PackageNode, DependencyEdge, CycleInfo, DiamondInfo, Ecosystem
)
from .graph import DependencyGraph
from .extensions import (
    ImportExtractor, RuntimeVerifier, PhantomDetector,
    GoAdapter, CargoAdapter, EcosystemDetector,
    get_file_ecosystem, is_stdlib, load_hybrid_manifest,
    normalize_package_name, get_package_aliases,
    IgnoreRule, IgnoreConfig,
    NODE_BUILTINS, PYTHON_STDLIB
)
from .analyzer import DependencyAnalyzer, analyze


class TestGraph(unittest.TestCase):
    """ê·¸ëž˜í”„ í…ŒìŠ¤íŠ¸"""
    
    def test_add_nodes_edges(self):
        """ë…¸ë“œ/ì—£ì§€ ì¶”ê°€"""
        g = DependencyGraph()
        g.add_node("A", "1.0.0")
        g.add_edge(DependencyEdge(source="A", target="B", version_range="^2.0.0"))
        
        self.assertEqual(g.node_count, 2)
        self.assertEqual(g.edge_count, 1)
        self.assertTrue(g.has_node("A"))
        self.assertTrue(g.has_edge("A", "B"))
    
    def test_find_cycles(self):
        """ìˆœí™˜ íƒì§€"""
        g = DependencyGraph()
        g.add_edge(DependencyEdge(source="A", target="B"))
        g.add_edge(DependencyEdge(source="B", target="C"))
        g.add_edge(DependencyEdge(source="C", target="A"))
        
        cycles = g.find_cycles()
        self.assertEqual(len(cycles), 1)
        self.assertEqual(set(cycles[0].path[:-1]), {"A", "B", "C"})
    
    def test_no_cycle(self):
        """ìˆœí™˜ ì—†ìŒ"""
        g = DependencyGraph()
        g.add_edge(DependencyEdge(source="A", target="B"))
        g.add_edge(DependencyEdge(source="B", target="C"))
        
        self.assertFalse(g.has_cycle())
    
    def test_find_diamonds(self):
        """ë‹¤ì´ì•„ëª¬ë“œ íƒì§€"""
        g = DependencyGraph()
        g.add_edge(DependencyEdge(source="A", target="B"))
        g.add_edge(DependencyEdge(source="A", target="C"))
        g.add_edge(DependencyEdge(source="B", target="D", version_range="^1.0.0"))
        g.add_edge(DependencyEdge(source="C", target="D", version_range="^2.0.0"))
        
        diamonds = g.find_diamonds()
        self.assertEqual(len(diamonds), 1)
        self.assertEqual(diamonds[0].bottom, "D")
        self.assertTrue(diamonds[0].has_version_conflict)
    
    def test_mermaid_output(self):
        """Mermaid ì¶œë ¥"""
        g = DependencyGraph()
        g.add_edge(DependencyEdge(source="A", target="B", version_range="^1.0.0"))
        
        mermaid = g.to_mermaid()
        self.assertIn("graph TD", mermaid)
        self.assertIn("-->", mermaid)
    
    def test_transitive_deps(self):
        """ì „ì´ì  ì˜ì¡´ì„±"""
        g = DependencyGraph()
        g.add_edge(DependencyEdge(source="A", target="B"))
        g.add_edge(DependencyEdge(source="B", target="C"))
        g.add_edge(DependencyEdge(source="C", target="D"))
        
        deps = g.get_transitive_dependencies("A")
        self.assertEqual(deps, {"B", "C", "D"})


class TestEcosystemDetection(unittest.TestCase):
    """ìƒíƒœê³„ ê°ì§€ í…ŒìŠ¤íŠ¸"""
    
    def test_js_extensions(self):
        """JS/TS í™•ìž¥ìž ê°ì§€"""
        self.assertEqual(get_file_ecosystem("app.js"), Ecosystem.JAVASCRIPT)
        self.assertEqual(get_file_ecosystem("App.tsx"), Ecosystem.JAVASCRIPT)
        self.assertEqual(get_file_ecosystem("index.mjs"), Ecosystem.JAVASCRIPT)
    
    def test_python_extensions(self):
        """Python í™•ìž¥ìž ê°ì§€"""
        self.assertEqual(get_file_ecosystem("main.py"), Ecosystem.PYTHON)
        self.assertEqual(get_file_ecosystem("utils.pyx"), Ecosystem.PYTHON)
    
    def test_unknown_extensions(self):
        """ì•Œ ìˆ˜ ì—†ëŠ” í™•ìž¥ìž"""
        self.assertEqual(get_file_ecosystem("readme.md"), Ecosystem.UNKNOWN)


class TestStdlibFiltering(unittest.TestCase):
    """í‘œì¤€ ë¼ì´ë¸ŒëŸ¬ë¦¬ í•„í„°ë§ í…ŒìŠ¤íŠ¸"""
    
    def test_node_builtins(self):
        """Node.js ë‚´ìž¥ ëª¨ë“ˆ"""
        self.assertTrue(is_stdlib('fs', Ecosystem.JAVASCRIPT))
        self.assertTrue(is_stdlib('https', Ecosystem.JAVASCRIPT))
        self.assertTrue(is_stdlib('path', Ecosystem.JAVASCRIPT))
        self.assertTrue(is_stdlib('node:fs', Ecosystem.JAVASCRIPT))
        
        self.assertFalse(is_stdlib('express', Ecosystem.JAVASCRIPT))
        self.assertFalse(is_stdlib('react', Ecosystem.JAVASCRIPT))
    
    def test_python_stdlib(self):
        """Python í‘œì¤€ ë¼ì´ë¸ŒëŸ¬ë¦¬"""
        self.assertTrue(is_stdlib('os', Ecosystem.PYTHON))
        self.assertTrue(is_stdlib('sys', Ecosystem.PYTHON))
        self.assertTrue(is_stdlib('json', Ecosystem.PYTHON))
        self.assertTrue(is_stdlib('pathlib', Ecosystem.PYTHON))
        
        self.assertFalse(is_stdlib('requests', Ecosystem.PYTHON))
        self.assertFalse(is_stdlib('numpy', Ecosystem.PYTHON))


class TestPackageNameNormalization(unittest.TestCase):
    """íŒ¨í‚¤ì§€ëª… ì •ê·œí™” í…ŒìŠ¤íŠ¸"""
    
    def test_hyphen_to_underscore(self):
        """í•˜ì´í”ˆ â†’ ì–¸ë”ìŠ¤ì½”ì–´"""
        self.assertEqual(normalize_package_name("pydantic-settings"), "pydantic_settings")
        self.assertEqual(normalize_package_name("scikit-learn"), "scikit_learn")
    
    def test_already_normalized(self):
        """ì´ë¯¸ ì •ê·œí™”ëœ ì´ë¦„"""
        self.assertEqual(normalize_package_name("pydantic_settings"), "pydantic_settings")
        self.assertEqual(normalize_package_name("requests"), "requests")
    
    def test_case_normalization(self):
        """ëŒ€ì†Œë¬¸ìž ì •ê·œí™”"""
        self.assertEqual(normalize_package_name("PyYAML"), "pyyaml")
        self.assertEqual(normalize_package_name("Flask"), "flask")
    
    def test_dot_handling(self):
        """ì  ì²˜ë¦¬"""
        self.assertEqual(normalize_package_name("zope.interface"), "zope_interface")
    
    def test_get_aliases(self):
        """ë³„ì¹­ ìƒì„±"""
        aliases = get_package_aliases("pydantic-settings")
        self.assertIn("pydantic-settings", aliases)
        self.assertIn("pydantic_settings", aliases)
        
        # ì´ë¯¸ ì •ê·œí™”ëœ ì´ë¦„
        aliases2 = get_package_aliases("requests")
        self.assertEqual(aliases2, {"requests"})


class TestIgnoreConfig(unittest.TestCase):
    """Ignore ê·œì¹™ í…ŒìŠ¤íŠ¸"""
    
    def test_basic_rule(self):
        """ê¸°ë³¸ ê·œì¹™"""
        config = IgnoreConfig()
        config.add_rule("pytest")
        
        ignored, _ = config.should_ignore_package("pytest", Ecosystem.PYTHON)
        self.assertTrue(ignored)
        ignored, _ = config.should_ignore_package("requests", Ecosystem.PYTHON)
        self.assertFalse(ignored)
    
    def test_regex_rule(self):
        """ì •ê·œì‹ ê·œì¹™ (ì™€ì¼ë“œì¹´ë“œ)"""
        config = IgnoreConfig()
        config.add_rule("mypy*")  # ê¸€ë¡œë¸Œ íŒ¨í„´ â†’ ì •ê·œì‹ìœ¼ë¡œ ë³€í™˜ë¨
        
        ignored, _ = config.should_ignore_package("mypy", Ecosystem.PYTHON)
        self.assertTrue(ignored)
        ignored, _ = config.should_ignore_package("mypy-extensions", Ecosystem.PYTHON)
        self.assertTrue(ignored)
        ignored, _ = config.should_ignore_package("pytest", Ecosystem.PYTHON)
        self.assertFalse(ignored)
    
    def test_ecosystem_specific_rule(self):
        """ìƒíƒœê³„ë³„ ê·œì¹™"""
        config = IgnoreConfig()
        config.add_rule("pytest", ecosystem=Ecosystem.PYTHON)
        
        ignored, _ = config.should_ignore_package("pytest", Ecosystem.PYTHON)
        self.assertTrue(ignored)
        ignored, _ = config.should_ignore_package("pytest", Ecosystem.JAVASCRIPT)
        self.assertFalse(ignored)
    
    def test_skip_dirs(self):
        """ìŠ¤í‚µ ë””ë ‰í† ë¦¬"""
        config = IgnoreConfig()
        config.add_skip_dir(".mypy_cache")
        
        self.assertTrue(config.should_skip_path(Path("/project/.mypy_cache/file.py")))
        self.assertFalse(config.should_skip_path(Path("/project/src/file.py")))
    
    def test_load_from_file(self):
        """íŒŒì¼ì—ì„œ ë¡œë“œ"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            
            # .depsolve-ignore íŒŒì¼ ìƒì„±
            ignore_file = project / ".depsolve-ignore"
            ignore_file.write_text("""
# í…ŒìŠ¤íŠ¸ ë„êµ¬
pytest
mypy
[python] black
[javascript] eslint
            """)
            
            config = IgnoreConfig.load_from_file(ignore_file)
            
            ignored, _ = config.should_ignore_package("pytest", Ecosystem.PYTHON)
            self.assertTrue(ignored)
            ignored, _ = config.should_ignore_package("mypy", Ecosystem.PYTHON)
            self.assertTrue(ignored)
            ignored, _ = config.should_ignore_package("black", Ecosystem.PYTHON)
            self.assertTrue(ignored)
            ignored, _ = config.should_ignore_package("black", Ecosystem.JAVASCRIPT)
            self.assertFalse(ignored)
    
    def test_load_json_config(self):
        """JSON ì„¤ì • ë¡œë“œ"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            
            config_file = project / "depsolve.config.json"
            config_file.write_text(json.dumps({
                "ignore_packages": [
                    "pytest",
                    {"pattern": "mypy*"}
                ],
                "skip_dirs": [".mypy_cache"]
            }))
            
            config = IgnoreConfig.load_from_file(config_file)
            
            ignored, _ = config.should_ignore_package("pytest", Ecosystem.PYTHON)
            self.assertTrue(ignored)
            ignored, _ = config.should_ignore_package("mypy-extensions", Ecosystem.PYTHON)
            self.assertTrue(ignored)
            self.assertTrue(config.should_skip_path(Path("/project/.mypy_cache/file.py")))


class TestImportExtractor(unittest.TestCase):
    """Import ì¶”ì¶œ í…ŒìŠ¤íŠ¸"""
    
    def setUp(self):
        self.extractor = ImportExtractor()
    
    def test_static_import(self):
        """ê¸°ë³¸ import"""
        imports = self.extractor.extract_content("import React from 'react';")
        self.assertEqual(len(imports), 1)
        self.assertEqual(imports[0].package, "react")
        self.assertEqual(imports[0].import_type, ImportType.STATIC)
    
    def test_type_import(self):
        """TypeScript type-only"""
        imports = self.extractor.extract_content("import type { FC } from 'react';")
        self.assertEqual(len(imports), 1)
        self.assertEqual(imports[0].import_type, ImportType.TYPE_ONLY)
        self.assertTrue(imports[0].is_type_only)
    
    def test_require(self):
        """CommonJS require"""
        imports = self.extractor.extract_content("const x = require('express');")
        self.assertEqual(imports[0].package, "express")
        self.assertEqual(imports[0].import_type, ImportType.REQUIRE)
    
    def test_re_export(self):
        """Re-export"""
        imports = self.extractor.extract_content("export * from 'lodash';")
        self.assertEqual(imports[0].import_type, ImportType.RE_EXPORT)
    
    def test_jest_mock(self):
        """Jest mock"""
        imports = self.extractor.extract_content("jest.mock('axios');")
        self.assertEqual(imports[0].import_type, ImportType.JEST_MOCK)
    
    def test_scoped_package(self):
        """Scoped íŒ¨í‚¤ì§€"""
        imports = self.extractor.extract_content("import { x } from '@babel/core';")
        self.assertEqual(imports[0].package, "@babel/core")
    
    def test_node_builtin_ignored(self):
        """Node.js ë‚´ìž¥ ëª¨ë“ˆ ë¬´ì‹œ"""
        imports = self.extractor.extract_content("import fs from 'fs';")
        self.assertEqual(len(imports), 0)
    
    def test_node_https_ignored(self):
        """Node.js https ëª¨ë“ˆ ë¬´ì‹œ (í•µì‹¬ ìˆ˜ì • ê²€ì¦)"""
        imports = self.extractor.extract_content("import https from 'https';")
        self.assertEqual(len(imports), 0)
    
    def test_file_context_config(self):
        """íŒŒì¼ ì»¨í…ìŠ¤íŠ¸ - config"""
        imports = self.extractor.extract_content(
            "import x from 'pkg';", "vite.config.ts")
        self.assertEqual(imports[0].file_context, FileContext.CONFIG)
    
    def test_file_context_test(self):
        """íŒŒì¼ ì»¨í…ìŠ¤íŠ¸ - test"""
        imports = self.extractor.extract_content(
            "import x from 'pkg';", "App.test.tsx")
        self.assertEqual(imports[0].file_context, FileContext.TEST)
    
    def test_with_ignore_config(self):
        """Ignore ì„¤ì •ê³¼ í•¨ê»˜"""
        config = IgnoreConfig()
        config.add_rule("axios")
        
        extractor = ImportExtractor(ignore_config=config)
        imports = extractor.extract_content("import axios from 'axios';")
        self.assertEqual(len(imports), 0)


class TestPythonImportExtraction(unittest.TestCase):
    """Python Import ì¶”ì¶œ í…ŒìŠ¤íŠ¸"""
    
    def setUp(self):
        self.extractor = ImportExtractor(filter_stdlib=True)
    
    def test_import_statement(self):
        """ê¸°ë³¸ import ë¬¸"""
        with tempfile.NamedTemporaryFile(suffix='.py', mode='w', delete=False) as f:
            f.write("import requests\nimport numpy as np\n")
            f.flush()
            
            imports = self.extractor.extract_file(Path(f.name))
            packages = {i.package for i in imports}
            self.assertIn('requests', packages)
            self.assertIn('numpy', packages)
    
    def test_from_import(self):
        """from ... import ë¬¸"""
        with tempfile.NamedTemporaryFile(suffix='.py', mode='w', delete=False) as f:
            f.write("from pandas import DataFrame\n")
            f.flush()
            
            imports = self.extractor.extract_file(Path(f.name))
            packages = {i.package for i in imports}
            self.assertIn('pandas', packages)
    
    def test_stdlib_filtered(self):
        """Python í‘œì¤€ ë¼ì´ë¸ŒëŸ¬ë¦¬ í•„í„°ë§"""
        with tempfile.NamedTemporaryFile(suffix='.py', mode='w', delete=False) as f:
            f.write("import os\nimport sys\nimport json\n")
            f.flush()
            
            imports = self.extractor.extract_file(Path(f.name))
            self.assertEqual(len(imports), 0)


class TestHybridManifest(unittest.TestCase):
    """í•˜ì´ë¸Œë¦¬ë“œ Manifest í…ŒìŠ¤íŠ¸"""
    
    def test_npm_only(self):
        """npm í”„ë¡œì íŠ¸"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            (project / "package.json").write_text(json.dumps({
                "dependencies": {"react": "^18.0.0"},
                "devDependencies": {"jest": "^29.0.0"}
            }))
            
            manifest = load_hybrid_manifest(project)
            self.assertIn(Ecosystem.JAVASCRIPT, manifest.detected_ecosystems)
            self.assertIn("react", manifest.js_deps)
    
    def test_python_only(self):
        """Python í”„ë¡œì íŠ¸"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            (project / "requirements.txt").write_text("requests>=2.28.0\n")
            
            manifest = load_hybrid_manifest(project)
            self.assertIn(Ecosystem.PYTHON, manifest.detected_ecosystems)
            self.assertIn("requests", manifest.py_deps)
    
    def test_hybrid_project(self):
        """í•˜ì´ë¸Œë¦¬ë“œ í”„ë¡œì íŠ¸"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            (project / "package.json").write_text(json.dumps({
                "dependencies": {"express": "^4.0.0"}
            }))
            (project / "requirements.txt").write_text("flask>=2.0.0\n")
            
            manifest = load_hybrid_manifest(project)
            self.assertIn(Ecosystem.JAVASCRIPT, manifest.detected_ecosystems)
            self.assertIn(Ecosystem.PYTHON, manifest.detected_ecosystems)
    
    def test_subdirectory_manifest(self):
        """ì„œë¸Œë””ë ‰í† ë¦¬ manifest íƒì§€"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            
            # ë£¨íŠ¸ì— package.json
            (project / "package.json").write_text(json.dumps({
                "dependencies": {"react": "^18.0.0"}
            }))
            
            # backend/ ì„œë¸Œë””ë ‰í† ë¦¬ì— requirements.txt
            backend = project / "backend"
            backend.mkdir()
            (backend / "requirements.txt").write_text("fastapi>=0.100.0\npydantic>=2.0\n")
            
            manifest = load_hybrid_manifest(project)
            
            self.assertIn("react", manifest.js_deps)
            self.assertIn("fastapi", manifest.py_deps)
            self.assertIn("pydantic", manifest.py_deps)
    
    def test_pyproject_toml_pep621(self):
        """pyproject.toml PEP 621 íŒŒì‹±"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            
            (project / "pyproject.toml").write_text("""
[project]
name = "test-project"
dependencies = [
    "fastapi>=0.100.0",
    "pydantic>=2.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "black>=23.0",
]
""")
            
            manifest = load_hybrid_manifest(project)
            
            self.assertIn("fastapi", manifest.py_deps)
            self.assertIn("pydantic", manifest.py_deps)
            self.assertIn("pytest", manifest.py_dev_deps)
            self.assertIn("black", manifest.py_dev_deps)
    
    def test_pyproject_toml_poetry(self):
        """pyproject.toml Poetry íŒŒì‹±"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            
            (project / "pyproject.toml").write_text("""
[tool.poetry]
name = "test-project"

[tool.poetry.dependencies]
python = "^3.9"
fastapi = "^0.100.0"
pydantic = "^2.0"

[tool.poetry.group.dev.dependencies]
pytest = "^7.0"
""")
            
            manifest = load_hybrid_manifest(project)
            
            self.assertIn("fastapi", manifest.py_deps)
            self.assertIn("pydantic", manifest.py_deps)
            # pythonì€ ì œì™¸ë˜ì–´ì•¼ í•¨
            self.assertNotIn("python", manifest.py_deps)
    
    def test_requirements_dev_txt(self):
        """requirements-dev.txt ì§€ì›"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            
            (project / "requirements.txt").write_text("fastapi>=0.100.0\n")
            (project / "requirements-dev.txt").write_text("pytest>=7.0\nmypy>=1.0\n")
            
            manifest = load_hybrid_manifest(project)
            
            self.assertIn("fastapi", manifest.py_deps)
            self.assertIn("pytest", manifest.py_dev_deps)
            self.assertIn("mypy", manifest.py_dev_deps)
    
    def test_package_name_normalization(self):
        """íŒ¨í‚¤ì§€ëª… ì •ê·œí™” (ë³„ì¹­ í¬í•¨)"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            
            (project / "requirements.txt").write_text("pydantic-settings>=2.0\n")
            
            manifest = load_hybrid_manifest(project)
            
            # ë‘˜ ë‹¤ í¬í•¨ë˜ì–´ì•¼ í•¨
            self.assertTrue(
                "pydantic-settings" in manifest.py_deps or 
                "pydantic_settings" in manifest.py_deps
            )


class TestPhantomDetection(unittest.TestCase):
    """Phantom íƒì§€ í…ŒìŠ¤íŠ¸"""
    
    def test_js_phantom(self):
        """JS Phantom íƒì§€"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            (project / "package.json").write_text(json.dumps({
                "dependencies": {"react": "^18.0.0"}
            }))
            
            src = project / "src"
            src.mkdir()
            (src / "App.js").write_text(
                "import React from 'react';\n"
                "import axios from 'axios';\n"
            )
            
            detector = PhantomDetector(
                project_path=project,
                js_deps={"react"},
                verify=False
            )
            
            phantoms = detector.detect()
            js_phantoms = [p for p in phantoms if p.ecosystem == Ecosystem.JAVASCRIPT]
            phantom_packages = {p.package for p in js_phantoms}
            
            self.assertIn("axios", phantom_packages)
            self.assertNotIn("react", phantom_packages)
    
    def test_python_phantom(self):
        """Python Phantom íƒì§€"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            (project / "requirements.txt").write_text("requests>=2.28.0\n")
            
            src = project / "src"
            src.mkdir()
            (src / "main.py").write_text(
                "import requests\n"
                "import pandas as pd\n"
            )
            
            detector = PhantomDetector(
                project_path=project,
                py_deps={"requests"},
                verify=False
            )
            
            phantoms = detector.detect()
            py_phantoms = [p for p in phantoms if p.ecosystem == Ecosystem.PYTHON]
            phantom_packages = {p.package for p in py_phantoms}
            
            self.assertIn("pandas", phantom_packages)
            self.assertNotIn("requests", phantom_packages)
    
    def test_ecosystem_isolation(self):
        """ìƒíƒœê³„ ê²©ë¦¬ - JS importê°€ Python depsë¡œ ê²€ì¦ë˜ì§€ ì•ŠìŒ"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            (project / "requirements.txt").write_text("openai>=1.0.0\n")
            
            src = project / "src"
            src.mkdir()
            (src / "client.js").write_text("import OpenAI from 'openai';\n")
            
            detector = PhantomDetector(
                project_path=project,
                py_deps={"openai"},
                js_deps=set(),
                verify=False
            )
            
            phantoms = detector.detect()
            js_phantoms = [p for p in phantoms if p.ecosystem == Ecosystem.JAVASCRIPT]
            
            self.assertEqual(len(js_phantoms), 1)
            self.assertEqual(js_phantoms[0].package, "openai")
            self.assertTrue(js_phantoms[0].is_phantom)
    
    def test_normalized_package_matching(self):
        """ì •ê·œí™”ëœ íŒ¨í‚¤ì§€ëª… ë§¤ì¹­"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            (project / "requirements.txt").write_text("pydantic-settings>=2.0\n")
            
            src = project / "src"
            src.mkdir()
            # importëŠ” ì–¸ë”ìŠ¤ì½”ì–´ë¡œ
            (src / "main.py").write_text("from pydantic_settings import BaseSettings\n")
            
            detector = PhantomDetector(
                project_path=project,
                py_deps={"pydantic-settings", "pydantic_settings"},
                verify=False
            )
            
            phantoms = detector.detect()
            py_phantoms = [p for p in phantoms if p.ecosystem == Ecosystem.PYTHON]
            phantom_packages = {p.package for p in py_phantoms}
            
            # pydantic_settingsëŠ” Phantomì´ ì•„ë‹ˆì–´ì•¼ í•¨
            self.assertNotIn("pydantic_settings", phantom_packages)


class TestRuntimeVerifier(unittest.TestCase):
    """ëŸ°íƒ€ìž„ ê²€ì¦ í…ŒìŠ¤íŠ¸"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.project = Path(self.temp_dir)
    
    def test_node_modules_scan(self):
        """node_modules ìŠ¤ìº”"""
        nm = self.project / "node_modules" / "lodash"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(json.dumps({
            "name": "lodash", "version": "4.17.21"
        }))
        
        verifier = RuntimeVerifier(self.project)
        version = verifier._scan_node_modules("lodash")
        self.assertEqual(version, "4.17.21")
    
    def test_scoped_package_scan(self):
        """Scoped íŒ¨í‚¤ì§€ ìŠ¤ìº”"""
        nm = self.project / "node_modules" / "@babel" / "core"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(json.dumps({
            "name": "@babel/core", "version": "7.23.0"
        }))
        
        verifier = RuntimeVerifier(self.project)
        version = verifier._scan_node_modules("@babel/core")
        self.assertEqual(version, "7.23.0")


class TestGoAdapter(unittest.TestCase):
    """Go ì–´ëŒ‘í„° í…ŒìŠ¤íŠ¸"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.project = Path(self.temp_dir)
    
    def test_detect(self):
        """Go í”„ë¡œì íŠ¸ ê°ì§€"""
        adapter = GoAdapter(self.project)
        self.assertFalse(adapter.detect())
        
        (self.project / "go.mod").write_text("module test\ngo 1.21\n")
        self.assertTrue(adapter.detect())
    
    def test_parse_go_mod(self):
        """go.mod íŒŒì‹±"""
        (self.project / "go.mod").write_text("""
module github.com/user/myproject

go 1.21

require (
    github.com/gin-gonic/gin v1.9.0
)
""")
        adapter = GoAdapter(self.project)
        info = adapter.get_info()
        
        self.assertEqual(info.name, "github.com/user/myproject")
        self.assertIn("github.com/gin-gonic/gin", info.dependencies)


class TestCargoAdapter(unittest.TestCase):
    """Cargo ì–´ëŒ‘í„° í…ŒìŠ¤íŠ¸"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.project = Path(self.temp_dir)
    
    def test_detect(self):
        """Cargo í”„ë¡œì íŠ¸ ê°ì§€"""
        adapter = CargoAdapter(self.project)
        self.assertFalse(adapter.detect())
        
        (self.project / "Cargo.toml").write_text(
            '[package]\nname = "test"\nversion = "0.1.0"\n'
        )
        self.assertTrue(adapter.detect())


class TestAnalyzer(unittest.TestCase):
    """ë¶„ì„ê¸° í…ŒìŠ¤íŠ¸"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.project = Path(self.temp_dir)
    
    def test_npm_analysis(self):
        """npm í”„ë¡œì íŠ¸ ë¶„ì„"""
        (self.project / "package.json").write_text(json.dumps({
            "name": "test-project",
            "dependencies": {"react": "^18.0.0", "lodash": "^4.17.0"},
            "devDependencies": {"jest": "^29.0.0"}
        }))
        
        src = self.project / "src"
        src.mkdir()
        (src / "App.tsx").write_text("""
        import React from 'react';
        import axios from 'axios';
        """)
        
        result = analyze(str(self.project), verify=False)
        
        self.assertEqual(result.ecosystem, "npm")
        self.assertGreater(result.summary.total_packages, 0)
        
        phantom_issues = [i for i in result.issues if i.type == IssueType.PHANTOM]
        phantom_packages = [i.locations[0].package for i in phantom_issues]
        self.assertIn("axios", phantom_packages)


class TestIntegration(unittest.TestCase):
    """í†µí•© í…ŒìŠ¤íŠ¸"""
    
    def test_full_workflow(self):
        """ì „ì²´ ì›Œí¬í”Œë¡œìš°"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            
            (project / "package.json").write_text(json.dumps({
                "name": "test-project",
                "dependencies": {"react": "^18.0.0"},
                "devDependencies": {"tailwindcss": "^3.0.0"}
            }))
            
            src = project / "src"
            src.mkdir()
            (src / "App.tsx").write_text("""
            import React from 'react';
            import axios from 'axios';
            """)
            
            (project / "tailwind.config.js").write_text(
                "module.exports = require('tailwindcss');"
            )
            
            result = analyze(str(project), verify=False)
            
            phantom_pkgs = [
                i.locations[0].package
                for i in result.issues
                if i.type == IssueType.PHANTOM
            ]
            self.assertIn("axios", phantom_pkgs)
            self.assertNotIn("tailwindcss", phantom_pkgs)
            
            self.assertIsNotNone(result.mermaid_diagram)
    
    def test_hybrid_project_workflow(self):
        """í•˜ì´ë¸Œë¦¬ë“œ í”„ë¡œì íŠ¸ ì›Œí¬í”Œë¡œìš°"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            
            # ë£¨íŠ¸: package.json (frontend)
            (project / "package.json").write_text(json.dumps({
                "name": "frontend",
                "dependencies": {"react": "^18.0.0"}
            }))
            
            # backend/: pyproject.toml
            backend = project / "backend"
            backend.mkdir()
            (backend / "pyproject.toml").write_text("""
[project]
name = "backend"
dependencies = [
    "fastapi>=0.100.0",
    "pydantic-settings>=2.0",
]

[project.optional-dependencies]
dev = ["pytest>=7.0"]
""")
            
            # ì†ŒìŠ¤ íŒŒì¼
            src = project / "src"
            src.mkdir()
            (src / "App.tsx").write_text("import React from 'react';\nimport axios from 'axios';")
            
            backend_src = backend / "src"
            backend_src.mkdir()
            (backend_src / "main.py").write_text("from fastapi import FastAPI\nfrom pydantic_settings import BaseSettings")
            
            result = analyze(str(project), verify=False)
            
            # í•˜ì´ë¸Œë¦¬ë“œ ìƒíƒœê³„ ê°ì§€
            self.assertTrue("javascript" in result.ecosystem.lower() or "npm" in result.ecosystem.lower())
            
            # JS phantom: axios
            js_phantoms = [
                i for i in result.issues 
                if i.type == IssueType.PHANTOM and "axios" in str(i.locations)
            ]
            self.assertGreater(len(js_phantoms), 0)


class TestNodeBuiltinComprehensive(unittest.TestCase):
    """Node.js ë‚´ìž¥ ëª¨ë“ˆ í¬ê´„ í…ŒìŠ¤íŠ¸"""
    
    def test_all_common_builtins(self):
        """ìžì£¼ ì“°ì´ëŠ” ë‚´ìž¥ ëª¨ë“ˆ"""
        common_builtins = [
            'fs', 'path', 'http', 'https', 'url', 'util', 'os',
            'crypto', 'stream', 'events', 'child_process', 'buffer',
        ]
        
        for mod in common_builtins:
            self.assertTrue(
                is_stdlib(mod, Ecosystem.JAVASCRIPT),
                f"{mod} should be Node.js builtin"
            )


class TestPythonStdlibComprehensive(unittest.TestCase):
    """Python í‘œì¤€ ë¼ì´ë¸ŒëŸ¬ë¦¬ í¬ê´„ í…ŒìŠ¤íŠ¸"""
    
    def test_all_common_stdlib(self):
        """ìžì£¼ ì“°ì´ëŠ” í‘œì¤€ ë¼ì´ë¸ŒëŸ¬ë¦¬"""
        common_stdlib = [
            'os', 'sys', 'json', 're', 'datetime', 'collections',
            'itertools', 'functools', 'pathlib', 'typing', 'logging',
        ]
        
        for mod in common_stdlib:
            self.assertTrue(
                is_stdlib(mod, Ecosystem.PYTHON),
                f"{mod} should be Python stdlib"
            )


class TestLocalModuleFiltering(unittest.TestCase):
    """ë‚´ë¶€ ëª¨ë“ˆ í•„í„°ë§ í…ŒìŠ¤íŠ¸"""
    
    def test_self_detection_filtered(self):
        """ë„êµ¬ ìžì‹ ì˜ ì†ŒìŠ¤ì½”ë“œê°€ Phantomìœ¼ë¡œ ìž¡ížˆì§€ ì•ŠìŒ"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            
            # ë‚´ë¶€ ëª¨ë“ˆ êµ¬ì¡° ìƒì„±
            (project / "analyzer.py").write_text("# analyzer module\n")
            (project / "models.py").write_text("# models module\n")
            (project / "main.py").write_text(
                "import analyzer\n"
                "import models\n"
            )
            
            detector = PhantomDetector(project_path=project, verify=False)
            phantoms = detector.detect()
            
            phantom_packages = {p.package for p in phantoms}
            # ë‚´ë¶€ ëª¨ë“ˆì€ Phantomìœ¼ë¡œ ìž¡ížˆë©´ ì•ˆë¨
            self.assertNotIn("analyzer", phantom_packages)
            self.assertNotIn("models", phantom_packages)
    
    def test_package_self_detection_filtered(self):
        """íŒ¨í‚¤ì§€ í˜•íƒœì˜ ë‚´ë¶€ ëª¨ë“ˆ í•„í„°ë§"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            
            # íŒ¨í‚¤ì§€ êµ¬ì¡°
            pkg = project / "mypackage"
            pkg.mkdir()
            (pkg / "__init__.py").write_text("# package init\n")
            (pkg / "utils.py").write_text("# utils\n")
            
            (project / "main.py").write_text("import mypackage\n")
            
            detector = PhantomDetector(project_path=project, verify=False)
            phantoms = detector.detect()
            
            phantom_packages = {p.package for p in phantoms}
            self.assertNotIn("mypackage", phantom_packages)


class TestASTBasedParsing(unittest.TestCase):
    """AST ê¸°ë°˜ íŒŒì‹± í…ŒìŠ¤íŠ¸ (ë¬¸ìžì—´ ë‚´ import ì˜¤íƒ ë°©ì§€)"""
    
    def test_string_import_ignored(self):
        """ë¬¸ìžì—´ ë‚´ì˜ import ë¬¸ì€ ë¬´ì‹œë¨"""
        with tempfile.NamedTemporaryFile(suffix='.py', mode='w', delete=False) as f:
            f.write('''
# í…ŒìŠ¤íŠ¸ìš© ë¬¸ìžì—´
test_code = """
import react from 'react';
import axios from 'axios';
"""
# ì‹¤ì œ import
import json
''')
            f.flush()
            
            extractor = ImportExtractor(filter_stdlib=True)
            imports = extractor.extract_file(Path(f.name))
            
            packages = {i.package for i in imports}
            # ë¬¸ìžì—´ ì•ˆì˜ react, axiosëŠ” ìž¡ížˆë©´ ì•ˆë¨
            self.assertNotIn("react", packages)
            self.assertNotIn("axios", packages)
    
    def test_comment_import_ignored(self):
        """ì£¼ì„ ë‚´ì˜ import ì–¸ê¸‰ì€ ë¬´ì‹œë¨"""
        with tempfile.NamedTemporaryFile(suffix='.py', mode='w', delete=False) as f:
            f.write('''
# import nonexistent_package
# from fake_module import something
import json  # ì‹¤ì œ import
''')
            f.flush()
            
            extractor = ImportExtractor(filter_stdlib=True)
            imports = extractor.extract_file(Path(f.name))
            
            packages = {i.package for i in imports}
            self.assertNotIn("nonexistent_package", packages)
            self.assertNotIn("fake_module", packages)


def run_tests():
    """í…ŒìŠ¤íŠ¸ ì‹¤í–‰"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    test_classes = [
        TestGraph,
        TestEcosystemDetection,
        TestStdlibFiltering,
        TestPackageNameNormalization,
        TestIgnoreConfig,
        TestImportExtractor,
        TestPythonImportExtraction,
        TestHybridManifest,
        TestPhantomDetection,
        TestRuntimeVerifier,
        TestGoAdapter,
        TestCargoAdapter,
        TestAnalyzer,
        TestIntegration,
        TestNodeBuiltinComprehensive,
        TestPythonStdlibComprehensive,
        TestLocalModuleFiltering,
        TestASTBasedParsing,
    ]
    
    for test_class in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(test_class))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    exit(run_tests())
