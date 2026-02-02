#!/usr/bin/env python3
"""
depsolve_ext/tests.py
=====================
통합 테스트

실행:
    python -m depsolve_ext.tests
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
    NODE_BUILTINS, PYTHON_STDLIB
)
from .analyzer import DependencyAnalyzer, analyze


class TestGraph(unittest.TestCase):
    """그래프 테스트"""
    
    def test_add_nodes_edges(self):
        """노드/엣지 추가"""
        g = DependencyGraph()
        g.add_node("A", "1.0.0")
        g.add_edge(DependencyEdge(source="A", target="B", version_range="^2.0.0"))
        
        self.assertEqual(g.node_count, 2)
        self.assertEqual(g.edge_count, 1)
        self.assertTrue(g.has_node("A"))
        self.assertTrue(g.has_edge("A", "B"))
    
    def test_find_cycles(self):
        """순환 탐지"""
        g = DependencyGraph()
        g.add_edge(DependencyEdge(source="A", target="B"))
        g.add_edge(DependencyEdge(source="B", target="C"))
        g.add_edge(DependencyEdge(source="C", target="A"))
        
        cycles = g.find_cycles()
        self.assertEqual(len(cycles), 1)
        self.assertEqual(set(cycles[0].path[:-1]), {"A", "B", "C"})
    
    def test_no_cycle(self):
        """순환 없음"""
        g = DependencyGraph()
        g.add_edge(DependencyEdge(source="A", target="B"))
        g.add_edge(DependencyEdge(source="B", target="C"))
        
        self.assertFalse(g.has_cycle())
    
    def test_find_diamonds(self):
        """다이아몬드 탐지"""
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
        """Mermaid 출력"""
        g = DependencyGraph()
        g.add_edge(DependencyEdge(source="A", target="B", version_range="^1.0.0"))
        
        mermaid = g.to_mermaid()
        self.assertIn("graph TD", mermaid)
        self.assertIn("-->", mermaid)
    
    def test_transitive_deps(self):
        """전이적 의존성"""
        g = DependencyGraph()
        g.add_edge(DependencyEdge(source="A", target="B"))
        g.add_edge(DependencyEdge(source="B", target="C"))
        g.add_edge(DependencyEdge(source="C", target="D"))
        
        deps = g.get_transitive_dependencies("A")
        self.assertEqual(deps, {"B", "C", "D"})


class TestEcosystemDetection(unittest.TestCase):
    """생태계 감지 테스트"""
    
    def test_js_extensions(self):
        """JS/TS 확장자 감지"""
        self.assertEqual(get_file_ecosystem("app.js"), Ecosystem.JAVASCRIPT)
        self.assertEqual(get_file_ecosystem("App.tsx"), Ecosystem.JAVASCRIPT)
        self.assertEqual(get_file_ecosystem("index.mjs"), Ecosystem.JAVASCRIPT)
    
    def test_python_extensions(self):
        """Python 확장자 감지"""
        self.assertEqual(get_file_ecosystem("main.py"), Ecosystem.PYTHON)
        self.assertEqual(get_file_ecosystem("utils.pyx"), Ecosystem.PYTHON)
    
    def test_unknown_extensions(self):
        """알 수 없는 확장자"""
        self.assertEqual(get_file_ecosystem("readme.md"), Ecosystem.UNKNOWN)


class TestStdlibFiltering(unittest.TestCase):
    """표준 라이브러리 필터링 테스트"""
    
    def test_node_builtins(self):
        """Node.js 내장 모듈"""
        self.assertTrue(is_stdlib('fs', Ecosystem.JAVASCRIPT))
        self.assertTrue(is_stdlib('https', Ecosystem.JAVASCRIPT))
        self.assertTrue(is_stdlib('path', Ecosystem.JAVASCRIPT))
        self.assertTrue(is_stdlib('node:fs', Ecosystem.JAVASCRIPT))
        
        self.assertFalse(is_stdlib('express', Ecosystem.JAVASCRIPT))
        self.assertFalse(is_stdlib('react', Ecosystem.JAVASCRIPT))
    
    def test_python_stdlib(self):
        """Python 표준 라이브러리"""
        self.assertTrue(is_stdlib('os', Ecosystem.PYTHON))
        self.assertTrue(is_stdlib('sys', Ecosystem.PYTHON))
        self.assertTrue(is_stdlib('json', Ecosystem.PYTHON))
        self.assertTrue(is_stdlib('pathlib', Ecosystem.PYTHON))
        
        self.assertFalse(is_stdlib('requests', Ecosystem.PYTHON))
        self.assertFalse(is_stdlib('numpy', Ecosystem.PYTHON))


class TestImportExtractor(unittest.TestCase):
    """Import 추출 테스트"""
    
    def setUp(self):
        self.extractor = ImportExtractor()
    
    def test_static_import(self):
        """기본 import"""
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
        """Scoped 패키지"""
        imports = self.extractor.extract_content("import { x } from '@babel/core';")
        self.assertEqual(imports[0].package, "@babel/core")
    
    def test_node_builtin_ignored(self):
        """Node.js 내장 모듈 무시"""
        imports = self.extractor.extract_content("import fs from 'fs';")
        self.assertEqual(len(imports), 0)
    
    def test_node_https_ignored(self):
        """Node.js https 모듈 무시 (핵심 수정 검증)"""
        imports = self.extractor.extract_content("import https from 'https';")
        self.assertEqual(len(imports), 0)
    
    def test_file_context_config(self):
        """파일 컨텍스트 - config"""
        imports = self.extractor.extract_content(
            "import x from 'pkg';", "vite.config.ts")
        self.assertEqual(imports[0].file_context, FileContext.CONFIG)
    
    def test_file_context_test(self):
        """파일 컨텍스트 - test"""
        imports = self.extractor.extract_content(
            "import x from 'pkg';", "App.test.tsx")
        self.assertEqual(imports[0].file_context, FileContext.TEST)


class TestPythonImportExtraction(unittest.TestCase):
    """Python Import 추출 테스트"""
    
    def setUp(self):
        self.extractor = ImportExtractor(filter_stdlib=True)
    
    def test_import_statement(self):
        """기본 import 문"""
        with tempfile.NamedTemporaryFile(suffix='.py', mode='w', delete=False) as f:
            f.write("import requests\nimport numpy as np\n")
            f.flush()
            
            imports = self.extractor.extract_file(Path(f.name))
            packages = {i.package for i in imports}
            self.assertIn('requests', packages)
            self.assertIn('numpy', packages)
    
    def test_from_import(self):
        """from ... import 문"""
        with tempfile.NamedTemporaryFile(suffix='.py', mode='w', delete=False) as f:
            f.write("from pandas import DataFrame\n")
            f.flush()
            
            imports = self.extractor.extract_file(Path(f.name))
            packages = {i.package for i in imports}
            self.assertIn('pandas', packages)
    
    def test_stdlib_filtered(self):
        """Python 표준 라이브러리 필터링"""
        with tempfile.NamedTemporaryFile(suffix='.py', mode='w', delete=False) as f:
            f.write("import os\nimport sys\nimport json\n")
            f.flush()
            
            imports = self.extractor.extract_file(Path(f.name))
            self.assertEqual(len(imports), 0)


class TestHybridManifest(unittest.TestCase):
    """하이브리드 Manifest 테스트"""
    
    def test_npm_only(self):
        """npm 프로젝트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            (project / "package.json").write_text(json.dumps({
                "dependencies": {"react": "^18.0.0"},
                "devDependencies": {"jest": "^29.0.0"}
            }))
            
            manifest = load_hybrid_manifest(project)
            self.assertIn(Ecosystem.JAVASCRIPT, manifest.detected_ecosystems)
            self.assertEqual(manifest.js_deps, {"react"})
    
    def test_python_only(self):
        """Python 프로젝트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            (project / "requirements.txt").write_text("requests>=2.28.0\n")
            
            manifest = load_hybrid_manifest(project)
            self.assertIn(Ecosystem.PYTHON, manifest.detected_ecosystems)
            self.assertIn("requests", manifest.py_deps)
    
    def test_hybrid_project(self):
        """하이브리드 프로젝트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            (project / "package.json").write_text(json.dumps({
                "dependencies": {"express": "^4.0.0"}
            }))
            (project / "requirements.txt").write_text("flask>=2.0.0\n")
            
            manifest = load_hybrid_manifest(project)
            self.assertIn(Ecosystem.JAVASCRIPT, manifest.detected_ecosystems)
            self.assertIn(Ecosystem.PYTHON, manifest.detected_ecosystems)


class TestPhantomDetection(unittest.TestCase):
    """Phantom 탐지 테스트"""
    
    def test_js_phantom(self):
        """JS Phantom 탐지"""
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
        """Python Phantom 탐지"""
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
        """생태계 격리 - JS import가 Python deps로 검증되지 않음"""
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


class TestRuntimeVerifier(unittest.TestCase):
    """런타임 검증 테스트"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.project = Path(self.temp_dir)
    
    def test_node_modules_scan(self):
        """node_modules 스캔"""
        nm = self.project / "node_modules" / "lodash"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(json.dumps({
            "name": "lodash", "version": "4.17.21"
        }))
        
        verifier = RuntimeVerifier(self.project)
        version = verifier._scan_node_modules("lodash")
        self.assertEqual(version, "4.17.21")
    
    def test_scoped_package_scan(self):
        """Scoped 패키지 스캔"""
        nm = self.project / "node_modules" / "@babel" / "core"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(json.dumps({
            "name": "@babel/core", "version": "7.23.0"
        }))
        
        verifier = RuntimeVerifier(self.project)
        version = verifier._scan_node_modules("@babel/core")
        self.assertEqual(version, "7.23.0")


class TestGoAdapter(unittest.TestCase):
    """Go 어댑터 테스트"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.project = Path(self.temp_dir)
    
    def test_detect(self):
        """Go 프로젝트 감지"""
        adapter = GoAdapter(self.project)
        self.assertFalse(adapter.detect())
        
        (self.project / "go.mod").write_text("module test\ngo 1.21\n")
        self.assertTrue(adapter.detect())
    
    def test_parse_go_mod(self):
        """go.mod 파싱"""
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
    """Cargo 어댑터 테스트"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.project = Path(self.temp_dir)
    
    def test_detect(self):
        """Cargo 프로젝트 감지"""
        adapter = CargoAdapter(self.project)
        self.assertFalse(adapter.detect())
        
        (self.project / "Cargo.toml").write_text(
            '[package]\nname = "test"\nversion = "0.1.0"\n'
        )
        self.assertTrue(adapter.detect())


class TestAnalyzer(unittest.TestCase):
    """분석기 테스트"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.project = Path(self.temp_dir)
    
    def test_npm_analysis(self):
        """npm 프로젝트 분석"""
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
    """통합 테스트"""
    
    def test_full_workflow(self):
        """전체 워크플로우"""
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


class TestNodeBuiltinComprehensive(unittest.TestCase):
    """Node.js 내장 모듈 포괄 테스트"""
    
    def test_all_common_builtins(self):
        """자주 쓰이는 내장 모듈"""
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
    """Python 표준 라이브러리 포괄 테스트"""
    
    def test_all_common_stdlib(self):
        """자주 쓰이는 표준 라이브러리"""
        common_stdlib = [
            'os', 'sys', 'json', 're', 'datetime', 'collections',
            'itertools', 'functools', 'pathlib', 'typing', 'logging',
        ]
        
        for mod in common_stdlib:
            self.assertTrue(
                is_stdlib(mod, Ecosystem.PYTHON),
                f"{mod} should be Python stdlib"
            )


def run_tests():
    """테스트 실행"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestGraph))
    suite.addTests(loader.loadTestsFromTestCase(TestEcosystemDetection))
    suite.addTests(loader.loadTestsFromTestCase(TestStdlibFiltering))
    suite.addTests(loader.loadTestsFromTestCase(TestImportExtractor))
    suite.addTests(loader.loadTestsFromTestCase(TestPythonImportExtraction))
    suite.addTests(loader.loadTestsFromTestCase(TestHybridManifest))
    suite.addTests(loader.loadTestsFromTestCase(TestPhantomDetection))
    suite.addTests(loader.loadTestsFromTestCase(TestRuntimeVerifier))
    suite.addTests(loader.loadTestsFromTestCase(TestGoAdapter))
    suite.addTests(loader.loadTestsFromTestCase(TestCargoAdapter))
    suite.addTests(loader.loadTestsFromTestCase(TestAnalyzer))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestNodeBuiltinComprehensive))
    suite.addTests(loader.loadTestsFromTestCase(TestPythonStdlibComprehensive))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    exit(run_tests())
