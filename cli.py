#!/usr/bin/env python3
"""
depsolve_ext/cli.py
===================
depsolve Ã­â„¢â€¢Ã¬Å¾Â¥ Ã«ÂªÂ¨Ã«â€œË† CLI

Usage:
    python -m depsolve_ext analyze ./my-project
    python -m depsolve_ext analyze . --verify --verbose
    python -m depsolve_ext phantoms .
    python -m depsolve_ext graph .
    python -m depsolve_ext imports ./src/App.tsx
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Set

from .analyzer import DependencyAnalyzer, analyze
from .graph import DependencyGraph
from .extensions import (
    ImportExtractor, PhantomDetector, RuntimeVerifier, EcosystemDetector
)
from .reporters import ConsoleReporter, MarkdownReporter, JsonReporter
from .models import Severity

# Override 모듈 (lazy import for backward compatibility)
def _get_override_modules():
    from .override_engine import OverrideConfig, OverrideApplicator, create_initial_overrides
    from .override_verifier import (
        OverrideVerifier, update_overrides_with_verification, generate_verification_report
    )
    return {
        'OverrideConfig': OverrideConfig,
        'OverrideApplicator': OverrideApplicator,
        'create_initial_overrides': create_initial_overrides,
        'OverrideVerifier': OverrideVerifier,
        'update_overrides_with_verification': update_overrides_with_verification,
        'generate_verification_report': generate_verification_report,
    }


def load_npm_deps(project_path: Path) -> tuple[Set[str], Set[str]]:
    """package.jsonÃ¬â€”ÂÃ¬â€žÅ“ Ã¬ÂËœÃ¬Â¡Â´Ã¬â€žÂ± Ã«Â¡Å“Ã«â€œÅ“"""
    pkg_json = project_path / "package.json"
    if not pkg_json.exists():
        return set(), set()
    
    try:
        with open(pkg_json) as f:
            data = json.load(f)
        return (
            set(data.get("dependencies", {}).keys()),
            set(data.get("devDependencies", {}).keys())
        )
    except Exception:
        return set(), set()


def print_header(text: str):
    print(f"\n{'=' * 60}")
    print(f"  {text}")
    print('=' * 60)


def print_section(text: str):
    print(f"\n--- {text} ---")


# =============================================================================
# Commands
# =============================================================================

def cmd_analyze(args):
    """Ã­â€â€žÃ«Â¡Å“Ã¬Â ÂÃ­Å Â¸ Ã¬Â â€žÃ¬Â²Â´ Ã«Â¶â€žÃ¬â€žÂ"""
    project = Path(args.path).resolve()
    
    if not project.exists():
        print(f"Error: Path not found: {project}", file=sys.stderr)
        return 1
    
    # Ã«Â¶â€žÃ¬â€žÂ Ã¬â€¹Â¤Ã­â€“â€°
    result = analyze(
        project_path=str(project),
        verify=args.verify,
        include_dev=not args.no_dev,
        max_nodes=args.max_nodes
    )
    
    # Ã¬Â¶Å“Ã«Â Â¥ Ã­Ëœâ€¢Ã¬â€¹Â Ã¬â€žÂ Ã­Æ’Â
    if args.format == "json":
        reporter = JsonReporter()
    elif args.format == "markdown":
        reporter = MarkdownReporter()
    else:
        reporter = ConsoleReporter(
            use_color=not args.no_color,
            verbose=args.verbose
        )
    
    reporter.report(result)
    
    # Ã¬Â¢â€¦Ã«Â£Å’ Ã¬Â½â€Ã«â€œÅ“: HIGH Ã¬ÂÂ´Ã¬Æ’Â Ã¬ÂÂ´Ã¬Å Ë†ÃªÂ°â‚¬ Ã¬Å¾Ë†Ã¬Å“Â¼Ã«Â©Â´ 1
    has_high = any(
        i.severity in (Severity.CRITICAL, Severity.HIGH)
        for i in result.issues
    )
    return 1 if has_high else 0


def cmd_phantoms(args):
    """Phantom Ã¬ÂËœÃ¬Â¡Â´Ã¬â€žÂ± Ã­Æ’ÂÃ¬Â§â‚¬"""
    project = Path(args.path).resolve()
    
    if not project.exists():
        print(f"Error: Path not found: {project}", file=sys.stderr)
        return 1
    
    deps, dev_deps = load_npm_deps(project)
    
    if not deps and not dev_deps:
        print("No package.json found or no dependencies declared")
        return 0
    
    print_header(f"Phantom Detection: {project}")
    print(f"  Dependencies: {len(deps)}")
    print(f"  DevDependencies: {len(dev_deps)}")
    
    detector = PhantomDetector(
        project_path=project,
        deps=deps,
        dev_deps=dev_deps,
        verify=args.verify
    )
    
    phantoms = detector.detect()
    
    reporter = ConsoleReporter(use_color=not args.no_color)
    reporter.report_phantoms(phantoms)
    
    real_phantoms = [p for p in phantoms if p.is_phantom]
    return 1 if real_phantoms else 0


def cmd_graph(args):
    """Ã¬ÂËœÃ¬Â¡Â´Ã¬â€žÂ± ÃªÂ·Â¸Ã«Å¾ËœÃ­â€â€ž Ã«Â¶â€žÃ¬â€žÂ"""
    project = Path(args.path).resolve()
    
    if not project.exists():
        print(f"Error: Path not found: {project}", file=sys.stderr)
        return 1
    
    analyzer = DependencyAnalyzer(project, verify_runtime=args.verify)
    analyzer._detect_ecosystem()
    analyzer._load_manifest()
    analyzer._build_graph()
    
    graph = analyzer.graph
    
    print_header(f"Graph Analysis: {project}")
    print(f"  Nodes: {graph.node_count}")
    print(f"  Edges: {graph.edge_count}")
    
    # Ã¬Ë†Å“Ã­â„¢Ëœ Ã­Æ’ÂÃ¬Â§â‚¬
    cycles = graph.find_cycles()
    if cycles:
        print_section(f"Circular Dependencies ({len(cycles)})")
        for cycle in cycles[:10]:
            print(f"  Ã¢â‚¬Â¢ {' Ã¢â€ â€™ '.join(cycle.path)}")
    
    # Ã«â€¹Â¤Ã¬ÂÂ´Ã¬â€¢â€žÃ«ÂªÂ¬Ã«â€œÅ“ Ã­Æ’ÂÃ¬Â§â‚¬
    diamonds = graph.find_diamonds()
    conflicts = [d for d in diamonds if d.has_version_conflict]
    
    if diamonds:
        print_section(f"Diamond Dependencies ({len(diamonds)})")
        print(f"  With version conflicts: {len(conflicts)}")
        
        for d in conflicts[:5]:
            print(f"\n  {d.top}")
            print(f"    Ã¢â€Å“Ã¢â€â‚¬ {d.left} Ã¢â€ â€™ {d.bottom}@{d.left_version}")
            print(f"    Ã¢â€â€Ã¢â€â‚¬ {d.right} Ã¢â€ â€™ {d.bottom}@{d.right_version}")
    
    # Mermaid Ã¬Â¶Å“Ã«Â Â¥
    if args.mermaid:
        print_section("Mermaid Diagram")
        print()
        print("```mermaid")
        print(graph.to_mermaid(max_nodes=args.max_nodes))
        print("```")
    
    print()
    return 0


def cmd_imports(args):
    """Ã­Å’Å’Ã¬ÂÂ¼Ã¬â€”ÂÃ¬â€žÅ“ import Ã¬Â¶â€Ã¬Â¶Å“"""
    path = Path(args.file).resolve()
    
    if not path.exists():
        print(f"Error: File not found: {path}", file=sys.stderr)
        return 1
    
    extractor = ImportExtractor()
    imports = extractor.extract_file(path)
    
    print_header(f"Imports: {path.name}")
    print(f"Total: {len(imports)}")
    
    # Ã­Æ’â‚¬Ã¬Å¾â€¦Ã«Â³â€ž ÃªÂ·Â¸Ã«Â£Â¹Ã­â„¢â€
    by_type = {}
    for imp in imports:
        t = imp.import_type.value
        if t not in by_type:
            by_type[t] = []
        by_type[t].append(imp)
    
    for imp_type, imps in sorted(by_type.items()):
        print(f"\n[{imp_type}] ({len(imps)})")
        for imp in imps:
            extra = " (type-only)" if imp.is_type_only else ""
            print(f"  Ã¢â‚¬Â¢ {imp.package}{extra}")
            if args.verbose:
                print(f"    {imp.module} (line {imp.line})")
    
    if args.json:
        print("\n--- JSON ---")
        data = [{"package": i.package, "type": i.import_type.value,
                 "line": i.line, "type_only": i.is_type_only} for i in imports]
        print(json.dumps(data, indent=2))
    
    print()
    return 0


def cmd_ecosystem(args):
    """Ã¬Æ’ÂÃ­Æ’Å“ÃªÂ³â€ž ÃªÂ°ÂÃ¬Â§â‚¬"""
    project = Path(args.path).resolve()
    
    if not project.exists():
        print(f"Error: Path not found: {project}", file=sys.stderr)
        return 1
    
    print_header(f"Ecosystem Detection: {project}")
    
    # Ã«â€šÂ´Ã¬Å¾Â¥ ÃªÂ°ÂÃ¬Â§â‚¬
    detected = EcosystemDetector.detect(project)
    
    # npm/pip Ã¬Â¶â€ÃªÂ°â‚¬ ÃªÂ°ÂÃ¬Â§â‚¬
    if (project / "package.json").exists():
        print("\n[NPM]")
        deps, dev_deps = load_npm_deps(project)
        print(f"  Dependencies: {len(deps)}")
        print(f"  DevDependencies: {len(dev_deps)}")
    
    if (project / "requirements.txt").exists():
        print("\n[PIP]")
        print("  requirements.txt detected")
    
    for name, adapter in detected:
        print(f"\n[{name.upper()}]")
        try:
            info = adapter.get_info()
            print(f"  Name: {info.name}")
            print(f"  Version: {info.version}")
            print(f"  Dependencies: {len(info.dependencies)}")
            for dep, ver in list(info.dependencies.items())[:5]:
                print(f"    Ã¢â‚¬Â¢ {dep}: {ver}")
        except Exception as e:
            print(f"  Error: {e}")
    
    print()
    return 0


def cmd_multi_version(args):
    """Ã«â€¹Â¤Ã¬Â¤â€˜ Ã«Â²â€žÃ¬Â â€ž Ã­Å’Â¨Ã­â€šÂ¤Ã¬Â§â‚¬ Ã­Æ’ÂÃ¬Â§â‚¬"""
    project = Path(args.path).resolve()
    
    print_header(f"Multi-Version Detection: {project}")
    
    verifier = RuntimeVerifier(project)
    
    if not verifier.npm_available:
        print("  Error: npm not available", file=sys.stderr)
        return 1
    
    multi = verifier.get_multi_versions()
    
    if not multi:
        print("  Ã¢Å“â€œ No multiple version packages found")
        return 0
    
    print(f"  Found {len(multi)} packages with multiple versions:\n")
    
    for m in multi:
        print(f"  Ã¢â‚¬Â¢ {m.package}")
        print(f"    Versions: {', '.join(m.versions)}")
        if args.verbose:
            for path in m.paths[:3]:
                print(f"    Path: {' Ã¢â€ â€™ '.join(path)}")
    
    print()
    return 0


def cmd_verify_overrides(args):
    """Override 검증"""
    project = Path(args.path).resolve()
    
    if not project.exists():
        print(f"Error: Path not found: {project}", file=sys.stderr)
        return 1
    
    override_modules = _get_override_modules()
    OverrideConfig = override_modules['OverrideConfig']
    OverrideVerifier = override_modules['OverrideVerifier']
    update_overrides_with_verification = override_modules['update_overrides_with_verification']
    generate_verification_report = override_modules['generate_verification_report']
    
    override_file = project / ".depsolve" / "overrides.yaml"
    if not override_file.exists():
        print(f"Error: No overrides.yaml found at {override_file}", file=sys.stderr)
        print("Run 'depsolve_ext init-overrides' first.", file=sys.stderr)
        return 1
    
    print_header("Override Verification")
    print(f"  Project: {project}")
    print(f"  Override file: {override_file}")
    
    # 설정 로드 (검증 대상이므로 미검증 항목도 포함)
    config = OverrideConfig.load(project, include_unverified=True)
    
    if not config.has_any_overrides():
        print("\n  No overrides to verify.")
        return 0
    
    # 검증 실행
    print_section("Running Verification")
    verifier = OverrideVerifier(project)
    results = verifier.verify_all(config)
    
    # 결과 출력
    success = [r for r in results if r.success]
    failed = [r for r in results if not r.success]
    
    print(f"\n  Total: {len(results)} entries")
    print(f"  ✓ Passed: {len(success)}")
    print(f"  ✗ Failed: {len(failed)}")
    
    if args.verbose:
        if success:
            print_section("Verified")
            for r in success:
                print(f"  ✓ {r.entry.key} → {r.entry.value}")
                if r.details:
                    for k, v in r.details.items():
                        print(f"      {k}: {v}")
        
        if failed:
            print_section("Failed")
            for r in failed:
                print(f"  ✗ {r.entry.key}")
                print(f"      Error: {r.error}")
    
    # overrides.yaml 업데이트
    success_count, fail_count = update_overrides_with_verification(project, results)
    
    print_section("Summary")
    print(f"  Updated overrides.yaml: {success_count} verified, {fail_count} failed")
    
    # 리포트 생성 (옵션)
    if args.report:
        report = generate_verification_report(results)
        report_path = project / ".depsolve" / "verification_report.md"
        report_path.write_text(report)
        print(f"  Report saved: {report_path}")
    
    print()
    return 1 if failed else 0


def cmd_init_overrides(args):
    """Override 템플릿 초기화"""
    project = Path(args.path).resolve()
    
    if not project.exists():
        print(f"Error: Path not found: {project}", file=sys.stderr)
        return 1
    
    override_modules = _get_override_modules()
    create_initial_overrides = override_modules['create_initial_overrides']
    
    override_dir = project / ".depsolve"
    override_file = override_dir / "overrides.yaml"
    
    if override_file.exists() and not args.force:
        print(f"Error: {override_file} already exists.", file=sys.stderr)
        print("Use --force to overwrite.", file=sys.stderr)
        return 1
    
    override_dir.mkdir(parents=True, exist_ok=True)
    
    # 템플릿 생성
    config = create_initial_overrides(project)
    config.save(project)
    
    print_header("Override Initialization")
    print(f"  Created: {override_file}")
    print()
    print("  Next steps:")
    print("  1. Edit .depsolve/overrides.yaml to add your overrides")
    print("  2. Run 'depsolve_ext verify-overrides .' to validate")
    print("  3. Run 'depsolve_ext analyze .' to apply overrides")
    print()
    
    return 0


def cmd_apply_overrides(args):
    """Override 적용 결과 미리보기"""
    project = Path(args.path).resolve()
    
    if not project.exists():
        print(f"Error: Path not found: {project}", file=sys.stderr)
        return 1
    
    override_modules = _get_override_modules()
    OverrideConfig = override_modules['OverrideConfig']
    OverrideApplicator = override_modules['OverrideApplicator']
    
    override_file = project / ".depsolve" / "overrides.yaml"
    if not override_file.exists():
        print(f"Error: No overrides.yaml found at {override_file}", file=sys.stderr)
        return 1
    
    print_header("Override Application Preview")
    print(f"  Project: {project}")
    
    # Phantom 탐지
    from .extensions import load_hybrid_manifest
    manifest = load_hybrid_manifest(project)
    
    detector = PhantomDetector(
        project,
        js_deps=manifest.js_deps,
        js_dev_deps=manifest.js_dev_deps,
        py_deps=manifest.py_deps,
        py_dev_deps=manifest.py_dev_deps,
        verify=args.verify
    )
    
    phantoms = detector.detect()
    original_count = len([p for p in phantoms if p.is_phantom])
    
    print_section("Before Override")
    print(f"  Phantoms detected: {original_count}")
    
    # Override 적용
    config = OverrideConfig.load(project)
    applicator = OverrideApplicator(config)
    modified = applicator.apply(phantoms)
    
    final_count = len([p for p in modified if p.is_phantom])
    
    print_section("After Override")
    print(f"  Phantoms remaining: {final_count}")
    print(f"  Resolved: {original_count - final_count}")
    
    stats = applicator.stats
    print_section("Override Stats")
    print(f"  Typo corrected: {stats['typo_corrected']}")
    print(f"  Alias resolved: {stats['alias_resolved']}")
    print(f"  Internal marked: {stats['internal_marked']}")
    print(f"  Ignored: {stats['ignored']}")
    
    if args.verbose:
        # 변경된 항목 상세
        print_section("Changed Items")
        for p in modified:
            if "[Override]" in p.reason:
                print(f"  • {p.package}: {p.reason}")
    
    print()
    return 0

# =============================================================================
# Main
# =============================================================================

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='depsolve_ext',
        description='depsolve 통합 의존성 분석기'
    )
    parser.add_argument('--version', action='version', version='0.3.0')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # analyze
    p_analyze = subparsers.add_parser('analyze', help='프로젝트 전체 분석')
    p_analyze.add_argument('path', help='프로젝트 경로')
    p_analyze.add_argument('--verify', '-v', action='store_true', help='런타임 검증')
    p_analyze.add_argument('--verbose', action='store_true', help='상세 출력')
    p_analyze.add_argument('--no-dev', action='store_true', help='devDependencies 제외')
    p_analyze.add_argument('--no-color', action='store_true', help='색상 비활성화')
    p_analyze.add_argument('--format', '-f', choices=['console', 'json', 'markdown'],
                          default='console', help='출력 형식')
    p_analyze.add_argument('--max-nodes', type=int, default=50, help='Mermaid 최대 노드 수')
    
    # phantoms
    p_phantoms = subparsers.add_parser('phantoms', help='Phantom 의존성 탐지')
    p_phantoms.add_argument('path', help='프로젝트 경로')
    p_phantoms.add_argument('--verify', '-v', action='store_true', help='런타임 검증')
    p_phantoms.add_argument('--no-color', action='store_true')
    
    # graph
    p_graph = subparsers.add_parser('graph', help='의존성 그래프 분석')
    p_graph.add_argument('path', help='프로젝트 경로')
    p_graph.add_argument('--verify', '-v', action='store_true')
    p_graph.add_argument('--mermaid', '-m', action='store_true', help='Mermaid 다이어그램 출력')
    p_graph.add_argument('--max-nodes', type=int, default=50, help='최대 노드 수')
    
    # imports
    p_imports = subparsers.add_parser('imports', help='파일 import 추출')
    p_imports.add_argument('file', help='파일 경로')
    p_imports.add_argument('--json', action='store_true', help='JSON 출력')
    p_imports.add_argument('--verbose', action='store_true')
    
    # ecosystem
    p_eco = subparsers.add_parser('ecosystem', help='생태계 감지')
    p_eco.add_argument('path', help='프로젝트 경로')
    
    # multi-version
    p_multi = subparsers.add_parser('multi-version', help='다중 버전 탐지')
    p_multi.add_argument('path', help='프로젝트 경로')
    p_multi.add_argument('--verbose', action='store_true')
    
    # verify-overrides
    p_verify_override = subparsers.add_parser('verify-overrides', help='Override 검증')
    p_verify_override.add_argument('path', help='프로젝트 경로')
    p_verify_override.add_argument('--verbose', action='store_true', help='상세 출력')
    p_verify_override.add_argument('--report', action='store_true', help='검증 리포트 생성')
    
    # init-overrides
    p_init_override = subparsers.add_parser('init-overrides', help='Override 템플릿 초기화')
    p_init_override.add_argument('path', help='프로젝트 경로')
    p_init_override.add_argument('--force', action='store_true', help='기존 파일 덮어쓰기')
    
    # apply-overrides
    p_apply_override = subparsers.add_parser('apply-overrides', help='Override 적용 미리보기')
    p_apply_override.add_argument('path', help='프로젝트 경로')
    p_apply_override.add_argument('--verify', '-v', action='store_true', help='런타임 검증')
    p_apply_override.add_argument('--verbose', action='store_true', help='상세 출력')
    
    args = parser.parse_args(argv)
    
    if not args.command:
        parser.print_help()
        return 0
    
    commands = {
        'analyze': cmd_analyze,
        'phantoms': cmd_phantoms,
        'graph': cmd_graph,
        'imports': cmd_imports,
        'ecosystem': cmd_ecosystem,
        'multi-version': cmd_multi_version,
        'verify-overrides': cmd_verify_overrides,
        'init-overrides': cmd_init_overrides,
        'apply-overrides': cmd_apply_overrides,
    }
    
    return commands[args.command](args)


if __name__ == '__main__':
    sys.exit(main())
