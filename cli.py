#!/usr/bin/env python3
"""
depsolve_ext/cli.py
===================
depsolve í™•ìž¥ ëª¨ë“ˆ CLI

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


def load_npm_deps(project_path: Path) -> tuple[Set[str], Set[str]]:
    """package.jsonì—ì„œ ì˜ì¡´ì„± ë¡œë“œ"""
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
    """í”„ë¡œì íŠ¸ ì „ì²´ ë¶„ì„"""
    project = Path(args.path).resolve()
    
    if not project.exists():
        print(f"Error: Path not found: {project}", file=sys.stderr)
        return 1
    
    # ë¶„ì„ ì‹¤í–‰
    result = analyze(
        project_path=str(project),
        verify=args.verify,
        include_dev=not args.no_dev,
        max_nodes=args.max_nodes
    )
    
    # ì¶œë ¥ í˜•ì‹ ì„ íƒ
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
    
    # ì¢…ë£Œ ì½”ë“œ: HIGH ì´ìƒ ì´ìŠˆê°€ ìžˆìœ¼ë©´ 1
    has_high = any(
        i.severity in (Severity.CRITICAL, Severity.HIGH)
        for i in result.issues
    )
    return 1 if has_high else 0


def cmd_phantoms(args):
    """Phantom ì˜ì¡´ì„± íƒì§€"""
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
    """ì˜ì¡´ì„± ê·¸ëž˜í”„ ë¶„ì„"""
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
    
    # ìˆœí™˜ íƒì§€
    cycles = graph.find_cycles()
    if cycles:
        print_section(f"Circular Dependencies ({len(cycles)})")
        for cycle in cycles[:10]:
            print(f"  â€¢ {' â†’ '.join(cycle.path)}")
    
    # ë‹¤ì´ì•„ëª¬ë“œ íƒì§€
    diamonds = graph.find_diamonds()
    conflicts = [d for d in diamonds if d.has_version_conflict]
    
    if diamonds:
        print_section(f"Diamond Dependencies ({len(diamonds)})")
        print(f"  With version conflicts: {len(conflicts)}")
        
        for d in conflicts[:5]:
            print(f"\n  {d.top}")
            print(f"    â”œâ”€ {d.left} â†’ {d.bottom}@{d.left_version}")
            print(f"    â””â”€ {d.right} â†’ {d.bottom}@{d.right_version}")
    
    # Mermaid ì¶œë ¥
    if args.mermaid:
        print_section("Mermaid Diagram")
        print()
        print("```mermaid")
        print(graph.to_mermaid(max_nodes=args.max_nodes))
        print("```")
    
    print()
    return 0


def cmd_imports(args):
    """íŒŒì¼ì—ì„œ import ì¶”ì¶œ"""
    path = Path(args.file).resolve()
    
    if not path.exists():
        print(f"Error: File not found: {path}", file=sys.stderr)
        return 1
    
    extractor = ImportExtractor()
    imports = extractor.extract_file(path)
    
    print_header(f"Imports: {path.name}")
    print(f"Total: {len(imports)}")
    
    # íƒ€ìž…ë³„ ê·¸ë£¹í™”
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
            print(f"  â€¢ {imp.package}{extra}")
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
    """ìƒíƒœê³„ ê°ì§€"""
    project = Path(args.path).resolve()
    
    if not project.exists():
        print(f"Error: Path not found: {project}", file=sys.stderr)
        return 1
    
    print_header(f"Ecosystem Detection: {project}")
    
    # ë‚´ìž¥ ê°ì§€
    detected = EcosystemDetector.detect(project)
    
    # npm/pip ì¶”ê°€ ê°ì§€
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
                print(f"    â€¢ {dep}: {ver}")
        except Exception as e:
            print(f"  Error: {e}")
    
    print()
    return 0


def cmd_multi_version(args):
    """ë‹¤ì¤‘ ë²„ì „ íŒ¨í‚¤ì§€ íƒì§€"""
    project = Path(args.path).resolve()
    
    print_header(f"Multi-Version Detection: {project}")
    
    verifier = RuntimeVerifier(project)
    
    if not verifier.npm_available:
        print("  Error: npm not available", file=sys.stderr)
        return 1
    
    multi = verifier.get_multi_versions()
    
    if not multi:
        print("  âœ“ No multiple version packages found")
        return 0
    
    print(f"  Found {len(multi)} packages with multiple versions:\n")
    
    for m in multi:
        print(f"  â€¢ {m.package}")
        print(f"    Versions: {', '.join(m.versions)}")
        if args.verbose:
            for path in m.paths[:3]:
                print(f"    Path: {' â†’ '.join(path)}")
    
    print()
    return 0


# =============================================================================
# Main
# =============================================================================

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='depsolve_ext',
        description='depsolve í†µí•© ì˜ì¡´ì„± ë¶„ì„ê¸°'
    )
    parser.add_argument('--version', action='version', version='0.2.0')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # analyze
    p_analyze = subparsers.add_parser('analyze', help='í”„ë¡œì íŠ¸ ì „ì²´ ë¶„ì„')
    p_analyze.add_argument('path', help='í”„ë¡œì íŠ¸ ê²½ë¡œ')
    p_analyze.add_argument('--verify', '-v', action='store_true', help='ëŸ°íƒ€ìž„ ê²€ì¦')
    p_analyze.add_argument('--verbose', action='store_true', help='ìƒì„¸ ì¶œë ¥')
    p_analyze.add_argument('--no-dev', action='store_true', help='devDependencies ì œì™¸')
    p_analyze.add_argument('--no-color', action='store_true', help='ìƒ‰ìƒ ë¹„í™œì„±í™”')
    p_analyze.add_argument('--format', '-f', choices=['console', 'json', 'markdown'],
                          default='console', help='ì¶œë ¥ í˜•ì‹')
    p_analyze.add_argument('--max-nodes', type=int, default=50, help='Mermaid ë‹¤ì´ì–´ê·¸ëž¨ ìµœëŒ€ ë…¸ë“œ ìˆ˜')
    
    # phantoms
    p_phantoms = subparsers.add_parser('phantoms', help='Phantom ì˜ì¡´ì„± íƒì§€')
    p_phantoms.add_argument('path', help='í”„ë¡œì íŠ¸ ê²½ë¡œ')
    p_phantoms.add_argument('--verify', '-v', action='store_true', help='ëŸ°íƒ€ìž„ ê²€ì¦')
    p_phantoms.add_argument('--no-color', action='store_true')
    
    # graph
    p_graph = subparsers.add_parser('graph', help='ì˜ì¡´ì„± ê·¸ëž˜í”„ ë¶„ì„')
    p_graph.add_argument('path', help='í”„ë¡œì íŠ¸ ê²½ë¡œ')
    p_graph.add_argument('--verify', '-v', action='store_true')
    p_graph.add_argument('--mermaid', '-m', action='store_true', help='Mermaid ë‹¤ì´ì–´ê·¸ëž¨ ì¶œë ¥')
    p_graph.add_argument('--max-nodes', type=int, default=50, help='ìµœëŒ€ ë…¸ë“œ ìˆ˜')
    
    # imports
    p_imports = subparsers.add_parser('imports', help='íŒŒì¼ import ì¶”ì¶œ')
    p_imports.add_argument('file', help='íŒŒì¼ ê²½ë¡œ')
    p_imports.add_argument('--json', action='store_true', help='JSON ì¶œë ¥')
    p_imports.add_argument('--verbose', action='store_true')
    
    # ecosystem
    p_eco = subparsers.add_parser('ecosystem', help='ìƒíƒœê³„ ê°ì§€')
    p_eco.add_argument('path', help='í”„ë¡œì íŠ¸ ê²½ë¡œ')
    
    # multi-version
    p_multi = subparsers.add_parser('multi-version', help='ë‹¤ì¤‘ ë²„ì „ íƒì§€')
    p_multi.add_argument('path', help='í”„ë¡œì íŠ¸ ê²½ë¡œ')
    p_multi.add_argument('--verbose', action='store_true')
    
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
    }
    
    return commands[args.command](args)


if __name__ == '__main__':
    sys.exit(main())
