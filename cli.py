#!/usr/bin/env python3
"""
depsolve_ext/cli.py
===================
depsolve 확장 모듈 CLI (Improved)

Usage:
    python -m depsolve_ext analyze ./my-project
    python -m depsolve_ext phantoms .
"""

import argparse
import sys
from pathlib import Path

from .analyzer import analyze_improved, print_improved_report, DependencyAnalyzer
from .extensions import (
    EcosystemAwarePhantomDetector,
    load_hybrid_manifest,
)


# =============================================================================
# Commands
# =============================================================================

def cmd_analyze(args):
    """프로젝트 전체 분석 (개선됨)"""
    project = Path(args.path).resolve()
    
    if not project.exists():
        print(f"Error: Path not found: {project}", file=sys.stderr)
        return 1
    
    # 분석 실행
    result = analyze_improved(
        project_path=str(project),
        verify=args.verify,
        source_dirs=None  # 기본값 사용
    )
    
    # 결과 출력
    print_improved_report(result, verbose=args.verbose)
    
    return 1 if result.confirmed_phantoms > 0 else 0


def cmd_phantoms(args):
    """Phantom 의존성 탐지 (개선됨)"""
    project = Path(args.path).resolve()
    
    if not project.exists():
        print(f"Error: Path not found: {project}", file=sys.stderr)
        return 1
    
    # Manifest 로드
    manifest = load_hybrid_manifest(project)
    print(f"Detected Ecosystems: {', '.join([e.value for e in manifest.detected_ecosystems])}")
    
    detector = EcosystemAwarePhantomDetector(
        project_path=project,
        js_deps=manifest.js_deps,
        js_dev_deps=manifest.js_dev_deps,
        py_deps=manifest.py_deps,
        py_dev_deps=manifest.py_dev_deps,
        verify=args.verify
    )
    
    phantoms = detector.detect()
    
    # 임시 리포트 (phantoms 명령어 전용)
    print(f"\nFound {len(phantoms)} candidates.")
    confirmed = [p for p in phantoms if p.is_phantom]
    print(f"Confirmed Phantoms: {len(confirmed)}")
    
    for p in confirmed:
        print(f"  [MISSING] {p.package} ({p.ecosystem.value})")
        if args.verbose:
            for imp in p.imports[:3]:
                print(f"    at {imp.file}:{imp.line}")
    
    return 1 if confirmed else 0


def cmd_graph(args):
    """의존성 그래프 분석 (복원됨)"""
    project = Path(args.path).resolve()
    
    if not project.exists():
        print(f"Error: Path not found: {project}", file=sys.stderr)
        return 1
    
    analyzer = DependencyAnalyzer(project, verify_runtime=args.verify)
    analyzer._detect_ecosystem()
    analyzer._load_manifest()
    analyzer._build_graph()
    
    graph = analyzer.graph
    
    print(f"\nGraph Analysis: {project}")
    print(f"  Nodes: {graph.node_count}")
    print(f"  Edges: {graph.edge_count}")
    
    # 순환 탐지
    cycles = graph.find_cycles()
    if cycles:
        print(f"\n--- Circular Dependencies ({len(cycles)}) ---")
        for cycle in cycles[:10]:
            print(f"  • {' -> '.join(cycle.path)}")
    
    # 다이아몬드 탐지
    diamonds = graph.find_diamonds()
    conflicts = [d for d in diamonds if d.has_version_conflict]
    
    if diamonds:
        print(f"\n--- Diamond Dependencies ({len(diamonds)}) ---")
        print(f"  With version conflicts: {len(conflicts)}")
        for d in conflicts[:5]:
            print(f"\n  {d.top}")
            print(f"    ├─ {d.left} → {d.bottom}@{d.left_version}")
            print(f"    └─ {d.right} → {d.bottom}@{d.right_version}")
    
    # Mermaid 출력
    if args.mermaid:
        print("\n--- Mermaid Diagram ---")
        print("```mermaid")
        print(graph.to_mermaid(max_nodes=args.max_nodes))
        print("```")
    
    print()
    return 0


# =============================================================================
# Main
# =============================================================================

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='depsolve_ext',
        description='depsolve 통합 의존성 분석기 (v2)'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # analyze
    p_analyze = subparsers.add_parser('analyze', help='프로젝트 전체 분석')
    p_analyze.add_argument('path', help='프로젝트 경로')
    p_analyze.add_argument('--verify', '-v', action='store_true', help='런타임 검증')
    p_analyze.add_argument('--verbose', action='store_true', help='상세 출력')
    
    # phantoms
    p_phantoms = subparsers.add_parser('phantoms', help='Phantom 의존성 탐지')
    p_phantoms.add_argument('path', help='프로젝트 경로')
    p_phantoms.add_argument('--verify', '-v', action='store_true', help='런타임 검증')
    p_phantoms.add_argument('--verbose', action='store_true')
    
    # graph
    p_graph = subparsers.add_parser('graph', help='의존성 그래프 분석')
    p_graph.add_argument('path', help='프로젝트 경로')
    p_graph.add_argument('--verify', '-v', action='store_true')
    p_graph.add_argument('--mermaid', '-m', action='store_true', help='Mermaid 다이어그램 출력')
    p_graph.add_argument('--max-nodes', type=int, default=50, help='최대 노드 수')
    
    args = parser.parse_args(argv)
    
    if not args.command:
        parser.print_help()
        return 0
    
    commands = {
        'analyze': cmd_analyze,
        'phantoms': cmd_phantoms,
        'graph': cmd_graph,
    }
    
    return commands.get(args.command, lambda x: parser.print_help())(args)


if __name__ == '__main__':
    sys.exit(main())
