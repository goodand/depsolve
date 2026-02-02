"""
depsolve_ext/graph.py
=====================
의존성 그래프 자료구조 및 분석 알고리즘

기능:
- 인접 리스트 기반 방향 그래프
- O(V + E) 순환 탐지 (DFS 색상 기반)
- 다이아몬드 의존성 탐지
- Mermaid/DOT 시각화
"""

from collections import defaultdict, deque
from typing import Dict, List, Set, Optional, Tuple
from enum import Enum

from .models import (
    PackageNode, DependencyEdge, CycleInfo, DiamondInfo
)


class _VisitState(Enum):
    """노드 방문 상태 (순환 탐지용)"""
    WHITE = 0  # 미방문
    GRAY = 1   # 방문 중 (현재 DFS 경로에 있음)
    BLACK = 2  # 방문 완료


class DependencyGraph:
    """
    의존성 그래프 (방향 그래프)
    
    내부 구조:
    - _nodes: 노드 정보 맵 {이름: PackageNode}
    - _adjacency: 인접 리스트 (정방향: A→B는 A가 B에 의존)
    - _reverse: 역방향 인접 리스트
    - _edges: 엣지 정보 맵
    """
    
    def __init__(self):
        self._nodes: Dict[str, PackageNode] = {}
        self._adjacency: Dict[str, List[str]] = defaultdict(list)
        self._reverse: Dict[str, List[str]] = defaultdict(list)
        self._edges: Dict[Tuple[str, str], DependencyEdge] = {}
        self._multi_edges: Dict[Tuple[str, str], List[DependencyEdge]] = defaultdict(list)
    
    # =========================================================================
    # 노드/엣지 추가
    # =========================================================================
    
    def add_node(self, name: str, version: Optional[str] = None):
        """노드 추가"""
        if name not in self._nodes:
            self._nodes[name] = PackageNode(name=name, version=version)
        elif version and self._nodes[name].version is None:
            self._nodes[name] = PackageNode(name=name, version=version)
    
    def add_edge(self, edge: DependencyEdge):
        """엣지 추가"""
        source, target = edge.source, edge.target
        key = (source, target)
        
        self.add_node(source)
        self.add_node(target, edge.resolved_version)
        
        self._multi_edges[key].append(edge)
        
        if key not in self._edges:
            self._edges[key] = edge
            self._adjacency[source].append(target)
            self._reverse[target].append(source)
    
    # =========================================================================
    # 조회 메서드
    # =========================================================================
    
    def has_node(self, name: str) -> bool:
        return name in self._nodes
    
    def has_edge(self, source: str, target: str) -> bool:
        return (source, target) in self._edges
    
    def get_node(self, name: str) -> Optional[PackageNode]:
        return self._nodes.get(name)
    
    def get_edge(self, source: str, target: str) -> Optional[DependencyEdge]:
        return self._edges.get((source, target))
    
    def get_dependencies(self, node: str) -> List[str]:
        """노드의 직접 의존성 (정방향)"""
        return list(self._adjacency.get(node, []))
    
    def get_dependents(self, node: str) -> List[str]:
        """노드를 의존하는 패키지 (역방향)"""
        return list(self._reverse.get(node, []))
    
    def get_all_nodes(self) -> List[str]:
        return list(self._nodes.keys())
    
    def get_all_edges(self) -> List[DependencyEdge]:
        return list(self._edges.values())
    
    @property
    def node_count(self) -> int:
        return len(self._nodes)
    
    @property
    def edge_count(self) -> int:
        return len(self._edges)
    
    # =========================================================================
    # 순환 탐지 (Cycle Detection)
    # =========================================================================
    
    def find_cycles(self) -> List[CycleInfo]:
        """
        모든 순환 의존성 찾기
        
        알고리즘: DFS + 색상 기반 방문 추적
        - WHITE: 미방문
        - GRAY: 현재 DFS 경로에 있음
        - BLACK: 방문 완료
        
        GRAY 노드를 다시 만나면 순환 발견
        
        Returns:
            CycleInfo 목록
        """
        cycles: List[CycleInfo] = []
        state = {n: _VisitState.WHITE for n in self._nodes}
        path: List[str] = []
        
        def dfs(node: str):
            state[node] = _VisitState.GRAY
            path.append(node)
            
            for neighbor in self._adjacency.get(node, []):
                if state.get(neighbor) == _VisitState.GRAY:
                    # 순환 발견: path에서 neighbor부터 현재까지
                    cycle_start = path.index(neighbor)
                    cycle_path = path[cycle_start:] + [neighbor]
                    cycles.append(CycleInfo(
                        path=cycle_path,
                        length=len(path) - cycle_start
                    ))
                elif state.get(neighbor) == _VisitState.WHITE:
                    dfs(neighbor)
            
            path.pop()
            state[node] = _VisitState.BLACK
        
        for node in self._nodes:
            if state[node] == _VisitState.WHITE:
                dfs(node)
        
        return self._deduplicate_cycles(cycles)
    
    def _deduplicate_cycles(self, cycles: List[CycleInfo]) -> List[CycleInfo]:
        """중복 순환 제거 (순환 회전 고려)"""
        seen: Set[frozenset] = set()
        unique: List[CycleInfo] = []
        
        for cycle in cycles:
            nodes = frozenset(cycle.path[:-1])
            if nodes not in seen:
                seen.add(nodes)
                unique.append(cycle)
        
        return unique
    
    def has_cycle(self) -> bool:
        """순환 존재 여부 (빠른 확인)"""
        state = {n: _VisitState.WHITE for n in self._nodes}
        
        def has_cycle_from(node: str) -> bool:
            state[node] = _VisitState.GRAY
            
            for neighbor in self._adjacency.get(node, []):
                if state.get(neighbor) == _VisitState.GRAY:
                    return True
                elif state.get(neighbor) == _VisitState.WHITE:
                    if has_cycle_from(neighbor):
                        return True
            
            state[node] = _VisitState.BLACK
            return False
        
        for node in self._nodes:
            if state[node] == _VisitState.WHITE:
                if has_cycle_from(node):
                    return True
        
        return False
    
    # =========================================================================
    # 다이아몬드 탐지 (Diamond Detection)
    # =========================================================================
    
    def find_diamonds(self) -> List[DiamondInfo]:
        """
        다이아몬드 의존성 찾기
        
        다이아몬드 정의:
            A (top)
           / \\
          B   C (left, right)
           \\ /
            D (bottom)
        
        A가 B, C에 의존하고, B와 C가 모두 D에 의존할 때 발생
        
        알고리즘:
        1. 각 노드(top)의 직접 의존성 쌍(left, right) 순회
        2. left와 right의 의존성 교집합(bottom) 계산
        3. 교집합이 있으면 다이아몬드
        
        Returns:
            DiamondInfo 목록
        """
        diamonds: List[DiamondInfo] = []
        seen: Set[frozenset] = set()
        
        for top in self._nodes:
            deps = self.get_dependencies(top)
            
            if len(deps) < 2:
                continue
            
            for i, left in enumerate(deps):
                for right in deps[i + 1:]:
                    left_deps = set(self.get_dependencies(left))
                    right_deps = set(self.get_dependencies(right))
                    common = left_deps & right_deps
                    
                    for bottom in common:
                        key = frozenset([top, left, right, bottom])
                        if key in seen:
                            continue
                        seen.add(key)
                        
                        left_edge = self.get_edge(left, bottom)
                        right_edge = self.get_edge(right, bottom)
                        
                        left_version = left_edge.version_range if left_edge else "*"
                        right_version = right_edge.version_range if right_edge else "*"
                        
                        diamonds.append(DiamondInfo(
                            top=top, left=left, right=right, bottom=bottom,
                            left_version=left_version, right_version=right_version
                        ))
        
        return diamonds
    
    def find_diamonds_with_conflict(self) -> List[DiamondInfo]:
        """버전 충돌이 있는 다이아몬드만 반환"""
        return [d for d in self.find_diamonds() if d.has_version_conflict]
    
    # =========================================================================
    # 전이적 의존성
    # =========================================================================
    
    def get_transitive_dependencies(self, node: str) -> Set[str]:
        """노드의 모든 전이적 의존성 (직접 + 간접)"""
        if node not in self._nodes:
            return set()
        
        visited: Set[str] = set()
        stack = [node]
        
        while stack:
            current = stack.pop()
            for dep in self._adjacency.get(current, []):
                if dep not in visited:
                    visited.add(dep)
                    stack.append(dep)
        
        return visited
    
    def get_depth(self, node: str) -> int:
        """노드의 깊이 (루트에서의 최단 거리)"""
        if node not in self._nodes:
            return -1
        
        roots = [n for n in self._nodes if not self._reverse.get(n)]
        if not roots:
            return -1
        if node in roots:
            return 0
        
        visited = set(roots)
        queue = deque((r, 0) for r in roots)
        
        while queue:
            current, depth = queue.popleft()
            for neighbor in self._adjacency.get(current, []):
                if neighbor == node:
                    return depth + 1
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, depth + 1))
        
        return -1
    
    # =========================================================================
    # Mermaid 시각화
    # =========================================================================
    
    def to_mermaid(self, max_nodes: int = 100) -> str:
        """
        Mermaid 형식 그래프 문자열 생성
        
        Args:
            max_nodes: 최대 표시 노드 수
            
        Returns:
            Mermaid 다이어그램 문자열 (graph TD 형식)
        """
        lines = ["graph TD"]
        nodes_to_show = list(self._nodes.keys())[:max_nodes]
        
        for source in nodes_to_show:
            source_node = self._nodes[source]
            source_label = self._mermaid_label(source_node)
            
            for target in self._adjacency.get(source, []):
                if target not in nodes_to_show:
                    continue
                
                target_node = self._nodes[target]
                target_label = self._mermaid_label(target_node)
                
                edge = self.get_edge(source, target)
                edge_label = edge.version_range if edge else ""
                
                src_id = self._mermaid_id(source)
                tgt_id = self._mermaid_id(target)
                
                if edge_label and edge_label != "*":
                    lines.append(f"    {src_id}[\"{source_label}\"] -->|{edge_label}| {tgt_id}[\"{target_label}\"]")
                else:
                    lines.append(f"    {src_id}[\"{source_label}\"] --> {tgt_id}[\"{target_label}\"]")
        
        if len(self._nodes) > max_nodes:
            lines.append(f"    %% ... and {len(self._nodes) - max_nodes} more nodes")
        
        return "\n".join(lines)
    
    def to_mermaid_diamond(self, diamond: DiamondInfo) -> str:
        """다이아몬드를 Mermaid로 시각화"""
        top_id = self._mermaid_id(diamond.top)
        left_id = self._mermaid_id(diamond.left)
        right_id = self._mermaid_id(diamond.right)
        bottom_id = self._mermaid_id(diamond.bottom)
        
        conflict_style = ":::conflict" if diamond.has_version_conflict else ""
        
        lines = [
            "graph TD",
            f"    {top_id}[\"{diamond.top}\"] --> {left_id}[\"{diamond.left}\"]",
            f"    {top_id} --> {right_id}[\"{diamond.right}\"]",
            f"    {left_id} -->|{diamond.left_version}| {bottom_id}[\"{diamond.bottom}\"]{conflict_style}",
            f"    {right_id} -->|{diamond.right_version}| {bottom_id}",
        ]
        
        if diamond.has_version_conflict:
            lines.append("    classDef conflict fill:#ff6b6b,stroke:#c92a2a")
        
        return "\n".join(lines)
    
    def to_mermaid_cycle(self, cycle: CycleInfo) -> str:
        """순환을 Mermaid로 시각화"""
        lines = ["graph LR"]
        
        for i in range(len(cycle.path) - 1):
            src = self._mermaid_id(cycle.path[i])
            tgt = self._mermaid_id(cycle.path[i + 1])
            lines.append(f"    {src}[\"{cycle.path[i]}\"] --> {tgt}[\"{cycle.path[i + 1]}\"]")
        
        # 순환 강조
        lines.append(f"    linkStyle {len(cycle.path) - 2} stroke:#ff0000,stroke-width:3px")
        
        return "\n".join(lines)
    
    def _mermaid_id(self, name: str) -> str:
        """Mermaid 노드 ID (특수문자 제거)"""
        return name.replace("@", "_").replace("/", "_").replace("-", "_").replace(".", "_")
    
    def _mermaid_label(self, node: PackageNode) -> str:
        """Mermaid 노드 라벨"""
        if node.version:
            return f"{node.name}@{node.version}"
        return node.name
    
    # =========================================================================
    # DOT (Graphviz) 시각화
    # =========================================================================
    
    def to_dot(self, max_nodes: int = 100) -> str:
        """DOT (Graphviz) 형식 그래프 문자열 생성"""
        lines = [
            "digraph DependencyGraph {",
            "    rankdir=TB;",
            '    node [shape=box, style=rounded];',
        ]
        
        nodes_to_show = list(self._nodes.keys())[:max_nodes]
        
        for name in nodes_to_show:
            node = self._nodes[name]
            label = f"{node.name}\\n{node.version}" if node.version else node.name
            node_id = self._dot_id(name)
            lines.append(f'    {node_id} [label="{label}"];')
        
        for source in nodes_to_show:
            for target in self._adjacency.get(source, []):
                if target not in nodes_to_show:
                    continue
                
                src_id = self._dot_id(source)
                tgt_id = self._dot_id(target)
                
                edge = self.get_edge(source, target)
                if edge and edge.version_range and edge.version_range != "*":
                    lines.append(f'    {src_id} -> {tgt_id} [label="{edge.version_range}"];')
                else:
                    lines.append(f'    {src_id} -> {tgt_id};')
        
        lines.append("}")
        return "\n".join(lines)
    
    def _dot_id(self, name: str) -> str:
        """DOT 노드 ID"""
        if any(c in name for c in '@/-. '):
            return f'"{name}"'
        return name
    
    # =========================================================================
    # 유틸리티
    # =========================================================================
    
    def get_roots(self) -> List[str]:
        """루트 노드들 (아무도 의존하지 않는 노드)"""
        return [n for n in self._nodes if not self._reverse.get(n)]
    
    def get_leaves(self) -> List[str]:
        """리프 노드들 (다른 것에 의존하지 않는 노드)"""
        return [n for n in self._nodes if not self._adjacency.get(n)]
    
    def subgraph(self, root: str, max_depth: Optional[int] = None) -> "DependencyGraph":
        """특정 노드를 루트로 하는 서브그래프 추출"""
        if root not in self._nodes:
            return DependencyGraph()
        
        sub = DependencyGraph()
        visited: Set[str] = set()
        queue = deque([(root, 0)])
        
        while queue:
            node, depth = queue.popleft()
            
            if node in visited:
                continue
            if max_depth is not None and depth > max_depth:
                continue
            
            visited.add(node)
            original = self._nodes[node]
            sub.add_node(node, original.version)
            
            for neighbor in self._adjacency.get(node, []):
                if neighbor not in visited:
                    queue.append((neighbor, depth + 1))
        
        for node in visited:
            for neighbor in self._adjacency.get(node, []):
                if neighbor in visited:
                    edge = self.get_edge(node, neighbor)
                    if edge:
                        sub.add_edge(edge)
        
        return sub
    
    def clear(self):
        """그래프 초기화"""
        self._nodes.clear()
        self._adjacency.clear()
        self._reverse.clear()
        self._edges.clear()
        self._multi_edges.clear()
    
    def __len__(self) -> int:
        return len(self._nodes)
    
    def __contains__(self, node: str) -> bool:
        return node in self._nodes
    
    def __repr__(self) -> str:
        return f"DependencyGraph(nodes={self.node_count}, edges={self.edge_count})"
