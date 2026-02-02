"""
depsolve_ext/reporters.py
=========================
ë¶„ì„ ê²°ê³¼ ë¦¬í¬í„°

ì§€ì› í˜•ì‹:
- Console: ANSI ìƒ‰ìƒ ì§€ì› í„°ë¯¸ë„ ì¶œë ¥
- Markdown: ë¬¸ì„œí™”ìš© ë§ˆí¬ë‹¤ìš´
- JSON: ê¸°ê³„ íŒë…ìš© JSON
"""

import json
import sys
import os
from typing import IO, Optional, Dict, List
from abc import ABC, abstractmethod

from .models import (
    AnalysisResult, Issue, Summary, Severity, IssueType,
    DiamondInfo, CycleInfo, PhantomResult
)


# =============================================================================
# ANSI ìƒ‰ìƒ ì½”ë“œ
# =============================================================================

class Colors:
    """ANSI ìƒ‰ìƒ ì½”ë“œ"""
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    GRAY = "\033[90m"
    WHITE = "\033[97m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


# =============================================================================
# ê¸°ë³¸ ë¦¬í¬í„°
# =============================================================================

class BaseReporter(ABC):
    """ë¦¬í¬í„° ê¸°ë³¸ í´ëž˜ìŠ¤"""
    
    def __init__(self, output: Optional[IO[str]] = None):
        self.output = output or sys.stdout
    
    def write(self, text: str):
        """ì¶œë ¥ ìŠ¤íŠ¸ë¦¼ì— ì“°ê¸°"""
        self.output.write(text)
    
    def writeln(self, text: str = ""):
        """ì¤„ ë°”ê¿ˆ í¬í•¨ ì“°ê¸°"""
        self.output.write(text + "\n")
    
    @abstractmethod
    def report(self, result: AnalysisResult):
        """ë¶„ì„ ê²°ê³¼ ì¶œë ¥"""
        pass


# =============================================================================
# ì½˜ì†” ë¦¬í¬í„°
# =============================================================================

class ConsoleReporter(BaseReporter):
    """
    ì½˜ì†” ì¶œë ¥ ë¦¬í¬í„° (ANSI ìƒ‰ìƒ ì§€ì›)
    
    ë¦¬í¬íŠ¸ êµ¬ì¡°:
    1. ìš”ì•½ (Summary) - í•µì‹¬ ì§€í‘œ
    2. ì´ìŠˆ ëª©ë¡ (Issues) - ì‹¬ê°ë„ë³„ ì •ë ¬
    3. ìƒì„¸ ì •ë³´ (Details) - verbose ëª¨ë“œ
    """
    
    SEVERITY_COLORS: Dict[Severity, str] = {
        Severity.CRITICAL: Colors.RED,
        Severity.HIGH: Colors.YELLOW,
        Severity.MEDIUM: Colors.BLUE,
        Severity.LOW: Colors.GRAY,
    }
    
    SEVERITY_LABELS: Dict[Severity, str] = {
        Severity.CRITICAL: "CRITICAL",
        Severity.HIGH: "HIGH",
        Severity.MEDIUM: "MEDIUM",
        Severity.LOW: "LOW",
    }
    
    def __init__(
        self,
        output: Optional[IO[str]] = None,
        use_color: bool = True,
        verbose: bool = False
    ):
        super().__init__(output)
        self.verbose = verbose
        
        # ìƒ‰ìƒ ì‚¬ìš© ì—¬ë¶€ ê²°ì •
        self.use_color = use_color
        if os.getenv("NO_COLOR"):
            self.use_color = False
        if hasattr(self.output, 'isatty') and not self.output.isatty():
            self.use_color = False
    
    def color(self, text: str, color: str) -> str:
        """ìƒ‰ìƒ ì ìš©"""
        if self.use_color:
            return f"{color}{text}{Colors.RESET}"
        return text
    
    def report(self, result: AnalysisResult):
        """ë¶„ì„ ê²°ê³¼ ì¶œë ¥"""
        self._report_header(result)
        self._report_summary(result.summary)
        
        if result.issues:
            self._report_issues(result.issues)
        
        if result.mermaid_diagram and self.verbose:
            self._report_mermaid(result.mermaid_diagram)
    
    def _report_header(self, result: AnalysisResult):
        """í—¤ë” ì¶œë ¥"""
        self.writeln()
        self.writeln(self.color("=" * 60, Colors.CYAN))
        self.writeln(self.color(f"  depsolve Analysis Report", Colors.BOLD))
        self.writeln(self.color("=" * 60, Colors.CYAN))
        self.writeln(f"  Project: {result.project_path}")
        self.writeln(f"  Ecosystem: {result.ecosystem}")
        self.writeln()
    
    def _report_summary(self, summary: Summary):
        """ìš”ì•½ ì¶œë ¥"""
        self.writeln(self.color("--- Summary ---", Colors.BOLD))
        self.writeln(f"  Packages: {summary.total_packages}")
        self.writeln(f"  Dependencies: {summary.total_dependencies}")
        
        if summary.issues_by_severity:
            self.writeln()
            self.writeln("  Issues by Severity:")
            for sev, count in summary.issues_by_severity.items():
                color = self.SEVERITY_COLORS.get(Severity(sev), Colors.WHITE)
                label = self.SEVERITY_LABELS.get(Severity(sev), sev.upper())
                self.writeln(f"    {self.color(label, color)}: {count}")
        
        self.writeln()
    
    def _report_issues(self, issues: List[Issue]):
        """ì´ìŠˆ ëª©ë¡ ì¶œë ¥"""
        # ì‹¬ê°ë„ë³„ ì •ë ¬
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        sorted_issues = sorted(issues, key=lambda i: severity_order.index(i.severity))
        
        self.writeln(self.color(f"--- Issues ({len(issues)}) ---", Colors.BOLD))
        
        for issue in sorted_issues:
            self._report_issue(issue)
        
        self.writeln()
    
    def _report_issue(self, issue: Issue):
        """ê°œë³„ ì´ìŠˆ ì¶œë ¥"""
        color = self.SEVERITY_COLORS.get(issue.severity, Colors.WHITE)
        label = self.SEVERITY_LABELS.get(issue.severity, "")
        
        self.writeln()
        self.writeln(f"  [{self.color(label, color)}] {issue.title}")
        self.writeln(f"    Type: {issue.type.value}")
        
        # ìœ„ì¹˜
        if issue.locations:
            self.writeln(f"    Locations:")
            for loc in issue.locations[:5]:  # ìµœëŒ€ 5ê°œ
                self.writeln(f"      â€¢ {loc}")
        
        # ì œì•ˆ
        if issue.suggestion:
            self.writeln(f"    Suggestion: {issue.suggestion}")
        
        # ì‹œê°í™” (verbose)
        if self.verbose and issue.evidence.visualization:
            self.writeln(f"    Visualization:")
            for line in issue.evidence.visualization.split('\n')[:10]:
                self.writeln(f"      {line}")
    
    def _report_mermaid(self, diagram: str):
        """Mermaid ë‹¤ì´ì–´ê·¸ëž¨ ì¶œë ¥"""
        self.writeln(self.color("--- Dependency Graph (Mermaid) ---", Colors.BOLD))
        self.writeln()
        self.writeln("```mermaid")
        self.writeln(diagram)
        self.writeln("```")
        self.writeln()
    
    # =========================================================================
    # íŽ¸ì˜ ë©”ì„œë“œ
    # =========================================================================
    
    def report_phantoms(self, phantoms: List[PhantomResult]):
        """Phantom ê²°ê³¼ ì¶œë ¥"""
        self.writeln(self.color("--- Phantom Dependencies ---", Colors.BOLD))
        
        real = [p for p in phantoms if p.is_phantom]
        trans = [p for p in phantoms if not p.is_phantom]
        
        if real:
            self.writeln(f"\n  {self.color('âœ—', Colors.RED)} Confirmed Phantoms ({len(real)}):")
            for p in real:
                ctx = p.imports[0].file_context.value if p.imports else "unknown"
                files = len(set(i.file for i in p.imports))
                self.writeln(f"    â€¢ {p.package} ({files} files, {ctx})")
        
        if trans:
            self.writeln(f"\n  {self.color('âœ“', Colors.GREEN)} Transitive Dependencies ({len(trans)}):")
            for p in trans:
                self.writeln(f"    â€¢ {p.package} (v{p.installed_version})")
        
        if not real and not trans:
            self.writeln(f"  {self.color('âœ“', Colors.GREEN)} No phantom dependencies found")
        
        self.writeln()
    
    def report_diamonds(self, diamonds: List[DiamondInfo]):
        """ë‹¤ì´ì•„ëª¬ë“œ ê²°ê³¼ ì¶œë ¥"""
        if not diamonds:
            return
        
        conflicts = [d for d in diamonds if d.has_version_conflict]
        
        self.writeln(self.color(f"--- Diamond Dependencies ({len(diamonds)}) ---", Colors.BOLD))
        
        if conflicts:
            self.writeln(f"\n  {self.color('âš ', Colors.YELLOW)} With Version Conflicts ({len(conflicts)}):")
            for d in conflicts[:10]:
                self.writeln(f"    â€¢ {d.top} â†’ {d.left}/{d.right} â†’ {d.bottom}")
                self.writeln(f"      {d.left_version} vs {d.right_version}")
        
        self.writeln()
    
    def report_cycles(self, cycles: List[CycleInfo]):
        """ìˆœí™˜ ê²°ê³¼ ì¶œë ¥"""
        if not cycles:
            return
        
        self.writeln(self.color(f"--- Circular Dependencies ({len(cycles)}) ---", Colors.BOLD))
        
        for cycle in cycles[:10]:
            self.writeln(f"  â€¢ {' â†’ '.join(cycle.path)}")
        
        if len(cycles) > 10:
            self.writeln(f"  ... and {len(cycles) - 10} more")
        
        self.writeln()


# =============================================================================
# Markdown ë¦¬í¬í„°
# =============================================================================

class MarkdownReporter(BaseReporter):
    """Markdown í˜•ì‹ ë¦¬í¬í„°"""
    
    def report(self, result: AnalysisResult):
        """ë¶„ì„ ê²°ê³¼ ì¶œë ¥"""
        self.writeln(f"# depsolve Analysis Report")
        self.writeln()
        self.writeln(f"- **Project**: {result.project_path}")
        self.writeln(f"- **Ecosystem**: {result.ecosystem}")
        self.writeln()
        
        # ìš”ì•½
        self._report_summary(result.summary)
        
        # ì´ìŠˆ
        if result.issues:
            self._report_issues(result.issues)
        
        # ë‹¤ì´ì–´ê·¸ëž¨
        if result.mermaid_diagram:
            self.writeln("## Dependency Graph")
            self.writeln()
            self.writeln("```mermaid")
            self.writeln(result.mermaid_diagram)
            self.writeln("```")
            self.writeln()
    
    def _report_summary(self, summary: Summary):
        """ìš”ì•½ ì¶œë ¥"""
        self.writeln("## Summary")
        self.writeln()
        self.writeln(f"| Metric | Value |")
        self.writeln(f"|--------|-------|")
        self.writeln(f"| Packages | {summary.total_packages} |")
        self.writeln(f"| Dependencies | {summary.total_dependencies} |")
        
        for sev, count in summary.issues_by_severity.items():
            self.writeln(f"| {sev.upper()} Issues | {count} |")
        
        self.writeln()
    
    def _report_issues(self, issues: List[Issue]):
        """ì´ìŠˆ ì¶œë ¥"""
        self.writeln("## Issues")
        self.writeln()
        
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        sorted_issues = sorted(issues, key=lambda i: severity_order.index(i.severity))
        
        for issue in sorted_issues:
            severity_emoji = {
                Severity.CRITICAL: "ðŸ”´",
                Severity.HIGH: "ðŸŸ ",
                Severity.MEDIUM: "ðŸŸ¡",
                Severity.LOW: "âšª"
            }.get(issue.severity, "âšª")
            
            self.writeln(f"### {severity_emoji} {issue.title}")
            self.writeln()
            self.writeln(f"- **Severity**: {issue.severity.value}")
            self.writeln(f"- **Type**: {issue.type.value}")
            
            if issue.locations:
                self.writeln(f"- **Locations**:")
                for loc in issue.locations[:5]:
                    self.writeln(f"  - {loc}")
            
            if issue.suggestion:
                self.writeln(f"- **Suggestion**: {issue.suggestion}")
            
            if issue.evidence.visualization:
                self.writeln()
                self.writeln("```mermaid")
                self.writeln(issue.evidence.visualization)
                self.writeln("```")
            
            self.writeln()


# =============================================================================
# JSON ë¦¬í¬í„°
# =============================================================================

class JsonReporter(BaseReporter):
    """JSON í˜•ì‹ ë¦¬í¬í„°"""
    
    def __init__(self, output: Optional[IO[str]] = None, indent: int = 2):
        super().__init__(output)
        self.indent = indent
    
    def report(self, result: AnalysisResult):
        """ë¶„ì„ ê²°ê³¼ ì¶œë ¥"""
        self.writeln(json.dumps(result.to_dict(), indent=self.indent))


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    'Colors',
    'BaseReporter',
    'ConsoleReporter',
    'MarkdownReporter',
    'JsonReporter',
]
