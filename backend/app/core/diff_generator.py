import difflib
import re
from typing import List, Optional, Tuple


class GitDiffGenerator:
    """
    Generates standards-compliant unified git diff strings,
    summarizes modification metrics, and validates patch hygiene.
    """

    @classmethod
    def generate(
        cls,
        file_path: str,
        before_code: str,
        after_code: str,
        context_lines: int = 3,
    ) -> str:
        """
        Produces a standard unified diff string formatted for `git apply`.
        """
        clean_path = file_path.strip().lstrip("/")
        if not clean_path:
            clean_path = "patched_file"

        # Split preserving line terminators for accurate patch calculations
        before_lines = before_code.splitlines(keepends=True)
        after_lines = after_code.splitlines(keepends=True)

        diff_iterator = difflib.unified_diff(
            before_lines,
            after_lines,
            fromfile=f"a/{clean_path}",
            tofile=f"b/{clean_path}",
            n=context_lines,
            lineterm="\n",
        )

        diff_text = "".join(diff_iterator)
        return diff_text

    @classmethod
    def calculate_stats(cls, git_diff: str) -> Tuple[int, int]:
        """
        Extracts patch metrics from unified diff text.
        Returns: (insertions_count, deletions_count)
        """
        insertions = 0
        deletions = 0

        for line in git_diff.splitlines():
            # Exclude diff file headers: '--- a/...' and '+++ b/...'
            if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
                continue
            if line.startswith("+"):
                insertions += 1
            elif line.startswith("-"):
                deletions += 1

        return insertions, deletions

    @classmethod
    def is_empty_diff(cls, git_diff: str) -> bool:
        """Determines whether the patch text contains actual modifications."""
        insertions, deletions = cls.calculate_stats(git_diff)
        return (insertions + deletions) == 0