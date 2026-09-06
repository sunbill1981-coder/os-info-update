from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
import re
from typing import Dict, List, Optional, Sequence, Tuple


SPACE_RE = re.compile(r"\s+")


def clean_text(value: str) -> str:
    return SPACE_RE.sub(" ", value).strip()


@dataclass
class Block:
    tag: str
    text: str
    attrs: Dict[str, str] = field(default_factory=dict)


class ArticleBlockParser(HTMLParser):
    BLOCK_TAGS = {"h1", "h2", "h3", "h4", "p", "li", "th", "td"}
    SKIP_TAGS = {"script", "style", "svg", "noscript"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.blocks: List[Block] = []
        self._main_depth = 0
        self._skip_depth = 0
        self._tag: Optional[str] = None
        self._attrs: Dict[str, str] = {}
        self._parts: List[str] = []

    def handle_starttag(self, tag: str, attrs: Sequence[Tuple[str, Optional[str]]]) -> None:
        tag = tag.lower()
        if tag == "main":
            self._main_depth += 1
        if tag in self.SKIP_TAGS:
            self._skip_depth += 1
        if self._main_depth and not self._skip_depth and tag in self.BLOCK_TAGS and self._tag is None:
            self._tag = tag
            self._attrs = {key: value or "" for key, value in attrs}
            self._parts = []

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if self._tag == tag:
            text = clean_text(" ".join(self._parts))
            if text:
                self.blocks.append(Block(tag=tag, text=text, attrs=self._attrs))
            self._tag = None
            self._attrs = {}
            self._parts = []
        if tag in self.SKIP_TAGS and self._skip_depth:
            self._skip_depth -= 1
        if tag == "main" and self._main_depth:
            self._main_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._tag and not self._skip_depth:
            self._parts.append(data)


class TableParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.rows: List[List[str]] = []
        self._in_row = False
        self._cell_tag: Optional[str] = None
        self._cell_parts: List[str] = []
        self._row: List[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: Sequence[Tuple[str, Optional[str]]]) -> None:
        tag = tag.lower()
        if tag in {"script", "style", "svg"}:
            self._skip_depth += 1
        if self._skip_depth:
            return
        if tag == "tr":
            self._in_row = True
            self._row = []
        elif self._in_row and tag in {"th", "td"}:
            self._cell_tag = tag
            self._cell_parts = []

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in {"script", "style", "svg"} and self._skip_depth:
            self._skip_depth -= 1
            return
        if self._skip_depth:
            return
        if self._cell_tag == tag:
            self._row.append(clean_text(" ".join(self._cell_parts)))
            self._cell_tag = None
            self._cell_parts = []
        elif tag == "tr" and self._in_row:
            if any(self._row):
                self.rows.append(self._row)
            self._in_row = False

    def handle_data(self, data: str) -> None:
        if self._cell_tag and not self._skip_depth:
            self._cell_parts.append(data)


def parse_article_blocks(html: str) -> List[Block]:
    parser = ArticleBlockParser()
    parser.feed(html)
    return parser.blocks


def parse_table_rows(html: str) -> List[List[str]]:
    parser = TableParser()
    parser.feed(html)
    return parser.rows

