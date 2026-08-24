"""A small Markdown renderer for the docs site.

Deliberately not a general Markdown implementation: it covers exactly the
constructs used in this repository's documents — headings, paragraphs, fenced
code, tables, lists, blockquotes, rules and the usual inline spans — and
nothing else. That keeps the site build dependency-free, which matters for the
same reason the reports are self-contained: this project should build and run
from a bare checkout with no network.

Anything it does not recognise is emitted as escaped text rather than dropped,
so a document is never silently truncated by the renderer.
"""

from __future__ import annotations

import html
import re

HEADING_RE = re.compile(r"^(?P<level>#{1,6})\s+(?P<text>.*?)\s*#*\s*$")
FENCE_RE = re.compile(r"^\s*```+\s*(?P<lang>[\w+-]*)\s*$")
UL_RE = re.compile(r"^(?P<indent>\s*)[-*+]\s+(?P<text>.*)$")
OL_RE = re.compile(r"^(?P<indent>\s*)(?P<number>\d+)[.)]\s+(?P<text>.*)$")
QUOTE_RE = re.compile(r"^\s*>\s?(?P<text>.*)$")
RULE_RE = re.compile(r"^\s*([-*_])\s*(\1\s*){2,}$")
TABLE_DIVIDER_RE = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?\s*$")

LINK_RE = re.compile(r"\[(?P<text>[^\]]*)\]\((?P<href>[^)\s]+)(?:\s+\"[^\"]*\")?\)")
CODE_RE = re.compile(r"`(?P<code>[^`]+)`")
BOLD_RE = re.compile(r"\*\*(?P<text>\S(?:.*?\S)?)\*\*")
ITALIC_RE = re.compile(r"(?<![\w*])\*(?P<text>[^*\n]+)\*(?![\w*])")

_PLACEHOLDER = "\x00{}\x00"


def _slug(text: str) -> str:
    cleaned = re.sub(r"[^\w\s-]", "", text.lower()).strip()
    return re.sub(r"[\s_]+", "-", cleaned) or "section"


def inline(text: str, *, link_rewriter=None) -> str:
    """Render inline spans. Code spans are extracted first so they stay literal."""
    codes: list[str] = []

    def stash_code(match: re.Match[str]) -> str:
        codes.append(html.escape(match.group("code"), quote=False))
        return _PLACEHOLDER.format(len(codes) - 1)

    text = CODE_RE.sub(stash_code, text)

    links: list[str] = []

    def stash_link(match: re.Match[str]) -> str:
        href = match.group("href")
        if link_rewriter is not None:
            href = link_rewriter(href)
        label = html.escape(match.group("text"), quote=False)
        links.append(f'<a href="{html.escape(href, quote=True)}">{label}</a>')
        return f"\x01{len(links) - 1}\x01"

    text = LINK_RE.sub(stash_link, text)
    text = html.escape(text, quote=False)
    text = BOLD_RE.sub(lambda m: f"<strong>{m.group('text')}</strong>", text)
    text = ITALIC_RE.sub(lambda m: f"<em>{m.group('text')}</em>", text)

    for index, rendered in enumerate(links):
        text = text.replace(f"\x01{index}\x01", rendered)
    for index, code in enumerate(codes):
        text = text.replace(_PLACEHOLDER.format(index), f"<code>{code}</code>")
    return text


class _Renderer:
    def __init__(self, link_rewriter=None):
        self.out: list[str] = []
        self.headings: list[tuple[int, str, str]] = []
        self.link_rewriter = link_rewriter

    def span(self, text: str) -> str:
        return inline(text, link_rewriter=self.link_rewriter)

    # ------------------------------------------------------------------ blocks

    def render(self, text: str) -> str:
        lines = text.replace("\r\n", "\n").split("\n")
        index = 0
        while index < len(lines):
            line = lines[index]

            if not line.strip():
                index += 1
                continue

            fence = FENCE_RE.match(line)
            if fence:
                index = self._code(lines, index, fence.group("lang"))
                continue

            heading = HEADING_RE.match(line)
            if heading:
                level = len(heading.group("level"))
                label = heading.group("text")
                anchor = _slug(label)
                self.headings.append((level, label, anchor))
                self.out.append(
                    f'<h{level} id="{anchor}">{self.span(label)}</h{level}>'
                )
                index += 1
                continue

            if RULE_RE.match(line):
                self.out.append("<hr>")
                index += 1
                continue

            if "|" in line and index + 1 < len(lines) and TABLE_DIVIDER_RE.match(lines[index + 1]):
                index = self._table(lines, index)
                continue

            if QUOTE_RE.match(line):
                index = self._quote(lines, index)
                continue

            if UL_RE.match(line) or OL_RE.match(line):
                index = self._list(lines, index)
                continue

            index = self._paragraph(lines, index)

        return "\n".join(self.out)

    def _code(self, lines: list[str], index: int, lang: str) -> int:
        body: list[str] = []
        index += 1
        while index < len(lines) and not FENCE_RE.match(lines[index]):
            body.append(lines[index])
            index += 1
        index += 1  # closing fence, or end of document
        klass = f' class="language-{html.escape(lang, quote=True)}"' if lang else ""
        self.out.append(
            f'<pre class="code"><code{klass}>'
            + html.escape("\n".join(body), quote=False)
            + "</code></pre>"
        )
        return index

    def _table(self, lines: list[str], index: int) -> int:
        def cells(row: str) -> list[str]:
            stripped = row.strip()
            if stripped.startswith("|"):
                stripped = stripped[1:]
            if stripped.endswith("|"):
                stripped = stripped[:-1]
            return [cell.strip() for cell in stripped.split("|")]

        header = cells(lines[index])
        aligns = []
        for spec in cells(lines[index + 1]):
            left, right = spec.startswith(":"), spec.endswith(":")
            aligns.append("center" if left and right else "right" if right else "left")
        index += 2

        rows: list[list[str]] = []
        while index < len(lines) and "|" in lines[index] and lines[index].strip():
            rows.append(cells(lines[index]))
            index += 1

        def cell(tag: str, value: str, position: int) -> str:
            align = aligns[position] if position < len(aligns) else "left"
            style = f' style="text-align:{align}"' if align != "left" else ""
            return f"<{tag}{style}>{self.span(value)}</{tag}>"

        head = "".join(cell("th", value, i) for i, value in enumerate(header))
        body = "".join(
            "<tr>" + "".join(cell("td", value, i) for i, value in enumerate(row)) + "</tr>"
            for row in rows
        )
        self.out.append(
            f'<div class="scroll"><table><thead><tr>{head}</tr></thead>'
            f"<tbody>{body}</tbody></table></div>"
        )
        return index

    def _quote(self, lines: list[str], index: int) -> int:
        body: list[str] = []
        while index < len(lines):
            match = QUOTE_RE.match(lines[index])
            if not match:
                break
            body.append(match.group("text"))
            index += 1
        inner = _Renderer(self.link_rewriter).render("\n".join(body))
        self.out.append(f"<blockquote>{inner}</blockquote>")
        return index

    def _list(self, lines: list[str], index: int) -> int:
        ordered = bool(OL_RE.match(lines[index]))
        base_indent = len(re.match(r"^\s*", lines[index]).group())
        items: list[list[str]] = []

        while index < len(lines):
            line = lines[index]
            if not line.strip():
                # A blank line ends the list unless the next line continues it.
                if index + 1 < len(lines) and (
                    UL_RE.match(lines[index + 1]) or OL_RE.match(lines[index + 1])
                ):
                    index += 1
                    continue
                break
            match = UL_RE.match(line) or OL_RE.match(line)
            indent = len(re.match(r"^\s*", line).group())
            if match and indent <= base_indent:
                items.append([match.group("text")])
                index += 1
                continue
            if items and indent > base_indent:
                items[-1].append(line[base_indent:])
                index += 1
                continue
            break

        tag = "ol" if ordered else "ul"
        rendered = []
        for item in items:
            # Lazy continuation: plain wrapped lines belong to the item's own text,
            # so an inline span may straddle a line break. Only a nested list
            # marker starts a child block.
            head_lines = [item[0]]
            rest: list[str] = []
            for position, line in enumerate(item[1:], start=1):
                if UL_RE.match(line) or OL_RE.match(line):
                    rest = item[position:]
                    break
                head_lines.append(line.strip())
            head = self.span(" ".join(part for part in head_lines if part))
            if rest:
                # Continuation lines already had the list's own indent removed.
                nested = _Renderer(self.link_rewriter).render("\n".join(rest))
                rendered.append(f"<li>{head}{nested}</li>")
            else:
                rendered.append(f"<li>{head}</li>")
        self.out.append(f"<{tag}>" + "".join(rendered) + f"</{tag}>")
        return index

    def _paragraph(self, lines: list[str], index: int) -> int:
        body: list[str] = []
        while index < len(lines) and lines[index].strip():
            line = lines[index]
            if (
                HEADING_RE.match(line)
                or FENCE_RE.match(line)
                or RULE_RE.match(line)
                or QUOTE_RE.match(line)
                or UL_RE.match(line)
                or OL_RE.match(line)
            ):
                break
            body.append(line.strip())
            index += 1
        if body:
            self.out.append(f"<p>{self.span(' '.join(body))}</p>")
        return index


def render(text: str, *, link_rewriter=None) -> tuple[str, list[tuple[int, str, str]]]:
    """Render Markdown to HTML. Returns (html, headings) for building a contents list."""
    renderer = _Renderer(link_rewriter)
    body = renderer.render(text)
    return body, renderer.headings
