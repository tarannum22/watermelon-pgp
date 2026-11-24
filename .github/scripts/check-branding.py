#!/usr/bin/env python3
"""Fail if the website calls the product anything but "WatermelonPGP".

Checks the visible text and the alt/aria-label/title attributes of site/*.html, and the
labels inside site/img/*.svg. Commands (<code>, <pre>), URLs and package names such as
`watermelon-pgp` are not prose and are skipped.
"""
import html
import pathlib
import re
import sys

# Any spelling of the name: watermelon, Watermelon PGP, watermelon-pgp, WATERMELONPGP, ...
NAME = re.compile(r"watermelon(?:[\s-]*pgp)?", re.IGNORECASE)
LABEL = re.compile(r'\b(?:alt|aria-label|title)="([^"]*)"')
site = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "site")
problems = []


def misnamed(text):
    """Every way `text` names the product other than exactly "WatermelonPGP"."""
    return [m for m in NAME.finditer(text) if m.group(0) != "WatermelonPGP"]


for page in sorted(site.glob("*.html")):
    source = page.read_text(encoding="utf-8")
    body = source[source.index("<body"):]
    body = re.sub(r"<(script|pre|code)\b.*?</\1>", "", body, flags=re.S)
    for label in LABEL.findall(body):
        if misnamed(label):
            problems.append(f"{page}: attribute {label!r}")
    text = html.unescape(re.sub(r"<[^>]+>", "", body))
    for match in misnamed(text):
        context = " ".join(text[max(0, match.start() - 40) : match.end() + 30].split())
        problems.append(f"{page}: text …{context}…")
    title = re.search(r"<title>(.*?)</title>", source, re.S)
    if title and misnamed(title.group(1)):
        problems.append(f"{page}: <title> {title.group(1)!r}")

for image in sorted(site.glob("img/*.svg")):
    for label in LABEL.findall(image.read_text(encoding="utf-8")):
        if misnamed(label):
            problems.append(f"{image}: label {label!r}")

if problems:
    print('Call the product "WatermelonPGP" (one word, PGP in capitals):')
    print("\n".join(f"  {p}" for p in problems))
    sys.exit(1)
print("Branding OK")
