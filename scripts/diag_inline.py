"""Inline-trace one probe to see what the FP-guard actually sees."""
from __future__ import annotations

import asyncio
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.http import get_client

URL = "https://www.artbreeder.com/lazizanizomiddinova"


async def main() -> int:
    client = await get_client()
    r = await client.get(URL)
    print("status_code =", r.status_code)
    body = r.text
    print("body length =", len(body))
    # page title extraction
    m = re.search(r"<title[^>]*>([^<]{1,200})</title>", body, re.IGNORECASE)
    page_title = m.group(1).strip() if m else ""
    print("page_title =", repr(page_title))
    # og:title extraction
    m = re.search(
        r'<meta\b[^>]*(?:property|name)=["\']og:title["\'][^>]*content=["\']([^"\']+)',
        body, re.IGNORECASE,
    )
    if not m:
        m = re.search(
            r'<meta\b[^>]*content=["\']([^"\']+)["\'][^>]*(?:property|name)=["\']og:title["\']',
            body, re.IGNORECASE,
        )
    og_title = m.group(1).strip() if m else ""
    print("og:title =", repr(og_title))
    # marker test
    markers = ("error", "404", "not found", "doesn't exist", "does not exist")
    for src_name, src in (("page_title", page_title), ("og:title", og_title)):
        for marker in markers:
            if marker in src.lower():
                print(f"  -> matched '{marker}' in {src_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
