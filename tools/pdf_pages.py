"""Counts the pages of a PDF and fails if there are more than allowed.

    python3 tools/pdf_pages.py SPEC.pdf 2

Chromium writes one uncompressed /Type /Page object per page, so a byte scan
is enough; no PDF library is needed.
"""
import re
import sys


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: pdf_pages.py FILE MAX_PAGES")
    with open(sys.argv[1], "rb") as f:
        data = f.read()
    if not data.startswith(b"%PDF-"):
        sys.exit("%s: not a PDF" % sys.argv[1])
    pages = len(re.findall(rb"/Type\s*/Page(?![s\w])", data))
    limit = int(sys.argv[2])
    print("%s: %d page(s), limit %d" % (sys.argv[1], pages, limit))
    if pages == 0 or pages > limit:
        sys.exit(1)


if __name__ == "__main__":
    main()
