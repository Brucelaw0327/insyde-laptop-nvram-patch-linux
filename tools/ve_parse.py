"""ve_parse.py -- parse an H2OUVE variable-record dump (the file H2OUVE -gv writes).

Usage:
    python ve_parse.py <dump.txt> [offset_hex] [record,record,...]

Prints a table of the interesting records, then the byte at `offset_hex`
(default 0x100 -- the fTPM selector on this firmware family) inside each of the
named records (default `Setup,Custom`).

The offset is whatever you located for YOUR firmware; see docs/how-it-works.md.
The record list is so that a patch which targets records other than
Setup/Custom can still be read here -- apply_patch.ps1 and restore_original.ps1
pass their patch's RECORDS in.
"""
import os
import re
import sys

DEFAULT_OFFSET = 0x100
DEFAULT_RECORDS = ['Setup', 'Custom']
LIST_RE = re.compile(r'(?i)setup|custom|presence|tree|varedit|restore|secureboot')


def parse(path):
    lines = open(path, encoding='utf-8', errors='replace').read().splitlines()
    hdr = re.compile(r'^\s*\[([0-9A-Fa-f]{3,})\]\s+"(.*)"\s*$')
    recs, cur = [], None
    for s in lines:
        h = hdr.match(s)
        if h:
            cur = {'idx': int(h.group(1), 16), 'name': h.group(2), 'guid': None,
                   'attr': None, 'size': None, 'data': bytearray()}
            recs.append(cur)
            continue
        if cur is None:
            continue
        t = s.strip()
        if t.startswith('GUID:'):
            cur['guid'] = t[5:].strip()
        elif t.startswith('Attributes:'):
            cur['attr'] = int(t.split(':', 1)[1].strip(), 16)
        elif t.startswith('DataSize:'):
            cur['size'] = int(t.split(':', 1)[1].strip(), 16)
        else:
            m = re.match(r'^([0-9A-Fa-f]{8}):\s*((?:[0-9A-Fa-f]{2}\s*)+)$', t)
            if m:
                cur['data'] += bytes.fromhex(m.group(2).replace(' ', ''))
    return recs


def detail(r, off):
    d = r['data']
    print()
    print('=== %s ===' % r['name'])
    print('  guid=%s attr=0x%02X size=0x%X len=%d' % (r['guid'], r['attr'] or 0, r['size'] or 0, len(d)))
    if off < len(d):
        print('  @0x%X = 0x%02X' % (off, d[off]))
    else:
        print('  @0x%X -- offset beyond record length (%d bytes)' % (off, len(d)))
    lo = max(0, off - 8)
    hi = min(len(d), off + 9)
    if hi > lo:
        print('  bytes 0x%X..0x%X: %s' % (lo, hi - 1, ' '.join('%02X' % b for b in d[lo:hi])))


if __name__ == '__main__':
    p = sys.argv[1] if len(sys.argv) > 1 else os.path.join('h2ouve', 'vars_orig.txt')
    off = int(sys.argv[2], 16) if len(sys.argv) > 2 else DEFAULT_OFFSET
    names = DEFAULT_RECORDS
    if len(sys.argv) > 3 and sys.argv[3].strip():
        names = [x.strip() for x in sys.argv[3].split(',') if x.strip()]
    recs = parse(p)
    print('records =', len(recs))
    print('%-6s %-30s %-40s %-6s %-8s %s' % ('idx', 'name', 'guid', 'attr', 'size', 'actual'))
    for r in recs:
        if LIST_RE.search(r['name']):
            g = r['guid'] or '?'
            print('%-6d %-30s %-40s 0x%-4s 0x%-6s %d' % (
                r['idx'], r['name'][:30], g, format(r['attr'] or 0, '02X'),
                format(r['size'] or 0, 'X'), len(r['data'])))
    for nm in names:
        for r in recs:
            if r['name'] == nm:
                detail(r, off)
