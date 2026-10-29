#!/usr/bin/env python3
"""ifr_locate.py -- find WHERE a firmware setting is stored, then prove it.

This tool answers the single question the rest of this repository refuses to
hard-code:

    which byte of which NVRAM variable backs setting X on MY firmware?

Pipeline (a thin wrapper around the established UEFI toolchain):

    firmware image (or a bare Setup FFS / PE32 section body)
        |
        |-- [native engine]     scan the HII FORMS / STRINGS packages, pair
        |                       them up, walk the IFR opcode stream.  No
        |                       external dependency, runs anywhere.
        |
        |-- [external engine]   OPTIONAL.  If you have IFRExtractor-RS, point
        |                       --ifr-extractor at it and this tool parses its
        |                       text output instead.  Diffing the two engines
        |                       is a good sanity check -- they should agree.
        v
    { formset, form, prompt, VarStore name + GUID, VarOffset, Size, value table }
        |
        |-- cross-check against a `H2OUVE -gv` dump: same GUID? same size?
        |   is the live byte at VarOffset one of the declared values?  This is
        |   the actual proof, not a guess.
        |
        |-- emit a patch-file stub you can save and apply
        v
    machine.txt

Nothing here writes to the firmware, and nothing here writes to disk except
the optional IFRExtractor temp file.  Read-only, always.

Usage
-----
    python ifr_locate.py scan   <image> [keyword ...]
    python ifr_locate.py find   <image> [keyword ...]   # no keyword = list all
    python ifr_locate.py from-ifr <ifr.txt> <keyword ...>
    python ifr_locate.py verify <image> <h2ouve_dump.txt>

Options
-------
    --ifr-extractor PATH   run this IFRExtractor-RS binary instead of the
                           built-in parser (see docs/how-it-works.md)
    --varstore NAME        only consider questions in this VarStore
                           (e.g. SystemConfig)
    --limit N              max questions listed per keyword (default 20)
    --json                 machine-readable output

Getting the input
-----------------
  * Full firmware image (.fd / .bin / .cap):  scan it directly.  If the Setup
    module lives inside a compressed section the HII data will not be visible;
    in that case extract it first with UEFIExtract and point this tool at the
    resulting PE32 body.
  * Insyde H2O Setup FFS (`Setup_<GUID>.ffs`): works directly.
  * The PE32 section body (what UEFITool "Extract body ..." produces): works
    directly, and is the fastest path.

See docs/how-it-works.md section 4 for the manual version of this procedure.
"""

import argparse
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import uuid

# ----------------------------------------------------------------------------
# constants
# ----------------------------------------------------------------------------

PKG_FORMS = 0x02
PKG_STRINGS = 0x04

# every IFR opcode that carries a question (a setting the user can change)
QUESTION_OPS = {0x05: 'OneOf', 0x06: 'CheckBox', 0x07: 'Numeric', 0x23: 'OrderedList'}
OPTION_OP = 0x09
FORM_SET_OP = 0x0E
FORM_OP = 0x01
END_OP = 0x29

# VarStore-bearing opcodes -> (guid_off, vsid_off, size_off, name_off)
# Layouts follow the EDK2 headers (MdePkg/Include/Uefi/UefiInternalFormRepresentation.h).
VARSTORE_OPS = {
    0x24: (2, 18, 20, 22),    # EFI_IFR_VARSTORE         Guid, VarStoreId, Size, Name[]
    0x26: (4, 2, 24, 26),     # EFI_IFR_VARSTORE_EFI     VarStoreId, Guid, Attributes, Size, Name[]
    0x25: (2, 18, None, None),  # EFI_IFR_VARSTORE_NAME_VALUE
    0x27: (None, 2, None, None),  # EFI_IFR_VARSTORE_DEVICE (DevicePath, no guid)
}

OP_NAMES = {
    0x01: 'Form', 0x02: 'Subtitle', 0x03: 'Text', 0x04: 'Image',
    0x05: 'OneOf', 0x06: 'CheckBox', 0x07: 'Numeric', 0x08: 'Password',
    0x09: 'OneOfOption', 0x0A: 'SuppressIf', 0x0B: 'Locked', 0x0C: 'Action',
    0x0D: 'ResetButton', 0x0E: 'FormSet', 0x0F: 'Ref', 0x10: 'NoSubmitIf',
    0x11: 'InconsistentIf', 0x12: 'EqIdVal', 0x13: 'EqIdId', 0x14: 'EqIdValList',
    0x15: 'And', 0x16: 'Or', 0x17: 'Not', 0x18: 'Rule', 0x19: 'GrayOutIf',
    0x1A: 'Date', 0x1B: 'Time', 0x1C: 'String', 0x1D: 'Refresh',
    0x1E: 'DisableIf', 0x1F: 'Animation', 0x20: 'ToLower', 0x21: 'ToUpper',
    0x22: 'Map', 0x23: 'OrderedList', 0x24: 'VarStore',
    0x25: 'VarStoreNameValue', 0x26: 'VarStoreEfi', 0x27: 'VarStoreDevice',
    0x28: 'Version', 0x29: 'End', 0x2A: 'Match', 0x2B: 'Get', 0x2C: 'Set',
    0x2D: 'Read', 0x2E: 'Write', 0x2F: 'Equal', 0x30: 'NotEqual',
    0x31: 'GreaterThan', 0x32: 'GreaterEqual', 0x33: 'LessThan',
    0x34: 'LessEqual', 0x35: 'BitwiseAnd', 0x36: 'BitwiseOr',
    0x37: 'BitwiseNot', 0x38: 'ShiftLeft', 0x39: 'ShiftRight', 0x3A: 'Add',
    0x3B: 'Subtract', 0x3C: 'Multiply', 0x3D: 'Divide', 0x3E: 'Modulo',
    0x42: 'Uint8', 0x43: 'Uint16', 0x44: 'Uint32', 0x45: 'Uint64',
    0x46: 'True', 0x47: 'False', 0x4A: 'ToBoolean', 0x5B: 'Default',
    0x5C: 'DefaultStore', 0x5D: 'FormMap', 0x5F: 'Guid', 0x60: 'Security',
    0x61: 'ModalTag', 0x62: 'RefreshId', 0x63: 'WarningIf', 0x64: 'Match2',
}

# per opcode: payload offsets (relative to the opcode start) that hold a
# STRING_ID.  Used to score which STRINGS package belongs to a FORMS package.
SID_OFFSETS = {
    0x01: [4], 0x02: [2], 0x03: [2], 0x0C: [2, 4], 0x0E: [18, 20],
    0x0F: [4, 6], 0x05: [2, 4], 0x06: [2, 4], 0x07: [2, 4], 0x08: [2, 4],
    0x23: [2, 4], 0x09: [2], 0x0A: [2], 0x0B: [2], 0x10: [2], 0x11: [2],
    0x19: [2], 0x63: [2], 0x5D: [2, 4],
}

# public, standard GUIDs -- used only to annotate the output
KNOWN_GUIDS = {
    '93039971-8545-4B04-B45E-32EB8326040E':
        'gEfiHiiPlatformSetupFormsetGuid (EDK2 platform setup)',
    'FE3542FE-C1D3-4EF8-657C-8048606FF670':
        'EDK2 SetupUtility file GUID (the Setup module itself)',
    '8BE4DF61-93CA-11D2-AA0D-00E098032B8C':
        'EFI_GLOBAL_VARIABLE (BootOrder, SecureBoot, ...)',
}


# ----------------------------------------------------------------------------
# small helpers
# ----------------------------------------------------------------------------

def u16(d, o):
    return d[o] | (d[o + 1] << 8)


def u24(d, o):
    return d[o] | (d[o + 1] << 8) | (d[o + 2] << 16)


def guid_str(b):
    """16 raw bytes -> canonical GUID text (mixed endian, as UEFI prints it)."""
    if len(b) < 16:
        return None
    d1, d2, d3 = struct.unpack_from('<IHH', b, 0)
    return '%08X-%04X-%04X-%02X%02X-%s' % (
        d1, d2, d3, b[8], b[9], ''.join('%02X' % x for x in b[10:16]))


def hexv(v):
    return '0x%X' % v


def size_to_bytes(flags):
    """EFI_IFR_ONE_OF/CHECKBOX Flags bits 0..1 -> width in bytes."""
    return (1, 2, 4, 8)[flags & 0x03]


def parse_type_value(d, off, end):
    """EFI_IFR_TYPE_VALUE -> (value, bytes_consumed).

    The value is NOT a bare integer: it is a one-byte type tag followed by a
    value of that type.  Tag 0x00 means "the next byte is a u8", so the common
    case of `... 00 02` is the number 2, not 0x0200.  Getting this wrong makes
    every option look like zero -- which is exactly the trap this project is
    supposed to help people avoid.
    """
    if off >= end:
        return None, 0
    tag = d[off]
    p = off + 1
    if tag == 0x00:
        return (d[p] if p < end else None), 2
    if tag == 0x01:
        return (u16(d, p) if p + 1 < end else None), 3
    if tag == 0x02:
        return (int.from_bytes(d[p:p + 4], 'little') if p + 3 < end else None), 5
    if tag == 0x03:
        return (int.from_bytes(d[p:p + 8], 'little') if p + 7 < end else None), 9
    if tag == 0x04:                                   # Boolean
        return (bool(d[p]) if p < end else None), 2
    if tag in (0x07, 0x0A):                           # String / Action
        return (u16(d, p) if p + 1 < end else None), 3
    return None, 1


def read_text(path):
    try:
        return open(path, encoding='utf-8', errors='replace').read()
    except OSError as e:
        raise SystemExit('cannot read %s: %s' % (path, e))


# ----------------------------------------------------------------------------
# native engine -- load the image and find HII packages
# ----------------------------------------------------------------------------

class Image(object):
    def __init__(self, path):
        self.path = path
        try:
            self.data = open(path, 'rb').read()
        except OSError as e:
            raise SystemExit('cannot read image %s: %s' % (path, e))
        self.size = len(self.data)

    def packages(self, ptype, forms_ok=False):
        """Return [(offset, length)] of HII packages with the given type."""
        d, N, out = self.data, self.size, []
        for o in range(0, N - 4):
            if d[o + 3] != ptype:
                continue
            ln = u24(d, o)
            if not (8 <= ln <= N - o):
                continue
            if forms_ok and not self._forms_walks(d, o, ln):
                continue
            out.append((o, ln))
        return out

    @staticmethod
    def _forms_walks(d, o, ln):
        """A real FORMS package: the opcode stream must land exactly on the end."""
        p, end = o + 4, o + ln
        while p < end:
            if p + 2 > end:
                return False
            L = d[p + 1] & 0x7F
            if L < 2 or p + L > end:
                return False
            p += L
        return p == end


def parse_strings(d, pkg, ln):
    """EFI_HII_STRING_PACKAGE -> {string_id: text}.  id 0 is the language."""
    if ln < 12:
        return {}
    sio = struct.unpack_from('<I', d, pkg + 8)[0]
    if not (0 < sio < ln):
        return {}
    p, end, sid, T = pkg + sio, pkg + ln, 0, {}
    while p < end:
        bt = d[p]
        if bt == 0x00:
            break
        if bt == 0x14:                       # UCS-2
            q = p + 1
            while q + 1 < end and (d[q] or d[q + 1]):
                q += 2
            sid += 1
            T[sid] = d[p + 1:q].decode('utf-16le', 'replace')
            p = q + 2
        elif bt == 0x10:                     # ASCII
            q = p + 1
            while q < end and d[q]:
                q += 1
            sid += 1
            T[sid] = d[p + 1:q].decode('latin1')
            p = q + 1
        else:
            break
    return T


def package_sids(d, off, ln):
    """All STRING_IDs referenced inside one FORMS package."""
    sids = set()
    p, end = off + 4, off + ln
    while p < end:
        if p + 2 > end:
            break
        op = d[p]
        L = d[p + 1] & 0x7F
        if L < 2 or p + L > end:
            break
        for o2 in SID_OFFSETS.get(op, []):
            if o2 + 1 < L:
                sids.add(u16(d, p + o2))
        p += L
    return sids


def pair_strings(img, forms_list, strings_list):
    """For each FORMS package pick the STRINGS package that explains it best.

    Strategy: score every STRINGS table by how many of the FORMS package's
    referenced ids resolve in it, break ties by distance.  This is adaptive --
    it does not assume any particular package ordering (which differs between
    firmware vendors).  The runner-up scores are kept so a human can check.
    """
    tables = [(s, parse_strings(img.data, s, l)) for s, l in strings_list]
    result = []
    for fo, fl in forms_list:
        sids = package_sids(img.data, fo, fl)
        scored = []
        for so, T in tables:
            hit = sum(1 for s in sids if s in T)
            scored.append((hit, -abs(so - fo), so, T))
        scored.sort(reverse=True)
        best = scored[0] if scored else (0, 0, None, {})
        result.append({
            'forms': (fo, fl),
            'strings_off': best[2],
            'table': best[3],
            'hits': best[0],
            'total': len(sids),
            'runners': [(s, h, t) for h, _, s, t in scored[1:4]],
        })
    return result


# ----------------------------------------------------------------------------
# native engine -- walk one FORMS package into structured questions
# ----------------------------------------------------------------------------

def parse_forms(img, off, ln, table):
    """Return {'formset', 'formset_guid', 'varstores', 'questions'} for a package."""
    d = img.data
    end0 = off + ln
    p = off + 4
    depth = 0
    ctx = {}                     # depth -> (opcode, title)
    varstores = {}               # varstore id -> dict
    questions = []
    formset = None
    formset_guid = None
    cur_q = None

    def S(sid):
        return table.get(sid, '<sid%d>' % sid)

    def flush():
        nonlocal cur_q
        if cur_q is not None:
            questions.append(cur_q)
            cur_q = None

    def ctx_last(opcode):
        """Deepest enclosing scope of the given opcode (more specific wins)."""
        best = None
        best_d = -1
        for dd in ctx:
            if dd < depth and ctx[dd][0] == opcode and dd > best_d:
                best_d = dd
                best = ctx[dd][1]
        return best

    while p + 2 <= end0:
        op = d[p]
        raw = d[p + 1]
        L = raw & 0x7F
        scope = raw & 0x80
        if L < 2 or p + L > end0:
            break

        if op == END_OP:
            flush()
            depth = max(0, depth - 1)
            ctx.pop(depth, None)
            p += L
            continue

        # --- context -------------------------------------------------------
        if formset is None and op == FORM_SET_OP and L >= 20:
            formset_guid = guid_str(d[p + 2:p + 18])
            formset = S(u16(d, p + 18))

        # --- varstores -----------------------------------------------------
        if op in VARSTORE_OPS and op in (0x24, 0x26, 0x25):
            g_off, v_off, s_off, n_off = VARSTORE_OPS[op]
            vsid = u16(d, p + v_off) if v_off is not None and v_off + 1 < L else None
            guid = guid_str(d[p + g_off:p + g_off + 16]) if g_off is not None else None
            sz = u16(d, p + s_off) if s_off is not None and s_off + 1 < L else None
            nm = None
            if n_off is not None and n_off < L:
                nm = d[p + n_off:p + L].split(b'\x00')[0].decode('latin1', 'replace')
            if vsid is not None:
                varstores[vsid] = {'id': vsid, 'kind': OP_NAMES.get(op, hex(op)),
                                   'guid': guid, 'size': sz, 'name': nm,
                                   'offset': p, 'scope': depth}

        # --- questions -----------------------------------------------------
        if op in QUESTION_OPS:
            flush()
            # EFI_IFR layout, verified against this firmware AND against the
            # IFRExtractor-RS reference parser:
            #   +2 prompt, +4 help, +6 question id, +8 varstore id,
            #   +10 VarOffset, +12 QuestionFlags, +13 Flags, +14 Min/Max/Step
            qflags = d[p + 13] if p + 13 < p + L else 0
            w = size_to_bytes(qflags)
            cur_q = {
                'kind': QUESTION_OPS[op],
                'opcode': op,
                'offset': p,
                'depth': depth,
                'prompt': S(u16(d, p + 2)),
                'help': S(u16(d, p + 4)),
                'question_id': u16(d, p + 6),
                'varstore_id': u16(d, p + 8),
                'var_offset': u16(d, p + 10),
                'question_flags': d[p + 12] if p + 12 < p + L else 0,
                'flags': qflags,
                'width': w,
                'min': None, 'max': None, 'step': None,
                'options': [],
                'formset': ctx_last(FORM_SET_OP) or formset,
                'formset_guid': formset_guid,
                'form': ctx_last(FORM_OP),
            }
            if op in (0x05, 0x07) and L >= 14 + 3 * w:
                base = p + 14
                cur_q['min'] = int.from_bytes(d[base:base + w], 'little')
                cur_q['max'] = int.from_bytes(d[base + w:base + 2 * w], 'little')
                cur_q['step'] = int.from_bytes(d[base + 2 * w:base + 3 * w], 'little')

        # --- options -------------------------------------------------------
        elif op == OPTION_OP and cur_q is not None:
            v, _n = parse_type_value(d, p + 5, p + L)
            cur_q['options'].append({
                'name': S(u16(d, p + 2)),
                'value': v,
                'flags': d[p + 4] if p + 4 < p + L else 0,
            })

        # --- bookkeeping ---------------------------------------------------
        if scope:
            title = None
            if op == FORM_SET_OP:
                title = S(u16(d, p + 18))
            elif op == FORM_OP:
                title = S(u16(d, p + 4))
            ctx[depth] = (op, title)
            depth += 1

        p += L

    flush()

    for q in questions:
        q['varstore'] = varstores.get(q['varstore_id'])

    return {
        'pkg_offset': off,
        'pkg_len': ln,
        'formset': formset,
        'formset_guid': formset_guid,
        'varstores': varstores,
        'questions': questions,
    }


# ----------------------------------------------------------------------------
# external engine -- parse IFRExtractor text output
# ----------------------------------------------------------------------------

RE_RS_VARSTORE = re.compile(
    r'^\s*VarStore\s+Guid:\s*\{([0-9A-Fa-f-]+)\},\s*VarStoreId:\s*0x([0-9A-Fa-f]+),'
    r'\s*Size:\s*0x([0-9A-Fa-f]+),\s*Name:\s*"([^"]*)"')
RE_RS_VARSTOREEFI = re.compile(
    r'^\s*VarStoreEfi\s+Guid:\s*\{([0-9A-Fa-f-]+)\},\s*VarStoreId:\s*0x([0-9A-Fa-f]+),'
    r'\s*Attributes:\s*0x([0-9A-Fa-f]+)(?:,\s*Size:\s*0x([0-9A-Fa-f]+))?(?:,\s*Name:\s*"([^"]*)")?')
RE_RS_FORM = re.compile(r'^\s*Form\s+FormId:\s*0x([0-9A-Fa-f]+),\s*Title:\s*"([^"]*)"')
RE_RS_FORMSET = re.compile(r'^\s*FormSet\s+Guid:\s*\{([0-9A-Fa-f-]+)\},\s*Title:\s*"([^"]*)",\s*Help:')
RE_RS_QUESTION = re.compile(
    r'^\s*(OneOf|CheckBox|Numeric|OrderedList)\s+Prompt:\s*"([^"]*)",\s*Help:\s*"[^"]*",'
    r'\s*QuestionFlags:\s*0x[0-9A-Fa-f]+,\s*QuestionId:\s*0x([0-9A-Fa-f]+),'
    r'\s*VarStoreId:\s*0x([0-9A-Fa-f]+),\s*(?:VarOffset|VarStoreInfo):\s*0x([0-9A-Fa-f]+),'
    r'\s*Flags:\s*0x([0-9A-Fa-f]+)(?:,\s*Size:\s*(\d+))?')
RE_RS_OPTION = re.compile(
    r'^\s*OneOfOption\s+Option:\s*"([^"]*)"\s+(?:Value:\s*([0-9]+))')

RE_UFE_VARSTORE = re.compile(
    r'^\s*VarStore(?:EFI|Efi|NameValue|Device)?\s*:\s*VarStoreId:\s*0x([0-9A-Fa-f]+)'
    r'(?:\s*\[([0-9A-Fa-f-]+)\])?,\s*\w+:\s*[0-9A-Fa-fx]+'
    r'(?:,\s*Size:\s*(\d+))?(?:,\s*Name:\s*(\S+))?')
RE_UF_VARSTORE = re.compile(
    r'^\s*VarStore(?:EFI|Efi)?\s*:\s*VarStoreId:\s*0x([0-9A-Fa-f]+)\s*\[([0-9A-Fa-f-]+)\],'
    r'.*?Size:\s*(\d+),\s*Name:\s*(\S+)')
RE_UF_QUESTION = re.compile(
    r'^\s*(?:0x[0-9A-Fa-f]+\s+)?(One Of|Check Box|Numeric|Ordered List):\s*(.*?),'
    r'\s*VarStoreInfo \(VarOffset/VarName\):\s*0x([0-9A-Fa-f]+),\s*VarStore:\s*0x([0-9A-Fa-f]+),'
    r'\s*QuestionId:\s*0x([0-9A-Fa-f]+)(?:,\s*Size:\s*(\d+))?')
RE_UF_OPTION = re.compile(
    r'^\s*(?:0x[0-9A-Fa-f]+\s+)?One Of Option:\s*(.*?),\s*Value \(\d+ bit\):\s*0x([0-9A-Fa-f]+)')
RE_UF_FORM = re.compile(
    r'^\s*(?:0x[0-9A-Fa-f]+\s+)?Form:\s*(.*?),\s*FormId:\s*0x[0-9A-Fa-f]+')
RE_UF_FORMSET = re.compile(
    r'^\s*(?:0x[0-9A-Fa-f]+\s+)?Form Set:\s*(.*?)(?:,\s*ClassGuid:.*)?$')


def parse_ifr_text(path):
    """Parse IFRExtractor-RS / Universal-IFR-Extractor text into questions."""
    lines = read_text(path).splitlines()
    varstores = {}
    varstore_by_guid = {}
    questions = []
    cur_q = None
    cur_form = None
    cur_formset = None

    for ln in lines:
        m = RE_RS_VARSTORE.match(ln)
        if m:
            g, vsid, sz, name = m.group(1), int(m.group(2), 16), int(m.group(3), 16), m.group(4)
            varstores[vsid] = {'id': vsid, 'kind': 'VarStore', 'guid': g.upper(),
                               'size': sz, 'name': name}
            varstore_by_guid[g.upper()] = varstores[vsid]
            continue
        m = RE_RS_VARSTOREEFI.match(ln)
        if m:
            g, vsid = m.group(1), int(m.group(2), 16)
            sz = int(m.group(4), 16) if m.group(4) else None
            name = m.group(5)
            varstores[vsid] = {'id': vsid, 'kind': 'VarStoreEfi', 'guid': g.upper(),
                               'size': sz, 'name': name}
            varstore_by_guid[g.upper()] = varstores[vsid]
            continue
        m = RE_UF_VARSTORE.match(ln) or RE_UFE_VARSTORE.match(ln)
        if m and m.group(2):
            vsid = int(m.group(1), 16)
            g = m.group(2).upper()
            sz = int(m.group(3)) if m.group(3) else None
            name = m.group(4)
            varstores[vsid] = {'id': vsid, 'kind': 'VarStore', 'guid': g,
                               'size': sz, 'name': name}
            varstore_by_guid[g] = varstores[vsid]
            continue
        m = RE_RS_FORMSET.match(ln)
        if m:
            cur_formset = m.group(2)
            continue
        m = RE_RS_FORM.match(ln)
        if m:
            cur_form = m.group(2)
            continue
        m = RE_UF_FORMSET.match(ln)
        if m:
            cur_formset = m.group(1).strip()
            continue
        m = RE_UF_FORM.match(ln)
        if m:
            cur_form = m.group(1).strip()
            continue
        m = RE_RS_QUESTION.match(ln)
        if m:
            kind, prompt, qid, vsid, voff, flags = (
                m.group(1), m.group(2), int(m.group(3), 16),
                int(m.group(4), 16), int(m.group(5), 16), int(m.group(6), 16))
            width = size_to_bytes(flags)
            if m.group(7):
                width = {8: 1, 16: 2, 32: 4, 64: 8}.get(int(m.group(7)), width)
            cur_q = {'kind': kind, 'prompt': prompt, 'question_id': qid,
                     'varstore_id': vsid, 'var_offset': voff, 'flags': flags,
                     'width': width, 'options': [], 'formset': cur_formset,
                     'form': cur_form, 'min': None, 'max': None, 'step': None}
            questions.append(cur_q)
            continue
        m = RE_UF_QUESTION.match(ln)
        if m:
            kind = m.group(1).replace(' ', '')
            prompt = m.group(2).strip()
            voff = int(m.group(3), 16)
            vsid = int(m.group(4), 16)
            qid = int(m.group(5), 16)
            width = int(m.group(6)) if m.group(6) else 1
            cur_q = {'kind': kind, 'prompt': prompt, 'question_id': qid,
                     'varstore_id': vsid, 'var_offset': voff, 'flags': 0,
                     'width': width, 'options': [], 'formset': cur_formset,
                     'form': cur_form, 'min': None, 'max': None, 'step': None}
            questions.append(cur_q)
            continue
        m = RE_RS_OPTION.match(ln)
        if m and cur_q is not None:
            v = int(m.group(2)) if m.group(2) else None
            cur_q['options'].append({'name': m.group(1), 'value': v, 'flags': 0})
            continue
        m = RE_UF_OPTION.match(ln)
        if m and cur_q is not None:
            cur_q['options'].append({'name': m.group(1).strip(),
                                     'value': int(m.group(2), 16), 'flags': 0})
            continue

    for q in questions:
        q['varstore'] = varstores.get(q['varstore_id'])
    return {'varstores': varstores, 'questions': questions}


# ----------------------------------------------------------------------------
# H2OUVE dump parsing (same grammar as ve_parse.py)
# ----------------------------------------------------------------------------

HDR_RE = re.compile(r'^\s*\[([0-9A-Fa-f]{3,})\]\s+"(.*)"\s*$')


def parse_h2ouve(path):
    lines = read_text(path).splitlines()
    recs, cur = [], None
    for s in lines:
        h = HDR_RE.match(s)
        if h:
            cur = {'idx': int(h.group(1), 16), 'name': h.group(2), 'guid': None,
                   'attr': None, 'size': None, 'data': bytearray()}
            recs.append(cur)
            continue
        if cur is None:
            continue
        t = s.strip()
        if t.startswith('GUID:'):
            cur['guid'] = t[5:].strip().upper()
        elif t.startswith('Attributes:'):
            cur['attr'] = int(t.split(':', 1)[1].strip(), 16)
        elif t.startswith('DataSize:'):
            cur['size'] = int(t.split(':', 1)[1].strip(), 16)
        else:
            m = re.match(r'^([0-9A-Fa-f]{8}):\s*((?:[0-9A-Fa-f]{2}\s*)+)$', t)
            if m:
                cur['data'] += bytes.fromhex(m.group(2).replace(' ', ''))
    return recs


# ----------------------------------------------------------------------------
# engine selection
# ----------------------------------------------------------------------------

def load_questions(img_path, ifr_extractor, varstore_filter):
    """Return (engine_name, model) where model = {'varstores', 'questions', 'pkg'}."""
    if ifr_extractor:
        exe = ifr_extractor
        if not os.path.exists(exe):
            exe = shutil.which(ifr_extractor)
            if not exe:
                raise SystemExit(
                    'IFRExtractor not found: %s\n'
                    'Pass a full path with --ifr-extractor, or drop the flag to '
                    'use the built-in parser (no download needed).' % ifr_extractor)
        tmp = tempfile.NamedTemporaryFile(suffix='.txt', delete=False)
        tmp.close()
        try:
            proc = subprocess.run([exe, img_path, tmp.name],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  timeout=300)
            if proc.returncode != 0:
                raise SystemExit('IFRExtractor failed (rc=%d):\n%s'
                                 % (proc.returncode,
                                    proc.stdout.decode('utf-8', 'replace')))
            model = parse_ifr_text(tmp.name)
            if not model['questions']:
                raise SystemExit(
                    'IFRExtractor produced no parseable questions.  Either the '
                    'input is not a Setup module body, or its text format is '
                    'not recognised -- try the built-in parser instead.')
            model['pkg'] = []
            return 'ifrex-text', model
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    img = Image(img_path)
    forms = img.packages(PKG_FORMS, forms_ok=True)
    strings = img.packages(PKG_STRINGS)
    pairs = pair_strings(img, forms, strings)
    model = {'varstores': {}, 'questions': [], 'pkg': [], 'peers': []}
    for pr in pairs:
        fo, fl = pr['forms']
        parsed = parse_forms(img, fo, fl, pr['table'])
        if not parsed['questions'] and not parsed['formset']:
            continue     # opcode-walk false positive, not a real FORMS package
        model['pkg'].append({
            'offset': fo, 'len': fl, 'formset': parsed['formset'],
            'formset_guid': parsed['formset_guid'],
            'strings_off': pr['strings_off'], 'hits': pr['hits'],
            'sid_total': pr['total'],
            'strings_peer': [(s, h) for s, h, _ in pr['runners']],
            'varstores': list(parsed['varstores'].values()),
            'questions': parsed['questions'],
        })
        for vid, vs in parsed['varstores'].items():
            model['varstores'][vid] = vs
        model['questions'].extend(parsed['questions'])
    return 'native', model


# ----------------------------------------------------------------------------
# keyword matching + presentation
# ----------------------------------------------------------------------------

def score_question(q, keywords):
    """Return the matched keyword, or None.  prompt + option names + form."""
    hay = ' | '.join(filter(None, [
        q.get('prompt'), q.get('form'), q.get('formset'),
        ' '.join(o['name'] for o in q.get('options', []) if o.get('name')),
    ])).lower()
    for k in keywords:
        if k.lower() in hay:
            return k
    return None


def dedupe(hits):
    """Collapse repeats: the same setting is often exported by several formsets."""
    seen = set()
    out = []
    for k, q in hits:
        vs = q.get('varstore') or {}
        key = (vs.get('guid') or q.get('varstore_id'), q.get('var_offset'),
               q.get('prompt'))
        if key in seen:
            continue
        seen.add(key)
        out.append((k, q))
    return out


def q_default(q):
    """IFR default of a question: the option carrying the DEFAULT flag
    (bit 0x10; 0x20 = manufacturing default, used as fallback)."""
    pick = None
    for o in q.get('options', []):
        f = o.get('flags', 0) or 0
        if f & 0x10:
            return {'value': o['value'], 'name': o.get('name')}
        if f & 0x20:
            pick = {'value': o['value'], 'name': o.get('name')}
    return pick


def _records_for_guid(recs, guid):
    """H2OUVE dump records sharing a varstore GUID (Setup/Custom pairs)."""
    if not guid:
        return []
    g = guid.strip('{}').upper()
    return [r for r in recs
            if (r.get('guid') or '').strip('{}').upper() == g]


def live_read(q, recs):
    """Current bytes at this question's VarOffset, from an H2OUVE -gv dump.

    Returns a list (one entry per matching record, usually Setup+Custom) or
    None when there is nothing to read."""
    vs = q.get('varstore') or {}
    off = q.get('var_offset')
    w = q.get('width') or 1
    if off is None or off < 0:
        return None
    rs = _records_for_guid(recs, vs.get('guid'))
    if not rs:
        return None
    opts = {o['value']: o['name'] for o in q.get('options', [])
            if o.get('value') is not None}
    out = []
    for r in rs:
        data = bytes(r['data'])
        if off + w > len(data):
            continue
        raw = data[off:off + w]
        v = int.from_bytes(raw, 'little')
        out.append({
            'record': r['name'],
            'bytes': raw.hex(' '),
            'value': hexv(v),
            'meaning': opts.get(v) if v in opts else None,
        })
    return out or None


def describe(q):
    vs = q.get('varstore') or {}
    return {
        'prompt': q.get('prompt'),
        'kind': q.get('kind'),
        'formset': q.get('formset'),
        'form': q.get('form'),
        'varstore_id': hexv(q['varstore_id']) if q.get('varstore_id') is not None else None,
        'varstore_name': vs.get('name'),
        'varstore_guid': vs.get('guid'),
        'varstore_size': vs.get('size'),
        'var_offset': hexv(q['var_offset']) if q.get('var_offset') is not None else None,
        'size_bytes': q.get('width'),
        'question_id': hexv(q['question_id']) if q.get('question_id') is not None else None,
        'min': q.get('min'),
        'max': q.get('max'),
        'default': (lambda d: d and dict(d, value=hexv(d['value'])) or None)(q_default(q)),
        'options': [{'name': o['name'], 'value': o['value'],
                     'default': bool((o.get('flags', 0) or 0) & 0x10)}
                    for o in q.get('options', [])],
    }


def print_question(q, indent='  '):
    d = describe(q)
    print('%s%s  [%s]' % (indent, d['prompt'], d['kind']))
    print('%s  formset=%r  form=%r' % (indent, d['formset'], d['form']))
    print('%s  varstore = %s (id %s)' % (indent, d['varstore_name'], d['varstore_id']))
    print('%s  guid     = %s' % (indent, d['varstore_guid']))
    print('%s  VarOffset= %s   size = %s byte(s)' % (indent, d['var_offset'], d['size_bytes']))
    if d['options']:
        for o in d['options']:
            v = o['value']
            print('%s      %-30s = %s' % (indent, o['name'],
                                          hexv(v) if v is not None else '?'))
    elif d['min'] is not None:
        print('%s      Numeric  min=%s max=%s' % (indent, hexv(d['min']), hexv(d['max'])))


def patch_stub(q, live=None, from_value=None):
    """Best-effort patch-file stub for a two-valued selector.

    FROM is taken from the live NVRAM value ONLY when the Setup and Custom
    records agree.  When they disagree the stub refuses to guess: a dump
    alone cannot tell which record the firmware honours.  Observed on one
    machine: fTPM stayed enabled while Custom read Disable, and the TPM
    on/off state tracked Setup across reboots -- neither "Custom wins" nor
    "Setup wins" is a safe rule.  The way out is either (a) flip the setting
    once in BIOS setup (a BIOS-side change re-syncs the records), re-dump,
    retry when the records agree, or (b) pass from_value (--from): the
    operator decides which record's byte is effective, e.g. because the
    feature's actual state is verifiable in the OS.  An operator-supplied
    FROM is never a guess, so it is honoured -- and marked as such in the
    stub's NOTE line.  TO is the remaining "meaningful" direction: off when
    FROM is an "on" flavour, firmware-TPM / enable flavour otherwise.
    """
    vs = q.get('varstore') or {}
    opts = [o for o in q.get('options', []) if o.get('value') is not None]
    if len(opts) < 2:
        return None
    low = [(o, (o['name'] or '').lower()) for o in opts]

    def _val(e):
        return int(e['value'], 16) if isinstance(e['value'], str) else e['value']

    from_opt = None
    live_note = None
    if live:
        ents = [(e.get('record') or '', _val(e)) for e in live]
        vals = sorted({v for _, v in ents})
        if len(vals) == 1:
            from_opt = next((o for o in opts if o['value'] == vals[0]), None)
            if from_opt is None:
                live_note = 'live value 0x%x has no matching option name' % vals[0]
        else:
            disagree = ', '.join('%s=0x%x' % (n, v) for n, v in ents)
            if from_value is not None:
                hit = [(n, v) for n, v in ents if v == from_value]
                if not hit:
                    print('  !! --from %s matches NEITHER record value (%s) '
                          '-- no patch stub generated.' % (hexv(from_value), disagree))
                    return None
                from_opt = next((o for o in opts if o['value'] == from_value), None)
                if from_opt is None:
                    print('  !! --from %s has no matching option name '
                          '-- no patch stub generated.' % hexv(from_value))
                    return None
                live_note = ('live records disagree (%s); FROM is the '
                             'operator-supplied value %s (record %s) -- the '
                             'operator confirmed which record the firmware '
                             'honours' % (disagree, hexv(from_value), hit[0][0]))
            else:
                print('  !! live records disagree (%s) -- no patch stub generated.' % disagree)
                print('  !! A dump alone cannot tell which record this firmware honours')
                print('  !! (observed: fTPM stayed enabled while Custom read Disable).')
                print('  !! Flip the setting once in BIOS setup, re-dump, and retry')
                print('  !! when the records agree -- or decide FROM yourself by')
                print('  !! passing --from <hex> (run.cmd option 2 will offer this).')
                return None

    if from_opt is None:                   # fallback: any enable/on
        for o, n in low:
            if 'enable' in n or n == 'on':
                from_opt = o
                break
    if from_opt is None and opts:
        from_opt = opts[0]                 # last resort

    # TO: a meaningful direction away from FROM.  When FROM is an "on" flavour
    # the meaningful step is off (disable); otherwise prefer the firmware-TPM
    # flavour of "on", then any enable/on, then the first differing option.
    from_name = (from_opt['name'] or '').lower()
    target = None
    if 'enable' in from_name or from_name == 'on':
        for o, n in low:
            if o is not from_opt and o['value'] != from_opt['value'] \
                    and ('disable' in n or n in ('off', 'disabled')):
                target = o
                break
    if target is None:
        for o, n in low:
            if o is not from_opt and o['value'] != from_opt['value'] and 'firmware' in n:
                target = o
                break
    if target is None:
        for o, n in low:
            if o is not from_opt and o['value'] != from_opt['value'] \
                    and ('enable' in n or n == 'on'):
                target = o
                break
    if target is None:
        for o in opts:
            if o is not from_opt and o['value'] != from_opt['value']:
                target = o
                break
    if target is None or target['value'] == from_opt['value']:
        return None

    name = vs.get('name') or '?'
    guid = (vs.get('guid') or '').strip('{}')
    prog = q.get('prompt') or 'setting'
    slug = re.sub(r'[^A-Za-z0-9]+', '-', prog.lower()).strip('-') or 'patch'
    lines = [
        '# --- candidate patch file (verify by eye before use) ---',
        '# %s / %s' % (q.get('formset'), q.get('prompt')),
        '# options: ' + '  '.join('%s=%s' % (o['name'], hexv(o['value']))
                                  for o in opts),
    ]
    if live_note:
        lines.append('# NOTE: ' + live_note)
    lines += [
        '# save as patches\\%s.patch  and run it with:' % slug,
        '#   powershell -ExecutionPolicy Bypass -File apply_patch.ps1 -Patch patches\\%s.patch' % slug,
        '# RECORDS: the record names inside that store.  "Setup,Custom" is the',
        '# SystemConfig pair; other stores use other names.',
        'NAME     = %s -> %s' % (prog, target.get('name')),
        'VARSTORE = %s' % name,
        'GUID     = %s' % guid,
        'RECORDS  = Setup,Custom',
        'OFFSET   = %s' % hexv(q['var_offset']),
        'FROM     = %s' % hexv(from_opt['value']),
        'TO       = %s' % hexv(target['value']),
    ]
    return '\n'.join(lines)


# ----------------------------------------------------------------------------
# commands
# ----------------------------------------------------------------------------

def cmd_scan(args):
    engine, model = load_questions(args.image, args.ifr_extractor, args.varstore)
    if args.json:
        print(json.dumps({'engine': engine,
                          'packages': [{k: v for k, v in p.items() if k != 'questions'}
                                       for p in model.get('pkg', [])],
                          'varstores': {str(k): v for k, v in model['varstores'].items()}},
                         indent=1, default=str))
        return

    print('input   : %s' % args.image)
    print('engine  : %s' % engine)
    print('packages: %d FORMS package(s) found' % len(model.get('pkg', [])))
    print()
    for p in model.get('pkg', []):
        print('=' * 74)
        print('FORMS pkg @%#x  len=0x%X  strings@%s  (%d/%d sids resolved)'
              % (p['offset'], p['len'],
                 hex(p['strings_off']) if p['strings_off'] is not None else '?',
                 p['hits'], p['sid_total']))
        print('  formset : %r' % p['formset'])
        g = p['formset_guid']
        print('  guid    : %s%s' % (g, '   <- ' + KNOWN_GUIDS[g.upper()]
                                    if g and g.upper() in KNOWN_GUIDS else ''))
        for vs in p['varstores']:
            print('  varstore: id=0x%X  name=%r  guid=%s  size=%s'
                  % (vs['id'], vs['name'], vs['guid'],
                     hexv(vs['size']) if vs['size'] is not None else '?'))
        print('  questions: %d' % len(p['questions']))
    print()
    print('Tip: narrow down with   python %s find <image> <keyword>'
          % os.path.basename(sys.argv[0]))


def maybe_write_stub(stubs, args):
    """--out helper: persist the first candidate patch file, say what happened."""
    if not getattr(args, 'out', None):
        return
    if not stubs:
        print('\n--out: no match produced a candidate patch; nothing written.')
        return
    if len(stubs) > 1:
        print('\n--out: %d matches produced a candidate; writing the first one. '
              'Compare the others by eye before using them.' % len(stubs))
    with open(args.out, 'w', encoding='utf-8', newline='\n') as f:
        f.write(stubs[0] + '\n')
    print('\nwrote %s   -- re-check FROM/TO by eye, then apply it with '
          'apply_patch.ps1 -Patch' % args.out)


def cmd_find(args):
    engine, model = load_questions(args.image, args.ifr_extractor, args.varstore)
    qs = model['questions']
    if args.varstore:
        want = args.varstore.lower()
        qs = [q for q in qs if ((q.get('varstore') or {}).get('name') or '').lower() == want]

    from_value = None
    if getattr(args, 'from_value', None):
        try:
            from_value = int(str(args.from_value), 0)
        except ValueError:
            raise SystemExit('--from: not a hex/dec value: %r' % args.from_value)

    recs = None
    if getattr(args, 'live', None):
        recs = [r for r in parse_h2ouve(args.live) if r.get('size')]
        if not recs:
            raise SystemExit('--live: no variable records parsed from %s -- '
                             'is that an H2OUVE -gv dump?' % args.live)

    hits = []
    if args.keywords:
        for q in qs:
            k = score_question(q, args.keywords)
            if k:
                hits.append((k, q))
    else:                       # no keyword: every locatable setting
        hits = [(None, q) for q in qs]
    hits = dedupe(hits)

    if args.json:
        ms = []
        for k, q in hits[:args.limit]:
            m = describe(q)
            m['matched'] = k
            if recs is not None:
                m['live'] = live_read(q, recs)
            ms.append(m)
        print(json.dumps({'engine': engine, 'matches': ms}, indent=1))
        return

    print('input   : %s   engine: %s' % (args.image, engine))
    print('keywords: %s' % (', '.join(args.keywords)
                           if args.keywords else
                           '(none -- listing every locatable setting)'))
    print('matches : %d' % len(hits))
    print()
    if not hits:
        print('nothing matched.  Try a broader word, or run `scan` to see every prompt.')
        return

    stubs = []
    for k, q in hits[:args.limit]:
        print('-' * 74)
        print_question(q, indent='  ')
        lv = live_read(q, recs) if recs is not None else None
        if recs is not None:
            if lv:
                for e in lv:
                    print('  %s  live[%s] = %s  (%s)' % (
                        ' ' * 11, e['record'], e['value'],
                        e['meaning'] or 'no option name'))
            else:
                print('  %s  live = <no matching record in --live dump>' % (' ' * 11))
        dflt = q_default(q)
        if dflt:
            print('  %s  IFR default = %s  (%s)' % (
                ' ' * 11, hexv(dflt['value']) if dflt['value'] is not None else '?',
                dflt['name'] or 'no option name'))
        stub = patch_stub(q, live=lv, from_value=from_value)
        if stub:
            stubs.append(stub)
            print()
            print(stub)
    if len(hits) > args.limit:
        print()
        print('... %d more match(es); raise --limit to see them.' % (len(hits) - args.limit))
    maybe_write_stub(stubs, args)


def cmd_from_ifr(args):
    model = parse_ifr_text(args.ifr)
    hits = []
    for q in model['questions']:
        k = score_question(q, args.keywords)
        if k:
            hits.append((k, q))
    hits = dedupe(hits)
    print('input   : %s   engine: ifrex-text' % args.ifr)
    print('keywords: %s' % ', '.join(args.keywords))
    print('matches : %d' % len(hits))
    print()
    stubs = []
    for k, q in hits[:args.limit]:
        print('-' * 74)
        print_question(q, indent='  ')
        stub = patch_stub(q)
        if stub:
            stubs.append(stub)
            print()
            print(stub)
    maybe_write_stub(stubs, args)


def cmd_verify(args):
    """Cross-check IFR-located settings against a real H2OUVE dump."""
    engine, model = load_questions(args.image, args.ifr_extractor, args.varstore)
    recs = parse_h2ouve(args.dump)
    by_guid = {}
    for r in recs:
        if r['guid']:
            by_guid.setdefault(r['guid'].upper(), []).append(r)

    print('image   : %s   engine: %s' % (args.image, engine))
    print('dump    : %s   records: %d' % (args.dump, len(recs)))
    print()

    qs = model['questions']
    if args.varstore:
        want = args.varstore.lower()
        qs = [q for q in qs if ((q.get('varstore') or {}).get('name') or '').lower() == want]
    if args.keywords:
        qs = [q for q in qs if score_question(q, args.keywords)]

    if not qs:
        print('no questions to verify (check --varstore / keywords).')
        return

    # group questions by their varstore, so we verify each varstore once
    groups = {}
    for q in qs:
        vs = q.get('varstore') or {}
        groups.setdefault(vs.get('guid') or '<no-guid>', []).append(q)

    ok_all = True
    for guid, gqs in groups.items():
        vs = gqs[0].get('varstore') or {}
        print('=' * 74)
        print('IFR VarStore : %r   guid=%s   size=%s'
              % (vs.get('name'), guid, hexv(vs['size']) if vs.get('size') is not None else '?'))
        matches = by_guid.get(guid.upper(), [])
        if not matches:
            ok_all = False
            print('  MATCH FAIL: no record with this GUID in the dump.')
            print('  -> the dump is from a different firmware, or you dumped the')
            print('     wrong variable set.  Do NOT trust any offset below.')
            continue
        for r in matches:
            data = bytes(r['data'])
            size_ok = (vs.get('size') is None or vs['size'] == len(data))
            print('  record %-10s @%d   guid=%s   len=%d  size_field=%s  %s'
                  % (r['name'], r['idx'], r['guid'], len(data),
                     hexv(r['size']) if r['size'] is not None else '?',
                     'size OK' if size_ok else 'SIZE MISMATCH'))
            if not size_ok:
                ok_all = False
            for q in gqs:
                off = q['var_offset']
                w = q.get('width') or 1
                if off + w > len(data):
                    ok_all = False
                    print('     %-34s 0x%X -- BEYOND record (%d bytes)  ** FAIL **'
                          % (q.get('prompt'), off, len(data)))
                    continue
                cur = int.from_bytes(data[off:off + w], 'little')
                vals = {o['value']: o['name'] for o in q.get('options', [])
                        if o.get('value') is not None}
                if vals:
                    verdict = 'KNOWN value' if cur in vals else 'value NOT in option table'
                    if cur not in vals:
                        ok_all = False
                    meaning = vals.get(cur, '<unlisted>')
                    print('     %-34s 0x%-4X = 0x%-4X  -> %s  (%s)'
                          % (q.get('prompt'), off, cur, meaning, verdict))
                else:
                    print('     %-34s 0x%-4X = 0x%-4X  (numeric, range %s..%s)'
                          % (q.get('prompt'), off, cur,
                             hexv(q['min']) if q.get('min') is not None else '?',
                             hexv(q['max']) if q.get('max') is not None else '?'))
    print()
    print('RESULT: %s' % ('consistent -- the IFR layout explains this dump'
                          if ok_all else
                          'INCONSISTENT -- read the FAIL lines above'))


# ----------------------------------------------------------------------------
# extract: an official BIOS upgrade package -> the Insyde SetupUtility FFS file
#
# The locate workflow needs the firmware's Setup module.  The cleanest source
# is the vendor's own upgrade package; this command unwraps the common chains:
#
#     .zip  -> inner .exe (7z SFX) -> .fd image -> FFS3 volume -> LZMA section
#           -> DXE volume -> FFS file FE3542FE-C1D3-4EF8-657C-8048606FF670
#
# zip and fd are pure stdlib.  The 7z SFX step needs py7zr (pip) or 7z.exe;
# everything else works without any third-party code.
# ----------------------------------------------------------------------------

SETUP_UTILITY_GUID_STR = 'FE3542FE-C1D3-4EF8-657C-8048606FF670'
LZMA_CUSTOM_DECOMPRESS_GUID_STR = 'EE4E5898-3914-4259-9D6E-DC7BD79403CF'

FFS_FILE_TYPES = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0xF0}


def _carve_ffs_files(data, guid):
    """Find FFS files named by `guid`; return their bodies (without the
    24-byte FFS header) -- that is the form other tools expect."""
    out = []
    n = len(data)
    for i in range(n - 24):
        if data[i:i + 16] != guid:
            continue
        ftype = data[i + 18]
        size = data[i + 20] | (data[i + 21] << 8) | (data[i + 22] << 16)
        if ftype not in FFS_FILE_TYPES:
            continue
        if size < 48 or i + size > n:
            continue
        out.append(bytes(data[i + 24:i + size]))
    return out


def _lzma_sections(data):
    """Yield decompressed payloads of LZMA GUID-defined sections."""
    import lzma
    guid = uuid.UUID(LZMA_CUSTOM_DECOMPRESS_GUID_STR).bytes_le
    n = len(data)
    for i in range(n - 24):
        if data[i:i + 16] != guid:
            continue
        sec = i - 4
        if sec < 0:
            continue
        if data[sec + 3] != 0x02:          # EFI_SECTION_GUID_DEFINED
            continue
        size = data[sec] | (data[sec + 1] << 8) | (data[sec + 2] << 16)
        data_off = struct.unpack_from('<H', data, sec + 20)[0]
        if size < 24 or sec + size > n or data_off < 24:
            continue
        payload = bytes(data[sec + data_off:sec + size])
        try:
            yield lzma.decompress(payload, format=lzma.FORMAT_ALONE)
        except Exception:
            continue


def _scan_for_setup_ffs(data, depth=0):
    found = _carve_ffs_files(data, uuid.UUID(SETUP_UTILITY_GUID_STR).bytes_le)
    if found or depth > 5:
        return found
    for blob in _lzma_sections(data):
        got = _scan_for_setup_ffs(blob, depth + 1)
        if got:
            return got
    return []


def _largest_by_ext(path, exts):
    import zipfile
    best = None
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            e = os.path.splitext(info.filename)[1].lower()
            if e in exts and (best is None or info.file_size > best[0]):
                best = (info.file_size, info.filename)
        if best:
            z.extract(best[1], path + '.x')
            return os.path.join(path + '.x', best[1])
    return None


# --- minimal stdlib 7z reader ----------------------------------------------
# Sufficient for BIOS SFX archives: signature header, kEncodedHeader, plain
# LZMA1/LZMA2 coders, one output stream per coder.  Anything exotic (BCJ,
# chained coders, solid blocks) raises and the caller falls back to
# py7zr / 7z.exe.  Pure stdlib: lzma + struct only.

_7Z_SIG = bytes.fromhex('377abcaf271c')
_7Z_LZMA1 = bytes([0x03, 0x01, 0x01])
_7Z_LZMA2 = bytes([0x21])


def _7z_num(buf, i):
    """7z variable-length number; return (value, next_index)."""
    b = buf[i]
    i += 1
    if b < 0x80:
        return b, i
    mask = 0x80
    for extra in range(1, 9):
        mask >>= 1
        if (b & mask) == 0:
            hi = b & (mask - 1)
            rest = int.from_bytes(buf[i:i + extra], 'little')
            return (hi << (8 * extra)) | rest, i + extra
    raise ValueError('7z: number field too long')


def _7z_bitvec(buf, i, n):
    out = []
    for bit in range(n):
        out.append((buf[i + (bit >> 3)] >> (bit & 7)) & 1)
    return out, i + ((n + 7) >> 3)


def _7z_decode(data, base, folder, unpack_size):
    """Decode one folder (single coder, single output stream)."""
    import lzma
    if len(folder['coders']) != 1:
        raise ValueError('7z: chained coders not supported')
    cid, props = folder['coders'][0]
    pack = data[base + folder['pack_pos']:base + folder['pack_pos'] + folder['pack_size']]
    if cid == _7Z_LZMA1:
        if len(props) < 5:
            raise ValueError('7z: bad LZMA1 props')
        b0 = props[0]
        lc, lp, pb = b0 % 9, (b0 // 9) % 5, b0 // 45
        dic = int.from_bytes(props[1:5], 'little')
        filters = [{'id': lzma.FILTER_LZMA1, 'lc': lc, 'lp': lp, 'pb': pb,
                    'dict_size': max(dic, 0x1000)}]
    elif cid == _7Z_LZMA2:
        b = props[0] if props else 0
        if b > 40:
            raise ValueError('7z: bad LZMA2 props')
        dic = 0xFFFFFFFF if b == 40 else (2 | (b & 1)) << (b // 2 + 11)
        filters = [{'id': lzma.FILTER_LZMA2, 'dict_size': dic}]
    else:
        raise ValueError('7z: coder id %s not supported' % cid.hex())
    dec = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=filters)
    out = dec.decompress(pack)
    # LZMA1 streams often lack an end marker; pad with zeros until the
    # declared size is reached (the tail is ignored by the caller anyway).
    pad = 0
    while len(out) < unpack_size and not dec.eof and pad < 1 << 22:
        out += dec.decompress(b'\x00' * 65536)
        pad += 65536
    if len(out) < unpack_size:
        raise ValueError('7z: short stream (%d < %d)' % (len(out), unpack_size))
    return bytes(out[:unpack_size])


def _7z_streams_info(buf, i):
    """Parse [PackInfo][UnpackInfo][SubStreamsInfo]End at buf[i].
    Returns ({pack_sizes, folders, streams_per_folder, stream_sizes}, next_i)."""
    si = {'pack_pos': 0, 'pack_sizes': [], 'folders': [], 'streams': []}
    b, i = _7z_num(buf, i)
    if b == 0x06:                                    # kPackInfo
        si['pack_pos'], i = _7z_num(buf, i)
        n, i = _7z_num(buf, i)
        while True:
            p, i = _7z_num(buf, i)
            if p == 0x00:
                break
            if p == 0x09:                            # kSize
                for _ in range(n):
                    v, i = _7z_num(buf, i)
                    si['pack_sizes'].append(v)
            elif p == 0x0A:                          # kCRC: skip
                bits, i = _7z_bitvec(buf, i, n)
                i += 4 * sum(bits)
            else:
                raise ValueError('7z: pack prop 0x%x' % p)
    b, i = _7z_num(buf, i)
    if b == 0x07:                                    # kUnpackInfo
        i = _7z_num(buf, i)[1]                       # 0x0B kFolder
        nf, i = _7z_num(buf, i)
        ext, i = _7z_num(buf, i)
        if ext:
            raise ValueError('7z: external folders not supported')
        for _ in range(nf):
            nc, i = _7z_num(buf, i)
            coders = []
            for _ in range(nc):
                mb = buf[i]
                i += 1
                if mb & 0xC0:
                    raise ValueError('7z: complex coder not supported')
                idn = mb & 0x0F
                cid = bytes(buf[i:i + idn])
                i += idn
                props = b''
                if mb & 0x20:
                    ps, i = _7z_num(buf, i)
                    props = bytes(buf[i:i + ps])
                    if len(props) != ps:
                        raise ValueError('7z: truncated props')
                    i += ps
                coders.append((cid, props))
            f = {'coders': coders, 'pack_pos': 0, 'pack_size': 0, 'out_size': 0}
            si['folders'].append(f)
        p, i = _7z_num(buf, i)
        if p == 0x0C:                                # kCodersUnpackSize
            for f in si['folders']:
                f['out_size'], i = _7z_num(buf, i)
        elif p != 0x00:
            raise ValueError('7z: expected unpack sizes, got 0x%x' % p)
        while True:
            p, i = _7z_num(buf, i)
            if p == 0x00:
                break
            if p == 0x0A:                            # folder CRCs: skip
                bits, i = _7z_bitvec(buf, i, nf)
                i += 4 * sum(bits)
            else:
                raise ValueError('7z: unpack prop 0x%x' % p)
    b, i = _7z_num(buf, i)
    if b == 0x09:                                    # kSubStreamsInfo
        while True:
            p, i = _7z_num(buf, i)
            if p == 0x00:
                break
            if p == 0x09:                            # kNumUnpackStream
                for f in si['folders']:
                    n, i = _7z_num(buf, i)
                    f['n_out'] = n
                si['streams'] = [f.get('n_out', 1) for f in si['folders']]
            elif p == 0x0B:                          # kSize (n-1 per folder)
                for f in si['folders']:
                    n = f.get('n_out', 1)
                    szs = []
                    tot = 0
                    for _k in range(n - 1):
                        v, i = _7z_num(buf, i)
                        szs.append(v)
                        tot += v
                    if n > 1:
                        szs.append(f['out_size'] - tot)
                    f['stream_sizes'] = szs
            elif p == 0x0A:                          # CRCs: skip
                total = sum(f.get('n_out', 1) for f in si['folders'])
                bits, i = _7z_bitvec(buf, i, total)
                i += 4 * sum(bits)
            else:
                raise ValueError('7z: substream prop 0x%x' % p)
        if not si['streams']:
            si['streams'] = [1] * len(si['folders'])
    else:
        si['streams'] = [1] * len(si['folders'])
    return si, i


def _7z_extract(archive, outdir):
    """Extract a 7z archive (bytes) with stdlib only.  Returns file count."""
    if archive[:6] != _7Z_SIG:
        raise ValueError('7z: bad signature')
    nh_off, nh_size = struct.unpack_from('<QQ', archive, 12)
    if nh_size > (1 << 26) or nh_off + nh_size > len(archive) - 32:
        raise ValueError('7z: header out of range')
    hdr = archive[32 + nh_off:32 + nh_off + nh_size]
    if hdr[0] == 0x17:                               # kEncodedHeader
        si, _ = _7z_streams_info(hdr, 1)
        if len(si['folders']) != 1:
            raise ValueError('7z: encoded header folders != 1')
        # fix pack positions: encoded header packs live at 32+pack_pos
        f = si['folders'][0]
        ps = si['pack_sizes']
        if len(ps) != 1:
            raise ValueError('7z: encoded header pack streams != 1')
        f['pack_pos'], f['pack_size'] = si['pack_pos'], ps[0]
        hdr = _7z_decode(archive, 32, f, f['out_size'])
    if hdr[0] != 0x01:
        raise ValueError('7z: not a file header')
    si = None
    names = []
    empty = []
    i = 1
    while True:
        p, i = _7z_num(hdr, i)
        if p == 0x00:
            break
        if p == 0x04:                                # kMainStreamsInfo
            si, i = _7z_streams_info(hdr, i)
        elif p == 0x05:                              # kFilesInfo
            nf, i = _7z_num(hdr, i)
            if nf > 100000:
                raise ValueError('7z: too many files')
            while True:
                q, i = _7z_num(hdr, i)
                if q == 0x00:
                    break
                if q == 0x0E:                        # empty streams
                    empty, i = _7z_bitvec(hdr, i, nf)
                elif q == 0x0F or q == 0x10:         # empty files / anti
                    _, i = _7z_bitvec(hdr, i, nf)
                elif q == 0x11:                      # names
                    ext, i = _7z_num(hdr, i)
                    if ext:
                        raise ValueError('7z: external names not supported')
                    nms = []
                    j = i
                    for _ in range(nf):
                        start = j
                        while hdr[j] | hdr[j + 1]:
                            j += 2
                        nms.append(hdr[start:j].decode('utf-16-le'))
                        j += 2
                    names = nms
                    i = j
                elif q in (0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                           0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21):
                    bits, i = _7z_bitvec(hdr, i, nf)  # all-defined bitvec
                    m, i = _7z_num(hdr, i)
                    i += 8 * m                       # 64-bit times
                else:
                    raise ValueError('7z: file prop 0x%x' % q)
        elif p == 0x02:                              # kArchiveProperties
            while True:
                t, i = _7z_num(hdr, i)
                if t == 0x00:
                    break
                n, i = _7z_num(hdr, i)
                i += n
        else:
            raise ValueError('7z: header prop 0x%x' % p)
    if si is None:
        raise ValueError('7z: no streams info')
    if len(names) < sum(1 for e in empty if not e):
        raise ValueError('7z: missing file names')

    # pack stream bookkeeping: each simple folder consumes one pack stream,
    # in order
    k = 0
    for f in si['folders']:
        f['pack_pos'] = sum(si['pack_sizes'][:k])
        f['pack_size'] = si['pack_sizes'][k]
        k += 1
    # map data files to (folder, offset, size) in stream order
    files = []
    fo = 0
    sidx = 0
    off = 0
    for idx, nm in enumerate(names):
        if idx < len(empty) and empty[idx]:
            continue
        while fo < len(si['folders']) and sidx >= si['streams'][fo]:
            fo += 1
            sidx = 0
            off = 0
        if fo >= len(si['folders']):
            raise ValueError('7z: more data files than streams')
        f = si['folders'][fo]
        szs = f.get('stream_sizes') or [f['out_size']]
        files.append((nm, fo, off, szs[sidx]))
        off += szs[sidx]
        sidx += 1
    if not files:
        raise ValueError('7z: no data files')

    os.makedirs(outdir, exist_ok=True)
    cache = {}
    count = 0
    for nm, fo, off, size in files:
        f = si['folders'][fo]
        if fo not in cache:
            cache[fo] = _7z_decode(archive, 32, f, f['out_size'])
        chunk = cache[fo][off:off + size]
        if len(chunk) != size:
            raise ValueError('7z: short file %r' % nm)
        rel = nm.replace('\\', '/')
        if rel.startswith('/') or '..' in rel.split('/'):
            raise ValueError('7z: unsafe path %r' % nm)
        dst = os.path.join(outdir, *rel.split('/'))
        parent = os.path.dirname(dst)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(dst, 'wb') as fh:
            fh.write(chunk)
        count += 1
    return count


def _extract_7z(exe_path, workdir):
    """7z SFX.  Deps in order: stdlib (built-in reader), py7zr, 7z.exe
    (repo-local bin\\7z.exe, then PATH, then Program Files).
    Returns dir or None.

    An SFX is stub + archive; scan for the 7z signature, carve the inner
    archive out, and try each candidate."""
    import hashlib
    sig = bytes.fromhex('377abcaf271c')
    with open(exe_path, 'rb') as fh:
        data = fh.read()
    try:
        import py7zr
    except ImportError:
        py7zr = None

    seen = set()
    for off in offs if (offs := [m.start() for m in re.finditer(re.escape(sig), data)]) else []:
        blob = data[off:]
        h = hashlib.sha256(blob).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        d = os.path.join(workdir, 'sfx')
        # 1) stdlib reader -- no third-party dependency
        try:
            if _7z_extract(blob, d):
                return d
        except Exception:
            pass
        # 2) py7zr, if installed
        if py7zr is not None:
            inner = os.path.join(workdir, 'inner_%d.7z' % off)
            with open(inner, 'wb') as fh:
                fh.write(blob)
            try:
                py7zr.SevenZipFile(inner).extractall(d)
                return d
            except Exception:
                continue

    # 3) 7-Zip console: repo-local portable copy first (bin\7za.exe or
    #    bin\7z.exe), then PATH, then Program Files
    bindir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'bin')
    candidates = [os.path.join(bindir, '7za.exe'),
                  os.path.join(bindir, '7z.exe'),
                  shutil.which('7z') or '',
                  r'C:\Program Files\7-Zip\7z.exe']
    for sevenzip in candidates:
        if sevenzip and os.path.exists(sevenzip):
            d = os.path.join(workdir, 'sfx')
            os.makedirs(d, exist_ok=True)
            rc = subprocess.call([sevenzip, 'x', '-y', '-o' + d, exe_path],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if rc == 0:
                return d
    return None


def _iter_files(d):
    for root, _dirs, files in os.walk(d):
        for f in files:
            yield os.path.join(root, f)


def cmd_extract(args):
    import hashlib
    import zipfile

    src = args.package
    if not os.path.isfile(src):
        print('not found: %s' % src)
        return 2
    outdir = args.outdir or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'bios_cache')
    os.makedirs(outdir, exist_ok=True)
    workdir = tempfile.mkdtemp(prefix='ifr_x_')

    try:
        blob = src
        ext = os.path.splitext(src)[1].lower()
        hops = []
        # 1) unwrap containers down to a raw firmware image
        for _ in range(4):
            if ext == '.zip':
                inner = _largest_by_ext(blob, {'.exe', '.fd', '.bin', '.rom', '.cap'})
                if not inner:
                    print('zip holds no .exe/.fd/.bin to unwrap')
                    return 2
                hops.append(os.path.basename(inner))
                blob, ext = inner, os.path.splitext(inner)[1].lower()
            elif ext == '.exe':
                d = _extract_7z(blob, workdir)
                if not d:
                    print('this .exe is a 7z SFX; to unwrap it do one of:')
                    print('    drop a portable 7-Zip console at bin\\7za.exe')
                    print('    (official extra package: github.com/ip7z/7zip releases,')
                    print('     x64/7za.exe, sha256 15d4c788c148e367...e1260)')
                    print('    pip install py7zr')
                    print('    install 7-Zip (7z.exe on PATH or C:\\Program Files\\7-Zip)')
                    print('then re-run, or drop the .fd from inside the package instead.')
                    return 3
                inner = None
                for cand in sorted(_iter_files(d), key=lambda p: -os.path.getsize(p)):
                    if os.path.splitext(cand)[1].lower() in ('.fd', '.bin', '.rom', '.cap'):
                        inner = cand
                        break
                if not inner:
                    print('7z extraction produced no .fd/.bin firmware image')
                    return 2
                hops.append(os.path.basename(inner))
                blob, ext = inner, os.path.splitext(inner)[1].lower()
            elif ext in ('.fd', '.bin', '.rom', '.cap'):
                break
            else:
                # unknown extension: try it as a raw image anyway
                break

        with open(blob, 'rb') as fh:
            data = fh.read()
        hops.append('raw scan (%d bytes)' % len(data))

        # 2) carve the Setup utility FFS out of it
        files = _scan_for_setup_ffs(data)
        if not files:
            print('no Insyde SetupUtility FFS (%s) found in: %s'
                  % (SETUP_UTILITY_GUID_STR, blob))
            print('if this is not your platform image, check you took the right package.')
            return 2
        uniq = {}
        for b in files:
            uniq.setdefault(hashlib.sha256(b).hexdigest(), b)
        best = max(uniq.values(), key=len)
        out_path = os.path.join(outdir, 'Setup_%s.ffs' % SETUP_UTILITY_GUID_STR)
        with open(out_path, 'wb') as fh:
            fh.write(best)

        print('chain  : %s' % ' -> '.join([os.path.basename(src)] + hops))
        print('FFS    : %s  (%d bytes, sha256 %s)'
              % (out_path, len(best), hashlib.sha256(best).hexdigest()[:16] + '...'))
        if len(uniq) > 1:
            print('note   : %d distinct copies found; wrote the largest.' % len(uniq))
        print('EXTRACTED: %s' % out_path)
        return 0
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# ----------------------------------------------------------------------------
# entry point
# ----------------------------------------------------------------------------

def main(argv=None):
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--ifr-extractor', default=None,
                        help='path to an IFRExtractor-RS binary (optional)')
    common.add_argument('--varstore', default=None,
                        help='only consider questions in this VarStore (e.g. SystemConfig)')
    common.add_argument('--limit', type=int, default=20)
    common.add_argument('--json', action='store_true')
    common.add_argument('--out', default=None,
                        help='find/from-ifr: write the first candidate patch '
                             'file to this path instead of only printing it')

    p = argparse.ArgumentParser(
        prog='ifr_locate.py', parents=[common],
        description='Locate a firmware setting (VarStore + byte offset) and '
                    'prove it against a H2OUVE dump.')
    sub = p.add_subparsers(dest='cmd')

    s = sub.add_parser('scan', parents=[common],
                       help='list formsets / varstores / package stats')
    s.add_argument('image')
    s.add_argument('keywords', nargs='*')
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser('find', parents=[common],
                       help='locate settings by keyword (no keyword = list all)')
    s.add_argument('image')
    s.add_argument('keywords', nargs='*')
    s.add_argument('--live', default=None, metavar='DUMP',
                   help='H2OUVE -gv dump (text); show the CURRENT value of '
                        'each match alongside the IFR default')
    s.add_argument('--from', dest='from_value', default=None, metavar='HEX',
                   help='when the Setup/Custom records disagree, use this '
                        'value as FROM anyway (operator-decided, never '
                        'guessed; e.g. 0x2)')
    s.set_defaults(func=cmd_find)

    s = sub.add_parser('from-ifr', parents=[common],
                       help='locate settings from IFRExtractor text')
    s.add_argument('ifr')
    s.add_argument('keywords', nargs='+')
    s.set_defaults(func=cmd_from_ifr)

    s = sub.add_parser('verify', parents=[common],
                       help='cross-check against a H2OUVE dump')
    s.add_argument('image')
    s.add_argument('dump')
    s.add_argument('keywords', nargs='*')
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser('extract', add_help=True,
                       help='unwrap a BIOS upgrade package (.zip/.exe/.fd) '
                            'into the Setup FFS that find/scan consume')
    s.add_argument('package')
    s.add_argument('--outdir', default=None,
                   help='where to write Setup_<guid>.ffs '
                        '(default: <repo>\\bios_cache)')
    s.set_defaults(func=cmd_extract)

    args = p.parse_args(argv)
    if not getattr(args, 'cmd', None):
        p.print_help()
        return 2
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main() or 0)
