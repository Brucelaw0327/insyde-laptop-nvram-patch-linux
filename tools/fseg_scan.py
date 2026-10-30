#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fseg_scan.py —— 诊断 F 段里到底有没有 $IHISI 标签。

背景：驱动 FindSmiMainFuncNum()（init:0x5680）扫物理 0xF0000 起 64KB、
步进 0x10、比对 6 字节 "$IHISI"，命中取 +6 那个字节做主功能号，
未命中则用 0xEF。实机跑出来是「没找到」，所以要看现场。

用法：
    sudo python3 tools/fseg_scan.py                 # 扫 0xE0000..0x100000
    sudo python3 tools/fseg_scan.py --out dump/     # 顺便落盘（推荐）

产出：
    dump/fseg_<起始>_<长度>.bin   可读区间的原始内容
    dump/manifest.json            每段对应哪块物理地址 + 统计
    终端上直接给结论：找到没有、在哪里、附近字节是什么
"""

import argparse
import json
import mmap
import os
import struct
import sys

PAGE = 4096
SIGS = [
    (b"$IHISI", "IHISI 标签（驱动找的就是这个）"),
    (b"IHISI", "IHISI 无 $ 前缀"),
    (b"O2H$", "驱动 SMI 报文魔数"),
    (b"$H2O", "H2OWriteVariable 报文魔数"),
    (b"RSD PTR ", "ACPI RSDP"),
]


def read_iomem():
    try:
        return open("/proc/iomem").read()
    except OSError:
        return ""


def iomem_lines(lo, hi, text):
    """挑出与 [lo,hi) 有交集的 /proc/iomem 行。"""
    out = []
    for ln in text.splitlines():
        try:
            rng, name = ln.split(":", 1)
            a, b = rng.strip().split("-")
            a, b = int(a, 16), int(b, 16)
        except ValueError:
            continue
        if b >= lo and a <= hi:
            out.append((a, b + 1, name.strip()))
    return out


def map_range(addr, size):
    """尝试一次映射；失败返回 None。"""
    try:
        fd = os.open("/dev/mem", os.O_RDONLY | os.O_SYNC)
    except OSError as e:
        sys.exit("/dev/mem 打不开：%s（需要 root）" % e)
    try:
        return mmap.mmap(fd, size, mmap.MAP_SHARED, mmap.PROT_READ, offset=addr)
    except (OSError, ValueError):
        return None
    finally:
        os.close(fd)


def collect(lo, hi):
    """按页收集可读区间，返回 [(start, bytes), ...]。"""
    segs = []
    cur_start = None
    cur = bytearray()
    for a in range(lo, hi, PAGE):
        m = map_range(a, PAGE)
        if m is None:
            if cur:
                segs.append((cur_start, bytes(cur)))
                cur_start, cur = None, bytearray()
            continue
        try:
            data = m[:]
        finally:
            m.close()
        if cur_start is None:
            cur_start = a
        cur.extend(data)
    if cur:
        segs.append((cur_start, bytes(cur)))
    return segs


def reserved_ranges(limit_bytes=4 << 20):
    """/proc/iomem 里所有「不是 System RAM、也不是 PCI」的小块保留区。

    标签可能被固件写进 OEM 保留区 / ACPI NVS，而不在 F 段。
    """
    out = []
    for a, b, name in iomem_lines(0, 1 << 32, read_iomem()):
        low = name.lower()
        if "system ram" in low or low.startswith("pci") or "kernel" in low:
            continue
        if b - a > limit_bytes or a >= 0x10000000:
            continue
        out.append((a, b, name))
    return out


def stats(b):
    nz = sum(1 for x in b if x)
    ff = b.count(0xFF)
    zero = b.count(0x00)
    return nz, ff, zero


def profile(b):
    """复用 ihisi.py 的画像判据，保证两个工具给同一个结论。

    内核在 CONFIG_STRICT_DEVMEM=y 下对非 RAM 页返回填充字节，特征是高熵、
    256 值全现；真固件一定大量出现 0x00 / 0xFF 和重复指令片段。
    """
    try:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        import ihisi
        st = ihisi.fseg_stats(b)
        code, why = ihisi.fseg_verdict(st)
        return code, why, st
    except Exception as e:                                  # noqa: BLE001
        return None, "画像失败（%s）" % e, None


def hexdump(b, base, n=64):
    out = []
    for i in range(0, min(n, len(b)), 16):
        chunk = b[i:i + 16]
        txt = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        out.append("  %08X  %-47s  %s" % (base + i, chunk.hex(" "), txt))
    return "\n".join(out)


def scan_all(outdir=None):
    """把 /proc/iomem 里所有小块保留区扫一遍，找 $IHISI。"""
    rngs = reserved_ranges()
    print("保留区候选 %d 块（≤4MB、非 System RAM / PCI）：" % len(rngs))
    hits = []
    for a, b, name in rngs:
        segs = collect(a, b)
        for s, blob in segs:
            p = 0
            while True:
                k = blob.find(b"$IHISI", p)
                if k < 0:
                    break
                hits.append((s + k, name))
                p = k + 1
        got = sum(len(x) for _, x in segs)
        print("  %08x-%08x  %-22s 可读 %5d/%5d" % (a, b - 1, name, got, b - a))
        if outdir:
            os.makedirs(outdir, exist_ok=True)
            for s, blob in segs:
                fn = os.path.join(outdir, "res_%08x_%06x.bin" % (s, len(blob)))
                with open(fn, "wb") as f:
                    f.write(blob)

    print()
    if not hits:
        print("所有保留区里都没有 $IHISI。")
        print("→ 标签只可能在 SMRAM 或其它用户态读不到的地方；")
        print("  驱动在这种情况下会退回 0xEF（见 FindSmiMainFuncNum 的 0x5732）。")
        return 1
    print("命中 %d 处：" % len(hits))
    for addr, name in hits:
        print("  %#010x  in %s" % (addr, name))
    return 0


def _fadt_sane(b):
    """判断这份 FACP 是不是真的。

    只看单个字段容易被巧合骗：`SMI_CMD=0x00b0` 可能碰巧是对的，
    所以要看整张表是否自洽 —— 签名、校验和、Length、Flags 保留位。
    """
    reasons = []
    if len(b) < 0x74:
        return False, ["长度不足 %d 字节，读不到 Flags" % len(b)]
    if b[:4] != b"FACP":
        reasons.append("签名不是 FACP 而是 %r" % b[:4])
    if (sum(b) & 0xFF) != 0:
        reasons.append("表校验和不对（sum=%#x）" % (sum(b) & 0xFF))
    length = struct.unpack_from("<I", b, 0x04)[0]
    if length != len(b):
        reasons.append("表头 Length=%#x 但实际读到 %d 字节" % (length, len(b)))
    flags = struct.unpack_from("<I", b, 0x70)[0]
    if flags & 0xFFC00000:
        reasons.append("Flags 高 10 位（bit22..31 规范定义为 0）实际 %#x"
                       % (flags >> 22))
    # FACS=0 只在 ACPI 1.0 老机器上可能；有 X_FACS 时它也允许为 0
    facs = struct.unpack_from("<I", b, 0x24)[0]
    xfacs = struct.unpack_from("<Q", b, 0x84)[0] if len(b) >= 0x8C else 0
    if facs == 0 and xfacs == 0:
        reasons.append("FIRMWARE_CTRL 和 X_FIRMWARE_CTRL 都是 0，无法定位 FACS")
    return (not reasons), reasons


def _fadt_flags_text(flags):
    """把 FADT.Flags 里置位的项翻成人话，只看常用几位。"""
    BITS = [
        (0, "WBINVD"), (1, "WBINVD_FLUSH"), (2, "PROC_C1"), (3, "P_LVL2_UP"),
        (4, "PWR_BUTTON"), (5, "SLEEP_BUTTON"), (6, "FIX_RTC"), (7, "RTC_S4"),
        (8, "TMR_VAL_EXT"), (9, "DCK_CAP"), (10, "RESET_REG_SUP"),
        (11, "SEALED_CASE"), (12, "HEADLESS"), (13, "CPU_SW_SLP"),
        (14, "PCI_EXP_WAK"), (15, "USE_PLATFORM_CLOCK"),
        (16, "S4_RTC_STS_VALID"), (17, "REMOTE_POWER_ON_CAPABLE"),
        (18, "FORCE_APIC_CLUSTER"), (19, "FORCE_APIC_PHYS_DEST"),
        (20, "HW_REDUCED_ACPI"), (21, "LOW_POWER_S0_IDLE"),
    ]
    return [name for bit, name in BITS if (flags >> bit) & 1]


def _ports_are_masked(txt):
    """判断 /proc/ioports 的地址是不是被内核清零了。

    CONFIG_IO_STRICT_DEVMEM 一类的加固会让内核把所有资源地址显示成
    "0000-0000"，只留名称。这种情况下 /proc/ioports 完全不能用来判断
    "某个端口有没有主人" —— 地址都变成 0 了，任何范围比较都无意义。
    """
    addrs = []
    for ln in txt.splitlines():
        sp = ln.strip().split()
        if not sp or "-" not in sp[0]:
            continue
        try:
            a, b = sp[0].split("-")
            addrs.append((int(a, 16), int(b, 16)))
        except ValueError:
            continue
    if not addrs:
        return False
    zero = sum(1 for a, b in addrs if a == 0 and b == 0)
    return zero > len(addrs) * 0.8


def _parse_ports(txt, needles):
    """从 /proc/ioports 里挑出与给定端口有交集的段。"""
    out = []
    for ln in txt.splitlines():
        s = ln.strip()
        if not s or "-" not in s:
            continue
        rng = s.split()[0] if s.split() else ""
        try:
            a, b = rng.split("-")
            a, b = int(a, 16), int(b, 16)
        except ValueError:
            continue
        for nd in needles:
            if a <= nd <= b:
                out.append((nd, s))
                break
    return out


def peek(params):
    """只读嗅探：SMM 到底在不在那个端口上。

    不发 SMI、不写任何字节：
      1) FACP 读出来自检（签名 / 校验和 / Length / Flags / FACS）
      2) /proc/ioports 里端口有没有主人
      3) /dev/port 在不在（决定能不能做 iopl 级验证）
    """
    print("端口嗅探（不发 SMI，纯读）")
    print("  /dev/port: %s" % ("存在" if os.path.exists("/dev/port") else "不存在"))

    # ---- FACP
    facp_path = "/sys/firmware/acpi/tables/FACP"
    port = None
    try:
        b = open(facp_path, "rb").read()
    except OSError as e:
        b = None
        print("  FACP 读不了：%s（需要 root）" % e)

    if b is not None:
        ok, reasons = _fadt_sane(b)
        port = struct.unpack_from("<H", b, 0x30)[0] if len(b) >= 0x32 else None
        print("  FACP: %d 字节，版本 %d，SMI_CMD=%s"
              % (len(b), b[8] if len(b) > 8 else -1,
                 ("%#06x" % port) if port else "读不到"))
        print("        自检: %s" % ("通过（这份表可信）" if ok else "**不通过**"))
        for r in reasons:
            print("          - %s" % r)
        if not ok:
            print("        结论：这份 FACP 不可信，下面的 SMI_CMD 不能当实测值用。")
            print("        多半是映射/偏移不对，而不是固件真长这样。")
        if len(b) >= 0x74:
            flags = struct.unpack_from("<I", b, 0x70)[0]
            facs = struct.unpack_from("<I", b, 0x24)[0]
            print("        FACS(32位)=%#x  Flags=%#010x" % (facs, flags))
            names = _fadt_flags_text(flags)
            print("        Flags 置位: %s" % (", ".join(names) if names else "无"))
            if flags & (1 << 20):
                print("        ⚠ HW_REDUCED_ACPI 置位 —— 这台机器走精简 ACPI，")
                print("          传统 SMI 通道可能根本不注册，H2OUVE 也不会生效。")
        if len(b) >= 0x8C:
            xfacs = struct.unpack_from("<Q", b, 0x84)[0]
            if xfacs:
                print("        X_FACS(64位)=%#x  ← ACPI 2.0+ 机器该看这个" % xfacs)

    # ---- /proc/ioports
    try:
        txt = open("/proc/ioports").read()
    except OSError as e:
        txt = ""
        print("  /proc/ioports 读不了：%s" % e)
    if txt:
        if _ports_are_masked(txt):
            print("  /proc/ioports: **地址被内核清零了**（全是 0000-0000，只剩名字）")
            print("        这是 CONFIG_IO_STRICT_DEVMEM 一类的加固行为。")
            print("        所以「里面没有 00b0」不说明任何问题 —— 它连 dma1、keyboard")
            print("        的地址也都没了。这一项不能作为端口归属的证据。")
            print("        名称里与 SMI/ACPI 相关的行：")
            for ln in txt.splitlines():
                s = ln.strip()
                low = s.lower()
                if any(k in low for k in ("smi", "acpi", "pnp0c02", "pm2")):
                    print("          %s" % s)
        else:
            needles = [0xB0, 0xB2] + ([port] if port else [])
            hits = _parse_ports(txt, sorted(set(needles)))
            if hits:
                for nd, ln in hits:
                    print("  /proc/ioports（含 %#04x）: %s" % (nd, ln))
            else:
                print("  /proc/ioports 里没有任何一段覆盖 0xb0 / 0xb2")
                print("        内核没给这个端口登记 owner，可能它没被 ACPI 声明。")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="lo", type=lambda s: int(s, 0), default=0xE0000)
    ap.add_argument("--to", dest="hi", type=lambda s: int(s, 0), default=0x100000)
    ap.add_argument("--out", default=None, help="dump 目录（默认不落盘）")
    ap.add_argument("--all", action="store_true",
                    help="扫 /proc/iomem 里所有小块保留区（标签可能不在 F 段）")
    ap.add_argument("--peek", action="store_true",
                    help="只嗅探端口与 ACPI 归属，不读内存（不发 SMI）")
    a = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("需要 root：sudo python3 tools/fseg_scan.py")

    if a.peek:
        return peek(a)
    if a.all:
        return scan_all(a.out)

    print("=" * 66)
    print("F 段扫描  %#x .. %#x  （%d KB）" % (a.lo, a.hi, (a.hi - a.lo) // 1024))
    print("=" * 66)

    for ln in ("/sys/kernel/security/lockdown",):
        try:
            print("lockdown:", open(ln).read().strip())
        except OSError:
            pass
    cfg = "/proc/config.gz"
    if os.path.exists(cfg):
        import gzip
        try:
            t = gzip.open(cfg, "rt", errors="replace").read()
            for k in ("CONFIG_STRICT_DEVMEM", "CONFIG_IO_STRICT_DEVMEM"):
                for line in t.splitlines():
                    if line.startswith(k + "="):
                        print("%s: %s" % (line.split("=")[0], line.split("=")[1]))
        except OSError:
            pass

    io = read_iomem()
    print("\n/proc/iomem 相关区段：")
    for s, e, name in iomem_lines(a.lo, a.hi, io):
        print("  %08x-%08x  %s" % (s, e - 1, name))

    print("\n逐页读取（4KB 一页，失败即跳过）：")
    segs = collect(a.lo, a.hi)
    if not segs:
        print("  全部页都读不了 —— /dev/mem 被拦，不是「没有标签」")
        sys.exit(2)
    total = sum(len(b) for _, b in segs)
    print("  可读 %d 段，共 %d 字节（占 %.1f%%）"
          % (len(segs), total, 100.0 * total / (a.hi - a.lo)))
    for s, b in segs:
        nz, ff, zero = stats(b)
        print("    %08x..%08x  %6d B   非零 %-6d 0xFF %-5d 0x00 %-6d"
              % (s, s + len(b) - 1, len(b), nz, ff, zero))
        code, why, st = profile(b)
        if st:
            print("        熵 %.3f bit/byte，%d 个字节值出现，32 位全 0 %d 个 / 全 1 %d 个"
                  % (st["entropy"], st["distinct"],
                     b.count(b"\x00\x00\x00\x00"), b.count(b"\xff\xff\xff\xff")))
        print("        画像：%s" % why)

    print("\n签名搜索（不要求 0x10 对齐）：")
    found_anchor = None
    for sig, desc in SIGS:
        hits = []
        for s, b in segs:
            o = 0
            while True:
                p = b.find(sig, o)
                if p < 0:
                    break
                hits.append(s + p)
                o = p + 1
                if len(hits) > 16:
                    break
        if hits:
            print("  %-8r %-32s %d 处 %s"
                  % (sig, desc, len(hits), " ".join("%#x" % h for h in hits[:8])))
        else:
            print("  %-8r %-32s 无" % (sig, desc))
        if sig == b"$IHISI" and hits:
            found_anchor = hits[0]

    if found_anchor is not None:
        print("\n命中 $IHISI @ %#x：" % found_anchor)
        for s, b in segs:
            if s <= found_anchor < s + len(b):
                o = found_anchor - s
                print(hexdump(b[max(0, o - 32):o + 32], s + max(0, o - 32), 64))
                tag = b[o + 6]
                print("  +6 字节 = %#04x  ← 主功能号%s"
                      % (tag, "" if found_anchor % 0x10 == 0 else "（但未按 0x10 对齐，驱动会漏）"))
    else:
        fill = any(profile(b)[0] == "looks_like_fill" for _, b in segs)
        print("\n$IHISI 在可读区间里完全不存在。")
        if fill:
            print("⚠ 但这段数据是内核填充（高熵、值均匀），不是固件内容。")
            print("  所以「不存在」这个结论不成立，只能说明 /dev/mem 不给真数据。")
            print("  CONFIG_STRICT_DEVMEM=y 时内核只对真 RAM 透传内容。")
            print("  本机固件静态确认主功能号 0x64（p1.fd @ 0x3DBA34），直接指定：")
            print("      ./insyde-nvram probe --via ihisi --func 0x64")
        else:
            print("两种解释：")
            print("  1) 本机固件不把标签放在 F 段 → 驱动会走 0xEF 回退值；")
            print("  2) 标签在别的物理区域（SMRAM / ACPI NVS），用户态根本读不到。")
        # 顺便看看 F 段开头到底长什么样
        for s, b in segs:
            if s <= 0xF0000 < s + len(b):
                print("\n0xF0000 处前 64 字节（判断这段是代码、全 0 还是全 FF）：")
                print(hexdump(b[0xF0000 - s:], 0xF0000, 64))
                break

    if a.out:
        os.makedirs(a.out, exist_ok=True)
        man = []
        for s, b in segs:
            fn = "fseg_%08x_%06x.bin" % (s, len(b))
            with open(os.path.join(a.out, fn), "wb") as f:
                f.write(b)
            man.append({"start": s, "len": len(b), "file": fn})
        with open(os.path.join(a.out, "manifest.json"), "w") as f:
            json.dump(man, f, indent=2)
        print("\n已落盘到 %s（%d 个文件）" % (os.path.abspath(a.out), len(man)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
