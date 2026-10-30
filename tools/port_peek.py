#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""port_peek.py —— 只读探测 IO 端口，判断 SMI 端口到底存不存在。

不写任何端口字节，因此不会触发 SMI。

思路：x86 上不存在的 IO 端口读回来是 0xFF；存在的端口返回各路设备
自己的值。对目标范围逐字节读 N 次，看：
  - 全是 0xFF    → 这个端口在芯片组里没被解码，写进去也不会进 SMM
  - 稳定非 0xFF  → 端口存在（至少被解码了）
  - 值在变       → 有东西在驱动它

实际探测由 tools/port_peek.c 编出的二进制完成（glibc 不导出 inb
符号，<sys/io.h> 里是内联宏，ctypes 拿不到）。本脚本负责调用、
解析、给结论。

用法（需要 root）：
    sudo python3 tools/port_peek.py
    sudo python3 tools/port_peek.py --range 0xb0:0xb8 --times 8
"""
import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
HELPER = os.path.join(HERE, "port_peek")
SRC = HELPER + ".c"


def ensure_helper():
    """确保 C 探测器已编译；没有就现场编。"""
    if os.path.isfile(HELPER) and os.access(HELPER, os.X_OK):
        return True
    if not os.path.isfile(SRC):
        print("既没有编译好的 %s，也没有源码 %s" % (HELPER, SRC), file=sys.stderr)
        return False
    try:
        r = subprocess.run(["gcc", "-Wall", "-O2", "-o", HELPER, SRC],
                           capture_output=True, text=True)
    except FileNotFoundError:
        print("没有 gcc，无法现场编译 %s" % SRC, file=sys.stderr)
        return False
    if r.returncode != 0:
        print(r.stderr, file=sys.stderr)
        return False
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--range", default="0xa0:0xc0",
                    help="探测范围 lo:hi（十六进制），默认 0xa0:0xc0")
    ap.add_argument("--times", type=int, default=4, help="每个端口读几次")
    a = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("需要 root：sudo python3 tools/port_peek.py")
    if not ensure_helper():
        sys.exit(1)

    lo, hi = a.range.split(":")
    lo, hi = int(lo, 16), int(hi, 16)
    if hi <= lo or hi - lo > 256:
        sys.exit("范围不对：hi>lo 且跨度 <=256")

    r = subprocess.run([HELPER, str(lo), str(hi), str(a.times)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(r.stderr)
        sys.exit(r.returncode)

    rows = []
    for ln in r.stdout.splitlines():
        if ln.startswith("#") or not ln.strip():
            continue
        parts = ln.split()
        # 格式: PORT v1..vN VERDICT last（N 可变）
        port = int(parts[0], 16)
        vals = parts[1:-2]
        verdict = parts[-2]
        rows.append((port, vals, verdict))

    print("IO 端口只读探测  %#04x..%#04x（in 指令 ×%d，不写端口、不发 SMI）"
          % (lo, hi - 1, a.times))
    print()
    print("  端口    读数（%d 次）                判定" % a.times)
    print("  " + "-" * 68)
    for p, vals, verdict in rows:
        seq = " ".join(vals)
        if verdict == "FF":
            txt = "全 0xFF —— 端口未解码？"
        elif verdict == "STABLE":
            txt = "稳定值 —— 已解码"
        else:
            ff = sum(1 for v in vals if v == "ff")
            if ff == len(vals) - 1 and len(set(vals)) == 2:
                txt = "近似浮空（仅 1 次非 FF）"
            elif ff >= len(vals) / 2:
                txt = "大部分 FF —— 疑似浮空"
            else:
                txt = "值在变 —— 有东西在驱动"
        print("  %#06x  %-40s  %s" % (p, seq, txt))

    print()
    alive = [p for p, vals, v in rows if v != "FF"]
    print("非全 FF 的端口：%s" % (" ".join("%#04x" % p for p in alive) or "无"))
    for want in (0xB0, 0xB1):
        row = next(((p, vals, v) for p, vals, v in rows if p == want), None)
        if row is None:
            print("(范围里没有 %#04x)" % want)
            continue
        p, vals, v = row
        if v == "FF":
            print()
            print("!! %#04x 读回全 0xFF —— 很可能没被芯片组解码。out 到它石沉大海。" % p)
            print("   保留：个别芯片组 SMI_CMD 是只写端口，读回 FF 不 100% 等于未解码。")
        else:
            print()
            print("☆ %#04x 读到 %s（verdict=%s）—— 端口已解码且有内容。" % (p, " ".join(vals), v))
    return 0


if __name__ == "__main__":
    sys.exit(main())
