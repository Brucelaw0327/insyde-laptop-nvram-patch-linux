#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ihisi_scan.py —— IHISI 寄存器维度扫描

带报文/不带报文的 probe 都静默后，剩下的自由度只有寄存器初值：
ECX（驱动参数块 +0x08，H2OUVE 用户态填，语义疑似协议版本号）。

本脚本对每个候选 ECX 发一条 IsSupportIhisi（无副作用），
找 handler 有反应（EAX 不再等于回显值）的组合。

用法（root）：
    sudo python3 tools/ihisi_scan.py              # ECX 0..255
    sudo python3 tools/ihisi_scan.py --ecx-max 1024
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import ihisi  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ecx-max", type=lambda s: int(s, 0), default=0x100)
    ap.add_argument("--func", type=lambda s: int(s, 0), default=None,
                    help="主功能号（默认两个都试：0x64 与 0xEF）")
    a = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("需要 root")

    info = {"port": 0xB0, "main_func": 0}          # 手动构造，绕过扫描
    funcs = [a.func] if a.func is not None else [0x64, 0xEF]

    print("IHISI ECX 扫描（IsSupportIhisi，无副作用）")
    print("命中判据：EAX ≠ (0x10<<8)|main 的回显值（即 handler 改了寄存器）\n")

    hits = []
    for mf in funcs:
        info["main_func"] = mf
        sent = (0x10 << 8) | (mf & 0xFF)
        for ecx in range(a.ecx_max):
            try:
                status, res, filled = ihisi.ping(info, ecx=ecx, main_func=mf)
            except ihisi.IhisiError as e:
                print("  ECX=%#04x 出错: %s" % (ecx, e))
                return 1
            eax = res.get("eax", 0)
            if eax != sent:
                print("  ★ 主号 %#02x ECX=%#04x → EAX=%#010x "
                      "(sent=%#010x) EBX=%#010x"
                      % (mf, ecx, eax, sent, res.get("ebx", 0)))
                hits.append((mf, ecx, eax, res))
        if not any(h[0] == mf for h in hits):
            print("  主号 %#02x：ECX 0..%#x 全部无响应"
                  % (mf, a.ecx_max - 1))

    print()
    if hits:
        print("命中 %d 组。下一步：用命中的 ECX 跑带报文的 probe ——\n"
              "  sudo ./insyde-nvram probe --record Setup --via ihisi "
              "--func 0x%02X --yes" % (len(hits), hits[0][0]))
    else:
        print("ECX 维度无解。剩余自由度：AH 子功能表、EDX 高位、"
              "或需要驱动的初始化序列。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
