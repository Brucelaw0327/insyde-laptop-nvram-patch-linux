#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ihisi_convention_probe.py —— IHISI SMI 约定矩阵探测（决定性实验）

背景（2026-10-30 Ghidra 逆向结论）：
  - 槽位路径死路：所有报文指针必须落在 SMRAM 内 192KB 池（FUN_0058f240），
    OS 指针永远 0x802B。剩余唯一可行路径 = 寄存器直传报文（ESI/EDI）。
  - 「主功能号 0x64」的出处（p1.fd @0x3DBA34 '$IHISI' +6）存疑：
    那个字节很可能是字符串 "$IHISId" 的 'd'（ASCII 0x64）。
  - DXE 侧探测代码实证的调用约定：EBX="O2H$"，EAX 低字节 = APM 命令
    （out 到 0xB0 的就是 AL），AH = 子功能：
        FUN_003d999c: EAX=0x83EF, EBX 未参与
        FUN_003da2b8: EAX=0x10EF, 报文指针在第三个字段
  - H2OUVE 驱动 0x3E78: AL=主功能号、AH=子功能、EBX="O2H$"、out dx,al

本脚本按危险度递增做五组实验，每组判定 SMM 是否真的处理了
（寄存器回显改变 / AL 变成错误码 / 报文被改写）：

  A. EAX=0x10EF  EBX="O2H$"              （固件自己的 IsSupport 探测，最安全）
  B. EAX=0x83EF  EBX="O2H$"              （固件自己的第二个探测）
  C. EAX=0x1064  EBX="O2H$"              （旧假设：主 0x64 + IsSupport）
  D. EAX=0x0100|0x64 + 写变量报文 v2       （旧假设：主 0x64 子 0x01 写变量）
  E. EAX=0x0100|0xEF + 写变量报文 v2       （新假设：主 0xEF 子 0x01 写变量）

写变量用的是无害测试变量（自定义 GUID，4 字节数据），成功后可用
efivarfs 验证。不做任何盲扫。

用法（需要 root + ihisi_diag 模块）：
  sudo python3 tools/ihisi_convention_probe.py
"""
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import ihisi  # noqa: E402

TEST_GUID = "3B1D5A0E-8C2F-4E47-9D6A-7F1E2B3C4D5E"   # 自定义测试 GUID
TEST_NAME = "IhisiConvProbe"
TEST_DATA = bytes([0x49, 0x48, 0x49, 0x53])            # "IHIS"
TEST_ATTR = 0x07                                       # NV|BS|RT


def show(tag, before, after, pkt_before=None, pkt_after=None):
    changed = []
    for k in ("eax", "ebx", "ecx", "edx", "esi", "edi"):
        b = before.get(k, 0)
        a = after.get(k, 0)
        if b != a:
            changed.append("%s %08X→%08X" % (k, b, a))
    al_in = before.get("eax", 0) & 0xFF
    al_out = after.get("eax", 0xFFFFFFFF) & 0xFF
    print("  寄存器: %s" % " ".join("%s=%08X" % (k, after.get(k, 0))
                                    for k in ("eax", "ebx", "ecx", "edx", "esi", "edi")))
    if pkt_after is not None and pkt_before is not None and pkt_after != pkt_before:
        diff = [i for i in range(min(len(pkt_before), len(pkt_after)))
                if pkt_before[i] != pkt_after[i]]
        print("  报文被 SMM 改写！差异偏移: %s"
              % " ".join("%02X(%02X→%02X)" % (i, pkt_before[i], pkt_after[i])
                         for i in diff[:16]))
    if not changed:
        print("  判定: 寄存器原样回显 → SMM 没有处理这条 SMI（或静默忽略）")
    elif al_out != al_in:
        print("  判定: AL %02X→%02X —— SMM 处理了！AL=返回状态 %s"
              % (al_in, al_out, "（0=成功）" if al_out == 0 else "（错误码）"))
    else:
        print("  判定: 寄存器有变化（%s）" % ", ".join(changed))


def main():
    port, src = ihisi.find_smi_port()
    if port is None:
        port = 0xB0
        src = "默认（AMD FCH APM）"
    print("SMI 端口 0x%02X（%s）" % (port, src))

    page = ihisi.alloc_low_page(0x200)
    pkt = ihisi.build_packet(TEST_GUID, TEST_NAME, TEST_DATA, TEST_ATTR)
    page.load(pkt)
    esi = page.paddr
    edi = page.paddr + 0x20 + 0x1A          # "$H2O" 处（0x20 + 14*2）
    print("报文 %d 字节 @ 物理 0x%08X，EDI=0x%08X\n" % (len(pkt), esi, edi))

    H2O = 0x2448324F                          # "O2H$"

    def run(tag, eax, ebx, ecxv, esiv, ediv):
        print("[%s] EAX=%08X EBX=%08X ECX=%08X ESI=%08X EDI=%08X"
              % (tag, eax, ebx, ecxv, esiv, ediv))
        before = {"eax": eax, "ebx": ebx, "ecx": ecxv,
                  "edx": port, "esi": esiv, "edi": ediv}
        try:
            after = ihisi.smi_generic(eax, ebx, ecxv, port, esiv, ediv, port)
        except ihisi.IhisiError as e:
            print("  错误: %s" % e)
            return
        show(tag, before, after)
        print()

    # ---- A/B：固件自己用过的探测（无报文，最安全） ----
    run("A 0x10EF 探测", 0x10EF, H2O, 0, 0, 0)
    run("B 0x83EF 探测", 0x83EF, H2O, 0, 0, 0)
    # ---- C：旧假设主 0x64 的 IsSupport ----
    run("C 0x1064 探测", 0x1064, H2O, 0, 0, 0)

    # ---- D/E：写变量（无害测试变量） ----
    pkt_before = page.read_back(len(pkt))
    run("E 写变量 主0xEF", 0x01EF, H2O, 0, esi, edi)
    pkt_e = page.read_back(len(pkt))
    if pkt_e != pkt_before:
        page.load(pkt)
    run("D 写变量 主0x64", 0x0164, H2O, 0, esi, edi)
    pkt_d = page.read_back(len(pkt))

    page.close()

    print("==== 汇总 ====")
    # efivarfs 验证
    found = False
    base = "/sys/firmware/efi/efivars/"
    try:
        for fn in os.listdir(base):
            if fn.startswith(TEST_NAME + "-"):
                found = True
                print("★ 变量已写入: %s%s" % (base, fn))
    except OSError:
        pass
    if not found:
        print("（efivarfs 里没有测试变量 —— D/E 至少有一个没成功，"
              "或成功的是别的约定）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
