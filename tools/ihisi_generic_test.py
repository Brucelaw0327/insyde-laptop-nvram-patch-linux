#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ihisi_generic_test.py —— SMI_GENERIC 槽位注册受控验证

逆向结论（p1.fd）：
  SMM 有一个"槽位寄存器阵列"（0x58F16C 读 / 0x58F1A8 写，签名 {槽号, 值}）：
    槽 0x27 = 通道标记（应为 "O2H$"）
    槽 0x28 = 报文缓冲物理基址（0x58F240 合法范围下界）
    槽 0x29 = 报文缓冲大小
    槽 0x2D = 校验器 0x58A9A4 用的缓冲指针
  OS 侧经 SMI_GENERIC（驱动 0x3EBA，六寄存器透传）操作槽位：
    SMM 0x58BA90 按 AL=EAX&0xFF 分派：2=写槽 3=读槽 4=? 0xEF=探测
    寄存器透传 → 槽写服务签名 {ecx=槽号, edx=值}

本脚本按以下顺序执行（每步打印观察点）：
  step1  GENERIC al=2 写槽 0x27 = "O2H$"
  step2  IHISI ping（对比静默基线）
  step3  GENERIC al=2 写槽 0x28 = 缓冲基址、槽 0x29 = 大小
  step4  GENERIC al=2 写槽 0x2D = 缓冲基址
  step5  IHISI WriteVariable 原样写回 probe（v1 布局）
每步只做一次，无循环、无盲扫。

用法（root，先 insmod kernel/ihisi_diag.ko）：
    sudo python3 tools/ihisi_generic_test.py
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import ihisi  # noqa: E402

GUID, NAME = "A04A27F4-DF00-4D42-B552-39511302113D", "Setup"


def read_setup():
    raw = open("/sys/firmware/efi/efivars/%s-%s" % (NAME, GUID), "rb").read()
    return int.from_bytes(raw[:4], "little"), raw[4:]


def build_v1(guid, name, data, attrs):
    nw = name.encode("utf-16-le") + b"\x00\x00"
    n = len(nw)
    buf = bytearray(0x30 + n + len(data))
    buf[0:16] = ihisi.guid_bytes_le(guid)
    buf[0x10:0x10 + n] = nw
    for i, m in enumerate((b"$H2O", b"$Var", b"$Tbl")):
        buf[0x10 + n + i * 4: 0x14 + n + i * 4] = m
    struct.pack_into("<I", buf, 0x20 + n, len(data))
    struct.pack_into("<I", buf, 0x24 + n, attrs)
    buf[0x2D + n] = 0x10
    struct.pack_into("<H", buf, 0x2E + n, ihisi.packet_checksum(data))
    buf[0x30 + n:] = data
    return bytes(buf), 0x10 + n


def main():
    if os.geteuid() != 0:
        sys.exit("需要 root；并先 sudo insmod kernel/ihisi_diag.ko")
    if not os.path.exists("/dev/ihisi_buf"):
        sys.exit("/dev/ihisi_buf 不存在 —— 先 sudo insmod kernel/ihisi_diag.ko")

    attrs, data = read_setup()
    pkt, magic_off = build_v1(GUID, NAME, data, attrs)
    page = ihisi.alloc_low_page(len(pkt))
    page.load(pkt)
    buf_paddr = page.paddr
    print("报文 %d 字节已载入物理页 0x%X（v1 布局，魔数 @+0x%X）\n"
          % (len(pkt), buf_paddr, magic_off))

    port = 0xB0
    W_SLOT = 4          # SMM 0x58BA90: al=4 → jmp [协议+0x78]（槽写服务
                        #   0x58F1A8，签名 {ecx=槽号, edx=值}，寄存器透传）。
                        #   注意 al=2 走 jbe→成功返回（无操作）！
    SLOT_MARK = 0x27    # 通道标记
    SLOT_BASE = 0x28    # 缓冲基址
    SLOT_SIZE = 0x29    # 缓冲大小
    SLOT_PTR = 0x2D     # 校验器用的缓冲指针

    # ---- step1: 写槽 0x27 = "O2H$"（开通道标记）
    R_SLOT = 3          # al=3 → [协议+0x80] 槽读服务（{ecx=槽号} → 返回值）

    def write_slot(slot, value):
        return ihisi.smi_generic(eax=W_SLOT, ebx=0, ecx=slot,
                                 edx=value, esi=0, edi=0, port=port)

    def read_slot(slot):
        return ihisi.smi_generic(eax=R_SLOT, ebx=0, ecx=slot,
                                 edx=0, esi=0, edi=0, port=port)

    def report(tag, r):
        print("  %s 回写: %s" % (tag, {k: hex(v) for k, v in sorted(r.items())}))

    def verify_slot(slot, expect, tag):
        rr = read_slot(slot)
        got = rr.get("eax", 0) & 0xFFFFFFFF
        ok = (got == (expect & 0xFFFFFFFF))
        print("  %s 读槽 %#02x → %#010x %s"
              % (tag, slot, got, "✓ 写入生效" if ok else "✗ 未生效/语义不同"))
        return ok

    # ---- step1: 写槽 0x27 = "O2H$"（开通道标记）
    print("step1  GENERIC 写槽 0x27 ← O2H$")
    r = write_slot(SLOT_MARK, 0x2448324F)
    report("写", r)
    verify_slot(SLOT_MARK, 0x2448324F, "step1")

    # ---- step2: IHISI ping 对比
    print("\nstep2  IHISI ping（子功能 0x10 / 主号 0xEF）")
    for mf in (0xEF, 0x64):
        try:
            st, res, filled = ihisi.ping(main_func=mf)
            print("  主号 %#02x: EAX=%#010x filled=%s"
                  % (mf, res.get("eax", 0), filled))
        except ihisi.IhisiError as e:
            print("  主号 %#02x: %s" % (mf, e))

    # ---- step3: 写槽 0x28/0x29 = 缓冲基址/大小
    print("\nstep3  GENERIC 写槽 0x28 ← 基址、槽 0x29 ← 大小")
    r = write_slot(SLOT_BASE, buf_paddr)
    report("槽0x28 写", r)
    verify_slot(SLOT_BASE, buf_paddr, "step3")
    r = write_slot(SLOT_SIZE, len(pkt))
    report("槽0x29 写", r)
    verify_slot(SLOT_SIZE, len(pkt), "step3")

    # ---- step4: 写槽 0x2D = 校验器缓冲指针
    print("\nstep4  GENERIC 写槽 0x2D ← 缓冲基址")
    r = write_slot(SLOT_PTR, buf_paddr)
    report("槽0x2D 写", r)
    verify_slot(SLOT_PTR, buf_paddr, "step4")

    # ---- step5: 原样写回 probe
    print("\nstep5  IHISI WriteVariable probe（原样写回，无副作用）")
    page.load(pkt)
    esi = buf_paddr
    edi = buf_paddr + magic_off
    res = ihisi.smi_call(0xEF, 0x01, port, esi=esi, edi=edi, ecx=0x01)
    eax = res.get("eax", 0)
    rb = page.read_back(len(pkt))
    diffs = [(i, pkt[i], rb[i]) for i in range(len(pkt)) if pkt[i] != rb[i]]
    print("  回写:", {k: hex(v) for k, v in sorted(res.items())})
    print("  sent EAX = 0x%08X（对照）" % ((0x01 << 8) | 0xEF))
    if diffs:
        print("  ★ SMM 改写报文缓冲 %d 处（前 16）：" % len(diffs))
        for i, a, b in diffs[:16]:
            print("    +%#05x: %02x -> %02x" % (i, a, b))
    else:
        print("  报文缓冲无改动")
    if (eax & 0xFF) == 0:
        print("\n★★ AL==0：WriteVariable 成功判据命中！通道完全打通。")
        print("   下一步：sudo ./insyde-nvram apply "
              "patches/ftpm-enable-RMGCZ6T0P0909.patch --via ihisi --func 0xEF")
    elif diffs:
        print("\n★ handler 有响应且改了缓冲——按 diff 内容继续分析。")
    else:
        print("\n仍未打通。把本输出完整贴回来。")

    # 收尾：清标记槽（保守起见，避免半开状态）
    write_slot(SLOT_MARK, 0)
    page.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
