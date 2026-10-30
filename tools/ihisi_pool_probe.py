#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ihisi_pool_probe.py —— 池基址探测 + 写变量（决定性一步）

前置事实（2026-10-30 convention probe 实测）：
  - 0x83EF 探测成功：ECX=0xCCDF4018（疑似 SMRAM 内 192KB 池物理基址）、EDX=0x30000（池大小）
  - 0x01EF 写变量：0x812B = 池范围校验失败（ESI/EDI 指向池外）
  → 只要 ESI/EDI 指进 [ECX, ECX+0x30000)，校验就过

本脚本五步，全部只动池内 0x100 起的 256 字节测试区（避开池头）：
  1. 重新调 0x83EF 拿最新池基址
  2. ESI/EDI 指进池（内容是池内已有数据）→ 看错误码是否从 0x812B 变成
     「校验和/魔数」类错误（证明范围校验过了）
  3. 试读池物理内存（/dev/mem，可能被 STRICT_DEVMEM 拒）
  4. 试写 16 字节 0xA5 到池 +0x100 再读回（OS 能否直写 SMRAM 池）
  5. 若可写：把 v2 报文写进池 +0x100，ESI/EDI 指向它，调 0x01EF，
     查 AL + 报文回读 + efivarfs 验证

用法：sudo python3 tools/ihisi_pool_probe.py
"""
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import ihisi  # noqa: E402

TEST_GUID = "3B1D5A0E-8C2F-4E47-9D6A-7F1E2B3C4D5E"
TEST_NAME = "IhisiPoolProbe"
TEST_DATA = bytes([0x50, 0x4F, 0x4F, 0x4C])            # "POOL"
TEST_ATTR = 0x07

H2O = 0x2448324F


def call(eax, esi=0, edi=0, ecx=0):
    return ihisi.smi_generic(eax, H2O, ecx, 0xB0, esi, edi, 0xB0)


def main():
    # ---- 1. 拿池基址 ----
    r = call(0x83EF)
    print("[1] 0x83EF: eax=%08X ecx=%08X edx=%08X" %
          (r.get("eax", 0), r.get("ecx", 0), r.get("edx", 0)))
    if (r.get("eax", 0xFFFFFFFF) & 0xFF) != 0:
        print("    0x83EF 没成功，中止")
        return 1
    pool = r.get("ecx", 0)
    size = r.get("edx", 0)
    print("    池基址 0x%08X，大小 0x%X\n" % (pool, size))
    if not (0 < pool < (1 << 32)) or size < 0x200:
        print("    池参数异常，中止")
        return 1

    # ---- 2. 指进池，看范围校验是否放行 ----
    r = call(0x01EF, esi=pool, edi=pool + 0x3A)
    print("[2] ESI/EDI 指进池: eax=%08X" % r.get("eax", 0))
    code = r.get("eax", 0xFFFFFFFF) & 0xFFFF
    if code == 0x812B or code == 0x802B:
        print("    仍是 0x...2B —— ECX 不是池基址（或池校验用别的基址）\n")
    else:
        print("    错误码变了（%04X）→ 范围校验通过！ECX 就是池基址\n" % code)

    # ---- 3. 试读池 ----
    print("[3] 试读池物理内存（/dev/mem）")
    m = None
    try:
        import mmap
        fd = os.open("/dev/mem", os.O_RDONLY | os.O_SYNC)
        m = mmap.mmap(fd, 0x1000, mmap.MAP_SHARED, mmap.PROT_READ, offset=pool)
        head = bytes(m[0:64])
        print("    池头 64 字节: %s" % head.hex(" "))
        m.close()
        os.close(fd)
    except (OSError, ValueError) as e:
        print("    读不了（预期内，STRICT_DEVMEM 挡 RAM）: %s" % e)
        try:
            if m:
                m.close()
        except Exception:
            pass

    # ---- 4. 试写池 +0x100 ----
    print("\n[4] 试写池 +0x100（16 字节 0xA5，随后恢复原值）")
    wr_ok = False
    saved = None
    try:
        import mmap
        fd = os.open("/dev/mem", os.O_RDWR | os.O_SYNC)
        m = mmap.mmap(fd, 0x1000, mmap.MAP_SHARED, mmap.PROT_WRITE, offset=pool)
        saved = bytes(m[0x100:0x110])
        m[0x100:0x110] = b"\xa5" * 16
        back = bytes(m[0x100:0x110])
        m[0x100:0x110] = saved
        m.close()
        os.close(fd)
        wr_ok = (back == b"\xa5" * 16)
        print("    读回 %s → OS %s池"
              % (back[:8].hex(" "), "可写" if wr_ok else "不可直接写（或映射是替身）"))
    except (OSError, ValueError) as e:
        print("    写不了: %s" % e)
        try:
            if m:
                m.close()
        except Exception:
            pass

    # ---- 5. 报文进池 + 写变量 ----
    print("\n[5] 报文写入池 +0x100 并调 0x01EF")
    pkt = ihisi.build_packet(TEST_GUID, TEST_NAME, TEST_DATA, TEST_ATTR)
    off = 0x100
    # 即使 OS 侧读回不对，也可能只是写路径被替身；仍然试一发
    try:
        import mmap
        fd = os.open("/dev/mem", os.O_RDWR | os.O_SYNC)
        m = mmap.mmap(fd, 0x1000, mmap.MAP_SHARED, mmap.PROT_WRITE, offset=pool)
        m[off:off + len(pkt)] = pkt
        m.close()
        os.close(fd)
        print("    报文 %d 字节已写入池 +0x%X（OS 视角）" % (len(pkt), off))
    except (OSError, ValueError) as e:
        print("    写报文失败: %s —— 仍会发起 SMI（池内可能是旧数据）" % e)

    base = pool + off
    r = call(0x01EF, esi=base, edi=base + 0x3A)
    print("    0x01EF: eax=%08X esi=%08X edi=%08X" %
          (r.get("eax", 0), r.get("esi", 0), r.get("edi", 0)))
    al = r.get("eax", 0xFFFFFFFF) & 0xFF
    if al == 0:
        print("    ★★★ AL=0 —— 写变量成功！★★★")
    elif (r.get("eax", 0xFFFFFFFF) & 0xFFFF) in (0x812B, 0x802B):
        print("    仍是范围校验失败 —— 池基址假设不对")
    else:
        print("    新错误码 %04X —— 范围校验过了，卡在报文内容"
              "（OS 写的是替身，SMM 读到的是池内旧数据）" %
              (r.get("eax", 0xFFFFFFFF) & 0xFFFF))

    # efivarfs 验证
    try:
        for fn in os.listdir("/sys/firmware/efi/efivars/"):
            if fn.startswith(TEST_NAME + "-"):
                print("    ★ 变量已出现: %s%s"
                      % ("/sys/firmware/efi/efivars/", fn))
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
