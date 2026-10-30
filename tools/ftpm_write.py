#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ftpm_write.py —— 通过 IHISI VatsWrite 打开 fTPM（最终攻击脚本）

逆向依据（p1.fd，全部已在 Ghidra/capstone 闭环）：

  IHISI 主功能 0xEF（SMI 端口 = FACP.SMI_CMD = 0xB0），EBX="O2H$"，
  AH=子功能号。分派器 FUN_0058f3dc 经 EFI_MM_CPU_PROTOCOL 读 OS 寄存器：
    RAX(0x26)=子功能  RBX(0x27)="O2H$"  RSI(0x2C)=报文基址  RDI(0x2D)=$H2O 区

  VatsWrite 真身 0x58ABA0（S01）校验链：
    1) 报文头校验器 0x58A9A4：RDI 落池(0x20B)、[RDI+0x1D]==0x10、
       $H2O/$Var/$Tbl 魔数
    2) RSI 落池(0x10)、RDI 落池(0x20)、数据区 [RDI+0x20,+DataSize) 落池
       —— 池 = [DAT_00596E6C, +0x30000)，失败统一 0x802B（用户态看到 0x812B
          = 0x8000|(sub<<8)|0x2B，由分派器包装）
    3) 布局：RSI+0x12+2*len(name) <= RDI（名与数据区不重叠）
    4) 校验和：(数据全体字节和 + [RDI+0x1E](低字节)) & 0xFF == 0，否则 0x8012
    5) 属性 [RDI+0x14] 为 0 时自动按 7 (NV|BS|RT) 处理
    6) SetVariable(name, &GUID@RSI, attr, size, data@RDI+0x20)，失败 0x8014

  GetCmdBuf 真身 0x58EA0C（S83）：WriteSaveState(RCX, DAT_00596E6C)、
  WriteSaveState(RDX, DAT_00596E7C) —— RCX 就是池基址、RDX 是池大小。
  实测 RCX=0xCCDF4018、RDX=0x30000。

  ⇒ 报文必须写进池。内核模块 ihisi_diag 的 /dev/ihisi_buf 新增
     IHISI_PHYS_READ/WRITE ioctl（memremap）代写物理内存。

流程：
  step0  efivarfs 读当前 Setup 变量 → 备份 + 打补丁（偏移 0x100: 0x00→0x02）
  step1  ping（IsSupportIhisi）确认通道
  step2  S83 GetCmdBuf → 池基址/大小
  step3  S00 VatsRead "Setup"（无副作用）→ 整链路 proof of concept
  step4  S01 VatsWrite 写入补丁后的 Setup → 打开 fTPM
  step5  回读池内报文，输出 SMM 修改痕迹

用法：sudo python3 ftpm_write.py [--off] [--apply] [--verify]
  默认 dry-run（只跑 step0-3，不写）。加 --apply 才执行 step4 写入；
  --off 把 fTPM 位写回 0x00（关闭），--verify 单独回读确认。
"""

import os
import sys
import struct
import fcntl
import ctypes

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import ihisi  # noqa: E402

SETUP_GUID = "A04A27F4-DF00-4D42-B552-39511302113D"
SETUP_NAME = "Setup"
FTPM_OFF = 0x100          # Setup 变量数据内偏移（不含 efivarfs 4 字节属性头）
FTPM_VALUE = 0x02         # fTPM: 0x00=关闭, 0x02=开启

EFIVAR_DIR = "/sys/firmware/efi/efivars"
BUF_DEV = "/dev/ihisi_buf"

# 与内核模块一致的 ioctl
_IOWR = lambda t, n, s: (ctypes.sizeof(s) << 16) | (ord(t) << 8) | n \
        | 0xC0000000  # 简化：方向读写都算 _IOWR(3)


class PhysIO(ctypes.Structure):
    _fields_ = [("paddr", ctypes.c_uint64),
                ("len", ctypes.c_uint64),
                ("ubuf", ctypes.c_uint64)]


IHISI_PHYS_READ = _IOWR("H", 1, PhysIO)
IHISI_PHYS_WRITE = _IOWR("H", 2, PhysIO)


def phys_read(fd, paddr, ln):
    b = ctypes.create_string_buffer(ln)
    io = PhysIO(paddr, ln, ctypes.addressof(b))
    fcntl.ioctl(fd, IHISI_PHYS_READ, io)
    return b.raw


def phys_write(fd, paddr, data):
    assert len(data) <= 0x1000
    assert (paddr & 0xFFF) + len(data) <= 0x1000, "ioctl 不跨页，需按页拆"
    b = ctypes.create_string_buffer(data, len(data))
    io = PhysIO(paddr, len(data), ctypes.addressof(b))
    fcntl.ioctl(fd, IHISI_PHYS_WRITE, io)


def read_setup_efivar():
    """efivarfs 读 Setup，返回 (attrs, data)。"""
    p = os.path.join(EFIVAR_DIR, "Setup-%s" % SETUP_GUID)
    with open(p, "rb") as f:
        raw = f.read()
    attrs = struct.unpack_from("<I", raw, 0)[0]
    return attrs, raw[4:]


def write_setup_efivar(attrs, data):
    p = os.path.join(EFIVAR_DIR, "Setup-%s" % SETUP_GUID)
    with open(p, "wb") as f:
        f.write(struct.pack("<I", attrs) + data)


def page_split(buf, base):
    """把 buf 切成不跨页的 (paddr, bytes) 片段。"""
    out = []
    off = 0
    while off < len(buf):
        room = 0x1000 - ((base + off) & 0xFFF)
        chunk = buf[off:off + room]
        out.append((base + off, chunk))
        off += len(chunk)
    return out


def stage_packet(fd, pkt, pool, off=0x40):
    """报文写进 SMM 池，返回 (pkt_pa, esi, edi)。"""
    pkt_pa = pool + off
    for pa, chunk in page_split(pkt, pkt_pa):
        phys_write(fd, pa, chunk)
    rn = (len(SETUP_NAME) + 1) * 2
    return pkt_pa, pkt_pa, pkt_pa + 0x20 + rn


def main(argv):
    apply_mode = "--apply" in argv
    verify_mode = "--verify" in argv
    # 目标值：默认开(0x02)；--off 写回 0x00 关闭
    global FTPM_VALUE
    if "--off" in argv:
        FTPM_VALUE = 0x00

    if verify_mode:
        # 通过 SMM VatsRead 回读 Setup，检查 fTPM 字节
        attrs, cur = read_setup_efivar()
        print("[*] efivarfs 当前 Setup+%#x = 0x%02X（期望 0x%02X）" %
              (FTPM_OFF, cur[FTPM_OFF], FTPM_VALUE))
        info = None
        try:
            info = ihisi.discover(verbose=False)
        except Exception:
            pass
        port = info["port"] if info else 0xB0
        mf = info["main_func"] if info else 0xEF
        res = ihisi.smi_call(mf, 0x83, port)
        pool = res.get("ecx", 0)
        fd = os.open(BUF_DEV, os.O_RDWR)
        RN = (len(SETUP_NAME) + 1) * 2
        pkt = ihisi.build_packet(SETUP_GUID, SETUP_NAME,
                                 b"\x00" * 0x400, attrs)
        pkt_pa, esi, edi = stage_packet(fd, pkt, pool)
        res = ihisi.smi_call(mf, 0x00, port, esi=esi, edi=edi)
        eax = res.get("eax", 0xFFFFFFFF)
        dsz = struct.unpack_from("<I", phys_read(fd, pkt_pa, 0x40 + RN),
                                 0x30 + RN)[0]
        data = phys_read(fd, edi + 0x20, min(dsz, 0x400)) if dsz else b""
        os.close(fd)
        print("[*] SMM VatsRead: EAX=%08X size=%d" % (eax, dsz))
        if data:
            print("[*] SMM 视角 Setup+%#x = 0x%02X（本机 efivarfs = 0x%02X，目标 = 0x%02X）"
                  % (FTPM_OFF, data[FTPM_OFF], cur[FTPM_OFF], FTPM_VALUE))
            ok = data[FTPM_OFF] == FTPM_VALUE
            if ok:
                print("[✓] Setup+0x100 已是目标值 0x%02X（%s）" %
                      (FTPM_VALUE, "fTPM 开启" if FTPM_VALUE == 0x02 else "fTPM 关闭"))
            else:
                print("[!] Setup+0x100 与目标不符：期望 0x%02X，实际 0x%02X"
                      % (FTPM_VALUE, data[FTPM_OFF]))
            return 0 if ok else 1
        return 1

    try:
        info = ihisi.discover(verbose=False)
        port, mf = info["port"], info["main_func"]
    except Exception as e:
        # discover 依赖 F 段扫描，本机被 STRICT_DEVMEM 内核填充挡死。
        # 静态逆向已确认：主功能号 0xEF（p1.fd 0x58Fxxx 分派器），
        # SMI 端口 0xB0（FACP.SMI_CMD 实测，AMD FCH 的 APM）。
        print("[!] discover 失败（%s），使用静态确认值: port=0xB0 main=0xEF" % e)
        port, mf = 0xB0, 0xEF
    print("[*] SMI 端口=0x%02X 主功能号=0x%02X" % (port, mf))

    # step1 ping
    status, res, filled = ihisi.ping({"port": port, "main_func": mf})
    print("[*] ping: eax=%08X status=%02X filled=%s" %
          (res.get("eax", 0), status, filled))

    # step2 GetCmdBuf
    res = ihisi.smi_call(mf, 0x83, port)
    pool = res.get("ecx", 0)
    psize = res.get("edx", 0)
    print("[*] GetCmdBuf: ECX=池基址=0x%08X EDX=池大小=0x%X" % (pool, psize))
    if not (0x100000 <= pool < 0xFFFFFFFF and psize == 0x30000):
        print("[!] 池基址/大小异常，谨慎继续")

    fd = os.open(BUF_DEV, os.O_RDWR)

    # step3 VatsRead "Setup" —— 无副作用，验证整条链路
    attrs, cur = read_setup_efivar()
    print("[*] 当前 Setup: attrs=0x%X size=%d" % (attrs, len(cur)))
    with open("setup_backup_%08X.bin" % (pool & 0xFFFFFFFF), "wb") as f:
        f.write(cur)
    print("[*] 已备份当前 Setup 数据到 setup_backup_*.bin")

    RN = (len(SETUP_NAME) + 1) * 2          # 名字字节数（含 NUL）
    read_data_len = 0x400
    pkt_r = ihisi.build_packet(SETUP_GUID, SETUP_NAME,
                               b"\x00" * read_data_len, attrs)
    pkt_pa, esi, edi = stage_packet(fd, pkt_r, pool)
    res = ihisi.smi_call(mf, 0x00, port, esi=esi, edi=edi)
    eax = res.get("eax", 0xFFFFFFFF)
    print("[*] VatsRead: EAX=%08X" % eax)
    # 回读报文头（DataSize 字段被 SMM 更新为实际大小）
    hdr = phys_read(fd, pkt_pa, 0x40 + RN)
    dsz = struct.unpack_from("<I", hdr, 0x30 + RN)[0]
    print("[*] VatsRead 回读: DataSize 字段=%d" % dsz)
    if dsz:
        data_back = phys_read(fd, edi + 0x20, min(dsz, 0x400))
        same = data_back[:len(cur)] == cur
        print("[*] VatsRead 数据与 efivarfs 一致: %s" % same)
        if eax == 0 and same:
            print("[✓] 链路验证通过：OS→池→SMM→变量服务全部工作")

    if not apply_mode:
        print("\n[=] dry-run 结束（未写入）。确认无误后加 --apply 执行写入。")
        os.close(fd)
        return 0

    # step4 VatsWrite 打开/关闭 fTPM
    patched = bytearray(cur)
    old = patched[FTPM_OFF]
    patched[FTPM_OFF] = FTPM_VALUE
    print("[*] 补丁: Setup+%#x: 0x%02X -> 0x%02X (%s)" %
          (FTPM_OFF, old, FTPM_VALUE,
           "fTPM 关闭" if FTPM_VALUE == 0x00 else "fTPM 开启"))
    pkt_w = ihisi.build_packet(SETUP_GUID, SETUP_NAME, bytes(patched), attrs)
    pkt_pa, esi, edi = stage_packet(fd, pkt_w, pool)
    res = ihisi.smi_call(mf, 0x01, port, esi=esi, edi=edi)
    eax = res.get("eax", 0xFFFFFFFF)
    print("[*] VatsWrite: EAX=%08X" % eax)
    if eax == 0:
        print("[✓✓] VatsWrite 返回 0 —— Setup 变量已写入，fTPM 应已开启！")
        print("    重启进 BIOS 或用 efivarfs/dmidecode 验证 TPM 设备。")
    elif (eax & 0xFFFF) == 0x8012:
        print("[!] 0x8012 = 校验和不匹配（检查 build_packet）")
    elif (eax & 0xFFFF) == 0x8014:
        print("[!] 0x8014 = SMM SetVariable 失败（可能属性不匹配/写保护）")
    elif (eax & 0xFFFF) == 0x802B:
        print("[!] 0x802B = 池/魔数校验失败（报文没进池或指针没指对）")
    echo = phys_read(fd, pkt_pa, min(len(pkt_w), 0x100))
    print("[*] 写后池内报文头 0x100 字节:")
    for i in range(0, len(echo), 16):
        print("    %03x: %s" % (i, echo[i:i+16].hex(" ")))
    os.close(fd)
    return 0 if eax == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
