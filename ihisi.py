#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ihisi.py —— Insyde IHISI SMI 写入通道（不依赖 H2OUVE / Windows）

本模块把「通过 SMI 写一个 EFI 变量」拆成四个可独立验证的步骤：

    1. discover()   只读：找 SMI 端口与 IHISI 主功能号
    2. PhysPage     只读：拿一页 <4GB 的物理内存，算出它的物理地址
    3. build_packet 纯函数：按 H2OWriteVariable 的报文布局拼字节
    4. smi_call()   执行：调 ihisi_smi 做 out dx, al

设计原则：C 侧只负责装寄存器，所有判断都在这里，方便单测和审计。

依据（见 h2ouve-re/REPORT.md 第 8 节）：
  - 驱动 segwindrvx64.sys RVA 0x3E78：EBX="O2H$"、AL=主功能号、DX=端口、out dx, al
  - 驱动 FindSmiMainFuncNum() @ init:0x5680：扫物理 0xF0000 起 64KB，
    每 0x10 字节比对 "$IHISI"，命中后取标签 +6 的字节作主功能号
  - 驱动 FindSmiCommadPort() @ init:0x5090：解析 RSD PTR→FADT，读 [FADT+0x30]
  - 主程序 H2OWriteVariable @ 0x50850：报文布局与校验和
"""

import ctypes
import errno
import mmap
import os
import struct
import subprocess
import sys

# ---------------------------------------------------------------- 常量

HERE = os.path.dirname(os.path.abspath(__file__))
SMI_HELPER = os.path.join(HERE, "ihisi", "ihisi_smi")

PAGE = 4096
FOUR_GB = 1 << 32

IHISI_SIG = b"$IHISI"
SMI_SCAN_BASE = 0xF0000
SMI_SCAN_SIZE = 0x10000
SMI_SCAN_STEP = 0x10

FADT_SMI_CMD_OFF = 0x30
FALLBACK_PORT = 0xB2
FALLBACK_FUNC = 0xEF        # 驱动 FindSmiMainFuncNum 找不到标签时用的值

SUB_WRITE_VARIABLE = 0x01
SUB_GET_NEXT_NAME = 0x05
SUB_IS_SUPPORT = 0x10

# H2OWriteVariable 报文里的三个魔数
MAGIC = (b"$H2O", b"$Var", b"$Tbl")
PACKET_HEAD = 0x40          # 名称之后的固定头长度（0x50850 确认版）
ATTR_FLAG_BYTE = 0x10       # 报文 +0x2D 处的固定字节


class IhisiError(RuntimeError):
    """通道不可用或调用失败。"""


# ---------------------------------------------------------------- 1. 探测

def _read_file(path, size=None):
    with open(path, "rb") as f:
        return f.read(size) if size else f.read()


def find_smi_port():
    """SMI 命令端口。

    首选 /sys/firmware/acpi/tables/FACP 的 +0x30（FADT.SMI_CMD），
    这与驱动 FindSmiCommadPort() 读的是同一个字段。
    失败则退回 /dev/mem 扫 RSDP。
    """
    for p in ("/sys/firmware/acpi/tables/FACP", "/sys/firmware/acpi/tables/FACP1"):
        try:
            blob = _read_file(p)
        except OSError:
            continue
        if len(blob) < FADT_SMI_CMD_OFF + 2:
            continue
        sig = blob[:4]
        if sig not in (b"FACP", b"FACP"):
            continue
        port = struct.unpack_from("<H", blob, FADT_SMI_CMD_OFF)[0]
        if port:
            return port, "FADT.SMI_CMD (%s+0x30)" % os.path.basename(p)
    return None, None


def _phys_map(addr, size, fd=None):
    """把物理地址映射成可读的 mmap。"""
    own = fd is None
    if own:
        fd = os.open("/dev/mem", os.O_RDONLY | os.O_SYNC)
    try:
        m = mmap.mmap(fd, size, mmap.MAP_SHARED, mmap.PROT_READ, offset=addr)
    finally:
        if own:
            os.close(fd)
    return m


def _acpi_tables_from_mem():
    """扫 RSDP 拿 RSDT/XSDT 的物理地址（驱动 FindSmiCommadPort 的同一套路）。"""
    try:
        m = _phys_map(0xE0000, 0x20000)
    except (OSError, ValueError) as e:
        raise IhisiError("/dev/mem 不可读（%s），拿不到 RSDP" % e)
    try:
        for off in range(0, 0x20000 - 20, 16):
            if m[off:off + 8] != b"RSD PTR ":
                continue
            if sum(m[off:off + 20]) & 0xFF:
                continue                      # 校验和不对，不是真 RSDP
            rsdt = struct.unpack_from("<I", m, off + 16)[0]
            xsdt = 0
            if len(m) >= off + 36 and m[off + 20] >= 2:
                xsdt = struct.unpack_from("<Q", m, off + 24)[0]
            return rsdt, xsdt
    finally:
        m.close()
    raise IhisiError("RSDP 未找到")


def find_smi_port_from_mem():
    """兜底路径：/dev/mem → RSDP → RSDT/XSDT → FADT → +0x30。"""
    rsdt, xsdt = _acpi_tables_from_mem()

    def scan_table(tbl_phys, entry_size):
        if not tbl_phys:
            return None
        hdr = _phys_map(tbl_phys & ~(PAGE - 1), PAGE)
        try:
            base = tbl_phys - (tbl_phys & ~(PAGE - 1))
            length = struct.unpack_from("<I", hdr, base + 4)[0]
        finally:
            hdr.close()
        n = (length - 36) // entry_size
        blob = _phys_map(tbl_phys & ~(PAGE - 1), ((length + PAGE - 1) // PAGE) * PAGE)
        try:
            b = tbl_phys - (tbl_phys & ~(PAGE - 1))
            for i in range(n):
                o = b + 36 + i * entry_size
                if blob[o:o + 4] == b"FACP":
                    addr = (struct.unpack_from("<Q", blob, o)[0] if entry_size == 8
                            else struct.unpack_from("<I", blob, o)[0])
                    return addr
        finally:
            blob.close()
        return None

    fadt = scan_table(xsdt, 8) or scan_table(rsdt, 4)
    if not fadt:
        raise IhisiError("ACPI 表里没有 FACP")
    mm = _phys_map(fadt & ~(PAGE - 1), PAGE)
    try:
        off = (fadt & (PAGE - 1)) + FADT_SMI_CMD_OFF
        port = struct.unpack_from("<H", mm, off)[0]
    finally:
        mm.close()
    if not port:
        raise IhisiError("FADT.SMI_CMD 为 0")
    return port, "/dev/mem 扫 ACPI 表"


def _fseg_blob():
    """把 F 段（0xF0000 起 64KB）整块读出来。"""
    try:
        m = _phys_map(SMI_SCAN_BASE, SMI_SCAN_SIZE)
    except (OSError, ValueError) as e:
        raise IhisiError(
            "mmap /dev/mem 0xF0000 失败：%s\n"
            "  说明 /dev/mem 被内核挡了（CONFIG_STRICT_DEVMEM 或 lockdown），"
            "不是「没有标签」。" % e)
    try:
        return bytes(m[:])
    finally:
        m.close()


def fseg_stats(blob):
    """F 段的粗略画像，用来区分「读到真固件」和「读到内核填充」。

    真固件里 0xFF（擦除态）和 0x00（填充）会大量出现，而且会有重复的指令
    片段；而内核在 STRICT_DEVMEM 下对非 RAM 页给的是一份高熵填充，
    特征是：256 个字节值全出现、每个约等频、熵接近 8.000。
    """
    import collections
    import math
    n = len(blob)
    c = collections.Counter(blob)
    h = -sum((v / n) * math.log2(v / n) for v in c.values()) if n else 0.0
    nz = sum(1 for x in blob if x)
    return {
        "len": n,
        "nonzero": nz,
        "ff": blob.count(0xFF),
        "zero": blob.count(0x00),
        "distinct": len(c),
        "entropy": h,
        "head": blob[:16].hex(" "),
    }


def fseg_verdict(st):
    """把画像翻译成一句话结论。

    返回 (代号, 中文说明)。代号供程序判断，说明给用户看。
    """
    n = st["len"]
    if n == 0:
        return "empty", "一个字节都没读到"
    if st["entropy"] > 7.99 and st["distinct"] >= 250:
        return ("looks_like_fill",
                "熵 %.3f bit/byte、%d 个字节值全现 —— 这是内核填充，不是固件"
                % (st["entropy"], st["distinct"]))
    if st["ff"] > n * 0.5 or st["zero"] > n * 0.5:
        return "mostly_padding", "过半是 0xFF / 0x00 —— 这段没被写过，或读不到真内容"
    return "plausible", "分布正常，像是真的固件内容"


def find_main_func_num(diag=None):
    """IHISI 主功能号。

    完全复刻驱动 FindSmiMainFuncNum()（init:0x5680）：物理 0xF0000 起
    64KB、步进 0x10、比对 6 字节 "$IHISI"，命中取标签 +6 的那个字节；
    未命中驱动自己用 0xEF。

    注意：驱动是内核态、用 MmMapIoSpace 直接映射物理内存；用户态只能走
    /dev/mem。本机 CachyOS（CONFIG_STRICT_DEVMEM=y）对非 RAM 页返回的是
    高熵填充，扫不到标签并不代表标签不存在。所以找不到时要把画像一起报出来，
    让用户知道该换 `--func` 而不是以为"固件没有"。

    返回 (功能号, 偏移, 是否 0x10 对齐)。
    """
    blob = _fseg_blob()
    n = len(blob)
    for off in range(0, n - 6, SMI_SCAN_STEP):
        if blob[off:off + 6] == IHISI_SIG:
            return blob[off + 6], off, True

    # 驱动只认 0x10 对齐；万一固件没对齐，这里也报出来（只是提示）
    p = blob.find(IHISI_SIG)
    if p >= 0:
        return blob[p + 6], p, False

    st = fseg_stats(blob)
    if diag is not None:
        diag.update(st)
    code, why = fseg_verdict(st)

    if code == "looks_like_fill":
        # 决定性判据：真固件不可能这么"干净"地均匀
        body = (
            "物理 0xF0000..0x%05X 里没有 $IHISI 标签 —— 但这份数据不可信。\n"
            "  画像：%s\n"
            "        非零 %d / 0xFF %d / 全零 %d，共 %d 字节，头 16 字节 %s\n"
            "  结论：内核没有把固件内容交给我们，扫出来的只是填充字节。\n"
            "        所以「没找到标签」既不能证明标签不存在，也不说明端口或功能号错。\n"
            "  处理：本机固件静态确认主功能号是 0x64（p1.fd @ 0x3DBA34），"
            "直接指定即可：\n"
            "        ./insyde-nvram probe --via ihisi --func 0x64"
            % (SMI_SCAN_BASE + n - 1, why, st["nonzero"], st["ff"], st["zero"], n,
               st["head"]))
    else:
        hint = ""
        if st["ff"] > n * 0.9:
            hint = "这段读回来几乎全是 0xFF —— 更像是 /dev/mem 没映射到真内存。"
        elif st["nonzero"] < 64:
            hint = "这段几乎是空的（全 0），同样可疑。"
        body = (
            "物理 0xF0000..0x%05X 里没有 $IHISI 标签。\n"
            "  画像：%s\n"
            "        非零 %d / 0xFF %d / 全零 %d，共 %d 字节，头 16 字节 %s\n"
            "  %s\n"
            "  两种解释：① 本机固件不把标签放在 F 段，驱动会退回 0xEF；\n"
            "            ② 标签压在压缩卷/SMRAM 里，用户态根本读不到。\n"
            "  先跑 `sudo python3 tools/fseg_scan.py --out dump/` 看现场。"
            % (SMI_SCAN_BASE + n - 1, why, st["nonzero"], st["ff"], st["zero"], n,
               st["head"], hint))
    raise IhisiError(body)


def probe_func(diag=None):
    """只拿主功能号，失败也把诊断塞进 diag。"""
    d = {} if diag is None else diag
    info = {}
    try:
        func, off, aligned = find_main_func_num(diag=d)
    except IhisiError:
        if d:
            info.update(d)
        raise
    info.update({"main_func": func, "tag_offset": off,
                 "tag_phys": SMI_SCAN_BASE + off, "aligned": aligned})
    return info


def discover(verbose=True):
    """一次性拿到端口 + 主功能号。两者都只读，不发任何 SMI。"""
    port, port_src = find_smi_port()
    if port is None:
        try:
            port, port_src = find_smi_port_from_mem()
        except IhisiError as e:
            port, port_src = FALLBACK_PORT, "回退默认值（%s）" % e
            if verbose:
                print("[!] 没能从 ACPI 读到端口，暂用 0x%02X —— 这是假设值，不是实测值"
                      % port, file=sys.stderr)

    func, off, aligned = find_main_func_num()
    info = {
        "port": port,
        "port_source": port_src,
        "main_func": func,
        "tag_offset": off,
        "tag_phys": SMI_SCAN_BASE + off,
        "aligned": aligned,
    }
    if verbose:
        print("SMI 端口     0x%02X   （%s）" % (port, port_src))
        print("主功能号     0x%02X   （$IHISI 标签物理 0x%05X，+6 = 0x%02X）"
              % (func, info["tag_phys"], func))
    return info


# ---------------------------------------------------------------- 2. 物理页

class KernelBuf(object):
    """内核分配的 DMA32 报文缓冲（/dev/ihisi_buf，ihisi_diag 模块提供）。

    接口与 PhysPage 对齐：vaddr / paddr / load / read_back / verify_paddr / close。
    物理地址来自 alloc_pages(GFP_DMA32)，内核页不迁移 → verify_paddr 恒过。
    """

    def __init__(self, size):
        import re
        if size > 8192:
            raise IhisiError("内核缓冲上限 8KB，报文 %d 字节超限" % size)
        self.fd = os.open("/dev/ihisi_buf", os.O_RDWR | os.O_SYNC)
        try:
            info = os.read(self.fd, 256).decode("utf-8", "replace")
        except OSError:
            os.close(self.fd)
            raise IhisiError("/dev/ihisi_buf 读不出缓冲信息（模块旧版？）")
        m = re.search(r"paddr=0x([0-9a-fA-F]+)", info)
        s = re.search(r"size=(\d+)", info)
        if not m or not s:
            os.close(self.fd)
            raise IhisiError("/dev/ihisi_buf 输出异常: %r" % info)
        self.paddr = int(m.group(1), 16)
        self.size = min(int(s.group(1)), 8192)
        self._mm = mmap.mmap(self.fd, self.size)

    @property
    def vaddr(self):
        return 0  # 报文直接放映射起始（内核页物理连续且页对齐）

    def verify_paddr(self):
        if not (0 < self.paddr < FOUR_GB):
            raise IhisiError("内核缓冲物理地址异常: %#x" % self.paddr)

    def load(self, data):
        self._mm[0:len(data)] = data

    def read_back(self, n):
        return bytes(self._mm[0:n])

    def close(self):
        try:
            self._mm.close()
        except (BufferError, ValueError):
            pass
        os.close(self.fd)


class PhysPage(object):
    """一页 <4GB 的、已锁定的匿名内存，能给出它的物理地址。

    SMM 通过 ESI/EDI 直接访问物理地址，绕过页表，所以必须：
      - mlock 住，防止被换出或回收
      - 从 /proc/self/pagemap 读出 PFN
      - 确认物理地址落在 4GB 以下（ESI/EDI 是 32 位）
    """

    def __init__(self, size):
        if size > PAGE:
            raise IhisiError(
                "报文 %d 字节超过一页（%d），跨页需要物理连续内存，当前未实现。"
                "Setup 变量 700 字节的报文 776 字节，正常不会走到这里。"
                % (size, PAGE))
        self.size = size
        self.buf = mmap.mmap(-1, PAGE * 2,
                             flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
        # 先写一遍，确保页真正落地（否则 pagemap 里 present=0）
        self.buf.write(b"\xa5" * (PAGE * 2))
        self._base = ctypes.addressof(ctypes.c_char.from_buffer(self.buf))
        self._mlock()
        self.vaddr = self._aligned_vaddr()
        self.paddr = self._paddr(self.vaddr)

    @classmethod
    def alloc(cls, size, tries=None):
        """拿一块物理地址 <4GB 的报文缓冲。

        优先走内核后端：ihisi_diag 模块的 /dev/ihisi_buf 用
        alloc_pages(GFP_DMA32) 分配低地址页并 mmap 出来 —— 等价于 Windows
        驱动的 MmAllocateContiguousMemorySpecifyCache(HighAddress=0xFFFFFFFF)。
        用户态匿名页做不到（Linux 物理分配自高向低，32GB 机器上低 4GB 的页
        用户态永远抢不到，实测 256 次全 >4GB），所以内核后端是首选。

        内核页无 MOVABLE 标志、compaction 不迁移，物理地址恒定，无需复核 PFN。
        没有 /dev/ihisi_buf 时退回匿名页 + pagemap 老路（重试 256 次）。
        """
        if os.path.exists("/dev/ihisi_buf"):
            try:
                return KernelBuf(size)
            except (OSError, IhisiError):
                pass  # 模块没加载成功/缓冲没分配出来，走老路

        if tries is None:
            tries = int(os.environ.get("IHISI_ALLOC_TRIES", "256"))
        hit = 0
        for i in range(tries):
            p = cls(size)
            if p.paddr < FOUR_GB:
                return p
            p.close()
            hit += 1
            # 每 32 次主动释放一次虚拟页，让内核有机会换一批物理页
            if i % 32 == 31:
                import ctypes as _c
                _c.CDLL("libc.so.6").malloc_trim(0)
        raise IhisiError(
            "连续 %d 次分配到的页都在 4GB 以上，ESI/EDI 装不下。\n"
            "  正解：加载内核模块拿 DMA32 缓冲 ——\n"
            "    sudo insmod kernel/ihisi_diag.ko\n"
            "  （用户态匿名页从高 zone 分配，本机 32GB 下 <4GB 页抢不到）\n"
            "  或者组合拳：\n"
            "  sync; echo 3 | sudo tee /proc/sys/vm/drop_caches; "
            "echo 1 | sudo tee /proc/sys/vm/compact_memory" % hit)

    def verify_paddr(self):
        """发 SMI 前复核物理地址没变。

        mlock 只保证「不被换出」，不保证「不被迁移」：compaction、NUMA balancing、
        内存热插拔都可能搬动页框，PFN 一变，SMM 就会去读一块完全无关的内存。
        窗口只有微秒级，但代价是往 NVRAM 里写垃圾，值得复核一次。
        """
        now = self._paddr(self.vaddr)
        if now != self.paddr:
            raise IhisiError(
                "物理地址在发 SMI 前被内核迁移了（0x%X → 0x%X）。为了不写坏 NVRAM，"
                "本次中止。重跑即可。" % (self.paddr, now))

    def _mlock(self):
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        if libc.mlock(ctypes.c_void_p(self._base), ctypes.c_size_t(PAGE * 2)) != 0:
            e = ctypes.get_errno()
            raise IhisiError("mlock 失败: %s (errno=%d)，需要 root" % (os.strerror(e), e))

    def _aligned_vaddr(self):
        """取页边界作为报文起点，保证整块不跨页。"""
        return self._base + ((PAGE - self._base % PAGE) % PAGE)

    def _paddr(self, vaddr):
        entry_off = (vaddr // PAGE) * 8
        try:
            with open("/proc/self/pagemap", "rb") as f:
                f.seek(entry_off)
                raw = f.read(8)
        except OSError as e:
            raise IhisiError("读不了 /proc/self/pagemap: %s" % e)
        if len(raw) != 8:
            raise IhisiError("pagemap 读取长度异常")
        entry = struct.unpack("<Q", raw)[0]
        if not (entry >> 63) & 1:
            raise IhisiError("目标页不在物理内存里（present=0）")
        pfn = entry & ((1 << 55) - 1)
        if pfn == 0:
            raise IhisiError(
                "pagemap 返回 PFN=0 —— 内核屏蔽了物理帧号。"
                "需要 CAP_SYS_ADMIN（root）；某些内核还需关闭 "
                "CONFIG_PROC_PAGE_MONITOR 的限制或加 CAP_SYS_RAWIO。")
        paddr = pfn * PAGE
        return paddr

    def load(self, data):
        off = self.vaddr - self._base
        self.buf[off:off + len(data)] = data

    def read_back(self, n):
        off = self.vaddr - self._base
        return self.buf[off:off + n]

    def close(self):
        try:
            self.buf.close()
        except (BufferError, ValueError):
            pass


def alloc_low_page(size):
    """统一入口：优先内核 DMA32 缓冲，没有模块再走匿名页重试。

    见 KernelBuf / PhysPage.alloc 的说明。
    """
    if os.path.exists("/dev/ihisi_buf"):
        try:
            k = KernelBuf(size)
            k.verify_paddr()
            return k
        except IhisiError:
            raise
        except (OSError, ValueError):
            pass
    return PhysPage.alloc(size)


# ---------------------------------------------------------------- 3. 报文

def guid_bytes_le(guid_str):
    """EFI_GUID 的内存布局：前三段小端，后两段原样。"""
    h = guid_str.replace("-", "")
    if len(h) != 32:
        raise IhisiError("GUID 长度不对: %s" % guid_str)
    d1 = struct.pack("<I", int(h[0:8], 16))
    d2 = struct.pack("<H", int(h[8:12], 16))
    d3 = struct.pack("<H", int(h[12:16], 16))
    d4 = bytes.fromhex(h[16:32])
    return d1 + d2 + d3 + d4


def build_packet(guid_str, name, data, attrs):
    """按 H2OWriteVariable（0x50850）的布局拼报文。

    偏移            内容
    0x00            GUID (16，混合端序)
    0x10            变量名 UTF-16LE，含结尾 NUL（长度记为 N）
    0x20+N          "$H2O"
    0x24+N          "$Var"
    0x28+N          "$Tbl"
    0x2C+N          保留 4
    0x30+N          数据长度 (u32)
    0x34+N          属性 (u32)
    0x38+N          保留 4
    0x3C+N          保留 1
    0x3D+N          0x10（固定字节，SMM 校验器查 [EDI+0x1D]==0x10）
    0x3E+N          校验和 (u16，只覆盖数据区)
    0x40+N          数据

    校验和 = 数据全部字节之和的 16 位二进制补码。
    （0x50850：bx 累加偶位、di 累加奇位、add bx,di; add bx,ax; not bx; inc bx
     —— 数学上等价于全体字节和取补。）

    注意：v1 逆向曾把整段算成 0x10+N 起（少 0x10），导致 handler 校验
    [ESI+0x1D]!=0x10 静默拒绝。2026-10-30 重反汇编 0x50850 修正。
    """
    if isinstance(name, str):
        name_w = name.encode("utf-16-le") + b"\x00\x00"
    else:
        name_w = name
        if not name_w.endswith(b"\x00\x00"):
            name_w += b"\x00\x00"
    n = len(name_w)
    total = PACKET_HEAD + n + len(data)
    buf = bytearray(total)

    buf[0:16] = guid_bytes_le(guid_str)
    buf[0x10:0x10 + n] = name_w
    for i, magic in enumerate(MAGIC):
        off = 0x20 + n + i * 4
        buf[off:off + 4] = magic
    struct.pack_into("<I", buf, 0x30 + n, len(data))
    struct.pack_into("<I", buf, 0x34 + n, attrs)
    buf[0x3D + n] = ATTR_FLAG_BYTE
    struct.pack_into("<H", buf, 0x3E + n, packet_checksum(data))
    buf[0x40 + n:0x40 + n + len(data)] = data
    return bytes(buf)


def packet_checksum(data):
    """数据全体字节之和的补码，使 (sum + checksum) & 0xFFFF == 0。"""
    return (-sum(data)) & 0xFFFF


def packet_apply_offset(namelen_bytes):
    """报文里数据区相对报文起点的偏移。"""
    return PACKET_HEAD + namelen_bytes


# ---------------------------------------------------------------- 4. 调用

def ensure_helper():
    """确保 C helper 已编译；没有就现场编。"""
    if os.path.isfile(SMI_HELPER) and os.access(SMI_HELPER, os.X_OK):
        return SMI_HELPER
    src = SMI_HELPER + ".c"
    if not os.path.isfile(src):
        raise IhisiError("找不到 %s" % src)
    cc = None
    for cand in ("cc", "gcc", "clang"):
        from shutil import which
        cc = which(cand)
        if cc:
            break
    if not cc:
        raise IhisiError("需要 C 编译器来构建 %s（试过 cc/gcc/clang）" % src)
    r = subprocess.run([cc, "-O2", "-Wall", "-o", SMI_HELPER, src],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise IhisiError("编译失败:\n%s" % (r.stderr or r.stdout))
    return SMI_HELPER


def smi_call(main_func, sub_func, port, esi=0, edi=0, ecx=0, edx=0):
    """发一条 SMI，返回 SMM 回写的寄存器字典。

    注意：调用后 CPU 已经进过 SMM，任何副作用都可能已经发生。
    """
    helper = ensure_helper()
    cmd = [helper, "0x%02X" % main_func, "0x%02X" % sub_func, "0x%X" % port,
           "0x%X" % esi, "0x%X" % edi, "0x%X" % ecx, "0x%X" % edx]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        msg = (r.stderr or r.stdout).strip()
        if r.returncode == 2:
            raise IhisiError("权限不足，需要 root 才能 out 到端口：\n%s" % msg)
        raise IhisiError("ihisi_smi 失败（退出码 %d）:\n%s" % (r.returncode, msg))
    out = {}
    for tok in r.stdout.split():
        if "=" in tok:
            k, v = tok.split("=", 1)
            out[k] = int(v, 16)
    return out


def smi_generic(eax, ebx, ecx, edx, esi, edi, port):
    """SMI_GENERIC 通道（驱动 0x3EBA）：六寄存器全透传。

    与 smi_call 的差别：EAX/EBX 不强制 (sub<<8)|main 和 "O2H$"，
    全部由调用者给定。SMM 侧 0x58BA90 按 AL 分派槽位服务。
    """
    helper = ensure_helper()
    cmd = [helper, "--generic",
           "0x%X" % eax, "0x%X" % ebx, "0x%X" % ecx, "0x%X" % edx,
           "0x%X" % esi, "0x%X" % edi, "0x%X" % port]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        msg = (r.stderr or r.stdout).strip()
        if r.returncode == 2:
            raise IhisiError("权限不足，需要 root 才能 out 到端口：\n%s" % msg)
        raise IhisiError("ihisi_smi --generic 失败（退出码 %d）:\n%s"
                         % (r.returncode, msg))
    out = {}
    for tok in r.stdout.split():
        if "=" in tok:
            k, v = tok.split("=", 1)
            out[k] = int(v, 16)
    return out


def ping(info=None, ecx=0, main_func=None):
    """IsSupportIhisi（子功能 0x10）——只问通道在不在，不改任何状态。

    判定看 **AL**（EAX & 0xFF）。依据驱动自己的代码，这是最硬的证据：

        ; segwindrvx64.sys 触发函数 @ 0x3E78
        3e8f  mov ebx, [0xE37F+..]   ; EBX = "O2H$"
        3e95  mov al,  [0xE37F]      ; AL  = 主功能号（覆盖掉 AH 里的子功能号）
        3e9b  mov dx,  [0xE3C8]      ; DX  = SMI 端口
        3ea2  out dx, al
        3ea3  mov [r8+0x00], esi
        3eaa  mov [r8+0x08], ecx
        3eb2  mov [r8+0x10], eax     ; ← 把 out 之后的 EAX 写回寄存器块

        ; 调用者 SMI_IHISI 分支 @ 0x13F3A
        13f3a call 0x3e78
        13f3f mov [rdi+4], eax
        13f42 cmp al, bl             ; ← AL == 0 判成功
        13f46 cmp al, [..]           ; 或等于另一个可接受值

    注意 `out dx, al` 只送 AL，AH 不出端口。SMM 回来后是**整个 EAX**被改写，
    所以状态位在 AL。之前的文档写成 DL 是错的。

    诊断价值：如果回来的 EAX 仍是 `(sub<<8)|main`（如 0x1064），说明
    SMM 根本没碰过寄存器 —— 即这条 SMI 没有被处理，而不是「返回了错误码」。

    ecx：驱动参数块 +0x08 的 ECX 由 H2OUVE 用户态填（语义疑似协议版本），
    我们此前一直送 0。扫描时用 ecx= 遍历找 handler 认的值。
    """
    info = info or discover(verbose=False)
    mf = info["main_func"] if main_func is None else main_func
    res = smi_call(mf, SUB_IS_SUPPORT, info["port"], ecx=ecx)
    status = res.get("eax", 0xFFFFFFFF) & 0xFF
    filled = res.get("eax", 0) == ((SUB_IS_SUPPORT << 8) | (mf & 0xFF))
    return status, res, filled


def write_variable(guid, name, data, attrs, info=None, dry_run=False):
    """通过 SMI 写一个 EFI 变量。

    dry_run=True 时只构造报文并拿到物理地址，不发 SMI。
    """
    info = info or discover()
    pkt = build_packet(guid, name, data, attrs)
    namelen = (len(name) + 1) * 2 if isinstance(name, str) else len(name) + 2

    page = alloc_low_page(len(pkt))
    try:
        page.load(pkt)
        esi = page.paddr
        edi = page.paddr + 0x20 + namelen          # 指向 "$H2O"（0x20+N）
        if dry_run:
            return {
                "packet": pkt, "esi": esi, "edi": edi,
                "packet_len": len(pkt), "namelen": namelen,
                "smi": None,
            }
        page.verify_paddr()                        # 发 SMI 前复核一次
        res = smi_call(info["main_func"], SUB_WRITE_VARIABLE, info["port"],
                       esi=esi, edi=edi)
        res["packet"] = pkt
        res["esi"] = esi
        res["edi"] = edi
        res["packet_len"] = len(pkt)
        res["namelen"] = namelen
        # 状态看 AL（EAX & 0xFF）：驱动 @ 0x13F42 就是 `cmp al, bl` 判成功，
        # 而 0x3EB2 把 out 之后的整个 EAX 写回寄存器块。AH 不出端口。
        res["status"] = res.get("eax", 0xFFFFFFFF) & 0xFF
        # SMM 可能改写报文（比如回填结果），把改后的前 64 字节也带回去
        res["echo"] = page.read_back(min(len(pkt), 64))
        return res
    finally:
        page.close()


# ---------------------------------------------------------------- 自检

def _selftest():
    ok = 0
    fail = 0

    def check(name, cond, extra=""):
        nonlocal ok, fail
        if cond:
            ok += 1
            print("  [ok]   %s %s" % (name, extra))
        else:
            fail += 1
            print("  [FAIL] %s %s" % (name, extra))

    print("报文布局自检")
    guid = "A04A27F4-DF00-4D42-B552-39511302113D"
    data = bytes(range(256)) + bytes(256) + bytes(188)   # 700 字节
    pkt = build_packet(guid, "Setup", data, 0x07)

    check("总长 = 0x40 + 12 + 700", len(pkt) == 0x40 + 12 + 700, "实际 %d" % len(pkt))
    check("GUID 混合端序", pkt[0:4] == b"\xf4\x27\x4a\xa0", pkt[0:4].hex())
    check("名称 UTF-16LE", pkt[0x10:0x1C] == "Setup".encode("utf-16-le") + b"\x00\x00",
          pkt[0x10:0x1C].hex())
    check("$H2O @0x2C", pkt[0x2C:0x30] == b"$H2O")
    check("$Var @0x30", pkt[0x30:0x34] == b"$Var")
    check("$Tbl @0x34", pkt[0x34:0x38] == b"$Tbl")
    check("长度字段 = 700", struct.unpack_from("<I", pkt, 0x3C)[0] == 700)
    check("属性字段 = 0x07", struct.unpack_from("<I", pkt, 0x40)[0] == 0x07)
    check("固定字节 0x10 @0x49", pkt[0x49] == 0x10, "实际 0x%02X" % pkt[0x49])
    check("数据区起点 0x4C", pkt[0x4C:0x4C + 700] == data)

    cs = struct.unpack_from("<H", pkt, 0x4A)[0]
    check("校验和 = -sum(data)", cs == (-sum(data)) & 0xFFFF,
          "0x%04X" % cs)
    check("sum + checksum ≡ 0 (mod 65536)", (sum(data) + cs) & 0xFFFF == 0)

    print("\n校验和边界")
    for n in (0, 1, 2, 255, 256, 700, 701):
        d = bytes((i * 7) & 0xFF for i in range(n))
        check("len=%d" % n, (sum(d) + packet_checksum(d)) & 0xFFFF == 0)

    print("\nGUID 编码")
    check("Microsoft GUID",
          guid_bytes_le("8BE4DF61-93CA-11D2-AA0D-00E098032B8C")
          == bytes.fromhex("61dfe48bca93d211aa0d00e098032b8c"))

    print("\n%s  自检 %d 项通过，%d 项失败" % ("✓" if fail == 0 else "✗", ok, fail))
    return 0 if fail == 0 else 1


def _main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print(__doc__)
        print("用法:")
        print("  ihisi.py selftest          报文布局与校验和自检（不需要 root）")
        print("  ihisi.py discover          只读探测端口与主功能号（需 root）")
        print("  ihisi.py ping              发子功能 0x10（需 root，无副作用）")
        print("  ihisi.py phys              测试能否拿到 <4GB 物理页（需 root）")
        print("  ihisi.py dryrun            构造 Setup 报文并打印物理地址（需 root）")
        return 0 if len(argv) > 1 else 1

    cmd = argv[1]
    if cmd == "selftest":
        return _selftest()

    try:
        if cmd == "discover":
            discover()
        elif cmd == "ping":
            info = discover()
            st, res = ping(info)
            print("\nIsSupportIhisi 返回 EAX&0xFF = 0x%02X" % st)
            print("寄存器: %s" % " ".join("%s=0x%X" % (k, v) for k, v in sorted(res.items())))
            print("判定: %s" % ("通道存在" if st == 0 else "通道未响应或返回异常"))
        elif cmd == "phys":
            for i in range(3):
                p = PhysPage(776)
                print("第 %d 次: 虚拟 0x%X → 物理 0x%X  %s"
                      % (i + 1, p.vaddr, p.paddr,
                         "✓ <4GB" if p.paddr < FOUR_GB else "✗ 超 4GB，alloc() 会重试"))
                p.close()
            p = PhysPage.alloc(776)
            print("alloc(): 物理 0x%X ✓ 可用" % p.paddr)
            p.close()
        elif cmd == "dryrun":
            info = discover()
            r = write_variable("A04A27F4-DF00-4D42-B552-39511302113D", "Setup",
                               bytes(700), 0x07, info=info, dry_run=True)
            print("\n报文长度 %d，名称 %d 字节" % (r["packet_len"], r["namelen"]))
            print("ESI = 0x%08X   （报文物理基址）" % r["esi"])
            print("EDI = 0x%08X   （指向 $H2O）" % r["edi"])
            print("前 64 字节:\n%s" % r["packet"][:64].hex(" "))
        else:
            print("未知命令: %s" % cmd, file=sys.stderr)
            return 2
    except IhisiError as e:
        print("错误: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
