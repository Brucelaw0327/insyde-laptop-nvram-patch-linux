#!/usr/bin/env python3
"""fw_unpack.py -- 把固件镜像里 GUID 定义的 LZMA 压缩卷解出来。

为什么需要它：`ifr_locate.py extract` 能从升级包里挖出 SetupUtility 那一支 FFS
（本机是 147 条可定位设置），但 AMD CBS / PBS、Secure Boot 这些 formset 住在
LZMA 压缩卷里，脚本不会去解。解开整片镜像后同一条 `find` 能定位 1028 条。

用法：
    python3 tools/fw_unpack.py <镜像.fd> [-o 输出目录]
    python3 tools/ifr_locate.py find fw/unpacked.fd tpm

结构说明（Insyde H2O 实测）：
    EFI_COMMON_SECTION_HEADER  3B size + 1B type(0x02 GUID_DEFINED)
    EFI_GUID_DEFINED_SECTION   16B SectionDefinitionGuid
                               2B DataOffset   <- 相对 section 起点，不是 GUID
                               2B Attributes
    载荷                        LZMA_ALONE（5B props + 8B 原始长度 + 数据）
"""
import argparse
import lzma
import os
import struct
import sys
import uuid

LZMA_GUID = "EE4E5898-3914-4259-9D6E-DC7BD79403CF"


def unpack(src, outdir, verbose=True):
    d = open(src, "rb").read()
    guid = uuid.UUID(LZMA_GUID).bytes_le
    made = []
    pos = 0
    idx = 0
    while True:
        g = d.find(guid, pos)
        if g < 0:
            break
        pos = g + 1
        sec_start = g - 4
        if sec_start < 0:
            continue
        data_off, attrs = struct.unpack_from("<HH", d, g + 16)
        # type 必须在 section 头里（0x02 = GUID_DEFINED）
        if d[sec_start + 3] != 0x02:
            continue
        start = sec_start + data_off
        payload = d[start:start + 0x4000000]
        try:
            dec = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
            out = dec.decompress(payload)
        except lzma.LZMAError as e:
            if verbose:
                print("  [%d] @0x%x 解压失败: %s" % (idx, g, e))
            continue
        if not out:
            continue
        idx += 1
        name = "p%d.fd" % idx
        path = os.path.join(outdir, name)
        with open(path, "wb") as fh:
            fh.write(out)
        made.append((path, g, len(out), out.count(b"_FVH")))
        if verbose:
            print("  [%d] section @0x%x  载荷 @0x%x  -> %s  %d 字节  %d 个 FFS 卷"
                  % (idx, sec_start, start, name, len(out), out.count(b"_FVH")))
    return made


def main(argv):
    ap = argparse.ArgumentParser(description="解开镜像里 GUID 定义的 LZMA 压缩卷")
    ap.add_argument("image", help="固件镜像（.fd/.bin/.rom）")
    ap.add_argument("-o", "--outdir", default=None,
                    help="输出目录（默认与镜像同目录）")
    a = ap.parse_args(argv)
    if not os.path.isfile(a.image):
        sys.exit("找不到文件: %s" % a.image)
    outdir = a.outdir or os.path.dirname(os.path.abspath(a.image))
    os.makedirs(outdir, exist_ok=True)
    print("输入: %s (%d 字节)" % (a.image, os.path.getsize(a.image)))
    made = unpack(a.image, outdir)
    if not made:
        print("没有找到可解的 LZMA 压缩卷 —— 镜像可能本来就是未压缩的，"
              "直接拿它去 ifr_locate.py find 即可。")
        return 0
    print("\n解出 %d 个压缩卷。下一步:" % len(made))
    for path, _g, _n, _fv in made:
        print("  python3 tools/ifr_locate.py find %s <关键字>" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
