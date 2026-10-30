#!/usr/bin/env bash
# install.sh -- 把 insyde-nvram 挂到 PATH 上（符号链接，不复制）。
# 卸载：rm /usr/local/bin/insyde-nvram
set -eu

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-/usr/local/bin/insyde-nvram}"

chmod +x "$HERE/insyde-nvram"

if [ -e "$TARGET" ] && [ ! -L "$TARGET" ]; then
    echo "已存在同名文件且不是符号链接: $TARGET" >&2
    echo "先自己处理掉它，或者换个路径: ./install.sh /usr/local/bin/nvram-patch" >&2
    exit 1
fi

ln -sf "$HERE/insyde-nvram" "$TARGET"
echo "已安装: $TARGET -> $HERE/insyde-nvram"

# IHISI 通道需要一个几十行的 C 调用器（用户态没法直接执行 out 指令）。
# 只在用到 ihisi 通道时才需要，efivarfs 通道不依赖它。
CCBIN="$(command -v cc || command -v gcc || command -v clang || true)"
if [ -n "$CCBIN" ] && [ -f "$HERE/ihisi/ihisi_smi.c" ]; then
    echo "编译 IHISI SMI 调用器 …"
    if "$CCBIN" -O2 -Wall -o "$HERE/ihisi/ihisi_smi" "$HERE/ihisi/ihisi_smi.c"; then
        echo "  $(python3 "$HERE/ihisi.py" selftest 2>&1 | tail -1)"
    else
        echo "  编译失败 —— ihisi 通道不可用，efivarfs 通道不受影响。" >&2
    fi
else
    echo "没找到 C 编译器（cc/gcc/clang）—— ihisi 通道首次使用时会再尝试。"
    echo "  efivarfs 通道不需要编译器。"
fi

echo "试试: insyde-nvram status"
