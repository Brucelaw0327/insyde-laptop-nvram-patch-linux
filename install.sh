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
echo "试试: insyde-nvram status"
