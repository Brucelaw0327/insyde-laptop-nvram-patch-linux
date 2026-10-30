#!/usr/bin/env bash
# load.sh —— 编译并加载 ihisi_diag 诊断模块
#
# 用法:
#   sudo bash kernel/load.sh                     # 只读 F 段 + MMIO
#   sudo bash kernel/load.sh 0x400               # 顺带 dump PM I/O（PM1a_EVT_BLK）
#
# 结果:  cat /proc/ihisi_diag
# 卸载:  sudo rmmod ihisi_diag

set -e
cd "$(dirname "$0")/.."          # 仓库根目录

if [ "$(id -u)" != 0 ]; then
    echo "需要 root：sudo bash kernel/load.sh" >&2
    exit 1
fi

if [ ! -d "/lib/modules/$(uname -r)/build" ]; then
    echo "缺内核 headers：sudo pacman -S linux-cachyos-headers" >&2
    exit 1
fi

echo "== 编译 =="
make -C kernel 2>&1 | tail -5

echo
echo "== 加载 =="
rmmod ihisi_diag 2>/dev/null || true
PM_ARG=""
if [ -n "$1" ]; then
    PM_ARG="pm_evt=$1"
    echo "PM I/O 基址: $1"
fi
insmod kernel/ihisi_diag.ko "$PM_ARG"

echo
echo "== dmesg 摘要 =="
dmesg | grep ihisi_diag | tail -10

echo
echo "== 完成。查看结果： =="
echo "  cat /proc/ihisi_diag | tee ihisi_diag.txt"
echo "  卸载: sudo rmmod ihisi_diag"
