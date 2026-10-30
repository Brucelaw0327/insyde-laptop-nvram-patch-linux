#!/usr/bin/env bash
# enable-ftpm.sh —— 一次跑完「打开 fTPM」的五道门，任何一步不符合预期就停。
#
# 为什么要这个脚本：每一步都依赖上一步的结论，手动敲容易在「以为通道通了」
# 的时候直接写坏 NVRAM。顺序固定成：
#
#   快照 → 探测 → 握手(ping) → 原样写回(probe) → 空跑(dry-run) → 写入 → 读回
#
# 其中「原样写回」是最关键的一步：它用真实的 0x01 报文走完整条 SMI 链路，
# 但写进去的字节和现在一模一样，所以成功了不改变任何东西，失败了也没副作用。
#
# 用法：
#   sudo bash scripts/enable-ftpm.sh               # 交互确认后写入
#   sudo bash scripts/enable-ftpm.sh --check-only  # 只做到 dry-run，不写
#   sudo bash scripts/enable-ftpm.sh --func 0xEF   # 换主功能号
#
set -u

HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "$HERE" || exit 1

PATCH=${PATCH:-patches/ftpm-enable-RMGCZ6T0P0909.patch}
FUNC=0x64          # 固件数据里确认的值：unpack/p1.fd @ 0x3DBA34 的 "$IHISI"+0x64
CHECK_ONLY=0

while [ $# -gt 0 ]; do
    case "$1" in
        --func) FUNC="$2"; shift 2 ;;
        --check-only) CHECK_ONLY=1; shift ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "未知参数: $1"; exit 2 ;;
    esac
done

[ "$(id -u)" = "0" ] || { echo "需要 root：sudo bash scripts/enable-ftpm.sh"; exit 3; }
[ -f "$PATCH" ] || { echo "找不到补丁: $PATCH"; exit 2; }

ok()   { printf '\n\033[32m== %s\033[0m\n' "$*"; }
warn() { printf '\033[33m!! %s\033[0m\n' "$*"; }
die()  { printf '\n\033[31mxx %s\033[0m\n' "$*"; exit 1; }

echo "=================================================================="
echo " 打开 fTPM   patch=$PATCH   func=$FUNC"
echo "=================================================================="
echo "目标：Setup 记录 0x100 处 0x00 -> 0x02"
echo "      （0=Disable / 1=Discrete TPM / 2=Firmware TPM）"
echo "这不是刷 BIOS，只改 NVRAM 里一个字节，可逐字节回滚。"
echo

# ---------------------------------------------------------------- 0. 快照
ok "0/6 写前快照"
./insyde-nvram dump --record Setup --label pre-ftpm || die "快照失败，先别继续"
SNAP=$(ls -td snapshots/*_pre-ftpm 2>/dev/null | head -1)
echo "   快照目录: ${SNAP:-（未生成）}"

# ---------------------------------------------------------------- 1. 探测
ok "1/6 探测 SMI 端口 + IHISI 主功能号（只读，不发 SMI）"
./insyde-nvram ihisi --discover --func "$FUNC" || die "端口都拿不到，通道无从谈起"

# ---------------------------------------------------------------- 2. 握手
ok "2/6 握手：子功能 0x10（IsSupportIhisi，无副作用）"
if ! ./insyde-nvram ihisi --ping --func "$FUNC"; then
    warn "握手没通过。按代价从低到高试："
    warn "  a) 换驱动自己的回退值：  sudo bash $0 --func 0xEF"
    warn "  b) 确认端口：            sudo python3 tools/fseg_scan.py --all"
    warn "  c) SMM 不接受用户态 SMI：退回 Windows + H2OUVE"
    die  "通道没通，绝不继续写"
fi

# ---------------------------------------------------------------- 3. 原样写回
ok "3/6 原样写回（真实 0x01 报文，写入内容与现状完全相同）"
if ! ./insyde-nvram probe --record Setup --via ihisi --func "$FUNC" --yes; then
    warn "原样写回失败 = 0x01 这条报文没被 SMM 接受。"
    warn "此时 NVRAM 没有被修改（写进去的就是原来的字节），可以放心重试。"
    die  "报文格式或通道参数还要再调，别急着做真实改动"
fi

# ---------------------------------------------------------------- 4. 空跑
ok "4/6 空跑：跑完全部门禁，不写"
./insyde-nvram apply "$PATCH" --via ihisi --dry-run --func "$FUNC" \
    || die "门禁没过，先看上面哪一条是红的"

if [ "$CHECK_ONLY" = "1" ]; then
    echo
    echo "==check-only== 到此为止，没有写入任何字节。"
    exit 0
fi

# ---------------------------------------------------------------- 5. 写
ok "5/6 准备真写"
cat <<'TXT'
写完之后请立刻做两件事，不要跳过：
  1. 完整关机（poweroff，不是 reboot），再冷开机 —— 固件要在冷启动时初始化 TPM
  2. 开机后跑 ./insyde-nvram tpm，看有没有 /dev/tpm0
TXT
echo
printf '确认写入请输入大写 YES：'
read -r ans
[ "$ans" = "YES" ] || { echo "已取消，未写入"; exit 0; }

./insyde-nvram apply "$PATCH" --via ihisi --func "$FUNC" --yes
RC=$?

# ---------------------------------------------------------------- 6. 校验
ok "6/6 读回核对"
./insyde-nvram check "$PATCH" || true

echo
if [ "$RC" = "0" ]; then
    echo "退出码 0 = 写入流程走完。但「写进去了」和「fTPM 生效了」是两件事："
    echo "  NVRAM 层：Setup 0x100 现在应当是 0x02（上面 check 的 now= 列）"
    echo "  固件层  ：要冷启动一次，./insyde-nvram tpm 才能看到 /dev/tpm0"
    echo
    echo "如果 check 仍显示 now=0x00，说明 SMM 收下报文但没落盘 —— 不要反复写，"
    echo "先看 logs/ 里最近那份 apply 日志里的状态字节。"
else
    echo "退出码 $RC，写入没有完成。把上面的输出发我，我按状态字节判断是报文被拒"
    echo "还是通道没通。NVRAM 未被修改（或已被工具回滚）。"
fi
exit "$RC"
