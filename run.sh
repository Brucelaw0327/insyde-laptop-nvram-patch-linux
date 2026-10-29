#!/usr/bin/env bash
# run.sh -- 菜单前端，对应 Windows 版的 run.cmd。
# 一个菜单，三个引擎：只读探针 / 定位 / 写入与回滚。
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$HERE/insyde-nvram"

if [ ! -x "$BIN" ]; then
    chmod +x "$BIN" 2>/dev/null
fi

say() { printf '%s\n' "$*"; }
hr() { printf '%s\n' "------------------------------------------------------------"; }

list_patches() {
    local i=0 f
    PATCHES=()
    for f in "$HERE"/patches/*.patch; do
        [ -e "$f" ] || continue
        PATCHES+=("$f")
        i=$((i + 1))
        printf '  %d) %s\n' "$i" "$(basename "$f")"
    done
    [ "$i" -eq 0 ] && say "  (patches/ 里还没有 .patch —— 先用选项 2 定位并生成一个)"
    return 0
}

pick_patch() {
    list_patches
    [ "${#PATCHES[@]}" -eq 0 ] && return 1
    printf '选择编号: '
    read -r n
    case "$n" in
        ''|*[!0-9]*) say "无效编号"; return 1 ;;
    esac
    if [ "$n" -lt 1 ] || [ "$n" -gt "${#PATCHES[@]}" ]; then
        say "无效编号"; return 1
    fi
    PICKED="${PATCHES[$((n - 1))]}"
    return 0
}

while true; do
    hr
    say "insyde-nvram —— Insyde H2O NVRAM 补丁工具（Linux / efivarfs）"
    hr
    say "  1) 状态探针               只读：身份 / 变量 / TPM / 加密 / 通道"
    say "  2) 差异化定位             打快照 → 在 BIOS 改一项 → diff 出候选补丁"
    say "  3) 检查补丁               只读：这个补丁会动哪个字节，现在是几"
    say "  4) 应用补丁               写 NVRAM（多重门禁 + 逐字节校验）"
    say "  5) 回滚                   按 undo 副本写回原始字节"
    say "  6) 写通道探针             把原字节原样写回，判断固件让不让写"
    say "  0) 退出"
    hr
    printf '选择: '
    read -r choice || exit 0

    case "$choice" in
        1)
            "$BIN" status
            ;;
        2)
            "$BIN" list
            printf '\n先打一份基线快照？输入标签（回车用 before）: '
            read -r label
            [ -z "$label" ] && label="before"
            "$BIN" dump --label "$label" || continue
            hr
            say "接下来："
            say "  1. 完全关机，开机时进 BIOS Setup，只改**一项**设置，保存退出"
            say "  2. 回到这里选 2，用标签 after 再打一份快照"
            say "  3. 用 insyde-nvram diff <基线目录> <新目录> --out patches/xxx.patch"
            hr
            printf '现在就再打一份快照吗？标签（回车跳过）: '
            read -r label2
            if [ -n "$label2" ]; then
                "$BIN" dump --label "$label2" || continue
                latest=$(ls -1dt "$HERE"/snapshots/* | head -2 | tail -1)
                newest=$(ls -1dt "$HERE"/snapshots/* | head -1)
                printf '对比 %s → %s\n' "$latest" "$newest"
                printf '候选补丁输出到 patches/ 里，文件名（回车用 candidate.patch）: '
                read -r pname
                [ -z "$pname" ] && pname="candidate.patch"
                "$BIN" diff "$latest" "$newest" --out "$HERE/patches/$pname" \
                    --guid "$("$BIN" list | head -1)" --name "$pname"
            fi
            ;;
        3)
            pick_patch || continue
            "$BIN" check "$PICKED"
            rc=$?
            say ""
            say "退出码 $rc （0=可以应用，8=偏移/取值对不上）"
            ;;
        4)
            pick_patch || continue
            "$BIN" check "$PICKED" || { say "先别写，check 没过"; continue; }
            hr
            sudo "$BIN" apply "$PICKED"
            ;;
        5)
            pick_patch || continue
            sudo "$BIN" restore "$PICKED"
            ;;
        6)
            printf '目标记录名（回车用 Setup）: '
            read -r rec
            [ -z "$rec" ] && rec="Setup"
            sudo "$BIN" probe --record "$rec"
            ;;
        0|q|Q)
            exit 0
            ;;
        *)
            say "无效选项"
            ;;
    esac
    printf '\n按回车继续…'
    read -r _ || exit 0
done
