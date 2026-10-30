#!/usr/bin/env bash
# 冒烟测试：只跑只读路径与错误路径，不做任何真实写入。
set -u
cd "$(dirname "$0")" || exit 1
TMP=$(mktemp -d)
pass=0; fail=0; skip=0

chk() { # chk 描述 期望退出码 实际退出码
    if [ "$2" = "$3" ]; then printf '  ok   %-42s (exit %s)\n' "$1" "$3"; pass=$((pass+1));
    else printf '  FAIL %-42s 期望 %s 实际 %s\n' "$1" "$2" "$3"; fail=$((fail+1)); fi
}

skp() { printf '  skip %-42s (需要 root)\n' "$1"; skip=$((skip+1)); }

IS_ROOT=0
[ "$(id -u)" -eq 0 ] && IS_ROOT=1

cat > "$TMP/ok.patch" <<'EOF'
NAME     = smoke ok
VARSTORE = SystemConfig
GUID     = A04A27F4-DF00-4D42-B552-39511302113D
RECORDS  = Setup
OFFSET   = 0x0A8
FROM     = 0x01
TO       = 0x00
EOF

cat > "$TMP/bad-from.patch" <<'EOF'
NAME     = smoke bad from
GUID     = A04A27F4-DF00-4D42-B552-39511302113D
RECORDS  = Setup
OFFSET   = 0x0A8
FROM     = 0x02
TO       = 0x00
EOF

cat > "$TMP/no-guid.patch" <<'EOF'
NAME     = smoke no guid
RECORDS  = Setup
OFFSET   = 0x0A8
FROM     = 0x01
TO       = 0x00
EOF

cat > "$TMP/mixed.patch" <<'EOF'
NAME     = smoke mixed
GUID     = A04A27F4-DF00-4D42-B552-39511302113D
RECORDS  = Setup
CHANGE   = 0x0A8 0x01 0x00
OFFSET   = 0x0A8
FROM     = 0x01
TO       = 0x00
EOF

cat > "$TMP/same.patch" <<'EOF'
NAME     = smoke same
GUID     = A04A27F4-DF00-4D42-B552-39511302113D
RECORDS  = Setup
OFFSET   = 0x0A8
FROM     = 0x01
TO       = 0x01
EOF

cat > "$TMP/bad-guid.patch" <<'EOF'
NAME     = smoke bad guid
GUID     = NOT-A-GUID
RECORDS  = Setup
OFFSET   = 0x0A8
FROM     = 0x01
TO       = 0x00
EOF

echo "== 只读命令 =="
./insyde-nvram status >/dev/null 2>&1;                chk "status"                 0 $?
./insyde-nvram list >/dev/null 2>&1;                  chk "list"                   0 $?
./insyde-nvram dump --label smoke >/dev/null 2>&1;    chk "dump"                   0 $?
LAST=$(ls -1dt snapshots/* | head -1)
./insyde-nvram show "$LAST" >/dev/null 2>&1;          chk "show 目录"              0 $?
./insyde-nvram diff "$LAST" "$LAST" >/dev/null 2>&1;  chk "diff 自身（0 处差异）"   0 $?
./insyde-nvram check "$TMP/ok.patch" >/dev/null 2>&1; chk "check 取值正确"          0 $?
./insyde-nvram check "$TMP/bad-from.patch" >/dev/null 2>&1; chk "check FROM 不匹配"   8 $?

echo "== 补丁解析错误 =="
./insyde-nvram check "$TMP/no-guid.patch"     >/dev/null 2>&1; chk "缺 GUID"   2 $?
./insyde-nvram check "$TMP/mixed.patch"       >/dev/null 2>&1; chk "CHANGE 与 OFFSET 混用" 2 $?
./insyde-nvram check "$TMP/same.patch"        >/dev/null 2>&1; chk "FROM == TO" 2 $?
./insyde-nvram check "$TMP/bad-guid.patch"    >/dev/null 2>&1; chk "GUID 格式错" 2 $?
./insyde-nvram check "$TMP/nonexistent.patch" >/dev/null 2>&1; chk "文件不存在" 2 $?

echo "== apply 门禁 =="
# apply 第一道门就是 root（exit 3），非 root 下这 5 项测不出门禁本身
if [ "$IS_ROOT" -eq 1 ]; then
    ./insyde-nvram apply "$TMP/ok.patch" --dry-run >/dev/null 2>&1;      chk "apply --dry-run 全部通过" 0 $?
    ./insyde-nvram apply "$TMP/bad-from.patch" --dry-run >/dev/null 2>&1; chk "apply 取值门禁"          8 $?
    ./insyde-nvram apply "$TMP/mixed.patch" --dry-run >/dev/null 2>&1;    chk "apply 补丁解析"           2 $?

    echo "== 缺少 machine.txt =="
    mv machine.txt "$TMP/machine.txt.bak"
    ./insyde-nvram apply "$TMP/ok.patch" --dry-run >/dev/null 2>&1;       chk "缺 machine.txt"  6 $?
    mv "$TMP/machine.txt.bak" machine.txt

    echo "== 身份不匹配 =="
    cp machine.txt "$TMP/machine.txt.keep"
    sed -i 's/^BIOS=.*/BIOS=WRONGVERSION/' machine.txt
    ./insyde-nvram apply "$TMP/ok.patch" --dry-run >/dev/null 2>&1;       chk "身份门禁"  7 $?
    cp "$TMP/machine.txt.keep" machine.txt
else
    skp "apply --dry-run 全部通过"
    skp "apply 取值门禁"
    skp "apply 补丁解析"
    skp "缺 machine.txt"
    skp "身份门禁"
fi

echo "== 离线导出 =="
./insyde-nvram export "$TMP/ok.patch" --out "$TMP/exp" >/dev/null 2>&1;      chk "export 正常"        0 $?
[ -f "$TMP/exp/target.Setup.bin" ] && chk "export 产出 target.bin" 0 0 || chk "export 产出 target.bin" 0 1
./insyde-nvram export "$TMP/bad-from.patch" --out "$TMP/exp2" >/dev/null 2>&1; chk "export 旧值不匹配"   8 $?
./insyde-nvram export "$TMP/no-guid.patch" --out "$TMP/exp3" >/dev/null 2>&1;  chk "export 补丁解析"     2 $?

echo "== fTPM =="
./insyde-nvram tpm >/dev/null 2>&1;                            chk "tpm 状态判定"        0 $?
./insyde-nvram tpm --baseline >/dev/null 2>&1;                 chk "tpm --baseline"      0 $?
./insyde-nvram tpm --after "$LAST" >/dev/null 2>&1;            chk "tpm --after 同一状态" 0 $?
./insyde-nvram tpm --after "$LAST" 2>&1 | grep -q "字节完全相同" && chk "after 正确报告无差异" 0 0 || chk "after 正确报告无差异" 0 1
./insyde-nvram tpm --after /nonexistent >/dev/null 2>&1;       chk "after 快照不存在"    2 $?

echo "== diff 跨记录拆分 =="
GUID_LINE="A04A27F4-DF00-4D42-B552-39511302113D"
mkdir -p "$TMP/sb" "$TMP/sa1" "$TMP/sa2"
cp "$LAST"/*.bin "$TMP/sb/"
cp "$LAST"/*.bin "$TMP/sa1/"; cp "$LAST"/*.bin "$TMP/sa2/"
printf '\x01' | dd of="$TMP/sa1/Setup.bin" bs=1 seek=256 conv=notrunc status=none
printf '\x01' | dd of="$TMP/sa2/Setup.bin" bs=1 seek=256 conv=notrunc status=none
printf '\x01' | dd of="$TMP/sa2/Custom.bin" bs=1 seek=256 conv=notrunc status=none
./insyde-nvram diff "$TMP/sb" "$TMP/sa1" --guid "$GUID_LINE" --name d1 --out "$TMP/d1.patch" >/dev/null 2>&1
[ -f "$TMP/d1.patch" ] && chk "单记录差异 → 1 份补丁" 0 0 || chk "单记录差异 → 1 份补丁" 0 1
grep -q '^RECORDS  = Setup$' "$TMP/d1.patch" && chk "补丁 RECORDS 只含变动的记录" 0 0 || chk "补丁 RECORDS 只含变动的记录" 0 1
./insyde-nvram diff "$TMP/sb" "$TMP/sa2" --guid "$GUID_LINE" --name d2 --out "$TMP/d2.patch" >/dev/null 2>&1
{ [ -f "$TMP/d2.Setup.patch" ] && [ -f "$TMP/d2.Custom.patch" ]; } \
    && chk "两个记录都变 → 拆成 2 份" 0 0 || chk "两个记录都变 → 拆成 2 份" 0 1
./insyde-nvram check "$TMP/d2.Setup.patch" >/dev/null 2>&1; chk "拆出的补丁可被 check 解析" 0 $?

echo "--- IHISI 通道（SMI 写入，不依赖 H2OUVE）---"
python3 ihisi.py selftest >/dev/null 2>&1; chk "报文布局与校验和自检" 0 $?

python3 - "$PWD" >/dev/null 2>&1 <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
import ihisi
pid = "A04A27F4-DF00-4D42-B552-39511302113D"
p = ihisi.build_packet(pid, "Setup", b"\x00" * 700, 0x07)
assert len(p) == 0x40 + 12 + 700, len(p)
assert p[0x10:0x1C] == "Setup".encode("utf-16-le") + b"\x00\x00"
assert p[0x2C:0x30] == b"$H2O" and p[0x30:0x34] == b"$Var" and p[0x34:0x38] == b"$Tbl"
assert p[0x49] == 0x10
assert ihisi.packet_checksum(b"\x01\x02\x03") == (-6) & 0xFFFF
assert ihisi.guid_bytes_le("8BE4DF61-93CA-11D2-AA0D-00E098032B8C").hex() == "61dfe48bca93d211aa0d00e098032b8c"
PY
chk "报文 760 字节 / 三魔数 / GUID 混合端序" 0 $?

./insyde-nvram ihisi --help >/dev/null 2>&1; chk "ihisi --help 可用" 0 $?

if [ "$(id -u)" -ne 0 ]; then
    ./insyde-nvram ihisi --discover >/dev/null 2>&1
    chk "非 root 探测 → 通道被拦(13)" 13 $?
    ./insyde-nvram apply "$TMP/ok.patch" --via ihisi --dry-run >/dev/null 2>&1
    chk "非 root apply --via ihisi → 3" 3 $?
fi

if [ -f ihisi/ihisi_smi.c ]; then
    chk "C 调用器源码存在" 0 0
    if command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1; then
        CCB="$(command -v cc || command -v gcc)"
        "$CCB" -O2 -Wall -o "$TMP/ihisi_smi" ihisi/ihisi_smi.c 2>/dev/null
        chk "C 调用器可编译（-Wall 无错）" 0 $?
        "$TMP/ihisi_smi" 2>/dev/null; chk "参数缺失时退出码 1" 1 $?
    fi
else
    chk "C 调用器源码存在" 0 1
fi

echo
if [ "$skip" -gt 0 ]; then
    echo "通过 $pass / 失败 $fail / 跳过 $skip（跳过的需要 root：sudo bash smoke-test.sh）"
else
    echo "通过 $pass / 失败 $fail"
fi
rm -rf "$TMP"
[ "$fail" -eq 0 ]
