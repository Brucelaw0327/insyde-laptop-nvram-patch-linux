# QUICKSTART —— 这台机器上怎么用

先记住一句话：**读能用，写不通。** 所以本机当前它的角色是「定位器 + 校验器 + 导出器」，不是写入器。

```bash
cd ~/WorkBuddy/2026-10-30-00-44-44/insyde-nvram-linux
./run.sh                # 菜单前端，不知道敲什么就用这个
./insyde-nvram --help   # 列全部子命令
```

---

## 1. 哪些命令在本机真的能用

| 命令 | 干什么 | 本机状态 |
|---|---|---|
| `status` | 身份 / 变量 / TPM / 加密 / 通道 | 可用（只读） |
| `list` | 列出 Setup 类变量 | 可用 |
| `tpm` | fTPM 开没开 | 可用 |
| `dump` | 打一份快照到 `snapshots/` | 可用 |
| `show` | 十六进制看快照 | 可用 |
| `diff` | 两份快照比字节 → 候选补丁 | 可用（主力） |
| `check` | 补丁会动哪个字节、当前是几 | 可用 |
| `export` | 算出目标字节 + 改动表 | 可用 |
| `probe` | 写通道诊断 | 可用（结论：被拦） |
| `apply` | 真的写 NVRAM | **不可用**，exit 13 |
| `restore` | 按 undo 回滚 | **不可用**，同一条通道 |

`apply` / `restore` 不可用不是 bug：固件对 `Setup` 变量的 runtime `SetVariable` 返回
`EFI_WRITE_PROTECTED`（内核映射成 `EROFS`，报错文字会误显示成 "Read-only file system"）。
换任何参数、加不加 `sudo` 都一样。

---

## 2. 场景 A：定位一项 BIOS 设置

### A1. 有官方 BIOS 升级包（首选，两条命令）

不用进 BIOS、不用改任何东西，偏移是固件自己说的：

```bash
python3 tools/ifr_locate.py extract ~/Downloads/RMGCZ6T0P0909.zip --out fw/extract
python3 tools/ifr_locate.py find fw/extract/Setup_*.ffs tpm
```

输出直接给你 `VarOffset`、取值表和一份候选补丁存根。再用实机转储对账：

```bash
python3 tools/ifr_locate.py verify fw/extract/Setup_*.ffs snapshots/<快照>/vars_live.txt
```

本机实测结果（BIOS `RMGCZ6T0P0909`）：

```
Trust Platform Module   SystemConfig   VarOffset=0x100
    0=Disable   1=Enable discrete TPM   2=Enable firmware TPM
```

细节和两个 Linux 坑见 [docs/from-bios-package.md](docs/from-bios-package.md)。

### A2. 没有升级包：差分定位

前提：这一项在 BIOS 界面里**看得见、能改**。目的是拿到它的偏移，好写进补丁。

```bash
# 1 基线快照
./insyde-nvram dump --label before

# 2 完全关机 → 进 BIOS Setup → 只改这一项 → 保存退出 → 回系统
#   （只改一项，改两项就分不清哪个字节对应哪项）

# 3 新快照
./insyde-nvram dump --label after

# 4 对比，顺手生成候选补丁
./insyde-nvram diff snapshots/<before目录> snapshots/<after目录> \
    --guid A04A27F4-DF00-4D42-B552-39511302113D \
    --name "xxx" --out patches/xxx.patch

# 5 校验：偏移是否合法、两个值是否像一对（比如 00/01）
./insyde-nvram check patches/xxx.patch

# 6 反向验证：改回去再快照一次，差异应当只剩同样这几处
```

第 6 步别省。差分只证明「改了之后这些字节变了」，不证明「这些字节就是你以为的那一项」——
同一趟里被固件顺带重算的字段也会混进来。

第 4 步有个细节：如果差异同时落在 `Setup` 和 `Custom` 上，工具会自动拆成
`xxx.Setup.patch` 和 `xxx.Custom.patch` 两份。这是有意的 —— `apply` 会把同一组偏移
套到 `RECORDS` 里**每一条**记录，合成一份就等于顺手改了另一份里你没动过的字节。

---

## 3. 场景 B：真要把它写进去

先试默认通道（efivarfs / SetVariable）：

```bash
sudo ./insyde-nvram apply patches/xxx.patch --dry-run   # 跑完所有门禁，不写
sudo ./insyde-nvram apply patches/xxx.patch             # 真写
```

本机会报 `Read-only file system` —— 那是固件返回 `EFI_WRITE_PROTECTED`（跟文件
系统无关）。**换 IHISI 通道**，这是 Linux 原生的绕行方案，不需要 H2OUVE、
不需要 Windows、不需要内核模块。

### B1. 一条命令跑完（推荐）

```bash
sudo bash scripts/enable-ftpm.sh               # 交互确认后写
sudo bash scripts/enable-ftpm.sh --check-only  # 只验通道，不写
```

它把五道门按顺序串起来，任何一步不符合预期就停：快照 → 探测 → 握手 → **原样
写回** → 空跑 → 写入 → 读回。其中「原样写回」是最关键的一步：用真实的 `0x01`
报文走完整条 SMI 链路，但写进去的字节和现在完全一样，**成功不改变任何东西，
失败也没有副作用**。它是「报文格式对不对」的唯一可靠判据。

### B2. 手动逐步跑

```bash
sudo ./insyde-nvram ihisi --discover --func 0x64        # 1 只读：端口 + 主功能号
sudo ./insyde-nvram ihisi --ping     --func 0x64        # 2 子功能 0x10，无副作用
sudo ./insyde-nvram probe --record Setup --via ihisi --func 0x64 --yes   # 3 原样写回
sudo ./insyde-nvram apply patches/xxx.patch --via ihisi --func 0x64 --dry-run
sudo ./insyde-nvram apply patches/xxx.patch --via ihisi --func 0x64     # 4 真写
```

`--func 0x64` 是因为**本机 F 段扫不到 `$IHISI` 标签**。扫描失败的原因已经查清：
`/dev/mem` 在 `CONFIG_STRICT_DEVMEM=y` 下对非 RAM 页给的是内核填充（熵 8.000、
256 个字节值全现、32 位全 0/全 1 各 0 个），**不是固件内容**，所以「扫不到」
不能说明标签不存在。`0x64` 这个值是从解压后的固件里直接读到的
（`p1.fd @ 0x3DBA34`，`"HFDM" "O2H$" "$IHISI" 0x64`），不是猜的。
驱动自己的回退值是 `0xEF`，握手失败时可以用 `--func 0xEF` 再试。

> **当前卡点**：实机 `--ping` 发出去后寄存器原样不动（`eax` 还是输入值、
> `ebx` 还是 `"O2H$"`），换 `0xEF` 也一样 —— 说明 `out 0xB0` 根本没进 SMM。
> 端口和功能号都已确认，最可能的原因是固件在开启 NVRAM 写保护时
> 连带关掉了 IHISI 的 runtime 入口。诊断下一步：
>
> ```bash
> sudo python3 tools/fseg_scan.py --peek   # 不发 SMI：查 00b0 端口归属 + FADT 字段
> ```

报文格式、寄存器约定、已知限制见 **`docs/ihisi-channel.md`**。

> 注意：IHISI 通道的协议是从 H2OUVE 和固件里双向逆向确认的，报文构造有 20 项
> 自检，**「原样写回」能过就说明报文被 SMM 接受了**，但这仍不等于真实改动
> 一定成功 —— 第一次请按上面的顺序走，别跳过第 3 步。

再不行就离线导出，走手工通道。工具负责把「写什么」算准：

```bash
./insyde-nvram export patches/xxx.patch --out export/xxx
```

产出两个文件：

```
export/xxx/target.Setup.bin    # 700 字节完整目标数据（喂给工具）
export/xxx/changes.txt        # 偏移表 + 上下文，人看
```

然后二选一：

- **Windows + H2OUVE**：`patches/xxx.patch` 格式和你原仓库完全一致，
  拷到 Windows 侧直接用 `apply_patch.ps1` 写，不用改一个字符。
- **UEFI Shell + RU.EFI**：按 `changes.txt` 里的 `0x0A8 01 -> 00` 逐条改。
  有些 Insyde 只在 boot services 里放行，值得一试。

写完**必须完全关机（`poweroff`）再开机**，`reboot` 不算 —— 设置项在开机早期就被固件消费了。

`export` 会先核对补丁里的 `FROM` 和实机当前值，对不上直接 exit 8 拒绝导出。
理由：手工通道里没人会替你再核一遍旧值。

---

## 4. 补丁文件最小示例

```
NAME     = fTPM -> Enable
VARSTORE = SystemConfig
GUID     = A04A27F4-DF00-4D42-B552-39511302113D
RECORDS  = Setup
OFFSET   = 0x100
FROM     = 0x00
TO       = 0x01
```

多处改动就重复 `OFFSET/FROM/TO`，或者一律用单行写法 `CHANGE = 0x100 0x00 0x01`
（两种写法不能混在同一个补丁里）。

`FROM` 是**门禁**，不是注释：实机当前值和它对不上，工具的 `apply` / `export` 都会拒绝执行。

---

## 5. 退出码对照

| 码 | 含义 | 怎么办 |
|---|---|---|
| 0 | 成功 | — |
| 2 | 补丁文件本身有问题 | 看提示，多半是缺 GUID 或格式错 |
| 6 | 缺 `machine.txt` | 删掉它重新跑 `status` 生成 |
| 7 | 身份不匹配（换了机器/刷了 BIOS） | 确认是本机后删 `machine.txt` 重建 |
| 8 | 偏移/取值对不上 | `check` 看实机当前值，改 `FROM` |
| 11/12 | 加密卷状态不明 | LUKS 解锁/未解锁的判定，别硬来 |
| 13 | **写通道被固件拦** | 本机的常态，见场景 B |
| 14 | 写入被接受但字节被改了 | 最坏情况，立刻用另一通道回滚 |

---

## 6. 别做的事

- 别在没快照的情况下改 NVRAM。`dump` 是唯一的后悔药。
- 别一次改多项再 `diff`，出来的字节没法归因。
- 别在不同 BIOS 版本之间复用偏移。刷过 BIOS 就重新 `status` 并重建 `machine.txt`。
- 别看 `patches/` 里没有预置文件就以为坏了 —— 仓库刻意不带任何偏移，因为偏移跟 BIOS 版本绑定。
