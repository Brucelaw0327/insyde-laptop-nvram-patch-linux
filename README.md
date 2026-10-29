# insyde-nvram（Linux / efivarfs 版）

**在 Insyde H2O 笔记本上安全地定位并修改 BIOS Setup 里被隐藏的设置项** —— 不刷 BIOS、不清 CMOS、不进 BIOS 菜单，直接编辑支撑该设置的 NVRAM 变量。

这是 [insyde-laptop-nvram-patch](https://github.com/Brucelaw0327/insyde-laptop-nvram-patch)（Windows / H2OUVE 版）的 Linux 对照实现，为 **TIMI A7S / TM2037（Redmi G 2021 锐龙版，R7 5800H，Insyde H2O）** 实测通过。

> ⚠️ **这会改固件 NVRAM。它可能让机器变砖。** 读 [DISCLAIMER.md](DISCLAIMER.md) 和 [docs/how-it-works.md](docs/how-it-works.md) 再动手。
>
> 🚀 **只想赶紧用起来？** 看 [QUICKSTART.md](QUICKSTART.md) —— 哪个命令在本机真能用、三种典型场景的照抄命令、退出码对照。下面是完整文档。

---

## 1. 复刻了什么，换掉了什么

| | Windows 版 | 本版 | 说明 |
|---|---|---|---|
| 写入通道 | H2OUVE + `segwindrv` 内核驱动（SMI 服务） | **efivarfs**（内核 SetVariable） | 不需要任何厂商工具或驱动 |
| 转储 | `H2OUVE -gv` | 直接读 `/sys/firmware/efi/efivars` | 免安装，免管理员 |
| 补丁文件格式 | `NAME/VARSTORE/GUID/RECORDS/OFFSET/FROM/TO` 或 `CHANGE` | **完全相同** | 已有 `.patch` 直接可用 |
| 身份门禁 | 注册表 BIOS/BOARD/MODEL | `/sys/class/dmi/id/*` | 同样的三道值 |
| 加密门禁 | BitLocker / TPM 保护卷 | LUKS + systemd-tpm2 token | 同一个风险，换了个外壳 |
| 逐字节回滚 | `undo_<slug>.txt` | `undo/<slug>.<record>.bin` | 首次写入前生成，永不覆盖 |
| 偏移定位 | `tools/ifr_locate.py` 解 IFR | **同一个脚本，未改一行** | 纯 Python，本来就跨平台 |
| 最小记录文件 | `setup_new.txt` / `setup_undo.txt`（喂给 `-sv`） | 不需要 | SetVariable 一次写整个变量 |

工作单元仍然是那个小文本文件：**patch** 说「在这个变量存储的这条记录里，把 0xNNN 从 0xA 改成 0xB」。所有闸门、快照、校验、回滚都围着它转。

**补丁里没有一个预置偏移。** 偏移描述的是某一版固件的内存布局，预置补丁对别的机器就是「自信地标注的错答案」。你机器上的偏移必须自己推导并证明。

---

## 2. 本机实测（TIMI A7S，BIOS RMGCZ6T0P0909，2022-05-06）

```
/proc/... 身份        TIMI / A7S / TM2037 / BIOS TIMI RMGCZ6T0P0909
变量存储              A04A27F4-DF00-4D42-B552-39511302113D
  Setup               700 字节  attrs=0x07 (NV|BS|RT)
  Custom              700 字节  attrs=0x07 (NV|BS|RT)
Secure Boot           关闭
TPM                   fTPM 关闭（固件层）：无 /dev/tpm0、ACPI 无 TPM2/TCPA 表、
                      SMBIOS 无 Type 43；内核 tpm_crb 是 builtin，排除驱动因素
加密卷                无 LUKS
引导                  Limine（efibootmgr 里有 Windows / OpenCore / Limine 三项）
写入通道              **Setup 被固件写保护**：write() 返回 EROFS = EFI_WRITE_PROTECTED
                      （open 成功、write 被拒，`probe --scan` 可复核；见第 9 节）
```

两条记录**内容不完全相同**：`0x061 / 0x066 / 0x0A8 / 0x226` 四处不一致（这是「当前设置」与「用户自定义默认值」的差别）。所以补丁默认只写 `Setup`；如果你确实要连 `Custom` 一起改，先看 [docs/making-a-patch.md](docs/making-a-patch.md) 第 6 节。

### fTPM 的偏移已由固件自证

拿官方升级包 `RMGCZ6T0P0909.zip` 拆出 `Cert_A7S_NAC.fd`，`tools/ifr_locate.py` 在里面定位到：

```
Trust Platform Module   [OneOf]   formset='Advanced' / form='Peripheral Configuration'
varstore SystemConfig   guid A04A27F4-DF00-4D42-B552-39511302113D
VarOffset = 0x100   0=Disable  1=Enable discrete TPM  2=Enable firmware TPM
实机 0x100 = 0x00 -> Disable     ← 与「fTPM 关闭」的判定一致
```

这不是猜：IFR 声明该 VarStore 为 `0x2BC` = 700 字节，与实机变量长度一致；`verify` 逐项比对时几十个设置的实机字节全部落在声明取值内。全套命令见 [docs/from-bios-package.md](docs/from-bios-package.md)，成品补丁见 `patches/ftpm-enable-RMGCZ6T0P0909.patch`。

---

## 3. 安装

```bash
cd insyde-nvram-linux
./insyde-nvram status          # 只读，首次运行会生成 machine.txt
sudo ./install.sh              # 可选：装到 /usr/local/bin，符号链接不复制
```

只依赖 Python 3 标准库和 `lsblk`。`cryptsetup` 只在你真的用 LUKS 时才需要。

---

## 4. 五个操作

```bash
insyde-nvram status                     # 1 只读探针：身份/变量/TPM/加密/通道
insyde-nvram dump --label before        # 2 打快照（差分定位的第一步）
insyde-nvram check  patches/xxx.patch   # 3 只读：它会动哪个字节，现在是几
sudo insyde-nvram apply patches/xxx.patch --dry-run   # 4 跑完所有门禁但不写
sudo insyde-nvram apply patches/xxx.patch             # 4 真的写
sudo insyde-nvram restore patches/xxx.patch           # 5 逐字节回滚
sudo insyde-nvram probe --record Setup                # 6 通道探针（原样写回）
sudo insyde-nvram probe --scan                        # 6 通道扫描（分清哪种封锁）
insyde-nvram export patches/xxx.patch --out export/x  # 7 离线导出（换通道时用）
insyde-nvram tpm                        # 8 fTPM 状态判定 / 开启实验（第 12 节）
```

`./run.sh` 是菜单前端，对应原仓库的 `run.cmd`。

**先跑 `probe`。** efivarfs 能读不代表能写：`Setup` 变量在 efivarfs 里带 `immutable` inode 标志，而且固件可以用 `EFI_WRITE_PROTECTED` 直接驳回对它的 `SetVariable`（本机就是这种情况，报错文字会显示成 `Read-only file system`）。`probe` 只把**当前字节原样写回**再比对 —— 它不改任何值，失败也没有副作用，但它能提前告诉你这条路通不通。

---

## 5. 补丁格式

```
NAME     = fTPM -> Disable          # 自由文本，出现在日志和回滚提示里
VARSTORE = SystemConfig             # 仅用于日志；真正标识存储的是 GUID
GUID     = A04A27F4-DF00-4D42-B552-39511302113D
RECORDS  = Setup                    # 这条存储里的记录名（逗号分隔）

OFFSET   = 0x100                    # 一处改动写成三个键
FROM     = 0x02
TO       = 0x00
```

多处改动用 `CHANGE`（与 `OFFSET/FROM/TO` **互斥**）：

```
CHANGE   = 0x100 0x02 0x00
CHANGE   = 0x2A0 0x01 0x00
```

`#` 是注释（整行或行内空白之后）。值为十六进制，带不带 `0x` 都行。完整规则见 [docs/making-a-patch.md](docs/making-a-patch.md)。

**偏移是「变量数据内偏移」** —— 不含 efivarfs 那 4 字节属性头。`dump` 出来的 `.bin` 直接就是数据，`show` 打印的行号就是补丁里该写的偏移。

---

## 6. 偏移从哪来

### 路线 A：从固件 IFR 定位并证明（推荐，和原仓库一致）

`tools/ifr_locate.py` 拿过来用，纯 Python、跨平台。实测跑通于 Xiaomi 官方包
`RMGCZ6T0P0909.zip`（详见 [docs/from-bios-package.md](docs/from-bios-package.md)）：

```bash
# 1. 拆包：zip → exe(7z SFX) → Cert_A7S_NAC.fd → SetupUtility FFS
python3 tools/ifr_locate.py extract ~/Downloads/RMGCZ6T0P0909.zip --out fw/extract

# 2. 按关键词定位，直接生成候选补丁存根
python3 tools/ifr_locate.py find fw/extract/Setup_*.ffs "trust platform" \
        --out patches/tpm.patch

# 3. 用真实转储证明这个偏移确实解释得了实机字节
python3 tools/ifr_locate.py verify fw/extract/Setup_*.ffs \
        snapshots/<某次>/vars_live.txt
```

`extract` 只挖出 SetupUtility 那一支 FFS（本机 147 条设置）；AMD CBS / PBS、
Secure Boot 这些 formset 在 LZMA 压缩卷里，要先解开整片镜像才能定位（1028 条）：

```bash
python3 tools/fw_unpack.py fw/RMGCZ6T0P0909/Cert_A7S_NAC.fd -o fw/
python3 tools/ifr_locate.py find fw/p1.fd tpm
```

第 3 步是用**你自己**的快照做的：`dump` 除了写 `.bin`，还会写一份 `vars_live.txt`，格式与 `H2OUVE -gv` 完全一致 —— 原仓库的 `ve_parse.py` 和 `ifr_locate.py verify` 不用改就能解析（已实测）。

`verify` 失败就意味着偏移不是你以为的那个。**不要写。**

### 路线 B：差异化定位（不碰固件镜像，Linux 上最省事）

无法拿到 BIOS 升级包时，用「改一项、比一次」的办法把偏移钉死：

```bash
sudo insyde-nvram dump --label before
# 完全关机 → 进 BIOS Setup → 只改一项设置 → 保存退出 → 回到系统
sudo insyde-nvram dump --label after
insyde-nvram diff snapshots/*before snapshots/*after \
    --guid A04A27F4-DF00-4D42-B552-39511302113D --out patches/candidate.patch
```

这条路只证明「改了那一项之后，这些字节变了」，不证明「这些字节就是那一项」。验证办法是**改回去再比一次**：差异应当只剩这几处，且方向相反。细节和纪律见 [docs/making-a-patch.md](docs/making-a-patch.md) 第 4 节。

---

## 7. 闸门与退出码

`apply` 写任何字节之前，无论补丁内容是什么，都跑同一组闸门：

| 闸门 | 检查什么 | 退出码 |
|---|---|---|
| root | 是不是真的 root（不是就不能写） | 3 |
| 补丁 | GUID / RECORDS / 十六进制 / 重复偏移 / `FROM==TO` | 2 |
| 身份 | BIOS / 主板 / 机型 与 `machine.txt` 一致 | 7（缺 `machine.txt` 为 6） |
| 加密 | 没有把密钥密封进 TPM 的卷 | 11（无法判定为 12） |
| 布局 | 变量长度与基线/补丁声明一致 | 8 |
| 取值 | 每个 `FROM` 都与实机当前字节一致 | 8（读不到为 4） |
| 合理性 | 构建出的目标数据里确实是 `TO` | 5 |
| 通道 | 固件接受 SetVariable | 13（写进被篡改为 14） |
| 校验 | 回读逐字节比对 | 1 |

`--force` **一次性跳过所有门禁**。它为已经进不了卷的操作者而存在，不是便利开关。门禁报警时「加 `--force`」的直觉，应该停下来读错误信息。

---

## 8. 回滚

```bash
sudo insyde-nvram restore patches/xxx.patch
```

读 `undo/<slug>.<record>.bin` —— 该补丁**第一次**写入前的逐字节原始副本。工具永不覆盖它（每次写入另存一份 `undo/pre_*` 审计副本），也不该移动或编辑它。

回滚只**报告**加密状态、不闸它：如果一个卷已经躺在恢复模式里，把 TPM 放回去才是修复。

---

## 9. 通道被拦怎么办

**本机实测结论（2026-10-30）**：`Setup` 变量写入返回 `EFI_WRITE_PROTECTED`，内核把它映射成 `EROFS`，所以报错文字是 `Read-only file system`（跟文件系统无关）。`open()` 是成功的，被拒的是 `write()` —— 也就是固件在 `SetVariable` 里驳回了这条变量。这正是 H2OUVE 的 SMI 通道存在的理由。

先分清是哪种封锁：

```bash
sudo insyde-nvram probe --scan
```

它会做两件事，结果写进 `logs/channel.json`（`status` 会显示）：

- 建一个一次性变量 `InsydeNvramProbe` 再删掉 → 判断**普通 SetVariable 通不通**
- 逐个写回每个 Setup 类变量的原字节 → 判断**哪几条被单独保护**

| 扫描结果 | 含义 | 出路 |
|---|---|---|
| 临时变量失败 | 整条 efivarfs 写路径被封（固件没声明 SET_VARIABLE） | 只能换通道 |
| 临时变量成功、`Setup` 失败 | 固件只保护了 `Setup` 这一条 | 其它标记「可用」的存储照常能 apply；`Setup` 换通道 |
| 全部可用 | 通道没问题 | 直接 apply |

换通道，按代价排序：

1. **Windows + H2OUVE**（最省事，这台机器有 Windows 分区）。补丁文件格式完全通用，把 `patches/*.patch` 拷过去用原仓库的 `apply_patch.ps1` 写。
2. **UEFI Shell + RU.EFI**。有些 Insyde 只在 runtime（虚拟模式）调用时拒绝，boot services 里执行的应用能写进去 —— 值得一试。手动按字节改，位置用下面 `export` 出的改动表。
3. **GRUB 的 `setup_var`**。需要在 U 盘里装一份带该模块的 GRUB；本机引导是 Limine，没有 GRUB，所以要先准备 U 盘。
4. **离线导出**（任何通道都能用，不含写入动作）：

   ```bash
   insyde-nvram export patches/xxx.patch --out export/xxx
   # export/xxx/target.Setup.bin  完整的 700 字节目标值
   # export/xxx/changes.txt       偏移 + 当前值 → 目标值 + 上下文
   ```

不要在没有回滚手段的情况下反复试。每换一条通道，先用它写回**原字节**验证通道，再写真实改动。

---

## 10. 什么时候设置会丢

- 刷写 / 更新 BIOS，或清 CMOS
- 在 BIOS Setup 里选 *Load Setup Defaults* 并保存
- 普通 *Save and Exit* 无害：它只是把 `Setup` 变量现有内容写回去

改完之后必须**完全关机（`poweroff`）**再开机 —— 设置项在开机早期被固件消费，`reboot` 不算。

---

## 11. 目录

```
insyde-nvram          主程序（Python 3，标准库，无第三方依赖）
run.sh                菜单前端（对应 run.cmd）
install.sh            符号链接到 /usr/local/bin
machine.txt           身份基线（首跑自动生成，git 忽略）
machine.sample.txt    手工模板
patches/              补丁（仓库不预置，见 patches/README.md）
snapshots/            每次 dump 的快照（.bin + dump.txt + vars_live.txt + meta.json）
undo/                 原始字节副本（<slug>.<record>.bin 与 pre_* 审计副本）
export/               export 的离线产物（target.*.bin + changes.txt）
logs/                 apply / restore 的完整日志；logs/channel.json 记着上次探针结果
tools/ifr_locate.py   从固件 IFR 定位偏移（原仓库脚本；本版修了两处 Linux 问题）
tools/fw_unpack.py    解开镜像里 GUID 定义的 LZMA 压缩卷（拿全量 formset 用）
tools/ve_parse.py     解析 H2OUVE 格式转储（原仓库脚本，未改）
docs/how-it-works.md  通道原理、为什么不刷 BIOS、为什么 poweroff
docs/making-a-patch.md 补丁格式、定位纪律、一次一个 patch 的理由
docs/from-bios-package.md 从官方 BIOS 升级包定位偏移的实测记录
fw/                   固件镜像与拆包产物（git 忽略，可由升级包重新生成）
```

---

## 12. fTPM 状态与开启

```bash
insyde-nvram tpm              # 只读：判定 fTPM 到底开没开
insyde-nvram tpm --baseline   # 打基线，并打印实验步骤
sudo insyde-nvram tpm --after snapshots/<基线> --out patches/ftpm-on.patch
```

`tpm` 不猜，只看固件说了什么，三条互相独立的证据：

| 证据 | 关着的样子 | 开着的样子 |
|---|---|---|
| `/sys/class/tpm/tpm0`、`/dev/tpm0` | 不存在 | 存在 |
| ACPI 表 `TPM2` / `TCPA` | **整张表都没有** | 有 |
| SMBIOS Type 43（TPM Device） | 没有这条记录 | 有 |

本机（TIMI A7S）三条全落在左边，而且内核里 `tpm_crb` 是 **builtin** —— 所以不是「驱动没加载」，是固件压根没向系统描述 TPM。判定的关键差别在这儿：

- ACPI 有 `TPM2` 表但没设备节点 → 固件开了，系统没接上，查驱动，**别动 NVRAM**
- 三样都没有 → 固件层就是关的，只能从 setup 里改

### 打开它，三条路

1. **BIOS 里直接开**（如果 setup 里看得见 TPM / Security Device / AMD fTPM switch）。有就直接开，用不着这个工具。
2. **差分实验**（推荐，也是唯一能同时拿到偏移的办法）：`tpm --baseline` → 重启进 BIOS **只改 fTPM 这一项** → 保存 → 回系统跑 `tpm --after`。它会告诉你两件事：字节差在哪、fTPM 到底起来没有。事后想反悔或者想批量部署，这几处字节就是一条补丁。
3. **改 NVRAM 写进去**：得有偏移（来自 2 或 IFR）＋一条能写的通道。本机写通道被固件拦着，这条路目前不通，见第 9 节。

### 两个坑

- **AMD 上 fTPM 首次启用要完全断电**（`poweroff` 或长按电源 10 秒），`reboot` 常常不够：PSP 得在冷启动时才会去初始化 fTPM。所以 `tpm --after` 报「字节变了但 TPM 还没起来」时先别下结论，先冷启动一次再看。
- **BitLocker / LUKS-TPM2 绑着的时候别动 fTPM**：清 fTPM 或换状态会触发恢复密钥。本机目前没有 LUKS，也没有 TPM2 token，所以是安全的。想给 LUKS 绑 TPM2：`systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0+7 <设备>`。

