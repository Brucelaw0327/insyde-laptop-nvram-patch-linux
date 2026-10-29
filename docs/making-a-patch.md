# 制作一个 patch

一个 patch 是一份小文本文件，内容是：*在这个变量存储的这条记录里，把这些字节从 A 改成 B*。工具的所有用途之间，唯一不同的就是它 —— 闸门、快照、写入、回读校验、回滚全都一样。

这正是要点：偏移和取值住在一个你可以阅读、编辑、审阅的文件里，而不是埋在脚本里。

---

## 1. 格式

```
NAME     = fTPM -> Disable
VARSTORE = SystemConfig
GUID     = A04A27F4-DF00-4D42-B552-39511302113D
RECORDS  = Setup

OFFSET   = 0x100          # 一处改动，写成三个键
FROM     = 0x02
TO       = 0x00
```

多字节写法（一个 patch 改几个字节）：

```
CHANGE   = 0x100 0x02 0x00     # OFFSET FROM TO
CHANGE   = 0x2A0 0x01 0x00
```

规则：

- `#` 开头是注释 —— 整行，或行内空白之后。
- 键名不区分大小写；值为十六进制，带不带 `0x` 都行。
- `GUID` 带不带花括号都可以。
- `VARSTORE` 是自由文本，只用在日志里；真正标识存储的是 `GUID`，因为名字跨厂商不唯一。
- `RECORDS` 必填：它指名该存储**里面**的记录。本机是 `Setup`（也可写 `Setup,Custom`，见第 6 节）。
- `OFFSET/FROM/TO` 与 `CHANGE` **互斥**。混用是报错，不是猜。
- `SIZE` 可选：声明该记录的字节数，布局变了会被布局门禁抓住。

解析器会大声拒绝（退出码 2）：缺 GUID；GUID 格式错；缺 RECORDS；非十六进制值；`CHANGE` 不是三个 token；同一偏移出现两次；`FROM == TO`（一个什么都没改的 patch）；`FROM / TO` 超过单字节。

**偏移是变量数据内偏移**，不含 efivarfs 的 4 字节属性头。`insyde-nvram show <快照>` 打印的行号可以直接抄进补丁。

---

## 2. 路线 A：从固件 IFR 定位（推荐）

和 Windows 版完全一样，`tools/ifr_locate.py` 未改一行：

```bash
# 解包 BIOS 升级包（.zip/.exe/.fd 都行），拿到 Setup 模块
python3 tools/ifr_locate.py extract <升级包> -o out/

# 看变量存储和表单结构
python3 tools/ifr_locate.py scan out/Setup_*.ffs

# 按关键词定位，同时生成候选补丁存根
python3 tools/ifr_locate.py find out/Setup_*.ffs "Trust Platform Module" \
        --varstore SystemConfig --out patches/tpm.patch

# 拿真实快照证明「这个偏移确实解释得了实机字节」
python3 tools/ifr_locate.py verify out/Setup_*.ffs snapshots/<某次>/vars_live.txt
```

`find` 的输出是**建议**。保存前读一遍 —— 尤其确认它标成 `TO` 的取值真的是你想要的。

`verify` 打印 `RESULT: consistent -- the IFR layout explains this dump` 才算证明过。失败就意味着偏移不是你以为的那个，**不要写**。

`dump` 生成的 `vars_live.txt` 与 `H2OUVE -gv` 格式一致，所以原仓库的 `ve_parse.py` 也能直接读：

```bash
python3 tools/ve_parse.py snapshots/<某次>/vars_live.txt 0x100 Setup
```

---

## 3. 路线 B：差异化定位（不碰固件镜像）

拿不到 BIOS 升级包时最省事的路。原理：BIOS Setup 里改一项 → 保存 → 对比 NVRAM 前后差异。

```bash
sudo insyde-nvram dump --label before
# 完全关机 → 进 BIOS Setup → **只改一项** → 保存退出
sudo insyde-nvram dump --label after

insyde-nvram diff snapshots/20261030-*_before snapshots/20261030-*_after \
    --guid A04A27F4-DF00-4D42-B552-39511302113D \
    --name "my-setting" --out patches/my-setting.patch
```

输出长这样，并顺手写出候选补丁：

```
Setup: 2 处差异
   0x0A8  01 -> 00   上下文 00 00 00 00 01 00 00 00 00
   0x0A9  00 -> 01   上下文 00 00 00 01 00 00 00 00 01
```

### 纪律（很重要）

1. **一次只改一项。** 改两项，差异会混在一起，你没法知道哪几个字节属于哪一项。
2. **反向验证。** 再把那一项改回去，打第三份快照。差异应当只剩刚才那几处，且方向相反。只做单向比对就下手，是在赌。
3. **差分只证明相关性，不证明语义。** 「改了这项之后这些字节变了」≠「这些字节就是这项」。带联动逻辑的设置（比如切换显卡模式会顺带改一排策略位）会一次动好几个字节，其中有些不是设置本身。
4. **两值设置好办，多值枚举要当心。** 一个字节 0x00/0x01 来回跳，基本可以放心；如果它在选项间跳 0x00→0x02→0x05，先把每个候选值都走一遍，把取值表记下来再写补丁。

---

## 4. 检查，然后应用

```bash
insyde-nvram check patches/my-setting.patch          # 只读，看当前值
sudo insyde-nvram apply patches/my-setting.patch --dry-run   # 跑完全部门禁但不写
sudo insyde-nvram apply patches/my-setting.patch     # 写
```

`check` 的三种结论：

| 输出 | 含义 |
|---|---|
| `当前 0x01 → 0x00  可应用` | 旧值对上，可以写 |
| `当前 0x00（已是目标值）` | 已经改过，或本来就是这个状态 |
| `当前 0x03 ≠ FROM 0x02 ≠ TO 0x00  不匹配` | 偏移不是你以为的那个 → 退出码 8，别写 |

`apply` 会打印将要发生的每一处改动，然后要求输入补丁名或 `YES`。

写完之后**完全关机**（`poweroff`），再开机才生效。`reboot` 不算。

---

## 5. 撤销

```bash
sudo insyde-nvram restore patches/my-setting.patch
```

写回 `undo/<slug>.<record>.bin` —— 该补丁第一次写入前的逐字节原始副本。这个文件是原始字节的唯一记录：工具不会删它，也不该移动或编辑它。

每次写入还会另存 `undo/pre_<slug>_<时间戳>.<record>.bin` 作为审计副本，方便回溯「第三次写入前是什么样」。

---

## 6. 关于 `RECORDS = Setup,Custom`

本机两份记录的字节并不完全一致（`Setup` 与 `Custom` 在 `0x061 / 0x066 / 0x0A8 / 0x226` 上不同）。它们分别是「当前设置」和「用户自定义默认值」。

- 只写 `Setup` 是常态：改完就生效。
- 写 `Setup,Custom` 的意义是「连自定义默认值一起改」，这样下次 Load User Defaults 也不会把它带回来。
- 但**同偏移旧值不同**时，取值门禁会报错并列出两边的值 —— 这是有意的：工具不会替你决定该覆盖哪一边。要写就分开写两个补丁，各自声明正确的 `FROM`。

`diff` / `tpm --after` 自动生成的补丁**永远只含一个记录**：差异落在两个记录上时，会拆成 `<名字>.Setup.patch` 和 `<名字>.Custom.patch` 两份。理由在于 `apply` 的语义 —— 同一组偏移会套到 `RECORDS` 里的**每一条**记录上，所以把两个记录的改动合成一份，等于顺手改了另一份里你根本没动过的字节。

---

## 7. 一次一个 patch —— 本版与 Windows 版的差别

Windows 版永远从 `vars_orig.txt`（干净首份转储）重建最小记录文件，所以 patch A、B 碰到同一记录时，先 A 后 B 会**把 A 撤掉**。那是为了「记录文件永远表示干净状态 + 恰好这些字节改动」，是唯一能被安全验证和回滚的东西。

本版直接改整条变量的当前字节，所以 A、B 可以**叠加**。代价是「当前字节」成了隐含输入 —— 因此：

- 每个 `FROM` 必须对上实机当前值（硬门禁，退出码 8）
- 写入后回读，非目标字节被改动会明确报出来
- 回滚以「首次写入前」为基准，不是「上一次写入前」

要一次改多个字节，放进**同一个** patch，而不是拆成两个：

```
CHANGE   = 0x0A8 0x01 0x00
CHANGE   = 0x2A0 0x01 0x00
```

---

## 8. 已移除的旧路径

更早的 Windows 版本把偏移放在 `machine.txt` 里（`TARGET_OFFSET/FROM/TO`、`FTPM_OFFSET/ON/OFF`）。那条路在新版和本版里都**不存在**：字节改动只能由 patch 文件描述，`machine.txt` 只做身份闸门。原因没变 —— 藏在 git 忽略文件里的偏移无法 diff、无法审阅，而内置的默认偏移就是某一家固件布局披着通用外衣。
