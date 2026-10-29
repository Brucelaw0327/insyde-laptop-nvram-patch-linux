# 工作原理

给动手之前想搞清楚「到底动了什么」的人看。

---

## 1. 一个字节是怎么跑到固件里的

BIOS Setup 界面上每一个选项，最后都落在某个 **UEFI 变量**的某个字节上。Insyde H2O 把这些变量放在 `SystemConfig` 这个变量存储里，本机实测是：

| 记录名 | 长度 | 属性 | 含义 |
|---|---|---|---|
| `Setup` | 700 字节 | `0x07` = NV\|BS\|RT | 当前生效的设置 |
| `Custom` | 700 字节 | `0x07` | 「用户自定义默认值」的一份副本 |

GUID：`A04A27F4-DF00-4D42-B552-39511302113D`。

界面只是这个字节的一个视图。菜单项被 OEM 藏起来，字节还在。改字节 = 改设置，不需要界面。

**刷 BIOS 是另一件事**：固件镜像不动，BIOS 版本号不变。这里改的是 NVRAM 里的一份数据。

---

## 2. 两条写入通道

### Windows 版：H2OUVE 的 SMI 服务

`Setup` 变量对 OS 是写保护的。Insyde 在 SMM 里留了一个服务，H2OUVE 通过 `segwindrv` 内核驱动去敲它。所以原仓库需要厂商工具 + 驱动 + 提权。

### 本版：efivarfs + SetVariable

Linux 把固件变量表挂成文件系统：

```
/sys/firmware/efi/efivars/Setup-a04a27f4-df00-4d42-b552-39511302113d
```

文件内容 = **4 字节属性头 + 变量数据**。读和写都走内核 → 固件 runtime service `SetVariable`。

三个必须知道的细节：

1. **偏移不含那 4 字节头。** 补丁里的 `OFFSET = 0x0A8` 指数据内的第 0xA8 个字节，也就是文件的第 0xAC 个字节。`dump` 写出的 `.bin` 已经剥掉头，所以 `show` 打印的行号就是补丁该写的数字。

2. **`immutable` inode 标志。** 内核会给这类变量打上 `FS_IMMUTABLE_FL`（`lsattr` 显示 `----i----`），直接 `open(O_WRONLY)` 会得到 `EPERM`。必须先清标志 —— 等价于 `chattr -i`。工具在 `write_var()` 里用 `FS_IOC_SETFLAGS` 自己做，不依赖 `e2fsprogs`。这个操作需要 `CAP_LINUX_IMMUTABLE`，容器 / 沙箱里通常没有。

3. **一次写整个变量。** efivarfs 的 `write()` 就是一次完整的 `SetVariable`，没有「改一个字节」的说法。Windows 版那套 `setup_new.txt` / `setup_undo.txt`（为了 `H2OUVE -sv` 而构造的最小记录文件）在本版**不需要**：目标数据 = 当前数据 + 恰好这些改动，一次写下去。

---

## 3. 通道被拦是什么样

固件可以在 `SetVariable` 的实现里做任何事情，包括对特定 GUID/名字的变量直接说「不行」。内核把 `EFI_STATUS` 翻译成 errno，所以报错看起来像 Linux 权限问题，其实全是固件在回答：

| 报错 | errno | 固件实际说的 | 含义 |
|---|---|---|---|
| `Read-only file system` | `EROFS` | `EFI_WRITE_PROTECTED` | 这条变量被写保护。**和文件系统无关** |
| `Input/output error` | `EIO` | `EFI_SECURITY_VIOLATION` 等 | 通用拒绝 |
| `Operation not permitted` | `EPERM` | 无（内核层） | inode immutable 没清掉，或在容器里 |
| `Operation not supported` | `EOPNOTSUPP` | 未声明 SET_VARIABLE | 整条写路径不可用 |

本机就是第一种：`open()` 成功、`write()` 返回 `EROFS`。这条区分很重要 —— 如果挂在 superblock 上的 `SB_RDONLY`，`open()` 就会在 `may_open()` 里先失败；既然 open 过了，说明挂载是 rw，拒绝来自固件。

`probe` 存在的意义就是把「能不能写」变成一次没有副作用的实验。它先把**当前字节原样写回**再比对。三种结果：

| 结果 | 含义 | 下一步 |
|---|---|---|
| `WRITE_OK` | 通道可用，字节没变 | 可以 apply |
| `WRITE_BLOCKED` | 固件拒绝，或你在容器里 | 换通道，见 README 第 9 节 |
| `WRITE_MUTATED` | 写被接受，但固件改了字节 | **不要**在这个通道上做真实改动 |

`probe --scan` 更进一步，把两种完全不同的封锁分开：

- 造一个一次性变量 `InsydeNvramProbe` 再删掉 → 普通 `SetVariable` 通不通
- 逐个写回每个 Setup 类变量的原字节 → 哪几条被单独保护

「连临时变量都建不出来」和「只有 `Setup` 被拒」是两件完全不同的事：前者是整条路径不可用，后者说明固件只保护了厂商关注的那几条，别的存储照常能改。

`WRITE_MUTATED` 是最坏的一种：它说明写入路径有副作用（校验和重算、双份变量同步之类），而工具的校验只覆盖它认识的那些字节。遇到它，先回滚，再换通道。

### 为什么 SMI 通道能绕过去

`EFI_WRITE_PROTECTED` 是 `SetVariable` 这个 runtime service 给出的回答。H2OUVE 不走它：它通过 `segwindrv` 向 SMM 发一个软件 SMI，SMM 里的代码直接改 NVRAM，根本不经过 `SetVariable`。所以固件对 `Setup` 的写保护只对「走标准路径的调用者」有效。

推论（值得一试，但没在这里验证过）：有些 Insyde 只在 **runtime / 虚拟模式** 调用时拒绝，boot services 里执行的 UEFI 应用（RU.EFI、UEFI Shell）可能写得进去。这也是为什么 README 第 9 节把 RU.EFI 排在 H2OUVE 之后、GRUB 之前。

---

## 4. 为什么必须完全关机

固件在 **PEI/DXE 早期**读 `Setup` 变量，把字节翻译成芯片寄存器、策略和菜单状态。之后的值只留在内存里：

- 写入 NVRAM → 变量表更新了
- 但已经启动的固件早读过它了
- `reboot` 有时会让固件从上次的内存状态续上，不重读

所以流程是 `poweroff` → 冷启动。这也是为什么 BIOS Setup 里改完要保存退出、而不是直接重启。

---

## 5. 为什么 `Setup` 和 `Custom` 会不一样

本机两份记录有 4 个字节不同（`0x061 / 0x066 / 0x0A8 / 0x226`）。`Custom` 是「用户自定义默认值」，在你没做过 *Save as User Defaults* 的机器上，它和当前值不一定同步。

后果：**同一处偏移在两份记录里可能有不同旧值**。所以

- 补丁默认只写 `Setup`（`RECORDS = Setup`）
- 如果写了 `RECORDS = Setup,Custom`，而那个偏移上两份的旧值不同，`apply` 会在取值门禁上直接报出来，而不是「两个都按补丁写死」——那会把 `Custom` 里原本的值也覆盖掉。

---

## 6. 校验策略

Windows 版的做法：写入后重新 dump，逐处比对目标值。

本版更严一点，分两级：

1. **强校验**：写后回读与目标数据**逐字节完全相同** → 通过。
2. **弱校验**：目标字节都到位了，但固件顺带改写了其它字节 → 报出来，列出被改的偏移，仍然算成功（因为那通常是固件自己的记账字段），但会在日志里留痕。
3. **失败**：目标字节没进去 → 退出码 1，提示回滚。

为什么允许弱校验存在：某些固件在 SetVariable 后会同步维护别处的状态，硬要求「一个字节都不许动」会让工具在正常机器上失败。但**不允许静默**——改了就说出来。

---

## 7. 爆炸半径

只改 NVRAM 里的一个变量。不会：

- 改固件镜像或 BIOS 版本
- 动 Secure Boot 密钥库（`PK` / `KEK` / `db`）
- 动引导项

会：

- 让依赖被改设置的功能失效（典型：关掉 fTPM 后，密封到 TPM 的 LUKS 自动解锁失效、Windows Hello / BitLocker 进恢复模式）
- 让机器在极端情况下不进 BIOS / 不引导。这类情况通常能靠拔电池 / 短接 CMOS 恢复默认值，但**不是保证**。

---

## 8. 和原仓库的差异清单（一句话版）

| 概念 | 原仓库 | 本版 |
|---|---|---|
| H2OUVE / segwindrv | 必需 | 不存在 |
| `-gv` 转储 | H2OUVE 生成 | 直接读 efivarfs，并输出同格式 `vars_live.txt` |
| 最小记录文件 | `setup_new.txt` | 不需要（整变量写） |
| 多补丁叠加 | 覆盖式（A 然后 B 会撤掉 A） | **增量式**（在实机当前字节上改，A 和 B 可叠加） |
| 加密门禁 | BitLocker | LUKS + systemd-tpm2 token |
| 回滚文件 | `undo_<slug>.txt` | `undo/<slug>.<record>.bin` + `pre_*` 审计副本 |

「多补丁叠加」这一条是唯一的行为差异，原因是写入模型不同：Windows 版永远从干净首份转储重建最小记录，本版直接改当前字节。代价是「当前字节」成了隐含输入 —— 所以取值门禁（每个 `FROM` 必须对上实机当前值）在本版是硬门禁，不是可选项。
