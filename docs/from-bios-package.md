# 从官方 BIOS 升级包定位偏移（实测记录）

对象：`RMGCZ6T0P0909.zip`（Xiaomi 官方，2022-05-06，TIMI A7S / Redmi G 2021 锐龙版）。
这台机器上跑的固件正是这个版本，所以下面每个偏移都对得上实机字节。

---

## 1. 拆包

```bash
python3 tools/ifr_locate.py extract ~/Downloads/RMGCZ6T0P0909.zip --out fw/extract
```

实测输出：

```
chain  : RMGCZ6T0P0909.zip -> RMGCZ6T0P0909.exe -> Cert_A7S_NAC.fd -> raw scan (18411160 bytes)
FFS    : fw/extract/Setup_FE3542FE-C1D3-4EF8-657C-8048606FF670.ffs  (2581654 bytes)
note   : 7 distinct copies found; wrote the largest.
```

`.exe` 是 7z 自解压（`Offset = 590965`），里面是 `Cert_A7S_NAC.fd` —— 18 MB 的完整镜像。

---

## 2. 定位

```bash
python3 tools/ifr_locate.py find fw/extract/Setup_*.ffs tpm
```

`tpm` 命中 8 条，其中三条是真正的开关（都在 `SystemConfig`，GUID `A04A27F4-…`）：

| 设置项 | 偏移 | 取值 | 实机当前 |
|---|---|---|---|
| **Trust Platform Module** | `0x100` | `0=Disable` `1=Enable discrete TPM` **`2=Enable firmware TPM`** | `0x00` → **Disable** |
| Enable LPC or SPI TPM | `0x102` | `0=Enable LPC TPM` `1=Enable SPI TPM` | `0x01` → SPI（已是正解） |
| Erase fTPM NV for factory reset | `0x107` | `0=Disable` `1=Enable` | `0x01` → Enable |

另有一组在 `formset='Security'`：`Current TPM Device` `0xE3`、`TPM Availability` `0x9D`、
`TPM Operation` `0x62`、`Clear TPM` `0x63`。

`0x107` 的帮助原文是 *“Control if need to erase the TPM NV when fTPM factory reset flag set.”* ——
它是「复位标志置位时才擦」，不是每次开机都擦，所以留着 Enable 是安全的。

---

## 3. 验证（这一步才叫证明）

```bash
python3 tools/ifr_locate.py verify fw/extract/Setup_*.ffs \
        snapshots/<快照>/vars_live.txt
```

```
IFR VarStore : 'SystemConfig'   guid=A04A27F4-DF00-4D42-B552-39511302113D   size=0x2BC
  record Custom     @0   len=700  size_field=0x2BC  size OK
     Trust Platform Module              0x100  = 0x0     -> Disable  (KNOWN value)
```

两条独立证据：

1. IFR 声明这个 VarStore 是 `0x2BC` = **700 字节**，实机 `Setup` / `Custom` 正好各 700 字节；
2. 逐项比对时，几十个设置的实机字节全部落在 IFR 声明的取值表里（`KNOWN value`），
   包括 `0x100 = 0x0 -> Disable`。

偏移不是猜的，是被这份固件自己解释出来的。

---

## 4. 拿到全部 1028 条设置

`extract` 只挖出 SetupUtility 那一支 FFS（147 条）。AMD CBS / PBS、Secure Boot、
网络配置这些 formset 住在 **LZMA 压缩卷**里，要先解开整片镜像：

```bash
python3 tools/fw_unpack.py fw/RMGCZ6T0P0909/Cert_A7S_NAC.fd -o fw/
#   [1] section @0x73a3c0  载荷 @0x73a3d8  -> fw/p1.fd  33788032 字节  10 个 FFS 卷
python3 tools/ifr_locate.py find fw/p1.fd tpm
```

整片镜像能定位 **1028** 条，`AMd_PBS_SETUP` / `AOD_SETUP` / `SecureBootData` 都在里面。

---

## 5. 两个真实坑

**`/tmp` 只有 10 MB。** Arch 系的 `/tmp` 是 tmpfs。`ifr_locate.py` 原先用
`tempfile.mkdtemp()` 解中间的 18 MB 镜像，直接 `errno=28 设备上没有空间`。
已改：workdir 落到 `--out` 指定的目录下。

**7-Zip 只认 Windows 的文件名。** 原候选表是 `bin\7za.exe`、`bin\7z.exe`、
`C:\Program Files\7-Zip\7z.exe`，Linux 上装了 7z 也报「this .exe is a 7z SFX」。
已补 `7zz` / `7za` / `7z` / `7zr`。

**`extract` 的目录参数是 `--out`，不是 `-o`。** 它挂在全局参数上。

---

## 6. 结论

fTPM 开关就是 `Setup[0x100]`，`0x00 → 0x02`。对应的补丁在
`patches/ftpm-enable-RMGCZ6T0P0909.patch`（只含这个偏移，且文件名带 BIOS 版本 ——
偏移与固件版本绑定，换版本必须重新走一遍本文流程）。
