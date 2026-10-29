# patches/

**这里按设计是空的。** 仓库不附带任何补丁。

理由和原仓库一样：一个补丁描述的是**某一版固件的字节布局**。同型号、同 BIOS 版本的两台机器上它可能有用；BIOS 一升级，布局就可能移位，而一个「看起来很像对的」补丁是最危险的东西 —— 它会被当真。

自己做一个：

```bash
# 路线 A：从固件 IFR 定位并证明
python3 tools/ifr_locate.py extract ~/Downloads/<升级包>.zip --out fw/extract
python3 tools/ifr_locate.py find fw/extract/Setup_*.ffs "<设置名>" --out patches/<名字>.patch
python3 tools/ifr_locate.py verify fw/extract/Setup_*.ffs snapshots/<某次>/vars_live.txt

# 路线 B：差异化定位
sudo insyde-nvram dump --label before
#   完全关机 → 进 BIOS Setup → 只改一项 → 保存退出
sudo insyde-nvram dump --label after
insyde-nvram diff <before目录> <after目录> --guid <GUID> --out patches/<名字>.patch
```

---

## 本机已生成的一份（不入库，但留在目录里）

`patches/ftpm-enable-RMGCZ6T0P0909.patch` —— fTPM 开关，`Setup[0x100]` `0x00 -> 0x02`。

- 偏移来自固件 IFR，不是差分猜的：`tools/ifr_locate.py` 在
  `Cert_A7S_NAC.fd` 里定位到 `Trust Platform Module`（`Advanced / Peripheral Configuration`），
  并用 `verify` 与实机转储对过账。全过程见 [docs/from-bios-package.md](../docs/from-bios-package.md)。
- **文件名带 BIOS 版本是必须的**：换固件版本必须重新走一遍流程，不能直接复用。
- 它被 `.gitignore` 里的 `patches/*.patch` 挡在版本库外 —— 这是有意的：
  补丁绑定具体固件布局，不该被当成通用配置传播。

格式、纪律、验证办法见 [../docs/making-a-patch.md](../docs/making-a-patch.md)。

写之前：

```bash
insyde-nvram check patches/<名字>.patch
sudo insyde-nvram apply patches/<名字>.patch --dry-run
```
