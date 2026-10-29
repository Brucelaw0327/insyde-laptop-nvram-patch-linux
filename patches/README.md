# patches/

**这里按设计是空的。** 仓库不附带任何补丁。

理由和原仓库一样：一个补丁描述的是**某一版固件的字节布局**。同型号、同 BIOS 版本的两台机器上它可能有用；BIOS 一升级，布局就可能移位，而一个「看起来很像对的」补丁是最危险的东西 —— 它会被当真。

自己做一个：

```bash
# 路线 A：从固件 IFR 定位并证明
python3 tools/ifr_locate.py find out/Setup_*.ffs "<设置名>" --out patches/<名字>.patch
python3 tools/ifr_locate.py verify out/Setup_*.ffs snapshots/<某次>/vars_live.txt

# 路线 B：差异化定位
sudo insyde-nvram dump --label before
#   完全关机 → 进 BIOS Setup → 只改一项 → 保存退出
sudo insyde-nvram dump --label after
insyde-nvram diff <before目录> <after目录> --guid <GUID> --out patches/<名字>.patch
```

格式、纪律、验证办法见 [../docs/making-a-patch.md](../docs/making-a-patch.md)。

写之前：

```bash
insyde-nvram check patches/<名字>.patch
sudo insyde-nvram apply patches/<名字>.patch --dry-run
```
