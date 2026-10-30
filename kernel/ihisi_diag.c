// ihisi_diag.c —— 最小内核诊断模块
//
// 用户态被三道墙挡住（CONFIG_STRICT_DEVMEM / IO_STRICT / MMIO 隐藏），
// 本模块在内核态做三件只读的事，把数据交出来：
//
//   1) 内核态读 F 段 0xE0000..0xFFFFF 真实内容
//      —— 终极验证 $IHISI 是否真的在 F 段（用户态读到的是内核填充）
//   2) dump AMD FCH ACPI MMIO 0xFED80000 起的 0x800 字节
//      —— SMI_STATUS / SMI_EN 就在这一片，dump 出来人工分析
//   3) dump PM I/O 端口（FACP 的 PM1a_EVT_BLK 起 0x60 字节）
//      —— AMD FCH 的 SMI 控制寄存器部分落在 PM I/O 空间
//
// 用法：
//   sudo insmod ihisi_diag.ko [pm_evt=0xNNN] [mmio_base=0xFED80000]
//   cat /proc/ihisi_diag
//   sudo rmmod ihisi_diag
//
// 只读，不发任何 SMI，不写任何寄存器。

#include <linux/module.h>
#include <linux/io.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <asm/cacheflush.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("insyde-nvram-linux");
MODULE_DESCRIPTION("read-only IHISI/FCH diagnostics (F segment + ACPI MMIO + PM I/O)");
MODULE_VERSION("0.1");

static unsigned long pm_evt = 0x400UL;  /* X_PM1a_EVT_BLK GAS 实测 = 0x400
                                 * （FACP 32 位老字段 0xA1A0 是过时垃圾值，
                                 *  内核用的 64 位 GAS 才是真值） */
module_param(pm_evt, ulong, 0444);
MODULE_PARM_DESC(pm_evt, "PM1a_EVT_BLK I/O base (hex), default 0x400 for this machine");

/* 注意必须是 ulong：0xFED80000 超过 int 上限，用 int 会符号溢出成负数，
 * 再符号扩展给 phys_addr_t 就是 0xFFFFFFFF_FED80000 —— 前三轮 MMIO
 * "映射失败"全是这个 bug，不是 memtype 冲突 */
static unsigned long mmio_base = 0xFED80000UL;
module_param(mmio_base, ulong, 0444);
MODULE_PARM_DESC(mmio_base, "AMD FCH ACPI MMIO base");

#define FSEG_LO   0xE0000
#define FSEG_SIZE 0x20000
#define MMIO_SIZE 0x1000

static u8  *fseg_copy;          /* 内核态读到的 F 段副本 */
static int  fseg_ready;
static u8  *mmio_copy;          /* FCH ACPI MMIO 副本 */
static int  mmio_ready;
static char mmio_note[128];     /* 怎么读到的 / 为什么失败 */

/* ---------------- SMI 前后对比实验 ----------------
 * 在内核态发一次 out 0xB0, 0x64（与用户态 --ping 完全等价），
 * 前后各抓一份 FCH MMIO 快照并 diff。
 *   有 diff  → handler 在跑，diff 位置就是 SMI 状态寄存器
 *   零 diff  → SMI 未触发或无人处理（固件 runtime 关了 IHISI）
 * 加载参数: smi_test=1 启用。*/
static int smi_test;
module_param(smi_test, int, 0444);
MODULE_PARM_DESC(smi_test, "1 = send one IsSupportIhisi SMI and diff MMIO");

#define SNAP_OFF 0x000           /* 对比范围: MMIO_BASE+0 .. +0x400 */
#define SNAP_LEN 0x400
static u8  snap_a[SNAP_LEN], snap_b[SNAP_LEN];
static int  smi_test_done;
static int  smi_diff_count;
/* 最多记录 32 个差异字节（偏移 + before/after） */
#define MAX_DIFF_LOG 32
static unsigned long smi_diff_off[MAX_DIFF_LOG];
static u8  smi_diff_bef[MAX_DIFF_LOG], smi_diff_aft[MAX_DIFF_LOG];
static unsigned long smi_status_last;   /* 0xB0 回声 */


/* ------------------------------------------------------------ F 段 */

static void scan_fseg(void)
{
    void __iomem *p;
    int i, hits = 0, nonzero = 0, zero = 0, ff = 0;

    fseg_copy = kvmalloc(FSEG_SIZE, GFP_KERNEL);
    if (!fseg_copy)
        return;

    p = memremap(FSEG_LO, FSEG_SIZE, MEMREMAP_WB);
    if (!p) {
        p = memremap(FSEG_LO, FSEG_SIZE, MEMREMAP_WT);
        if (!p) {
            kvfree(fseg_copy);
            fseg_copy = NULL;
            return;
        }
    }
    memcpy_fromio(fseg_copy, p, FSEG_SIZE);
    memunmap(p);

    for (i = 0; i < FSEG_SIZE; i++) {
        u8 c = fseg_copy[i];
        if (c) nonzero++;
        if (c == 0x00) zero++;
        if (c == 0xFF) ff++;
    }
    /* $IHISI 全区间搜索（不要求对齐） */
    for (i = 0; i <= FSEG_SIZE - 6; i++) {
        if (!memcmp(&fseg_copy[i], "$IHISI", 6)) {
            hits++;
            pr_info("ihisi_diag: $IHISI @ %#x, +6 = %#x (主功能号)\n",
                    FSEG_LO + i, fseg_copy[i + 6]);
        }
    }
    /* 32 位全 0 / 全 1 字计数——判"是填充还是真固件"的硬指标 */
    {
        int w0 = 0, w1 = 0, words = FSEG_SIZE / 4;
        u32 *w = (u32 *)fseg_copy;
        for (i = 0; i < words; i++) {
            if (w[i] == 0x00000000u) w0++;
            if (w[i] == 0xFFFFFFFFu) w1++;
        }
        pr_info("ihisi_diag: F 段统计: 非零 %d / 0x00 %d / 0xFF %d, "
                "32位全0 %d 全1 %d (共 %d 字)\n",
                nonzero, zero, ff, w0, w1, words);
    }
    fseg_ready = 1;
    pr_info("ihisi_diag: F 段扫描完成, $IHISI 命中 %d 处\n", hits);
}

/* ------------------------------------------------------------ MMIO */

static void dump_mmio(void)
{
    mmio_copy = kvmalloc(MMIO_SIZE, GFP_KERNEL);
    if (!mmio_copy)
        return;

    /* 1) ioremap（UC）。对 0xFED80000 可能因 memtype 冲突失败
     *    （ACPI 核心/其它驱动常已把它映射为 WB，UC+WB = EBUSY） */
    {
        void __iomem *p = ioremap(mmio_base, MMIO_SIZE);
        if (p) {
            memcpy_fromio(mmio_copy, p, MMIO_SIZE);
            iounmap(p);
            mmio_ready = 1;
            strscpy(mmio_note, "ioremap (UC)", sizeof(mmio_note));
            goto done;
        }
    }
    /* 2) ioremap_cache（WB）——与 ACPI 核心的既有 WB 映射同类型，不冲突 */
    {
        void __iomem *p = ioremap_cache(mmio_base, MMIO_SIZE);
        if (p) {
            memcpy_fromio(mmio_copy, p, MMIO_SIZE);
            iounmap(p);
            mmio_ready = 1;
            strscpy(mmio_note, "ioremap_cache (WB, 同 ACPI 核心类型)",
                    sizeof(mmio_note));
            goto done;
        }
    }
    /* 3) memremap WT/WB */
    {
        void *p = memremap(mmio_base, MMIO_SIZE, MEMREMAP_WT);
        if (!p)
            p = memremap(mmio_base, MMIO_SIZE, MEMREMAP_WB);
        if (p) {
            memcpy(mmio_copy, p, MMIO_SIZE);
            memunmap(p);
            mmio_ready = 1;
            strscpy(mmio_note, "memremap fallback", sizeof(mmio_note));
            goto done;
        }
    }
    snprintf(mmio_note, sizeof(mmio_note),
             "UC/WB/memremap 全部失败（映射被内核拒绝）");
    pr_warn("ihisi_diag: FCH MMIO %#lx 无法映射\n", mmio_base);
    kvfree(mmio_copy);
    mmio_copy = NULL;
    return;

done:
    pr_info("ihisi_diag: FCH ACPI MMIO %#lx..%#lx 已拷贝（%s）\n",
            mmio_base, mmio_base + MMIO_SIZE - 1, mmio_note);
}

/* ------------------------------------------------------------ SMI 对比实验 */

static void mmio_snap(u8 *dst)
{
    void __iomem *p = ioremap(mmio_base, SNAP_LEN);
    if (p) {
        memcpy_fromio(dst, p, SNAP_LEN);
        iounmap(p);
    }
}

static void run_smi_test(void)
{
    int i;

    /* 快照 A */
    mmio_snap(snap_a);

    /* 内核态发 SMI：out 0xB0, 0x64 —— AL=主功能号 0x64，
     * 子功能号在 AH（0x10=IsSupportIhisi），由 SMM 从保存区读。
     * 与用户态 insyde-nvram ihisi --ping 完全等价。 */
    pr_info("ihisi_diag: 发送 SMI out 0xB0, 0x64 (IsSupportIhisi)\n");
    __asm__ __volatile__("outb %b0, %w1" :: "a"(0x64), "Nd"(0xB0));
    mdelay(100);                 /* 给 handler 充分时间 */

    /* 0xB0 回声（顺便看是否被改） */
    {
        unsigned char v;
        __asm__ __volatile__("inb %w1, %b0" : "=a"(v) : "Nd"(0xB0));
        smi_status_last = v;
    }

    /* 快照 B + diff */
    mmio_snap(snap_b);
    smi_diff_count = 0;
    for (i = 0; i < SNAP_LEN; i++) {
        if (snap_a[i] != snap_b[i]) {
            if (smi_diff_count < MAX_DIFF_LOG) {
                smi_diff_off[smi_diff_count] = i;
                smi_diff_bef[smi_diff_count] = snap_a[i];
                smi_diff_aft[smi_diff_count] = snap_b[i];
            }
            smi_diff_count++;
        }
    }
    smi_test_done = 1;
    pr_info("ihisi_diag: SMI 对比完成: %d 字节差异, 0xB0 回声=%#lx\n",
            smi_diff_count, smi_status_last);
}

/* ------------------------------------------------------------ DMA32 报文缓冲
 *
 * 用户态匿名页永远从高 zone 分配（Linux 物理分配自高向低），本机 32GB
 * 内存下 <4GB 的页用户态抢不到（实测 256 次全 >4GB，而 DMA32 free 有 3GB）。
 * 这里用 alloc_pages(GFP_DMA32) 直接向内核要低地址页 —— 等价于 Windows
 * 驱动的 MmAllocateContiguousMemorySpecifyCache(HighAddress=0xFFFFFFFF)。
 *
 * 用户态接口 /dev/ihisi_buf：
 *   read  → "paddr=0x%lx size=%lu\n"（物理地址与可用大小）
 *   mmap  → 把缓冲映射到用户态，报文写进去，SMM 经 ESI/EDI 读同一物理页
 *
 * 内核页无 MIGRATE_MOVABLE 标志，compaction 不迁移 → 物理地址恒定，
 * 用户态无需再复核 PFN。*/

static unsigned long buf_size;      /* 实际字节数 */
static unsigned long buf_paddr;
static void        *buf_vaddr;
static DEFINE_MUTEX(buf_lock);

static int buf_open(struct inode *ino, struct file *f)
{
    mutex_lock(&buf_lock);
    if (!buf_vaddr) {
        buf_size = 4 * PAGE_SIZE;                     /* order=2, 16KB */
        buf_vaddr = (void *)__get_free_pages(GFP_KERNEL | __GFP_DMA32 |
                                             __GFP_ZERO, 2);
        if (!buf_vaddr) {
            mutex_unlock(&buf_lock);
            return -ENOMEM;
        }
        buf_paddr = virt_to_phys(buf_vaddr);
        pr_info("ihisi_buf: DMA32 缓冲 paddr=%#lx size=%lu\n",
                buf_paddr, buf_size);
    }
    mutex_unlock(&buf_lock);
    return 0;
}

static ssize_t buf_read(struct file *f, char __user *u, size_t n, loff_t *pp)
{
    char line[96];
    int len;
    if (!buf_vaddr)
        return -ENODEV;
    len = snprintf(line, sizeof(line),
                   "paddr=0x%lx size=%lu\n", buf_paddr, buf_size);
    if (*pp >= len)
        return 0;
    len -= *pp;
    if (copy_to_user(u, line + *pp, min((size_t)len, n)))
        return -EFAULT;
    *pp += min((size_t)len, n);
    return min((size_t)len, n);
}

static int buf_mmap(struct file *f, struct vm_area_struct *vma)
{
    unsigned long want = vma->vm_end - vma->vm_start;

    if (!buf_vaddr)
        return -ENODEV;
    if (want > buf_size)
        return -EINVAL;
    vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);
    return remap_pfn_range(vma, vma->vm_start,
                           buf_paddr >> PAGE_SHIFT, want,
                           vma->vm_page_prot);
}

/* ------------------------------------------------------------ 物理内存读写 IOCTL
 *
 * IHISI VatsWrite/VatsRead 的硬性前提：报文必须落在 SMM 池里
 * （SMM 侧 FUN_0058f240 校验 [addr, addr+size) ⊂ [DAT_00596E6C, +0x30000)）。
 * 池基址由子功能 0x83 (GetCmdBuf) 经 RCX 返回（实测 0xCCDF4018）。
 * 用户态无法写 RAM 物理地址（STRICT_DEVMEM），这里用 memremap 代写。
 *
 * 用法（对 /dev/ihisi_buf ioctl）：
 *   struct ihisi_phys_io io = { .paddr=..., .len=..., .buf=(u64)userbuf };
 *   ioctl(fd, IHISI_PHYS_READ,  &io);
 *   ioctl(fd, IHISI_PHYS_WRITE, &io);
 */

struct ihisi_phys_io {
    __u64 paddr;
    __u64 len;      /* ≤ 0x1000，且不得跨页（简化校验） */
    __u64 ubuf;     /* 用户态缓冲指针 */
};

#define IHISI_PHYS_MAGIC  'H'
#define IHISI_PHYS_READ   _IOWR(IHISI_PHYS_MAGIC, 1, struct ihisi_phys_io)
#define IHISI_PHYS_WRITE  _IOWR(IHISI_PHYS_MAGIC, 2, struct ihisi_phys_io)

#define PHYS_MAX_LEN 0x1000

static long buf_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct ihisi_phys_io io;
    void *p;
    u8 *kbuf;
    long rc = 0;

    if (cmd != IHISI_PHYS_READ && cmd != IHISI_PHYS_WRITE)
        return -ENOTTY;
    if (copy_from_user(&io, (void __user *)arg, sizeof(io)))
        return -EFAULT;
    if (io.len == 0 || io.len > PHYS_MAX_LEN)
        return -EINVAL;
    if ((io.paddr & ~PAGE_MASK) + io.len > PAGE_SIZE)
        return -EINVAL;              /* 拒绝跨页，调用方按页拆 */

    /* memremap 对普通 RAM 走直接映射（__va），对设备内存走 ioremap。
     * 这里目标是 SMM 池（RAM），WB 直接映射即可。 */
    p = memremap(io.paddr, io.len, MEMREMAP_WB);
    if (!p)
        return -EFAULT;

    kbuf = kvmalloc(io.len, GFP_KERNEL);
    if (!kbuf) { memunmap(p); return -ENOMEM; }

    if (cmd == IHISI_PHYS_READ) {
        memcpy(kbuf, p, io.len);
        if (copy_to_user((void __user *)io.ubuf, kbuf, io.len))
            rc = -EFAULT;
    } else {
        if (copy_from_user(kbuf, (void __user *)io.ubuf, io.len))
            rc = -EFAULT;
        else {
            memcpy(p, kbuf, io.len);
            /* SMM 侧无缓存一致性要求（WB 同核共享），但保险起见刷行 */
            clflush_cache_range(p, io.len);
        }
    }

    kvfree(kbuf);
    memunmap(p);
    pr_info("ihisi_buf: phys %s paddr=%#llx len=%llu rc=%ld\n",
            (cmd == IHISI_PHYS_READ) ? "READ " : "WRITE", io.paddr, io.len, rc);
    return rc;
}

static const struct file_operations buf_fops = {
    .owner = THIS_MODULE,
    .open  = buf_open,
    .read  = buf_read,
    .mmap  = buf_mmap,
    .unlocked_ioctl = buf_ioctl,
    .llseek = noop_llseek,
};

static struct miscdevice buf_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "ihisi_buf",
    .fops  = &buf_fops,
    .mode  = 0600,
};

/* ------------------------------------------------------------ 输出 */

static void hex_line(struct seq_file *m, const u8 *b, int off, int n)
{
    int i;
    seq_printf(m, "  %06x  ", off);
    for (i = 0; i < n; i++)
        seq_printf(m, "%02x%s", b[off + i], (i == 7) ? "  " : " ");
    seq_puts(m, " ");
    for (i = 0; i < n; i++) {
        u8 c = b[off + i];
        seq_putc(m, (c >= 0x20 && c < 0x7f) ? c : '.');
    }
    seq_putc(m, '\n');
}

static int diag_show(struct seq_file *m, void *v)
{
    int i, j;
    unsigned long hits = 0;

    seq_puts(m, "== ihisi_diag 只读诊断 ==\n\n");

    /* 1. F 段 */
    seq_printf(m, "-- 1. F 段 %#x..%#x（内核态读，绕过 STRICT_DEVMEM）--\n",
               FSEG_LO, FSEG_LO + FSEG_SIZE - 1);
    if (!fseg_ready) {
        seq_puts(m, "  扫描失败（见 dmesg）\n\n");
    } else {
        int nonzero = 0, zero = 0, ff = 0, w0 = 0, w1 = 0;
        u32 *w = (u32 *)fseg_copy;
        for (i = 0; i < FSEG_SIZE; i++) {
            if (fseg_copy[i]) nonzero++;
            if (fseg_copy[i] == 0x00) zero++;
            if (fseg_copy[i] == 0xFF) ff++;
        }
        for (i = 0; i < FSEG_SIZE / 4; i++) {
            if (w[i] == 0) w0++;
            if (w[i] == 0xFFFFFFFFu) w1++;
        }
        seq_printf(m, "  非零 %d / 0x00 %d / 0xFF %d\n", nonzero, zero, ff);
        seq_printf(m, "  32位字: 全0 %d 个、全1 %d 个（真固件应成百上千，"
                      "全 0 说明还是填充）\n", w0, w1);
        for (i = 0; i <= FSEG_SIZE - 6; i++)
            if (!memcmp(&fseg_copy[i], "$IHISI", 6)) {
                hits++;
                seq_printf(m, "  ★ $IHISI @ %#x, 主功能号 = %#x\n",
                           FSEG_LO + i, fseg_copy[i + 6]);
            }
        if (!hits)
            seq_puts(m, "  $IHISI 在 F 段不存在（真内容！）→ 功能号只能靠"
                        "静态 p1.fd @ 0x3DBA34 = 0x64\n");
        seq_puts(m, "  F 段头 128 字节:\n");
        for (i = 0; i < 128; i += 16)
            hex_line(m, fseg_copy, i, 16);
        seq_putc(m, '\n');
    }

    /* 2. FCH ACPI MMIO */
    seq_printf(m, "-- 2. FCH ACPI MMIO %#lx 起 %d 字节（%s）--\n",
               mmio_base, MMIO_SIZE, mmio_note);
    if (!mmio_ready) {
        seq_puts(m, "  映射失败（见上）\n\n");
    } else {
        for (i = 0; i < MMIO_SIZE; i += 16)
            hex_line(m, mmio_copy, i, 16);
        seq_putc(m, '\n');
    }

    /* 3. PM I/O（AMD FCH 的 SMI 状态/使能寄存器在 PM 块 0x60..0x7F） */
    seq_printf(m, "-- 3. PM I/O 端口 pm_evt=%#lx 起 0x80 字节 --\n", pm_evt);
    if (!pm_evt) {
        seq_puts(m, "  未指定 pm_evt（用 FACP 的 PM1a_EVT_BLK，本机是 0xA1A0）\n\n");
    } else {
        for (i = 0; i < 0x80; i += 16) {
            u8 b[16];
            seq_printf(m, "  %04lx  ", pm_evt + i);
            for (j = 0; j < 16; j++) {
                b[j] = inb(pm_evt + i + j);
                seq_printf(m, "%02x ", b[j]);
            }
            seq_putc(m, '\n');
        }
        seq_putc(m, '\n');
    }

    seq_puts(m, "-- 用法提示 --\n");
    seq_puts(m, "  判「是填充还是真固件」：32位全0/全1字 >> 0 即真内容\n");
    seq_puts(m, "  判「SMI 使能」：把 MMIO dump 给分析者，重点看 PM/SMI 块\n");

    /* 4. SMI 前后对比 */
    seq_puts(m, "\n-- 4. SMI 前后 MMIO 对比（out 0xB0,0x64 IsSupportIhisi）--\n");
    if (!smi_test) {
        seq_puts(m, "  未启用。加载时加参数: sudo insmod ihisi_diag.ko smi_test=1\n");
    } else if (!smi_test_done) {
        seq_puts(m, "  实验未完成（见 dmesg）\n");
    } else {
        int i, shown = min(smi_diff_count, MAX_DIFF_LOG);
        seq_printf(m, "  快照范围: MMIO+0x%03x..+0x%03x, 发 SMI 后等 100ms\n",
                   SNAP_OFF, SNAP_OFF + SNAP_LEN - 1);
        seq_printf(m, "  发 SMI 后 0xB0 回声 = %#lx\n", smi_status_last);
        if (smi_diff_count == 0) {
            seq_puts(m, "  ** 零差异 ** —— 发命令后 MMIO 一个字节都没变。\n");
            seq_puts(m, "  结论：这条 SMI 未被处理（handler 没动任何寄存器），\n");
            seq_puts(m, "  或 SMI 根本没触发（SMI 使能关闭）。软件侧无解。\n");
        } else {
            seq_printf(m, "  ** %d 字节差异 **（列出前 %d 个）—— handler 有动作：\n",
                       smi_diff_count, shown);
            for (i = 0; i < shown; i++)
                seq_printf(m, "    MMIO+%03lx: %02x -> %02x\n",
                           smi_diff_off[i], smi_diff_bef[i], smi_diff_aft[i]);
        }
    }
    return 0;
}

static int diag_open(struct inode *ino, struct file *f)
{
    return single_open(f, diag_show, NULL);
}

static const struct proc_ops diag_pops = {
    .proc_open    = diag_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/* ------------------------------------------------------------ init/exit */

static int __init ihisi_diag_init(void)
{
    int rc;

    scan_fseg();
    dump_mmio();
    if (smi_test)
        run_smi_test();
    proc_create("ihisi_diag", 0444, NULL, &diag_pops);
    rc = misc_register(&buf_misc);
    if (rc)
        pr_warn("ihisi_diag: /dev/ihisi_buf 注册失败 %d（报文缓冲不可用）\n", rc);
    else
        pr_info("ihisi_diag: /dev/ihisi_buf 就绪（DMA32 报文缓冲）\n");
    pr_info("ihisi_diag: 已加载，cat /proc/ihisi_diag 查看结果\n");
    return 0;
}

static void __exit ihisi_diag_exit(void)
{
    remove_proc_entry("ihisi_diag", NULL);
    misc_deregister(&buf_misc);
    if (buf_vaddr) {
        free_pages((unsigned long)buf_vaddr, 2);
        buf_vaddr = NULL;
    }
    if (fseg_copy) { kvfree(fseg_copy); fseg_copy = NULL; }
    if (mmio_copy) { kvfree(mmio_copy); mmio_copy = NULL; }
    pr_info("ihisi_diag: 已卸载\n");
}

module_init(ihisi_diag_init);
module_exit(ihisi_diag_exit);
