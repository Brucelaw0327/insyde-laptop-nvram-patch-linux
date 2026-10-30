/*
 * smi_probe.c —— APM 状态端口探针：验证 SMI handler 到底跑没跑
 *
 * 原理：0xB0 = APM 命令端口（写触发 SMI），0xB1 = APM 状态端口。
 * 实测 0xB1 稳定读回 0x01。如果 handler 真的响应命令，状态位
 * 大概率会翻转（busy -> done）。三次探测互为对照：
 *
 *   1) 基线：读 0xB1 一段（不发 SMI）
 *   2) 探针 A：out 0xB0, 0x64（IsSupportIhisi，与 ping 等价、已发过多次），
 *      前后各读 0xB1
 *   3) 探针 B：out 0xB0, 0x00（无意义命令，看非法命令是否翻转状态）
 *
 * 用法: smi_probe [命令字节，默认 0x64]
 * 输出人类可读。退出码 0。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/io.h>
#include <time.h>

static unsigned char inb_(unsigned short p)
{
    unsigned char v;
    __asm__ __volatile__("inb %w1, %b0" : "=a"(v) : "d"(p));
    return v;
}

static void outb_(unsigned char v, unsigned short p)
{
    __asm__ __volatile__("outb %b0, %w1" :: "a"(v), "d"(p));
}

static void spin_us(long us)
{
    struct timespec ts = {0, us * 1000L};
    nanosleep(&ts, NULL);
}

/* 读 N 次状态口，打印基线与抖动 */
static void baseline(int n)
{
    unsigned char v = inb_(0xB1);
    int changes = 0;
    printf("基线 0xB1 x%d: ", n);
    for (int i = 0; i < n; i++) {
        unsigned char x = inb_(0xB1);
        if (x != v) changes++;
        if (i < 8) printf("%02x ", x);
        spin_us(100);
    }
    printf("... 首值=%02x 变化次数=%d\n", v, changes);
}

/* 发一条命令，微秒级轮询状态口，抓翻转 */
static void probe(unsigned char cmd, int poll_us)
{
    unsigned char before = inb_(0xB1);
    printf("发 out 0xB0, 0x%02x   （0xB1 before=%02x）\n", cmd, before);

    outb_(cmd, 0xB0);

    /* 立刻高频采样 0xB1，看有没有翻转；总时长 poll_us 微秒 */
    unsigned char first = 0, last = before;
    int distinct = 0;
    unsigned char seen[256] = {0};
    long polls = 0;
    for (long i = 0; i < (long)poll_us * 20; i++) {
        unsigned char x = inb_(0xB1);
        if (!polls) first = x;
        if (!seen[x]) { seen[x] = 1; distinct++; }
        last = x;
        polls++;
    }
    printf("  采样 %ld 次（约 %d us）：", polls, poll_us);
    for (int v = 0; v < 256; v++)
        if (seen[v]) printf("%02x ", v);
    printf("\n  before=%02x first=%02x last=%02x distinct=%d\n",
           before, first, last, distinct);
    spin_us(1000);
    printf("  1ms 后 0xB1=%02x  0xB0=%02x\n", inb_(0xB1), inb_(0xB0));
}

int main(int argc, char **argv)
{
    unsigned char cmd = (argc > 1) ? (unsigned char)strtoul(argv[1], NULL, 0) : 0x64;

    if (iopl(3) != 0) {
        fprintf(stderr, "iopl(3) 失败: %s（需要 root）\n", strerror(errno));
        return 2;
    }

    printf("APM 状态端口探针（0xB0 命令 / 0xB1 状态）\n");
    printf("目的：判定 SMI handler 是否真的在跑（它会动 0xB1 的状态位）\n\n");
    baseline(16);
    printf("\n--- 探针 A：命令 0x%02x ---\n", cmd);
    probe(cmd, 2000);
    printf("\n--- 探针 B：命令 0x00（非法命令对照）---\n");
    probe(0x00, 2000);
    printf("\n--- 收尾基线 ---\n");
    baseline(16);
    printf("\n解读：\n");
    printf("  0xB1 在发命令后出现新值（尤其回 0）→ handler 确实在跑，\n");
    printf("    「原样返回寄存器」只是它没写回用户态快照；\n");
    printf("  0xB1 全程纹丝不动 → out 触发的 SMI 无人处理（与之前判断一致）；\n");
    printf("  0xB0 读回值跟随命令字节 → 它是「上次命令」寄存器，纯回声。\n");
    return 0;
}
