/*
 * port_peek.c —— 只读 IO 端口探测
 *
 * glibc 不导出 inb 符号（<sys/io.h> 里是内联宏），ctypes 拿不到，
 * 所以探测必须走 C。只执行 in 指令，不写任何端口，不会触发 SMI。
 *
 * 用法: port_peek <lo> <hi> <times>
 *   例: port_peek 0xa0 0xc0 4
 * 输出每端口一行: "PORT v1 v2 ... verdict"
 *   verdict: FF(全FF=未解码) / STABLE(稳定值) / CHANGING(有东西在驱动)
 * 退出码 0。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/io.h>

static unsigned char peek_inb(unsigned short port)
{
    unsigned char v;
    __asm__ __volatile__("inb %w1, %b0" : "=a"(v) : "d"(port));
    return v;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "用法: %s <lo> <hi> <times>\n", argv[0]);
        return 1;
    }
    unsigned long lo = strtoul(argv[1], NULL, 0);
    unsigned long hi = strtoul(argv[2], NULL, 0);
    int times = atoi(argv[3]);
    if (hi <= lo || hi - lo > 256 || times < 1 || times > 16) {
        fprintf(stderr, "参数范围不对（hi>lo，跨度<=256，1<=times<=16）\n");
        return 1;
    }

    if (iopl(3) != 0) {
        fprintf(stderr, "iopl(3) 失败: %s（需要 CAP_SYS_RAWIO / root）\n",
                strerror(errno));
        return 2;
    }

    printf("# port v1..vN verdict\n");
    for (unsigned long p = lo; p < hi; p++) {
        unsigned char v[16];
        char vals[16 * 4];
        int off = 0;
        int all_ff = 1, same = 1;
        for (int i = 0; i < times; i++) {
            v[i] = peek_inb((unsigned short)p);
            if (v[i] != 0xFF) all_ff = 0;
            if (v[i] != v[0]) same = 0;
            off += sprintf(vals + off, "%02x ", v[i]);
        }
        const char *verdict = all_ff ? "FF"
                            : same   ? "STABLE"
                                     : "CHANGING";
        printf("%04lx %s %s %02x\n", p, vals, verdict, v[0]);
    }
    return 0;
}
