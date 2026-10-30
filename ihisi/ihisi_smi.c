/*
 * ihisi_smi.c —— 最小 IHISI SMI 调用器
 *
 * 只做一件事：按 Insyde segwindrv 的方式把六个寄存器装好，执行 `out dx, al`，
 * 再把 SMM 回写的寄存器打印出来。所有报文构造、物理地址、校验和都不在这里，
 * 留在 Python 侧，便于审计和单测。
 *
 * 对应驱动 segwindrvx64.sys 的函数 @ RVA 0x3E78：
 *     mov r8, rdx                  ; 16 字节寄存器块
 *     mov ah, cl                   ; AH = 子功能号
 *     mov esi, [r8]                ; ESI
 *     mov edi, [r8+4]              ; EDI
 *     mov ecx, [r8+8]              ; ECX
 *     mov edx, [r8+0xc]            ; EDX
 *     mov ebx, [0xD168]            ; EBX = "O2H$" (0x2448324F)
 *     mov al,  [0xE37F]            ; AL  = 主功能号
 *     mov dx,  [0xE3C8]            ; DX  = SMI 端口
 *     out dx, al
 *
 * 用法:
 *   ihisi_smi <main> <sub> <port> <esi> <edi> <ecx> <edx>
 *   ihisi_smi --generic <eax> <ebx> <ecx> <edx> <esi> <edi> <port>
 *     --generic: SMI_GENERIC 通道（驱动 0x3EBA，六寄存器全透传：
 *     EAX/EBX 不强制 "O2H$"/(sub<<8)|main 组合，全部来自参数块）
 * 输出（单行，供 Python 解析）:
 *   esi=xxxxxxxx edi=xxxxxxxx ecx=xxxxxxxx edx=xxxxxxxx eax=xxxxxxxx ebx=xxxxxxxx
 *
 * 退出码: 0 成功，1 参数错，2 iopl 失败（权限不足），3 端口范围非法
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/io.h>

#define H2O_MAGIC 0x2448324Fu   /* "O2H$" 小端 */

/* 六寄存器透传执行 out dx, al（SMI_GENERIC，驱动 0x3EBA）。
 *
 * 注意：EBX 用 "+b" 显式约束（GCC 自动保存 callee-saved rbx），
 * 不要在 asm 里 pushq/popq rbx —— 那会让 GCC 的栈上操作数（含
 * stack canary）按进入时 RSP 编码而错位，触发 stack smashing。
 * 端口固定写 0xB0（FADT.SMI_CMD），DX 高 16 位保留调用者的值
 * （与驱动 0x3ED7 的 mov dx,[0xE3C8] 行为一致）。
 */
static unsigned int do_generic(unsigned int *r)
{
    /* r[0]=esi r[1]=edi r[2]=ecx r[3]=edx r[4]=eax r[5]=ebx */
    register unsigned int a __asm__("rax") = r[4];
    register unsigned int b __asm__("rbx") = r[5];
    register unsigned int c __asm__("rcx") = r[2];
    register unsigned int d __asm__("rdx") = r[3];
    register unsigned int s __asm__("rsi") = r[0];
    register unsigned int D __asm__("rdi") = r[1];
    __asm__ __volatile__(
        "movw $0xb0, %%dx\n\t"
        "outb %%al, %%dx\n\t"
        : "+a"(a), "+b"(b), "+c"(c), "+d"(d), "+S"(s), "+D"(D)
        :
        : "memory"
    );
    r[4] = a; r[5] = b; r[2] = c; r[3] = d; r[0] = s; r[1] = D;
    return 0;
}

int main(int argc, char **argv)
{
    int generic = (argc > 1 && strcmp(argv[1], "--generic") == 0);
    int argbase = generic ? 2 : 1;

    if (generic ? (argc != 9) : (argc != 8)) {
        fprintf(stderr,
                "用法: %s <main> <sub> <port> <esi> <edi> <ecx> <edx>\n"
                "      %s --generic <eax> <ebx> <ecx> <edx> <esi> <edi> <port>\n"
                "  例如: %s 0x64 0x01 0xb2 0x12345000 0x1234501c 0 0\n",
                argv[0], argv[0], argv[0]);
        return 1;
    }

    unsigned int eax, ebx, ecx, edx, esi, edi;
    unsigned long port;

    if (generic) {
        eax = (unsigned int)strtoul(argv[argbase + 0], NULL, 0);
        ebx = (unsigned int)strtoul(argv[argbase + 1], NULL, 0);
        ecx = (unsigned int)strtoul(argv[argbase + 2], NULL, 0);
        edx = (unsigned int)strtoul(argv[argbase + 3], NULL, 0);
        esi = (unsigned int)strtoul(argv[argbase + 4], NULL, 0);
        edi = (unsigned int)strtoul(argv[argbase + 5], NULL, 0);
        port = strtoul(argv[argbase + 6], NULL, 0);
    } else {
        unsigned long mainf = strtoul(argv[1], NULL, 0);
        unsigned long subf  = strtoul(argv[2], NULL, 0);
        port = strtoul(argv[3], NULL, 0);
        esi = (unsigned int)strtoul(argv[4], NULL, 0);
        edi = (unsigned int)strtoul(argv[5], NULL, 0);
        ecx = (unsigned int)strtoul(argv[6], NULL, 0);
        edx = (unsigned int)strtoul(argv[7], NULL, 0);
        eax  = ((unsigned int)(subf & 0xff) << 8) | (unsigned int)(mainf & 0xff);
        ebx  = H2O_MAGIC;
    }

    if (port > 0xFFFFul) {
        fprintf(stderr, "端口 0x%lx 超出 16 位范围\n", port);
        return 3;
    }

    /*
     * iopl(3) 把 EFLAGS.IOPL 提到 3，允许 CPL=3 执行 in/out。
     * 需要 CAP_SYS_RAWIO —— 也就是 root。失败的绝大多数原因是权限。
     */
    if (iopl(3) != 0) {
        fprintf(stderr, "iopl(3) 失败: %s (errno=%d)\n"
                        "  需要 CAP_SYS_RAWIO，请用 root 运行。\n",
                strerror(errno), errno);
        return 2;
    }

    if (generic) {
        /* SMI_GENERIC（驱动 0x3EBA）：六寄存器全透传，
         * DX 低 16 位由 do_generic 内部设为端口。 */
        unsigned int regs[6] = { esi, edi, ecx, edx, eax, ebx };
        (void)port;   /* 端口在 do_generic 里固定 0xB0 */
        do_generic(regs);
        esi = regs[0]; edi = regs[1]; ecx = regs[2];
        edx = regs[3]; eax = regs[4]; ebx = regs[5];
        printf("esi=%08x edi=%08x ecx=%08x edx=%08x eax=%08x ebx=%08x\n",
               esi, edi, ecx, edx, eax, ebx);
        return 0;
    }

    unsigned int edxr = (edx & 0xffff0000u) | (unsigned int)(port & 0xffffu);

    /*
     * EBX 必须精确等于 "O2H$"，否则 SMM 侧直接拒绝（驱动每次 out 前都重设，
     * 说明 handler 在入口就校验这个魔数）。
     * "+b" 显式约束让 GCC 分配/保存 rbx —— 不要在这里 pushq/popq rbx，
     * 那会错位 GCC 的栈上操作数（stack canary 会被踩）。
     */
    __asm__ __volatile__(
        "outb  %%al, %%dx\n\t"
        : [a] "+a"(eax), [d] "+d"(edxr), [s] "+S"(esi),
          [D] "+D"(edi), [c] "+c"(ecx), [b] "+b"(ebx)
        :
        : "memory"
    );

    printf("esi=%08x edi=%08x ecx=%08x edx=%08x eax=%08x ebx=%08x\n",
           esi, edi, ecx, edxr, eax, ebx);
    return 0;
}
