/* This Software is part of Wind River Simics. The rights to copy, distribute,
   modify, or otherwise make use of this Software may be licensed only
   pursuant to the terms of an applicable Wind River license agreement.

   Copyright 2016 Intel Corporation */

#ifndef SIMICS_AGENT_MAGIC_H
#define SIMICS_AGENT_MAGIC_H

#ifndef __GNUC__
#error "Unsupported compiler"
#endif

#define __MAGIC_CASSERT(p) typedef int __check_magic_argument[(p) ? 1 : -1] \
        __attribute__((unused));

#if defined __i386 || defined __x86_64__ || defined _M_IX86 || defined _M_AMD64

#define MAGIC_ASM(n,p) do {                                             \
        void *dummy_eax, *dummy_ebx, *dummy_ecx, *dummy_edx;            \
        __MAGIC_CASSERT((unsigned)(n) < 0x10000);                       \
        __asm__ __volatile__ ("cpuid"                                   \
                              : "=a" (dummy_eax), "=b" (dummy_ebx),     \
                                "=c" (dummy_ecx), "=d" (dummy_edx)      \
                              : "a" (0x4711 | ((unsigned)(n) << 16)),   \
                                "b" (p) : "memory");                    \
} while (0)

#elif defined __powerpc__ || defined __ppc
 #if defined __powerpc64__ || defined SIM_NEW_RLWIMI_MAGIC

#define MAGIC_ASM(n,p)                                                  \
        __MAGIC_CASSERT((n) >= 0 && (n) < (1 << 13));                   \
        __asm__ __volatile__ ("mr 14,%3; rlwimi %0,%0,0,%1,%2"          \
                              :: "i" (((n) >> 8) & 0x1f),               \
                                 "i" (((n) >> 4) & 0xf),                \
                                 "i" ((((n) >> 0) & 0xf) | 0x10),       \
                                 "r" (p) : "r14", "memory")

 #else /* !__powerpc64__ && !SIM_NEW_RLWIMI_MAGIC */

#define MAGIC_ASM(n,p)                                          \
        __MAGIC_CASSERT((n) >= 0 && (n) < (1 << 15));           \
        __asm__ __volatile__ ("mr 14,%3; rlwimi %0,%0,0,%1,%2"  \
                              :: "i" (((n) >> 10) & 0x1f),      \
                                 "i" (((n) >>  5) & 0x1f),      \
                                 "i" (((n) >>  0) & 0x1f),      \
                                 "r" (p) : "r14", "memory")

 #endif /* __powerpc64__ && !SIM_NEW_RLWIMI_MAGIC */
#elif defined __aarch64__

#define MAGIC_ASM(n,p)                                                  \
        __MAGIC_CASSERT((n) >= 0 && (n) <= 31);                         \
        __asm__ __volatile__ ("mov x12, %0; orr x" #n ", x" #n ", x" #n \
                              :: "r" (p) : "x12", "memory")

#elif defined __arm__
 #ifdef __thumb__

#define MAGIC_ASM(n,p)                                                      \
        __MAGIC_CASSERT((n) >= 0 && (n) <= 12);                             \
        __asm__ __volatile__ ("mov.w r12, %0; orr.w r" #n ", r" #n ", r" #n \
                              :: "r" (p) : "r12", "memory")

 #else /* !__thumb__ */

#define MAGIC_ASM(n,p)                                                  \
        __MAGIC_CASSERT((n) >= 0 && (n) <= 14);                         \
        __asm__ __volatile__ ("mov r12, %0; orr r" #n ", r" #n ", r" #n \
                              :: "r" (p) : "r12", "memory")

 #endif /* __thumb__ */
#elif defined __mips__
#define MAGIC_ASM(n,p)                                                  \
	__MAGIC_CASSERT((n) >= 0 && (n) <= 0xffff);                     \
        __asm__ __volatile__ ("move $8,%0; li $zero," #n                \
                              :: "r" (p) : "$8", "memory")

#else
#error "Unsupported architecture"
#endif

#endif /* SIMICS_AGENT_MAGIC_H */
