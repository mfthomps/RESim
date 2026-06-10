#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdint.h>

// Explicitly fallback if host headers don't have SYS_clone3 defined for ARM32
#ifndef SYS_clone3
#define SYS_clone3 435
#endif

// Packed and aligned layout identical to the Linux kernel UAPI
struct my_clone_args {
    uint64_t flags;
    uint64_t pidfd;
    uint64_t child_tid;
    uint64_t parent_tid;
    uint64_t exit_signal;
    uint64_t stack;
    uint64_t stack_size;
    uint64_t tls;
    uint64_t set_tid;
    uint64_t set_tid_size;
    uint64_t cgroup;
} __attribute__((aligned(8)));

void child_func(void *arg) {
    const char msg[] = "Hello from the raw ARM32 clone3 child thread!\n";
    
    // Direct kernel syscall to ensure the output is written directly to the terminal
    asm volatile (
        "mov r0, #1\n\t"       // File descriptor 1 = STDOUT
        "mov r1, %0\n\t"       // Buffer pointer
        "mov r2, %1\n\t"       // Message length
        "mov r7, #4\n\t"       // __NR_write system call number on ARM32
        "svc #0\n\t"           // Kernel Trap
        
        // Terminate cleanly to prevent falling off the stack boundary
        "mov r0, #0\n\t"       // Return code 0
        "mov r7, #1\n\t"       // __NR_exit system call number on ARM32
        "svc #0\n\t"
        :: "r"(msg), "r"(sizeof(msg) - 1) : "r0", "r1", "r2", "r7"
    );
}
int child_funcxx(void *arg) {
    int dummy;
    void *stack_approx = (void *)&dummy;
    
    printf("child stack pointer: %p\n", stack_approx);
    printf("Child process running inside 32-bit ARM environment.\n");
    fflush(stdout);
    return 0;
}

int main() {
    size_t stack_size = 65536; // 64 KB
    
    // Allocate memory using standard flags
    void *stack_mem = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
                           
    if (stack_mem == MAP_FAILED) {
        perror("mmap failed");
        exit(1);
    }

    // clone3 requires the absolute SMALLEST memory address for the base pointer
    uintptr_t stack_base = (uintptr_t)stack_mem;
    
    struct my_clone_args args = {
        .flags = CLONE_VM | CLONE_FILES,
        .stack = (uint64_t)stack_base, 
        .stack_size = (uint64_t)stack_size,
    };

    printf("stack base 0x%llx\n", args.stack);
    // Invoke the raw kernel system call directly via register-based mapping
    long pid = syscall(SYS_clone3, &args, sizeof(args));

    if (pid == 0) {
        child_func(NULL);
        _exit(0);
    } else if (pid > 0) {
        printf("Parent process built child with PID: %ld\n", pid);
        usleep(10000);
    } else {
        perror("clone3 execution error");
    }

    munmap(stack_mem, stack_size);
    return 0;
}

