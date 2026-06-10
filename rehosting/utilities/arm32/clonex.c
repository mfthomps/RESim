#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdint.h>

#ifndef SYS_clone3
#define SYS_clone3 435
#endif

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

int main() {
    size_t stack_size = 65536; // 64 KB
    
    void *stack_mem = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
                           
    if (stack_mem == MAP_FAILED) {
        perror("mmap failed");
        exit(1);
    }

    uintptr_t stack_lowest = (uintptr_t)stack_mem;
    uintptr_t stack_highest = stack_lowest + stack_size; 

    struct my_clone_args args = {
        .flags = CLONE_VM | CLONE_FILES,
        .stack = (uint64_t)stack_lowest, // Bottom address (smallest address)
        .stack_size = (uint64_t)stack_size,
    };

    // Explicit template string for the child thread.
    // The format logic replaces "XXXXXXXX" natively in memory with the child's SP.
    static char child_msg[] = "Success! Child process running. Actual SP value: 0xXXXXXXXX\n";
    int result_pid = 0;

    asm volatile (
        "push {r4, r5, r6, r7, lr}\n\t" 
        "mov r0, %1\n\t"            // r0 = pointer to args struct
        "mov r1, %2\n\t"            // r1 = sizeof(args)
        "mov r7, %3\n\t"            // r7 = SYS_clone3 (435)
        "svc #0\n\t"                // Invoke Linux kernel
        
        "cmp r0, #0\n\t"            // Check syscall return value
        "bne 1f\n\t"                // PARENT: Skip child execution block

        // --- CHILD INNER LAYER ---
        "mov r1, %4\n\t"            // Load stack_highest parameter into r1
        "bic r1, r1, #7\n\t"        // Force 8-byte boundary alignment
        "mov sp, r1\n\t"            // Assign to Stack Pointer (SP)
        
        // --- NATIVE HEX TO STRING CONVERSION ENGINE ---
        // Converts current 'sp' hex digits into characters to overwrite "XXXXXXXX"
        "mov r3, sp\n\t"            // Copy the active SP address into r3
        "mov r4, %5\n\t"            // Load string pointer
        "add r4, r4, #57\n\t"       // Point exactly to the last 'X' index in "0xXXXXXXXX"
        "mov r5, #8\n\t"            // Loop counter (8 hex nibbles)

        "2:\n\t"
        "and r6, r3, #15\n\t"       // Isolate lower 4 bits (nibble)
        "cmp r6, #10\n\t"           // Check if it is a number or letter (A-F)
        "addlt r6, r6, #48\n\t"     // If 0-9: add ASCII '0'
        "addge r6, r6, #55\n\t"     // If A-F: add ASCII 'A'-10
        "strb r6, [r4], #-1\n\t"    // Store character into the string template and step backward
        "lsr r3, r3, #4\n\t"        // Shift address right by 4 bits for the next nibble
        "subs r5, r5, #1\n\t"       // Decrement counter
        "bne 2b\n\t"                // Repeat for all 8 digits

        // --- DIRECT KERNEL WRITE ---
        "mov r0, #1\n\t"            // fd = 1 (STDOUT)
        "mov r1, %5\n\t"            // Hand over pointer to the updated string buffer
        "mov r2, %6\n\t"            // String payload length
        "mov r7, #4\n\t"            // __NR_write (Syscall 4)
        "svc #0\n\t"                // Execute raw terminal write
        
        "mov r0, #0\n\t"            // Exit status code 0
        "mov r7, #1\n\t"            // __NR_exit (Syscall 1)
        "svc #0\n\t"                // Terminate child cleanly

        // --- PARENT LAYER ---
        "1:\n\t"
        "mov %0, r0\n\t"            // Capture result PID cleanly
        "pop {r4, r5, r6, r7, lr}\n\t" // Restore parent workspace registers
        : "=r" (result_pid)
        : "r" (&args), "r" (sizeof(args)), "r" (SYS_clone3), 
          "r" (stack_highest), "r" (child_msg), "r" (sizeof(child_msg) - 1)
        : "r0", "r1", "r2", "r3", "r4", "r5", "r6", "memory"
    );

    if (result_pid > 0) {
        // Ensure standard I/O streams are fully flushed in parent context
        fflush(stdout);
        printf("Parent process successfully built child thread. PID: %d stack was 0x%llx\n", result_pid, args.stack);
        fflush(stdout);
        
        usleep(50000); 
    } else if (result_pid < 0) {
        perror("clone3 execution error");
    }

    munmap(stack_mem, stack_size);
    return 0;
}

