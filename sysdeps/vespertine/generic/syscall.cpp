#include <stdint.h>
#include <stddef.h>
#include <abi/vespertine_abi.hpp>

using HandleID = uintptr_t;

extern "C" {

SyscallResult sys_invoke(HandleID handle, const void *op) {
    size_t ret;
    size_t payload;

    asm volatile(
        "mov $0, %%rax\n\t"
        "syscall"
        : "=a"(ret), "=d"(payload)
        : "D"(handle), "S"(op)
        : "rcx", "r11", "memory"
    );

    if (ret == 0) {
        return {payload, SysError::Success};
    } else {
        return {0, static_cast<SysError>(ret)};
    }
}

SyscallResult sys_close(HandleID handle) {
    size_t ret;
    asm volatile(
        "mov $1, %%rax\n\t"
        "syscall"
        : "=a"(ret)
        : "D"(handle)
        : "rdx", "rcx", "r11", "memory"
    );

    if (ret == 0) {
        return {0, SysError::Success};
    } else {
        return {0, static_cast<SysError>(ret)};
    }
}

SyscallResult sys_thread_terminate() {
    size_t ret;
    asm volatile(
        "mov $2, %%rax\n\t"
        "syscall"
        : "=a"(ret)
        : 
        : "rcx", "r11", "memory"
    );
    __builtin_unreachable(); 
}

SyscallResult sys_thread_yield() {
    size_t ret;
    asm volatile(
        "mov $3, %%rax\n\t"
        "syscall"
        : "=a"(ret)
        :
        : "rcx", "r11", "memory"
    );
    return {0, static_cast<SysError>(ret)};
}

SyscallResult sys_futex_wait(uintptr_t addr, uint32_t expected) {
    size_t ret;
    size_t payload;
    asm volatile(
        "mov $4, %%rax\n\t"
        "syscall"
        : "=a"(ret), "=d"(payload)
        : "D"(addr), "S"(expected)
        : "rcx", "r11", "memory"
    );
    return {0, static_cast<SysError>(ret)};
}

SyscallResult sys_futex_wake(uintptr_t addr, size_t count) {
    size_t ret;
    size_t payload;
    asm volatile(
        "mov $5, %%rax\n\t"
        "syscall"
        : "=a"(ret), "=d"(payload)
        : "D"(addr), "S"(count)
        : "rcx", "r11", "memory"
    );
    return {0, static_cast<SysError>(ret)};
}

} // extern "C"
