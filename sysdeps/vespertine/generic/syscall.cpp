#include <stdint.h>
#include <stddef.h>

using HandleID = uintptr_t;

enum class SysError : size_t {
    Success = 0,
    InvalidPointer = 1,
    BadAddress = 2,
    OutOfMemory = 3,
    InvalidHandle = 21,
    AccessDenied = 22,
    InvalidArgument = 23,
    UnsupportedOperation = 24,
    BufferFull = 25,
    WouldBlock = 26,
    PoolExhausted = 27,
    NameTooLong = 28,
    InvalidEncoding = 29,
    NotMapped = 30,
    UnknownSyscall = 41,
    ThreadSpawnFail = 50,
};

struct SyscallResult {
    size_t value;
    SysError error;
};

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
