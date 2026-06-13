#pragma once
#include <stdint.h>
#include <stddef.h>
#include <abi/vespertine_abi.hpp>

extern "C" {
    SyscallResult sys_invoke(HandleID handle, const void *op);
    SyscallResult sys_close(HandleID handle);
    [[noreturn]] void sys_thread_terminate(uint32_t exit_code);
    SyscallResult sys_thread_yield();
    SyscallResult sys_futex_wait(uintptr_t addr, uint32_t expected);
    SyscallResult sys_futex_wake(uintptr_t addr, size_t count);
}
