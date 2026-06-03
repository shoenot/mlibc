#include <mlibc/sysdeps.hpp>
#include <abi/vespertine_abi.hpp>
#include <abi/flags.hpp>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

using ssize_t = ptrdiff_t;

// --- Basic types from syscall.cpp and entry.cpp ---
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

struct FdTable {
    HandleID *entries;
    size_t capacity;
};

// --- Externs ---
extern HandleID g_self_handle;
extern HandleID g_mem_pool;
extern FdTable g_fd_table;

extern "C" SyscallResult sys_invoke(HandleID handle, const void *op);
extern "C" SyscallResult sys_close(HandleID handle);
extern "C" SyscallResult sys_futex_wait(uintptr_t addr, uint32_t expected);
extern "C" SyscallResult sys_futex_wake(uintptr_t addr, size_t count);

// --- Error Mapping ---
int map_error(SysError err) {
    switch(err) {
        case SysError::Success:         return 0;
        case SysError::OutOfMemory:     return ENOMEM;
        case SysError::PoolExhausted:   return ENOMEM;
        case SysError::InvalidHandle:   return EBADF;
        case SysError::AccessDenied:    return EACCES;
        case SysError::InvalidArgument: return EINVAL;
        case SysError::WouldBlock:      return EAGAIN;
        default:                        return ENOSYS;
    }
}

namespace mlibc {

// ----------------------------------------------------
// 1. Threading & Panics
// ----------------------------------------------------

void sys_exit(int status) {
    ProcOp proc_op;
    proc_op.tag = ProcOp::Tag::ProcOp_Kill;
    // Note: kill is a unit variant, so it has no body to set!

    Invocation inv;
    inv.tag = Invocation::Tag::Invocation_Proc;
    inv.proc._0 = proc_op;

    sys_invoke(g_self_handle, &inv);
    while (true) {} // Should never reach here
}


int sys_tcb_set(void *tcb) {
    ProcOp::ProcOp_SetFsBase_Body fs_body;
    fs_body.fs_base = reinterpret_cast<uintptr_t>(tcb);

    ProcOp proc_op;
    proc_op.tag = ProcOp::Tag::ProcOp_SetFsBase;
    proc_op.set_fs_base = fs_body;

    Invocation inv;
    inv.tag = Invocation::Tag::Invocation_Proc;
    inv.proc._0 = proc_op;

    SyscallResult res = sys_invoke(g_self_handle, &inv);
    return map_error(res.error);
}

int sys_futex_wait(int *pointer, int expected, const struct timespec *time) {
    // Ignore timeout for now
    SyscallResult res = ::sys_futex_wait(reinterpret_cast<uintptr_t>(pointer), expected);
    return map_error(res.error);
}

int sys_futex_wake(int *pointer) {
    SyscallResult res = ::sys_futex_wake(reinterpret_cast<uintptr_t>(pointer), 1);
    return map_error(res.error);
}

// ----------------------------------------------------
// 2. Memory Allocation
// ----------------------------------------------------
int sys_anon_allocate(size_t size, void **pointer) {
    MemPoolOp::MemPoolOp_AllocateVmo_Body alloc_body;
    alloc_body.size = size;

    MemPoolOp pool_op;
    pool_op.tag = MemPoolOp::Tag::MemPoolOp_AllocateVmo;
    pool_op.allocate_vmo = alloc_body;

    Invocation inv;
    inv.tag = Invocation::Tag::Invocation_MemPool;
    inv.mem_pool._0 = pool_op;

    SyscallResult vmo_res = sys_invoke(g_mem_pool, &inv);
    if (vmo_res.error != SysError::Success) return map_error(vmo_res.error);

    HandleID vmo_handle = vmo_res.value;

    VmoOp::VmoOp_MapIntoProc_Body map_body;
    map_body.vaddr = 0;
    map_body.len = size;
    map_body.vm_flags = 5; // R | X or standard allocations

    VmoOp vmo_op;
    vmo_op.tag = VmoOp::Tag::VmoOp_MapIntoProc;
    vmo_op.map_into_proc = map_body;

    Invocation map_inv;
    map_inv.tag = Invocation::Tag::Invocation_Vmo;
    map_inv.vmo._0 = vmo_op;

    SyscallResult map_res = sys_invoke(vmo_handle, &map_inv);
    sys_close(vmo_handle); 

    if (map_res.error != SysError::Success) return map_error(map_res.error);

    *pointer = reinterpret_cast<void*>(map_res.value);
    return 0;
}

int sys_anon_free(void *pointer, size_t size) {
    ProcOp::ProcOp_Unmap_Body unmap_body;
    unmap_body.vaddr = reinterpret_cast<uintptr_t>(pointer);
    unmap_body.len = size;

    ProcOp proc_op;
    proc_op.tag = ProcOp::Tag::ProcOp_Unmap;
    proc_op.unmap = unmap_body;

    Invocation inv;
    inv.tag = Invocation::Tag::Invocation_Proc;
    inv.proc._0 = proc_op;

    SyscallResult res = sys_invoke(g_self_handle, &inv);
    return map_error(res.error);
}

// ----------------------------------------------------
// 3. I/O
// ----------------------------------------------------
int sys_write(int fd, const void *buf, size_t count, ssize_t *bytes_written) {
    if (fd < 0 || (size_t)fd >= g_fd_table.capacity) return EBADF;
    HandleID handle = g_fd_table.entries[fd];
    if (handle == 0) return EBADF;

    FileOp::FileOp_Write_Body write_body;
    write_body.offset = 0;
    write_body.buffer_ptr = reinterpret_cast<uintptr_t>(buf);
    write_body.len = count;

    FileOp file_op;
    file_op.tag = FileOp::Tag::FileOp_Write;
    file_op.write = write_body;

    Invocation inv;
    inv.tag = Invocation::Tag::Invocation_File;
    inv.file._0 = file_op;

    SyscallResult res = sys_invoke(handle, &inv);
    if (res.error != SysError::Success) return map_error(res.error);

    *bytes_written = count;
    return 0;
}

void sys_libc_log(const char *message) {
    size_t written;
    sys_write(2, message, strlen(message), reinterpret_cast<ssize_t*>(&written));
}

void sys_libc_panic() {
    sys_libc_log("\nmlibc panic!\n");
    sys_exit(1);
}

} // namespace mlibc
