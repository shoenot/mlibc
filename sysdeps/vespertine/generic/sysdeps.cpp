#include <mlibc/all-sysdeps.hpp>
#include <abi/vespertine_abi.hpp>
#include <abi/flags.hpp>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <bits/ensure.h>

[[noreturn]] static inline int stub_called(const char *func) {
    (void)func;
    __ensure(!"STUB function was called");
    __builtin_unreachable();
}

#define STUB() return stub_called(__func__)

using ssize_t = ptrdiff_t;

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

// --- globals ---
HandleID g_self_handle = 1;
HandleID g_root_handle = 0;
HandleID g_mem_pool = 0;

#define STATIC_FD_BOOTSTRAP_CAP 256
static HandleID bootstrap_fds[STATIC_FD_BOOTSTRAP_CAP] = {0};
FdTable g_fd_table = { bootstrap_fds, STATIC_FD_BOOTSTRAP_CAP };

extern "C" SyscallResult sys_invoke(HandleID handle, const void *op);
extern "C" SyscallResult sys_close(HandleID handle);
extern "C" SyscallResult sys_futex_wait(uintptr_t addr, uint32_t expected);
extern "C" SyscallResult sys_futex_wake(uintptr_t addr, size_t count);

// --- error mapping ---
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
// 1. threading & panics
// ----------------------------------------------------

void Sysdeps<Exit>::operator()(int status) {
    (void)status;
    ProcOp proc_op;
    proc_op.tag = ProcOp::Tag::ProcOp_Kill;

    Invocation inv;
    inv.tag = Invocation::Tag::Invocation_Proc;
    inv.proc._0 = proc_op;

    sys_invoke(g_self_handle, &inv);
    while (true) {} 
}

int Sysdeps<TcbSet>::operator()(void *tcb) {
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

int Sysdeps<FutexWait>::operator()(int *pointer, int expected, const struct timespec *time) {
    (void)time;
    SyscallResult res = ::sys_futex_wait(reinterpret_cast<uintptr_t>(pointer), expected);
    return map_error(res.error);
}

int Sysdeps<FutexWake>::operator()(int *pointer, bool wake_all) {
    size_t count = wake_all ? SIZE_MAX : 1;
    SyscallResult res = ::sys_futex_wake(reinterpret_cast<uintptr_t>(pointer), count);
    return map_error(res.error);
}

// ----------------------------------------------------
// 2. memory allocation
// ----------------------------------------------------

int Sysdeps<AnonAllocate>::operator()(size_t size, void **pointer) {
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
    map_body.vm_flags = 5; 

    VmoOp vmo_op;
    vmo_op.tag = VmoOp::Tag::VmoOp_MapIntoProc;
    vmo_op.map_into_proc = map_body;

    Invocation map_inv;
    map_inv.tag = Invocation::Tag::Invocation_Vmo;
    map_inv.vmo._0 = vmo_op;

    SyscallResult map_res = sys_invoke(vmo_handle, &map_inv);
    ::sys_close(vmo_handle); 

    if (map_res.error != SysError::Success) return map_error(map_res.error);

    *pointer = reinterpret_cast<void*>(map_res.value);
    return 0;
}

int Sysdeps<AnonFree>::operator()(void *pointer, size_t size) {
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

int Sysdeps<VmMap>::operator()(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **out) {
    (void)offset;
    HandleID vmo_handle = 0;
    bool close_vmo = false;

    if (flags & 0x20) { 
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
        
        vmo_handle = vmo_res.value;
        close_vmo = true;
    } else {
        if (fd < 0 || (size_t)fd >= g_fd_table.capacity) return EBADF;
        HandleID file_handle = g_fd_table.entries[fd];
        if (file_handle == 0) return EBADF;

        FileOp file_op;
        file_op.tag = FileOp::Tag::FileOp_GetVmo;
        
        Invocation inv;
        inv.tag = Invocation::Tag::Invocation_File;
        inv.file._0 = file_op;

        SyscallResult vmo_res = sys_invoke(file_handle, &inv);
        if (vmo_res.error != SysError::Success) return map_error(vmo_res.error);
        
        vmo_handle = vmo_res.value;
        close_vmo = true;
    }

    VmoOp::VmoOp_MapIntoProc_Body map_body;
    map_body.vaddr = reinterpret_cast<uintptr_t>(hint);
    map_body.len = size;
    map_body.vm_flags = prot; 

    VmoOp vmo_op;
    vmo_op.tag = VmoOp::Tag::VmoOp_MapIntoProc;
    vmo_op.map_into_proc = map_body;

    Invocation map_inv;
    map_inv.tag = Invocation::Tag::Invocation_Vmo;
    map_inv.vmo._0 = vmo_op;

    SyscallResult map_res = sys_invoke(vmo_handle, &map_inv);
    
    if (close_vmo) {
        ::sys_close(vmo_handle);
    }

    if (map_res.error != SysError::Success) return map_error(map_res.error);

    *out = reinterpret_cast<void*>(map_res.value);
    return 0;
}

int Sysdeps<VmUnmap>::operator()(void *pointer, size_t size) {
    return Sysdeps<AnonFree>()(pointer, size);
}

// ----------------------------------------------------
// 3. i/o
// ----------------------------------------------------

int Sysdeps<Write>::operator()(int fd, const void *buf, size_t count, ssize_t *bytes_written) {
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

    *bytes_written = res.value; 
    return 0;
}

int Sysdeps<Read>::operator()(int fd, void *buf, size_t count, ssize_t *bytes_read) {
    if (fd < 0 || (size_t)fd >= g_fd_table.capacity) return EBADF;
    HandleID handle = g_fd_table.entries[fd];
    if (handle == 0) return EBADF;

    FileOp::FileOp_Read_Body read_body;
    read_body.offset = 0; 
    read_body.buffer_ptr = reinterpret_cast<uintptr_t>(buf);
    read_body.len = count;

    FileOp file_op;
    file_op.tag = FileOp::Tag::FileOp_Read;
    file_op.read = read_body;

    Invocation inv;
    inv.tag = Invocation::Tag::Invocation_File;
    inv.file._0 = file_op;

    SyscallResult res = sys_invoke(handle, &inv);
    if (res.error != SysError::Success) return map_error(res.error);

    *bytes_read = res.value; 
    return 0;
}

int Sysdeps<Close>::operator()(int fd) {
    if (fd < 0 || (size_t)fd >= g_fd_table.capacity) return EBADF;
    HandleID handle = g_fd_table.entries[fd];
    if (handle == 0) return EBADF;

    SyscallResult res = ::sys_close(handle);
    if (res.error != SysError::Success) return map_error(res.error);

    g_fd_table.entries[fd] = 0;
    return 0;
}

void Sysdeps<LibcLog>::operator()(const char *message) {
    ssize_t written;
    Sysdeps<Write>()(2, message, strlen(message), &written);
}

void Sysdeps<LibcPanic>::operator()() {
    Sysdeps<LibcLog>()("\nmlibc panic!\n");
    Sysdeps<Exit>()(1);
}


// ----------------------------------------------------
// 4. stubs
// ----------------------------------------------------

int Sysdeps<Isatty>::operator()(int) {
    return 0;
}

int Sysdeps<Seek>::operator()(int, off_t, int, off_t *) {
    return ESPIPE; 
}

int Sysdeps<Open>::operator()(const char *, int, unsigned int, int *) {
    STUB(); 
}

int Sysdeps<ClockGet>::operator()(int, time_t *, long *) {
    STUB();
}

} // namespace mlibc

extern "C" {
float _Complex __mulsc3(float a, float b, float c, float d) { STUB(); }
double _Complex __muldc3(double a, double b, double c, double d) { STUB(); }
long double _Complex __mulxc3(long double a, long double b, long double c, long double d) { STUB(); }
}
