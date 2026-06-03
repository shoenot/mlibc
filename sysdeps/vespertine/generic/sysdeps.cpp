#include <mlibc/sysdeps.hpp>
#include <abi/vespertine_abi.hpp>
#include <abi/flags.hpp>
#include <errno.h>
#include <string.h>
#include <stdint.h>

extern uintptr_t g_self_handle;
extern uintptr_t g_mem_pool;
extern FdTable g_fd_table;

extern "C" SyscallResult sys_invoke(uintptr_t handle, const void *op);
extern "C" SyscallResult sys_close(uintptr_t handle);

int map_error(SysError err) {
    switch(err) {
        case SysError::Success:         return 0;
        case SysError::OutOfMemory:     return ENOMEM;
        case SysError::PoolExhausted:   return ENOMEM;
        case SysError::InvalidHandle:   return EBADF;
        case SysError::AccessDenied:    return EACCES;
        case SysError::InvalidArgument: return EINVAL;
        case SysError::WouldBlock:     return EAGAIN;
        default:                        return ENOSYS;
    }
}

namespace mlibc {

int sys_tcb_set(void *tcb) {
    ProcOp::SetFsBase_Body fs_body;
    fs_body.fs_base = reinterpret_cast<uintptr_t>(tcb);

    ProcOp proc_op;
    proc_op.tag = ProcOp::Tag::SetFsBase;
    proc_op.set_fs_base = fs_body;

    Invocation inv;
    inv.tag = Invocation::Tag::Proc;
    inv.proc._0 = proc_op;

    SyscallResult res = sys_invoke(g_self_handle, &inv);
    return map_error(res.error);
}

int sys_anon_allocate(size_t size, void **pointer) {
    MemPoolOp::AllocateVmo_Body alloc_body;
    alloc_body.size = size;

    MemPoolOp pool_op;
    pool_op.tag = MemPoolOp::Tag::AllocateVmo;
    pool_op.allocate_vmo = alloc_body;

    Invocation inv;
    inv.tag = Invocation::Tag::MemPool;
    inv.mem_pool._0 = pool_op;

    SyscallResult vmo_res = sys_invoke(g_mem_pool, &inv);
    if (vmo_res.error != SysError::Success) return map_error(vmo_res.error);

    uintptr_t vmo_handle = vmo_res.value;

    VmoOp::MapIntoProc_Body map_body;
    map_body.vaddr = 0;
    map_body.len = size;
    map_body.vm_flags = 5; // R | X or standard allocations

    VmoOp vmo_op;
    vmo_op.tag = VmoOp::Tag::MapIntoProc;
    vmo_op.map_into_proc = map_body;

    Invocation map_inv;
    map_inv.tag = Invocation::Tag::Vmo;
    map_inv.vmo._0 = vmo_op;

    SyscallResult map_res = sys_invoke(vmo_handle, &map_inv);
    sys_close(vmo_handle); 

    if (map_res.error != SysError::Success) return map_error(map_res.error);

    *pointer = reinterpret_cast<void*>(map_res.value);
    return 0;
}

int sys_anon_free(void *pointer, size_t size) {
    ProcOp::Unmap_Body unmap_body;
    unmap_body.vaddr = reinterpret_cast<uintptr_t>(pointer);
    unmap_body.len = size;

    ProcOp proc_op;
    proc_op.tag = ProcOp::Tag::Unmap;
    proc_op.unmap = unmap_body;

    Invocation inv;
    inv.tag = Invocation::Tag::Proc;
    inv.proc._0 = proc_op;

    SyscallResult res = sys_invoke(g_self_handle, &inv);
    return map_error(res.error);
}

int sys_write(int fd, const void *buf, size_t count, ssize_t *bytes_written) {
    if (fd < 0 || (size_t)fd >= g_fd_table.capacity) return EBADF;
    uintptr_t handle = g_fd_table.entries[fd];
    if (handle == 0) return EBADF;

    FileOp::Write_Body write_body;
    write_body.offset = 0;
    write_body.buffer_ptr = reinterpret_cast<uintptr_t>(buf);
    write_body.len = count;

    FileOp file_op;
    file_op.tag = FileOp::Tag::Write;
    file_op.write = write_body;

    Invocation inv;
    inv.tag = Invocation::Tag::File;
    inv.file._0 = file_op;

    SyscallResult res = sys_invoke(handle, &inv);
    if (res.error != SysError::Success) return map_error(res.error);

    *bytes_written = count;
    return 0;
}

} // namespace mlibc
