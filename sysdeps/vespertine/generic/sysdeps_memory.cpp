#include "sysdeps_shared.hpp"

namespace mlibc {

static int allocate_vmo(size_t size, HandleID *out) {
    for (;;) {
        MemPoolOp op{};
        op.tag = MemPoolOp::Tag::MemPoolOp_AllocateVmo;
        op.allocate_vmo.size = size;

        Invocation inv{};
        inv.tag = Invocation::Tag::Invocation_MemPool;
        inv.mem_pool._0 = op;

        SyscallResult result = sys_invoke(g_mem_pool, &inv);
        if (result.error == SysError::Success) {
            *out = result.value;
            return 0;
        }
        if (result.error != SysError::PoolExhausted)
            return map_error(result.error);

        MemPoolOp expand{};
        expand.tag = MemPoolOp::Tag::MemPoolOp_RequestExpansion;
        expand.request_expansion.additional_bytes = size;
        inv.mem_pool._0 = expand;

        result = sys_invoke(g_mem_pool, &inv);
        if (result.error != SysError::Success)
            return map_error(result.error);
    }
}

static constexpr uintptr_t VM_FLAG_WRITE = 1 << 0;
static constexpr uintptr_t VM_FLAG_EXEC  = 1 << 1;
static constexpr uintptr_t VM_FLAG_USER  = 1 << 2;
static constexpr uintptr_t VM_FLAG_NO_ACCESS = 1 << 7;

static uintptr_t convert_prot(int prot) {
    uintptr_t vm_flags = VM_FLAG_USER;

    if (prot == PROT_NONE)
        return vm_flags | VM_FLAG_NO_ACCESS;

    if (prot & PROT_WRITE)
        vm_flags |= VM_FLAG_WRITE;

    if (prot & PROT_EXEC)
        vm_flags |= VM_FLAG_EXEC;

    return vm_flags;
}

static int map_vmo(
    HandleID vmo,
    void *hint,
    size_t size,
    int prot,
    void **out
) {
    VmoOp op{};
    op.tag = VmoOp::Tag::VmoOp_MapIntoProc;
    op.map_into_proc.vaddr = reinterpret_cast<uintptr_t>(hint);
    op.map_into_proc.len = size;
    op.map_into_proc.vm_flags = convert_prot(prot);

    Invocation inv{};
    inv.tag = Invocation::Tag::Invocation_Vmo;
    inv.vmo._0 = op;

    SyscallResult result = sys_invoke(vmo, &inv);
    if (result.error != SysError::Success)
        return map_error(result.error);

    *out = reinterpret_cast<void *>(result.value);
    return 0;
}
int Sysdeps<AnonAllocate>::operator()(size_t size, void **pointer) {
    ensure_handles();

    if (!pointer || size == 0)
        return EINVAL;

    HandleID vmo;
    int error = allocate_vmo(size, &vmo);
    if (error)
        return error;

    VmoOp op{};
    op.tag = VmoOp::Tag::VmoOp_MapIntoProc;
    op.map_into_proc.vaddr = 0;
    op.map_into_proc.len = size;
    op.map_into_proc.vm_flags =
        VM_FLAG_USER | VM_FLAG_WRITE;

    Invocation inv{};
    inv.tag = Invocation::Tag::Invocation_Vmo;
    inv.vmo._0 = op;

    SyscallResult result = sys_invoke(vmo, &inv);
    ::sys_close(vmo);

    if (result.error != SysError::Success)
        return map_error(result.error);

    *pointer = reinterpret_cast<void *>(result.value);
    return 0;
}

int Sysdeps<AnonFree>::operator()(void *pointer, size_t size) {
    ensure_handles();
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

int Sysdeps<VmMap>::operator()(
    void *hint,
    size_t size,
    int prot,
    int flags,
    int fd,
    off_t offset,
    void **out
) {
    ensure_handles();

    if (!out || size == 0)
        return EINVAL;

    if (offset < 0)
        return EINVAL;

    if (static_cast<uintptr_t>(offset) & 0xFFF)
        return EINVAL;

    if ((flags & MAP_FIXED) && !hint)
        return EINVAL;

    const bool anonymous = flags & MAP_ANONYMOUS;

    if (anonymous && offset != 0)
        return EINVAL;

    // File-backed MAP_SHARED needs shared dirty-page/writeback semantics.
    if (!anonymous && (flags & MAP_SHARED))
        return ENOTSUP;
    HandleID vmo = 0;

    if (anonymous) {
        int error = allocate_vmo(size, &vmo);
        if (error)
            return error;
    } else {
        if (fd < 0 || static_cast<size_t>(fd) >= g_fd_table.capacity)
            return EBADF;

        HandleID file = g_fd_table.entries[fd];
        if (!file)
            return EBADF;

        FileOp file_op{};
        file_op.tag = FileOp::Tag::FileOp_GetVmo;

        Invocation file_inv{};
        file_inv.tag = Invocation::Tag::Invocation_File;
        file_inv.file._0 = file_op;

        SyscallResult result = sys_invoke(file, &file_inv);
        if (result.error != SysError::Success)
            return map_error(result.error);

        vmo = result.value;
    }

    // create a vmo representing the requested file range.
    if (!anonymous && offset != 0) {
        VmoOp clone_op{};
        clone_op.tag = VmoOp::Tag::VmoOp_Clone;
        clone_op.clone.offset = static_cast<uintptr_t>(offset);
        clone_op.clone.len = size;

        Invocation clone_inv{};
        clone_inv.tag = Invocation::Tag::Invocation_Vmo;
        clone_inv.vmo._0 = clone_op;

        SyscallResult result = sys_invoke(vmo, &clone_inv);
        ::sys_close(vmo);

        if (result.error != SysError::Success)
            return map_error(result.error);

        vmo = result.value;
    }

    VmoOp map_op{};
    map_op.tag = VmoOp::Tag::VmoOp_MapIntoProc;
    // Non-fixed hints are advisory. MapIntoProc-at currently has replacement
    // semantics, so only pass an address when replacement was requested.
    map_op.map_into_proc.vaddr =
        (flags & MAP_FIXED) ? reinterpret_cast<uintptr_t>(hint) : 0;
    map_op.map_into_proc.len = size;
    map_op.map_into_proc.vm_flags = convert_prot(prot);

    Invocation map_inv{};
    map_inv.tag = Invocation::Tag::Invocation_Vmo;
    map_inv.vmo._0 = map_op;

    SyscallResult result = sys_invoke(vmo, &map_inv);

    ::sys_close(vmo);

    if (result.error != SysError::Success)
        return map_error(result.error);

    *out = reinterpret_cast<void *>(result.value);
    return 0;
}

int Sysdeps<VmUnmap>::operator()(void *pointer, size_t size) {
    return Sysdeps<AnonFree>()(pointer, size);
}

int Sysdeps<VmProtect>::operator()(void *pointer, size_t size, int prot) {
    ensure_handles();
    ProcOp::ProcOp_Mprotect_Body mprot_body;
    mprot_body.vaddr = reinterpret_cast<uintptr_t>(pointer);
    mprot_body.len = size;
    
    mprot_body.prot = convert_prot(prot);

    ProcOp proc_op;
    proc_op.tag = ProcOp::Tag::ProcOp_Mprotect;
    proc_op.mprotect = mprot_body;

    Invocation inv;
    inv.tag = Invocation::Tag::Invocation_Proc;
    inv.proc._0 = proc_op;

    SyscallResult res = sys_invoke(g_self_handle, &inv);
    return map_error(res.error);
}

// stubbed
int Sysdeps<Madvise>::operator()(void *addr, size_t length, int advice) {
    return 0;
}

} // namespace mlibc
