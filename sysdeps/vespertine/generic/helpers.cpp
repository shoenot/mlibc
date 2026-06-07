#include "helpers.hpp"
#include "syscall.hpp"
#include <stdint.h>

SysError socket_write_exact(HandleID h, const void *data, size_t len) {
    const uint8_t *p = static_cast<const uint8_t*>(data);
    size_t rem = len;
    while (rem > 0) {
        FileOp::FileOp_Write_Body body;
        body.offset = (uintptr_t)-1;
        body.buffer_ptr = reinterpret_cast<uintptr_t>(p);
        body.len = rem;
        FileOp op; op.tag = FileOp::Tag::FileOp_Write; op.write = body;
        Invocation inv; inv.tag = Invocation::Tag::Invocation_File; inv.file._0 = op;
        SyscallResult r = sys_invoke(h, &inv);
        if (r.error != SysError::Success) return r.error;
        if (r.value == 0) return SysError::InvalidHandle;
        p += r.value; rem -= r.value;
    }
    return SysError::Success;
}

SysError socket_read_exact(HandleID h, void *data, size_t len) {
    uint8_t *p = static_cast<uint8_t*>(data);
    size_t rem = len;
    while (rem > 0) {
        FileOp::FileOp_Read_Body body;
        body.offset = (uintptr_t)-1;
        body.buffer_ptr = reinterpret_cast<uintptr_t>(p);
        body.len = rem;
        FileOp op; op.tag = FileOp::Tag::FileOp_Read; op.read = body;
        Invocation inv; inv.tag = Invocation::Tag::Invocation_File; inv.file._0 = op;
        SyscallResult r = sys_invoke(h, &inv);
        if (r.error != SysError::Success) return r.error;
        if (r.value == 0) return SysError::InvalidHandle;
        p += r.value; rem -= r.value;
    }
    return SysError::Success;
}
