#include <stdint.h>
#include <abi/vespertine_abi.hpp>
#include <abi/flags.hpp>

static SysError socket_write_exact(HandleID h, const void *data, size_t len) {
    const uint8_t *p = static_cast<const uint8_t*>(data);
    size_t rem = len;
    while (rem > 0) {
        FileOp::FileOp_Write_Body body;
        body.offset = 0;
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

static SysError socket_read_exact(HandleID h, void *data, size_t len) {
    uint8_t *p = static_cast<uint8_t*>(data);
    size_t rem = len;
    while (rem > 0) {
        FileOp::FileOp_Read_Body body;
        body.offset = 0;
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

template<typename T>
static SysError ctrl_send(HandleID h, const T &payload) {
    PacketHeader hdr{};
    hdr.magic        = VESPER_MAGIC;
    hdr.version      = 1;
    hdr.packet_flags = 1; // IS_BUFFER
    hdr.packet_type  = 0; // terminal doesn't validate this field
    hdr.payload_len  = sizeof(T);
    SysError e = socket_write_exact(h, &hdr, sizeof(hdr));
    if (e != SysError::Success) return e;
    return socket_write_exact(h, &payload, sizeof(T));
}

template<typename T>
static SysError ctrl_recv(HandleID h, T *out) {
    PacketHeader hdr{};
    SysError e = socket_read_exact(h, &hdr, sizeof(hdr));
    if (e != SysError::Success) return e;
    if (hdr.magic != VESPER_MAGIC) return SysError::InvalidArgument;
    if (hdr.payload_len != sizeof(T)) return SysError::InvalidArgument;
    return socket_read_exact(h, out, sizeof(T));
}
