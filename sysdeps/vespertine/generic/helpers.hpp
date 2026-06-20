#pragma once
#include <abi/vespertine_abi.hpp>

SysError socket_write_exact(HandleID h, const void *data, size_t len);
SysError socket_read_exact(HandleID h, void *data, size_t len);

template<typename T>
inline SysError ctrl_send(HandleID h, const T &payload) {
    PacketHeader hdr{};
    hdr.magic        = VESPER_MAGIC;
    hdr.version      = 1;
    hdr.packet_flags = 1; // IS_BUFFER
    hdr.packet_type  = static_cast<uint32_t>(PacketType::TermCommand);
    hdr.payload_len  = sizeof(T);
    SysError e = socket_write_exact(h, &hdr, sizeof(hdr));
    if (e != SysError::Success) return e;
    return socket_write_exact(h, &payload, sizeof(T));
}

template<typename T>
inline SysError ctrl_recv(HandleID h, T *out) {
    PacketHeader hdr{};
    SysError e = socket_read_exact(h, &hdr, sizeof(hdr));
    if (e != SysError::Success) return e;
    if (hdr.magic != VESPER_MAGIC) return SysError::InvalidArgument;
    if (hdr.payload_len != sizeof(T)) return SysError::InvalidArgument;
    return socket_read_exact(h, out, sizeof(T));
}
