#pragma once

#include "mlibc/sysdep-tags.hpp"
#include <mlibc/sysdep-signatures.hpp>

namespace mlibc {

struct VespertineSysdepTags :
    LibcPanic,
    LibcLog,
    Sigaction,
    Isatty,
    Write,
    TcbSet,
    AnonAllocate,
    AnonFree,
    Seek,
    Exit,
    Close,
    FutexWake,
    FutexWait,
    Read,
    Open,
    Mkdir,
    Unlinkat,
    Rmdir,
    Chdir,
    Ftruncate,
    VmMap,
    VmUnmap,
    VmProtect,
    ClockGet,
    Tcgetattr,
    Tcsetattr,
    Tcgetwinsize,
    Ioctl
{};

template<typename Tag>
using Sysdeps = SysdepOf<VespertineSysdepTags, Tag>;

} // namespace mlibc
