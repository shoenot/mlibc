#pragma once

#include "mlibc/sysdep-tags.hpp"
#include <mlibc/sysdep-signatures.hpp>

namespace mlibc {

struct VespertineSysdepTags :
    LibcPanic,
    LibcLog,
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
    VmMap,
    VmUnmap,
    VmProtect,
    ClockGet,
    Tcgetattr,
    Tcsetattr,
    Tcsetwinsize
{};

template<typename Tag>
using Sysdeps = SysdepOf<VespertineSysdepTags, Tag>;

} // namespace mlibc
