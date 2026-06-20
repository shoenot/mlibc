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
    Stat,
    OpenDir,
    ReadEntries,
    Dup,
    Dup2,
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
    Ioctl,
    GetUid,
    GetEuid,
    GetGid,
    GetEgid,
    Madvise
{};

template<typename Tag>
using Sysdeps = SysdepOf<VespertineSysdepTags, Tag>;

} // namespace mlibc
