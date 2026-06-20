#include "sysdeps_shared.hpp"

namespace mlibc {

uid_t Sysdeps<GetUid>::operator()() {
    ensure_handles();
    return 0;
}

uid_t Sysdeps<GetEuid>::operator()() {
    ensure_handles();
    return 0;
}

gid_t Sysdeps<GetGid>::operator()() {
    ensure_handles();
    return 0;
}

gid_t Sysdeps<GetEgid>::operator()() {
    ensure_handles();
    return 0;
}


} // namespace mlibc
