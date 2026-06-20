#include "sysdeps_shared.hpp"

namespace mlibc {

int Sysdeps<ClockGet>::operator()(int clock, time_t *secs, long *nanos) {
    (void)clock;
    ensure_handles();
    uintptr_t sys_clock = find_capability(CAP_CLOCK);
    if (sys_clock == 0) return EPERM;

    ClockOp::ClockOp_GetTimestamp_Body ts_body;
    ts_body.s_ptr = reinterpret_cast<uintptr_t>(secs);
    ts_body.ns_ptr = reinterpret_cast<uintptr_t>(nanos);

    ClockOp op;
    op.tag = ClockOp::Tag::ClockOp_GetTimestamp;
    op.get_timestamp = ts_body;

    Invocation inv;
    inv.tag = Invocation::Tag::Invocation_Clock;
    inv.clock._0 = op;

    SyscallResult res = sys_invoke(sys_clock, &inv);
    if (res.error == SysError::UnsupportedOperation) return ESPIPE; 
    if (res.error != SysError::Success) return map_error(res.error);

    return 0;
}


} // namespace mlibc
