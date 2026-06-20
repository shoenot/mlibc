#include "sysdeps_shared.hpp"

namespace mlibc {

void Sysdeps<Exit>::operator()(int status) {
    sys_thread_terminate(static_cast<uint32_t>(status));
}

int Sysdeps<TcbSet>::operator()(void *tcb) {
    ensure_handles();
    ProcOp::ProcOp_SetFsBase_Body fs_body;
    fs_body.fs_base = reinterpret_cast<uintptr_t>(tcb);

    ProcOp proc_op;
    proc_op.tag = ProcOp::Tag::ProcOp_SetFsBase;
    proc_op.set_fs_base = fs_body;

    Invocation inv;
    inv.tag = Invocation::Tag::Invocation_Proc;
    inv.proc._0 = proc_op;

    SyscallResult res = sys_invoke(g_self_handle, &inv);
    return map_error(res.error);
}

int Sysdeps<FutexWait>::operator()(int *pointer, int expected, const struct timespec *time) {
    (void)time;
    SyscallResult res = ::sys_futex_wait(reinterpret_cast<uintptr_t>(pointer), expected);
    return map_error(res.error);
}

int Sysdeps<FutexWake>::operator()(int *pointer, bool wake_all) {
    size_t count = wake_all ? SIZE_MAX : 1;
    SyscallResult res = ::sys_futex_wake(reinterpret_cast<uintptr_t>(pointer), count);
    return map_error(res.error);
}
void Sysdeps<LibcLog>::operator()(const char *message) {
    ssize_t written;
    Sysdeps<Write>()(2, message, strlen(message), &written);
}

void Sysdeps<LibcPanic>::operator()() {
    Sysdeps<LibcLog>()("\nmlibc panic!\n");
    Sysdeps<Exit>()(1);
}


} // namespace mlibc
