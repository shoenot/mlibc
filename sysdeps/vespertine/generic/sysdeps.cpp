#include <mlibc/all-sysdeps.hpp>
#include <abi/vespertine_abi.hpp>
#include <abi/flags.hpp>
#include <abi-bits/termios.h>
#include <abi-bits/ioctls.h>
#include "helpers.hpp"
#include "mlibc/sysdep-tags.hpp"
#include "syscall.hpp"
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <bits/ensure.h>

static const ProcessInitPackage *g_init_pkg = nullptr;

[[noreturn]] static inline int stub_called(const char *func) {
    (void)func;
    __ensure(!"STUB function was called");
    __builtin_unreachable();
}

#define STUB() do { stub_called(__func__); __builtin_unreachable(); } while(0)

using ssize_t = ptrdiff_t;

struct FdTable {
    HandleID *entries;
    size_t capacity;
};

// --- globals ---
HandleID g_self_handle = 1;
HandleID g_root_handle = 0;
HandleID g_mem_pool = 0; HandleID g_sink_handle = 3; // Default debug sink

#define STATIC_FD_BOOTSTRAP_CAP 256
// Reserve slots 0, 1, 2 for stdio, and 3 for the internal debug sink
static HandleID bootstrap_fds[STATIC_FD_BOOTSTRAP_CAP] = {0, 0, 0, 3};
FdTable g_fd_table = { bootstrap_fds, STATIC_FD_BOOTSTRAP_CAP };

// --- error mapping ---
int map_error(SysError err) {
    switch(err) {
        case SysError::Success:         return 0;
        case SysError::OutOfMemory:     return ENOMEM;
        case SysError::PoolExhausted:   return ENOMEM;
        case SysError::InvalidHandle:   return EBADF;
        case SysError::AccessDenied:    return EACCES;
        case SysError::InvalidArgument: return EINVAL;
        case SysError::WouldBlock:      return EAGAIN;
        default:                        return ENOSYS;
    }
}


namespace mlibc {

static void debug_print_str(const char *prefix, const char *str) {
    char buf[512];
    size_t p = 0;
    
    // Safely copy prefix
    size_t i = 0;
    while (prefix[i] && p < 509) {
        buf[p++] = prefix[i++];
    }
    
    // Safely copy string
    size_t s = 0;
    while (str[s] && p < 509) {
        buf[p++] = str[s++];
    }
    
    buf[p++] = '\n';
    buf[p] = '\0';
    
    FileOp::FileOp_Write_Body write_body;
    write_body.offset = (uintptr_t)-1; // Use kernel cursor
    write_body.buffer_ptr = reinterpret_cast<uintptr_t>(buf);
    write_body.len = p;
    
    FileOp file_op;
    file_op.tag = FileOp::Tag::FileOp_Write;
    file_op.write = write_body;
    
    Invocation inv;
    inv.tag = Invocation::Tag::Invocation_File;
    inv.file._0 = file_op;
    
    sys_invoke(g_sink_handle, &inv);
}

static void debug_print_num(const char *prefix, size_t num) {
    char buf[128];
    char *p = buf;
    while (*prefix) {
        *p++ = *prefix++;
    }
    char num_buf[32];
    int i = 0;
    if (num == 0) {
        num_buf[i++] = '0';
    } else {
        while (num > 0) {
            num_buf[i++] = '0' + (num % 10);
            num = num / 10;
        }
    }
    while (i > 0) {
        *p++ = num_buf[--i];
    }
    *p++ = '\n';
    *p = '\0';
    
    FileOp::FileOp_Write_Body write_body;
    write_body.offset = (uintptr_t)-1;
    write_body.buffer_ptr = reinterpret_cast<uintptr_t>(buf);
    write_body.len = p - buf;
    
    FileOp file_op;
    file_op.tag = FileOp::Tag::FileOp_Write;
    file_op.write = write_body;
    
    Invocation inv;
    inv.tag = Invocation::Tag::Invocation_File;
    inv.file._0 = file_op;
    
    sys_invoke(g_sink_handle, &inv);
}

static void ensure_handles();
static HandleID resolve_path(const char *path);
static HandleID find_tag(uintptr_t tag);

// ----------------------------------------------------
// 1. threading & panics
// ----------------------------------------------------

void Sysdeps<Exit>::operator()(int status) {
    (void)status;
    ensure_handles();
    ProcOp proc_op;
    proc_op.tag = ProcOp::Tag::ProcOp_Kill;

    Invocation inv;
    inv.tag = Invocation::Tag::Invocation_Proc;
    inv.proc._0 = proc_op;

    sys_invoke(g_self_handle, &inv);
    sys_thread_terminate();
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

// ----------------------------------------------------
// 2. memory allocation
// ----------------------------------------------------

int Sysdeps<AnonAllocate>::operator()(size_t size, void **pointer) {
    ensure_handles();
    MemPoolOp::MemPoolOp_AllocateVmo_Body alloc_body;
    alloc_body.size = size;

    MemPoolOp pool_op;
    pool_op.tag = MemPoolOp::Tag::MemPoolOp_AllocateVmo;
    pool_op.allocate_vmo = alloc_body;

    Invocation inv;
    inv.tag = Invocation::Tag::Invocation_MemPool;
    inv.mem_pool._0 = pool_op;

    SyscallResult vmo_res = sys_invoke(g_mem_pool, &inv);
    if (vmo_res.error != SysError::Success) return map_error(vmo_res.error);

    HandleID vmo_handle = vmo_res.value;

    VmoOp::VmoOp_MapIntoProc_Body map_body;
    map_body.vaddr = 0;
    map_body.len = size;
    map_body.vm_flags = 5; 

    VmoOp vmo_op;
    vmo_op.tag = VmoOp::Tag::VmoOp_MapIntoProc;
    vmo_op.map_into_proc = map_body;

    Invocation map_inv;
    map_inv.tag = Invocation::Tag::Invocation_Vmo;
    map_inv.vmo._0 = vmo_op;

    SyscallResult map_res = sys_invoke(vmo_handle, &map_inv);
    ::sys_close(vmo_handle); 

    if (map_res.error != SysError::Success) return map_error(map_res.error);

    *pointer = reinterpret_cast<void*>(map_res.value);
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

int Sysdeps<VmMap>::operator()(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **out) {
    (void)offset;
    ensure_handles();
    HandleID vmo_handle = 0;
    bool close_vmo = false;

    if (flags & 0x20) { // MAP_ANONYMOUS
        MemPoolOp::MemPoolOp_AllocateVmo_Body alloc_body;
        alloc_body.size = size;

        MemPoolOp pool_op;
        pool_op.tag = MemPoolOp::Tag::MemPoolOp_AllocateVmo;
        pool_op.allocate_vmo = alloc_body;

        Invocation inv;
        inv.tag = Invocation::Tag::Invocation_MemPool;
        inv.mem_pool._0 = pool_op;

        SyscallResult vmo_res = sys_invoke(g_mem_pool, &inv);
        if (vmo_res.error != SysError::Success) return map_error(vmo_res.error);
        
        vmo_handle = vmo_res.value;
        close_vmo = true;
    } else {
        if (fd < 0 || (size_t)fd >= g_fd_table.capacity) return EBADF;
        HandleID file_handle = g_fd_table.entries[fd];
        if (file_handle == 0) return EBADF;

        FileOp file_op;
        file_op.tag = FileOp::Tag::FileOp_GetVmo;
        
        Invocation inv;
        inv.tag = Invocation::Tag::Invocation_File;
        inv.file._0 = file_op;

        SyscallResult vmo_res = sys_invoke(file_handle, &inv);
        if (vmo_res.error != SysError::Success) return map_error(vmo_res.error);
        
        vmo_handle = vmo_res.value;
        close_vmo = true;
    }

    if (!(flags & 0x20) && offset != 0) { 
        VmoOp::VmoOp_Clone_Body clone_body;
        clone_body.offset = offset;
        clone_body.len = size;

        VmoOp clone_op;
        clone_op.tag = VmoOp::Tag::VmoOp_Clone;
        clone_op.clone = clone_body;

        Invocation clone_inv;
        clone_inv.tag = Invocation::Tag::Invocation_Vmo;
        clone_inv.vmo._0 = clone_op;

        SyscallResult clone_res = sys_invoke(vmo_handle, &clone_inv);
        if (clone_res.error != SysError::Success) {
            if (close_vmo) ::sys_close(vmo_handle);
            return map_error(clone_res.error);
        }

        if (close_vmo) ::sys_close(vmo_handle);
        vmo_handle = clone_res.value;
        close_vmo = true;
    }

    // Attempt the mapping with the requested address hint
    VmoOp::VmoOp_MapIntoProc_Body map_body;
    map_body.vaddr = reinterpret_cast<uintptr_t>(hint);
    map_body.len = size;
    // Translate flags: mlibc (1=R, 2=W, 4=X) to kernel (1=W, 2=X, 4=U)
    int vm_flags = 4; // VM_FLAG_USER
    if (prot & 2) vm_flags |= 1; // PROT_WRITE -> VM_FLAG_WRITE
    if (prot & 4) vm_flags |= 2; // PROT_EXEC -> VM_FLAG_EXEC
    map_body.vm_flags = vm_flags;

    VmoOp vmo_op;
    vmo_op.tag = VmoOp::Tag::VmoOp_MapIntoProc;
    vmo_op.map_into_proc = map_body;

    Invocation map_inv;
    map_inv.tag = Invocation::Tag::Invocation_Vmo;
    map_inv.vmo._0 = vmo_op;

    SyscallResult map_res = sys_invoke(vmo_handle, &map_inv);
    
    // Fallback: If the fixed placement collided, and MAP_FIXED (0x10) was NOT specified,
    // clear the vaddr requirement and let the kernel assign a free region safely.
    if (map_res.error != SysError::Success && !(flags & 0x10) && hint != nullptr) {
        map_body.vaddr = 0; 
        vmo_op.map_into_proc = map_body;
        map_inv.vmo._0 = vmo_op;
        map_res = sys_invoke(vmo_handle, &map_inv);
    }

    if (close_vmo) {
        ::sys_close(vmo_handle);
    }

    if (map_res.error != SysError::Success) return map_error(map_res.error);

    *out = reinterpret_cast<void*>(map_res.value);
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
    
    // Translate flags: mlibc (1=R, 2=W, 4=X) to kernel (1=W, 2=X, 4=U)
    int vm_flags = 4; // VM_FLAG_USER
    if (prot & 2) vm_flags |= 1; // PROT_WRITE -> VM_FLAG_WRITE
    if (prot & 4) vm_flags |= 2; // PROT_EXEC -> VM_FLAG_EXEC
    mprot_body.prot = vm_flags;

    ProcOp proc_op;
    proc_op.tag = ProcOp::Tag::ProcOp_Mprotect;
    proc_op.mprotect = mprot_body;

    Invocation inv;
    inv.tag = Invocation::Tag::Invocation_Proc;
    inv.proc._0 = proc_op;

    SyscallResult res = sys_invoke(g_self_handle, &inv);
    return map_error(res.error);
}

// ----------------------------------------------------
// 3. i/o
// ----------------------------------------------------

int Sysdeps<Write>::operator()(int fd, const void *buf, size_t count, ssize_t *bytes_written) {
    if (fd < 0 || (size_t)fd >= g_fd_table.capacity) return EBADF;
    HandleID handle = g_fd_table.entries[fd];
    if (handle == 0) return EBADF;

    FileOp::FileOp_Write_Body write_body;
    write_body.offset = (uintptr_t)-1; // Request kernel-side cursor
    write_body.buffer_ptr = reinterpret_cast<uintptr_t>(buf);
    write_body.len = count;

    FileOp file_op;
    file_op.tag = FileOp::Tag::FileOp_Write;
    file_op.write = write_body;

    Invocation inv;
    inv.tag = Invocation::Tag::Invocation_File;
    inv.file._0 = file_op;

    SyscallResult res = sys_invoke(handle, &inv);
    if (res.error != SysError::Success) return map_error(res.error);

    *bytes_written = res.value;
    return 0;
}

int Sysdeps<Read>::operator()(int fd, void *buf, size_t count, ssize_t *bytes_read) {
    if (fd < 0 || (size_t)fd >= g_fd_table.capacity) return EBADF;
    HandleID handle = g_fd_table.entries[fd];
    if (handle == 0) return EBADF;

    FileOp::FileOp_Read_Body read_body;
    read_body.offset = (uintptr_t)-1; // Request kernel-side cursor
    read_body.buffer_ptr = reinterpret_cast<uintptr_t>(buf);
    read_body.len = count;

    FileOp file_op;
    file_op.tag = FileOp::Tag::FileOp_Read;
    file_op.read = read_body;

    Invocation inv;
    inv.tag = Invocation::Tag::Invocation_File;
    inv.file._0 = file_op;

    SyscallResult res = sys_invoke(handle, &inv);
    if (res.error != SysError::Success) return map_error(res.error);

    *bytes_read = res.value;
    return 0;
}

int Sysdeps<Seek>::operator()(int fd, off_t offset, int whence, off_t *new_offset) {
    if (fd < 0 || (size_t)fd >= g_fd_table.capacity) return EBADF;
    HandleID handle = g_fd_table.entries[fd];
    if (handle == 0) return EBADF;

    FileOp::FileOp_Seek_Body seek_body;
    seek_body.offset = offset;
    seek_body.whence = whence;

    FileOp file_op;
    file_op.tag = FileOp::Tag::FileOp_Seek;
    file_op.seek = seek_body;

    Invocation inv;
    inv.tag = Invocation::Tag::Invocation_File;
    inv.file._0 = file_op;

    SyscallResult res = sys_invoke(handle, &inv);
    if (res.error == SysError::UnsupportedOperation) return ESPIPE; 
    if (res.error != SysError::Success) return map_error(res.error);

    if (new_offset) {
        *new_offset = res.value;
    }
    return 0;
}

int Sysdeps<Close>::operator()(int fd) {
    if (fd < 0 || (size_t)fd >= g_fd_table.capacity) return EBADF;
    HandleID handle = g_fd_table.entries[fd];
    if (handle == 0) return EBADF;

    SyscallResult res = ::sys_close(handle);
    if (res.error != SysError::Success) return map_error(res.error);

    g_fd_table.entries[fd] = 0;
    return 0;
}

void Sysdeps<LibcLog>::operator()(const char *message) {
    ssize_t written;
    Sysdeps<Write>()(2, message, strlen(message), &written);
}

void Sysdeps<LibcPanic>::operator()() {
    Sysdeps<LibcLog>()("\nmlibc panic!\n");
    Sysdeps<Exit>()(1);
}

// ----------------------------------------------------
// 4. stubs
// ----------------------------------------------------

extern "C" [[gnu::weak]] uintptr_t *entryStack;

int Sysdeps<Open>::operator()(const char *path, int flags, unsigned int mode, int *fd) {
    (void)flags; (void)mode;

    char local_path[256];
    size_t i = 0;
    while (path[i] && i < 255) {
        local_path[i] = path[i];
        i++;
    }
    local_path[i] = '\0';

    ensure_handles();

    HandleID file_handle = resolve_path(local_path);
    if (file_handle == 0) {
        return ENOENT;
    }

    for (size_t i = 3; i < g_fd_table.capacity; i++) {
        if (g_fd_table.entries[i] == 0) {
            g_fd_table.entries[i] = file_handle;
            *fd = i;
            return 0;
        }
    }

    ::sys_close(file_handle);
    return EMFILE;
}

int Sysdeps<ClockGet>::operator()(int clock, time_t *secs, long *nanos) {
    (void)clock;
    ensure_handles();
    uintptr_t sys_clock = find_tag(TAG_SYS_CLOCK);
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

int Sysdeps<Tcgetattr>::operator()(int fd, struct termios *attr) {
    (void)fd;
    ensure_handles();
    uintptr_t g_term_ctrl = find_tag(TAG_APP_TERM);
    if (g_term_ctrl == 0) return ENOTTY;

    TermCommand cmd{};
    cmd.tag = TermCommand::Tag::TermCommand_GetTermios;

    SysError e = ctrl_send(g_term_ctrl, cmd);
    if (e != SysError::Success) return map_error(e);

    termios t{};
    e = ctrl_recv(g_term_ctrl, &t);
    if (e != SysError::Success) return map_error(e);

    attr->c_iflag  = t.c_iflag;
    attr->c_oflag  = t.c_oflag;
    attr->c_cflag  = t.c_cflag;
    attr->c_lflag  = t.c_lflag;
    attr->c_line   = t.c_line;
    memcpy(attr->c_cc, t.c_cc, sizeof(t.c_cc));
    attr->c_ibaud = t.c_ibaud;
    attr->c_obaud = t.c_obaud;
    return 0;
}

int Sysdeps<Tcsetattr>::operator()(int fd, int optional_actions, const struct termios *attr) {
    (void)fd; (void)optional_actions;
    ensure_handles();
    uintptr_t g_term_ctrl = find_tag(TAG_APP_TERM);
    if (g_term_ctrl == 0) return ENOTTY;

    TermCommand cmd{};
    cmd.tag = TermCommand::Tag::TermCommand_SetTermios;
    cmd.set_termios._0.c_iflag  = attr->c_iflag;
    cmd.set_termios._0.c_oflag  = attr->c_oflag;
    cmd.set_termios._0.c_cflag  = attr->c_cflag;
    cmd.set_termios._0.c_lflag  = attr->c_lflag;
    cmd.set_termios._0.c_line   = attr->c_line;
    memcpy(cmd.set_termios._0.c_cc, attr->c_cc, sizeof(cmd.set_termios._0.c_cc));
    cmd.set_termios._0.c_ibaud = attr->c_ibaud;
    cmd.set_termios._0.c_obaud = attr->c_obaud;

    SysError e = ctrl_send(g_term_ctrl, cmd);
    return map_error(e);
    // no response expected for SetTermios
}

int Sysdeps<Tcgetwinsize>::operator()(int fd, struct winsize *winsz) {
    (void)fd;
    ensure_handles();
    uintptr_t g_term_ctrl = find_tag(TAG_APP_TERM);
    if (g_term_ctrl == 0) return ENOTTY;

    TermCommand cmd{};
    cmd.tag = TermCommand::Tag::TermCommand_GetWindowSize;

    SysError e = ctrl_send(g_term_ctrl, cmd);
    if (e != SysError::Success) return map_error(e);

    // terminal responds with send_packet::<(u32, u32)> — cols then rows
    struct { uint32_t cols; uint32_t rows; } size{};
    e = ctrl_recv(g_term_ctrl, &size);
    if (e != SysError::Success) return map_error(e);

    // width/height returned as chars 
    winsz->ws_row    = static_cast<unsigned short>(size.rows);
    winsz->ws_col    = static_cast<unsigned short>(size.cols);
    winsz->ws_xpixel = static_cast<unsigned short>(size.cols * 8);   
    winsz->ws_ypixel = static_cast<unsigned short>(size.rows * 16);  
    return 0;
}

int Sysdeps<Isatty>::operator()(int fd) {
    ensure_handles();
    uintptr_t g_term_ctrl = find_tag(TAG_APP_TERM);
    if (g_term_ctrl != 0 && (fd == 0 || fd == 1 || fd == 2))
        return 0; // 0 = Success (Is a TTY)
    return ENOTTY; // Error (Not a TTY)
}

int Sysdeps<Ioctl>::operator()(int fd, unsigned long request, void *arg, int *result) {
    (void)fd;
    ensure_handles();

    if (request == TIOCGWINSZ) {
        struct winsize *ws = static_cast<struct winsize *>(arg);
        if (!ws) return EINVAL;
        uintptr_t g_term_ctrl = find_tag(TAG_APP_TERM);
        if (g_term_ctrl == 0) return ENOTTY;

        TermCommand cmd{};
        cmd.tag = TermCommand::Tag::TermCommand_GetWindowSize;

        SysError e = ctrl_send(g_term_ctrl, cmd);
        if (e != SysError::Success) return map_error(e);

        struct { uint32_t cols; uint32_t rows; } size{};
        e = ctrl_recv(g_term_ctrl, &size);
        if (e != SysError::Success) return map_error(e);

        ws->ws_col    = static_cast<unsigned short>(size.cols);
        ws->ws_row    = static_cast<unsigned short>(size.rows);
        ws->ws_xpixel = static_cast<unsigned short>(size.cols * 8);
        ws->ws_ypixel = static_cast<unsigned short>(size.rows * 16);
        if (result) *result = 0;
        return 0;
    }

    return ENOSYS;
}

// ----------------------------------------------------
// 5. helpers
// ----------------------------------------------------

static void ensure_handles() {
    static bool pool_initialized = false;
    static bool stack_initialized = false;

    // 1. Initialize the memory pool as early as possible.
    if (!pool_initialized && g_mem_pool == 0) {
        HandleID mem_man = resolve_path("/System/Services/MemoryManager");
        if (mem_man != 0) {
            MemManOp::MemManOp_CreatePool_Body body;
            body.limit = 0; // 0 = unlimited or default

            MemManOp op;
            op.tag = MemManOp::Tag::MemManOp_CreatePool;
            op.create_pool = body;

            Invocation mem_inv;
            mem_inv.tag = Invocation::Tag::Invocation_MemoryManager;
            mem_inv.memory_manager._0 = op;

            SyscallResult res = ::sys_invoke(mem_man, &mem_inv);
            if (res.error == SysError::Success) {
                g_mem_pool = res.value;
                pool_initialized = true;
            }
            ::sys_close(mem_man);
        }
    }

    // 2. Initialize stack-dependent handles once entryStack is populated by the runtime.
    if (!stack_initialized && &entryStack && entryStack) {
        uintptr_t *stack = entryStack;
        size_t argc = stack[0];
        size_t env_idx = 1 + argc + 1;
        while (stack[env_idx]) {
            env_idx++;
        }
        size_t aux_idx = env_idx + 1;
        struct AuxEntry {
            uintptr_t type;
            uintptr_t val;
        };
        AuxEntry *auxv = reinterpret_cast<AuxEntry *>(&stack[aux_idx]);
        size_t i = 0;
        while (auxv[i].type != 0) {
            i++;
        }
        auto *pkg = reinterpret_cast<ProcessInitPackage *>(&auxv[i + 1]);
        if (pkg) {
            g_init_pkg = pkg;
            g_self_handle = pkg->self_handle;
            g_root_handle = pkg->root_handle;
            g_sink_handle = pkg->sink_handle;
            g_fd_table.entries[0] = pkg->source_handle; // STDIN_FILENO
            g_fd_table.entries[1] = pkg->sink_handle;   // STDOUT_FILENO
            g_fd_table.entries[2] = pkg->sink_handle;   // STDERR_FILENO
            g_fd_table.entries[3] = pkg->sink_handle;   // Reserve slot 3
        }
        stack_initialized = true;
    }
}

static HandleID resolve_path(const char *path) {
    if (!path || *path == '\0') return 0;
    
    HandleID curr = g_root_handle;

    auto do_lookup = [](HandleID dir, const char *name, size_t len) -> HandleID {
        DirectoryOp dir_op;
        dir_op.tag = DirectoryOp::Tag::DirectoryOp_Lookup;
        dir_op.lookup.name = reinterpret_cast<uintptr_t>(name);
        dir_op.lookup.name_len = len;

        Invocation inv;
        inv.tag = Invocation::Tag::Invocation_Directory;
        inv.directory._0 = dir_op;

        SyscallResult res = ::sys_invoke(dir, &inv);
        if (res.error != SysError::Success) {
            return 0;
        }
        return res.value;
    };

    const char *p = path;
    while (*p == '/') {
        p++;
    }

    while (*p) {
        const char *start = p;
        while (*p && *p != '/') {
            p++;
        }
        size_t len = p - start;
        if (len > 0) {
            HandleID next = do_lookup(curr, start, len);
            if (next == 0) {
                if (curr != g_root_handle) ::sys_close(curr);
                return 0;
            }
            if (curr != g_root_handle) ::sys_close(curr);
            curr = next;
        }
        while (*p == '/') {
            p++;
        }
    }
    return curr;
}

static HandleID find_tag(uintptr_t tag) {
    if (!g_init_pkg) return 0;
    for (size_t i = 0; i < g_init_pkg->extra_handles_len; i++) {
        if (g_init_pkg->extra_handles_ptr[i].tag == tag) {
            return g_init_pkg->extra_handles_ptr[i].id;
        }
    }
    return 0;
}

} // namespace mlibc

extern "C" {
float _Complex __mulsc3(float a, float b, float c, float d) { STUB(); }
double _Complex __muldc3(double a, double b, double c, double d) { STUB(); }
long double _Complex __mulxc3(long double a, long double b, long double c, long double d) { STUB(); }
}
