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
#include <signal.h>
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
HandleID g_root_handle = 0;
HandleID g_self_handle = 1;
HandleID g_sink_handle = 3; // Default debug sink
HandleID g_mem_pool = VESPERTINE_HANDLE_MEMORY_POOL; 

#define STATIC_FD_BOOTSTRAP_CAP 256
// Reserve slots 0, 1, 2 for stdio
static HandleID bootstrap_fds[STATIC_FD_BOOTSTRAP_CAP] = {0, 0, 0};
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
static HandleID find_capability(CapabilityID capability);
static char *find_last_char(char *string, char character);

static ProcessInitPackage *find_init_package(uintptr_t *stack) {
    if (!stack)
        return nullptr;

    size_t argc = stack[0];
    size_t env_idx = 1 + argc + 1;

    while (stack[env_idx])
        env_idx++;

    struct AuxEntry {
        uintptr_t type;
        uintptr_t val;
    };

    auto *auxv = reinterpret_cast<AuxEntry *>(&stack[env_idx + 1]);

    for (size_t i = 0; auxv[i].type != 0; i++) {
        if (auxv[i].type == AT_VESPERTINE_INITPKG) {
            return reinterpret_cast<ProcessInitPackage *>(auxv[i].val);
        }
    }

    return nullptr;
}


static int allocate_vmo(size_t size, HandleID *out) {
    MemPoolOp op{};
    op.tag = MemPoolOp::Tag::MemPoolOp_AllocateVmo;
    op.allocate_vmo.size = size;

    Invocation inv{};
    inv.tag = Invocation::Tag::Invocation_MemPool;
    inv.mem_pool._0 = op;

    SyscallResult result = sys_invoke(g_mem_pool, &inv);
    if (result.error != SysError::Success)
        return map_error(result.error);

    *out = result.value;
    return 0;
}

static constexpr uintptr_t VM_FLAG_WRITE = 1 << 0;
static constexpr uintptr_t VM_FLAG_EXEC  = 1 << 1;
static constexpr uintptr_t VM_FLAG_USER  = 1 << 2;
static constexpr uintptr_t VM_FLAG_NO_ACCESS = 1 << 7;

static uintptr_t convert_prot(int prot) {
    uintptr_t vm_flags = VM_FLAG_USER;

    if (prot == PROT_NONE)
        return vm_flags | VM_FLAG_NO_ACCESS;

    if (prot & PROT_WRITE)
        vm_flags |= VM_FLAG_WRITE;

    if (prot & PROT_EXEC)
        vm_flags |= VM_FLAG_EXEC;

    return vm_flags;
}

static int map_vmo(
    HandleID vmo,
    void *hint,
    size_t size,
    int prot,
    void **out
) {
    VmoOp op{};
    op.tag = VmoOp::Tag::VmoOp_MapIntoProc;
    op.map_into_proc.vaddr = reinterpret_cast<uintptr_t>(hint);
    op.map_into_proc.len = size;
    op.map_into_proc.vm_flags = convert_prot(prot);

    Invocation inv{};
    inv.tag = Invocation::Tag::Invocation_Vmo;
    inv.vmo._0 = op;

    SyscallResult result = sys_invoke(vmo, &inv);
    if (result.error != SysError::Success)
        return map_error(result.error);

    *out = reinterpret_cast<void *>(result.value);
    return 0;
}

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

    if (!pointer || size == 0)
        return EINVAL;

    HandleID vmo;
    int error = allocate_vmo(size, &vmo);
    if (error)
        return error;

    VmoOp op{};
    op.tag = VmoOp::Tag::VmoOp_MapIntoProc;
    op.map_into_proc.vaddr = 0;
    op.map_into_proc.len = size;
    op.map_into_proc.vm_flags =
        VM_FLAG_USER | VM_FLAG_WRITE;

    Invocation inv{};
    inv.tag = Invocation::Tag::Invocation_Vmo;
    inv.vmo._0 = op;

    SyscallResult result = sys_invoke(vmo, &inv);
    ::sys_close(vmo);

    if (result.error != SysError::Success)
        return map_error(result.error);

    *pointer = reinterpret_cast<void *>(result.value);
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

int Sysdeps<VmMap>::operator()(
    void *hint,
    size_t size,
    int prot,
    int flags,
    int fd,
    off_t offset,
    void **out
) {
    ensure_handles();

    if (!out || size == 0)
        return EINVAL;

    if (offset < 0)
        return EINVAL;

    if (static_cast<uintptr_t>(offset) & 0xFFF)
        return EINVAL;

    if ((flags & MAP_FIXED) && !hint)
        return EINVAL;

    const bool anonymous = flags & MAP_ANONYMOUS;

    if (anonymous && offset != 0)
        return EINVAL;

    // File-backed MAP_SHARED needs shared dirty-page/writeback semantics.
    if (!anonymous && (flags & MAP_SHARED))
        return ENOTSUP;
    HandleID vmo = 0;

    if (anonymous) {
        int error = allocate_vmo(size, &vmo);
        if (error)
            return error;
    } else {
        if (fd < 0 || static_cast<size_t>(fd) >= g_fd_table.capacity)
            return EBADF;

        HandleID file = g_fd_table.entries[fd];
        if (!file)
            return EBADF;

        FileOp file_op{};
        file_op.tag = FileOp::Tag::FileOp_GetVmo;

        Invocation file_inv{};
        file_inv.tag = Invocation::Tag::Invocation_File;
        file_inv.file._0 = file_op;

        SyscallResult result = sys_invoke(file, &file_inv);
        if (result.error != SysError::Success)
            return map_error(result.error);

        vmo = result.value;
    }

    // create a vmo representing the requested file range.
    if (!anonymous && offset != 0) {
        VmoOp clone_op{};
        clone_op.tag = VmoOp::Tag::VmoOp_Clone;
        clone_op.clone.offset = static_cast<uintptr_t>(offset);
        clone_op.clone.len = size;

        Invocation clone_inv{};
        clone_inv.tag = Invocation::Tag::Invocation_Vmo;
        clone_inv.vmo._0 = clone_op;

        SyscallResult result = sys_invoke(vmo, &clone_inv);
        ::sys_close(vmo);

        if (result.error != SysError::Success)
            return map_error(result.error);

        vmo = result.value;
    }

    VmoOp map_op{};
    map_op.tag = VmoOp::Tag::VmoOp_MapIntoProc;
    // Non-fixed hints are advisory. MapIntoProc-at currently has replacement
    // semantics, so only pass an address when replacement was requested.
    map_op.map_into_proc.vaddr =
        (flags & MAP_FIXED) ? reinterpret_cast<uintptr_t>(hint) : 0;
    map_op.map_into_proc.len = size;
    map_op.map_into_proc.vm_flags = convert_prot(prot);

    Invocation map_inv{};
    map_inv.tag = Invocation::Tag::Invocation_Vmo;
    map_inv.vmo._0 = map_op;

    SyscallResult result = sys_invoke(vmo, &map_inv);

    ::sys_close(vmo);

    if (result.error != SysError::Success)
        return map_error(result.error);

    *out = reinterpret_cast<void *>(result.value);
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
    
    mprot_body.prot = convert_prot(prot);

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

    size_t total = 0;
    while (total < count) {
        FileOp::FileOp_Write_Body write_body;
        write_body.offset = (uintptr_t)-1; // Request kernel-side cursor
        write_body.buffer_ptr = reinterpret_cast<uintptr_t>(buf) + total;
        write_body.len = count - total;

        FileOp file_op;
        file_op.tag = FileOp::Tag::FileOp_Write;
        file_op.write = write_body;

        Invocation inv;
        inv.tag = Invocation::Tag::Invocation_File;
        inv.file._0 = file_op;

        SyscallResult res = sys_invoke(handle, &inv);
        if (res.error == SysError::InvalidArgument || res.error == SysError::UnsupportedOperation) {
            inv.file._0.write.offset = 0;
            res = sys_invoke(handle, &inv);
        }

        if (res.error != SysError::Success) {
            if (total != 0) break;
            return map_error(res.error);
        }
        if (res.value == 0) break;
        total += res.value;
    }

    *bytes_written = total;
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
    if (res.error == SysError::InvalidArgument || res.error == SysError::UnsupportedOperation) {
        inv.file._0.read.offset = 0;
        res = sys_invoke(handle, &inv);
    }

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

int Sysdeps<Sigaction>::operator()(
      int signal,
      const struct sigaction *action,
      struct sigaction *old_action) {
  if (signal <= 0 || signal >= _NSIG)
      return EINVAL;

  // STUBBED
  if (old_action) {
      memset(old_action, 0, sizeof(*old_action));
      old_action->sa_handler = SIG_DFL;
  }

  (void)action;
  return 0;
}

extern "C" [[gnu::weak]] uintptr_t *entryStack;

int Sysdeps<Open>::operator()(
        const char *path,
        int flags,
        unsigned int mode,
        int *fd) {
    (void)mode;
    ensure_handles();
    
    if (!path || !*path || !fd)
        return EINVAL;
    
    char local_path[256];
    size_t length = strlen(path);
    
    if (length >= sizeof(local_path))
        return ENAMETOOLONG;
    
    memcpy(local_path, path, length + 1);
    
    HandleID file_handle = resolve_path(local_path);
    
    if (file_handle != 0) {
        // O_CREAT | O_EXCL must fail when the file already exists.
        if ((flags & O_CREAT) && (flags & O_EXCL)) {
            ::sys_close(file_handle);
            return EEXIST;
        }
    } else {
        if (!(flags & O_CREAT))
            return ENOENT;
    
        // Split path into parent directory and final filename.
        char *last_slash = find_last_char(local_path, '/');
        const char *filename = local_path;
        HandleID parent_handle = g_root_handle;
    
        if (last_slash) {
            filename = last_slash + 1;
    
            if (!*filename)
                return EINVAL;
    
            if (last_slash != local_path) {
                *last_slash = '\0';
                parent_handle = resolve_path(local_path);
    
                if (parent_handle == 0)
                    return ENOENT;
            }
            // If last_slash == local_path, this is "/file", whose parent is root.
        }
    
        DirectoryOp dir_op;
        dir_op.tag = DirectoryOp::Tag::DirectoryOp_CreateFile;
        dir_op.create_file.name =
            reinterpret_cast<uintptr_t>(filename);
        dir_op.create_file.name_len = strlen(filename);
    
        Invocation invocation;
        invocation.tag = Invocation::Tag::Invocation_Directory;
        invocation.directory._0 = dir_op;
    
        SyscallResult result = ::sys_invoke(parent_handle, &invocation);
    
        if (parent_handle != g_root_handle)
            ::sys_close(parent_handle);
    
        if (result.error != SysError::Success) {
            // The kernel reports an existing filename as InvalidArgument.
            if (result.error == SysError::InvalidArgument)
                return EEXIST;
    
            return map_error(result.error);
        }
    
        file_handle = result.value;
    }


    if (flags & O_TRUNC) {
        int access_mode = flags & O_ACCMODE;
        if (access_mode != O_WRONLY && access_mode != O_RDWR) {
            ::sys_close(file_handle);
            return EINVAL;
        }
    
        FileOp file_op;
        file_op.tag = FileOp::Tag::FileOp_Truncate;
        file_op.truncate.size = 0;
    
        Invocation invocation;
        invocation.tag = Invocation::Tag::Invocation_File;
        invocation.file._0 = file_op;
    
        SyscallResult result = ::sys_invoke(file_handle, &invocation);
        if (result.error != SysError::Success) {
            ::sys_close(file_handle);
            return map_error(result.error);
        }
    }
    
    for (size_t candidate = 3;
            candidate < g_fd_table.capacity;
            candidate++) {
        if (g_fd_table.entries[candidate] == 0) {
            g_fd_table.entries[candidate] = file_handle;
            *fd = static_cast<int>(candidate);
            return 0;
        }
    }
    
    ::sys_close(file_handle);
    return EMFILE;
}

int Sysdeps<Ftruncate>::operator()(int fd, size_t size) {
    if (fd < 0 || static_cast<size_t>(fd) >= g_fd_table.capacity)
        return EBADF;

    HandleID handle = g_fd_table.entries[fd];
    if (handle == 0)
        return EBADF;

    FileOp file_op;
    file_op.tag = FileOp::Tag::FileOp_Truncate;
    file_op.truncate.size = size;

    Invocation invocation;
    invocation.tag = Invocation::Tag::Invocation_File;
    invocation.file._0 = file_op;

    SyscallResult result = ::sys_invoke(handle, &invocation);
    return map_error(result.error);
}

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

int Sysdeps<Tcgetattr>::operator()(int fd, struct termios *attr) {
    (void)fd;
    ensure_handles();
    uintptr_t g_term_ctrl = find_capability(CAP_TERMINAL_CONTROL);
    if (g_term_ctrl == 0) return ENOTTY;

    TermCommand cmd{};
    cmd.tag = TermCommand::Tag::TermCommand_GetTermios;

    SysError e = ctrl_send(g_term_ctrl, cmd);
    if (e != SysError::Success) return map_error(e);

    Termios t{};
    e = ctrl_recv(g_term_ctrl, &t);
    if (e != SysError::Success) return map_error(e);

    attr->c_iflag  = t.c_iflag;
    attr->c_oflag  = t.c_oflag;
    attr->c_cflag  = t.c_cflag;
    attr->c_lflag  = t.c_lflag;
    attr->c_line   = t.c_line;
    memcpy(attr->c_cc, t.c_cc, sizeof(t.c_cc));
    attr->c_ibaud = t.c_ispeed;
    attr->c_obaud = t.c_ospeed;
    return 0;
}

int Sysdeps<Tcsetattr>::operator()(int fd, int optional_actions, const struct termios *attr) {
    (void)fd; (void)optional_actions;
    ensure_handles();
    uintptr_t g_term_ctrl = find_capability(CAP_TERMINAL_CONTROL);
    if (g_term_ctrl == 0) return ENOTTY;

    TermCommand cmd{};
    cmd.tag = TermCommand::Tag::TermCommand_SetTermios;
    cmd.set_termios._0.c_iflag  = attr->c_iflag;
    cmd.set_termios._0.c_oflag  = attr->c_oflag;
    cmd.set_termios._0.c_cflag  = attr->c_cflag;
    cmd.set_termios._0.c_lflag  = attr->c_lflag;
    cmd.set_termios._0.c_line   = attr->c_line;
    memcpy(cmd.set_termios._0.c_cc, attr->c_cc, sizeof(cmd.set_termios._0.c_cc));
    cmd.set_termios._0.c_ispeed = attr->c_ibaud;
    cmd.set_termios._0.c_ospeed = attr->c_obaud;

    SysError e = ctrl_send(g_term_ctrl, cmd);
    return map_error(e);
    // no response expected for SetTermios
}

int Sysdeps<Tcgetwinsize>::operator()(int fd, struct winsize *winsz) {
    (void)fd;
    ensure_handles();
    uintptr_t g_term_ctrl = find_capability(CAP_TERMINAL_CONTROL);
    if (g_term_ctrl == 0) return ENOTTY;

    TermCommand cmd{};
    cmd.tag = TermCommand::Tag::TermCommand_GetWindowSize;

    SysError e = ctrl_send(g_term_ctrl, cmd);
    if (e != SysError::Success) return map_error(e);

    // terminal responds with send_packet::<(u32, u32)> — cols then rows
    struct TerminalWinSize {
        uint16_t rows;
        uint16_t cols;
        uint16_t xpixel;
        uint16_t ypixel;
    } size{};
    
    e = ctrl_recv(g_term_ctrl, &size);
    if (e != SysError::Success)
        return map_error(e);
    
    winsz->ws_row = size.rows;
    winsz->ws_col = size.cols;
    winsz->ws_xpixel = size.xpixel;
    winsz->ws_ypixel = size.ypixel;

    return 0;
}

int Sysdeps<Isatty>::operator()(int fd) {
    ensure_handles();
    uintptr_t g_term_ctrl = find_capability(CAP_TERMINAL_CONTROL);
    if (g_term_ctrl != 0 && (fd == 0 || fd == 1 || fd == 2))
        return 0; // 0 = Success (Is a TTY)
    return ENOTTY; // Error (Not a TTY)
}

int Sysdeps<Ioctl>::operator()(int fd, unsigned long request, void *arg, int *result) {
    (void)fd;
    ensure_handles();

    if (request == TIOCGWINSZ) {
        struct winsize *winsz = static_cast<struct winsize *>(arg);
        uintptr_t g_term_ctrl = find_capability(CAP_TERMINAL_CONTROL);
        if (g_term_ctrl == 0) return ENOTTY;

        TermCommand cmd{};
        cmd.tag = TermCommand::Tag::TermCommand_GetWindowSize;

        SysError e = ctrl_send(g_term_ctrl, cmd);
        if (e != SysError::Success) return map_error(e);

        // terminal responds with send_packet::<(u32, u32)> — cols then rows
        struct TerminalWinSize {
            uint16_t rows;
            uint16_t cols;
            uint16_t xpixel;
            uint16_t ypixel;
        } size{};
        
        e = ctrl_recv(g_term_ctrl, &size);
        if (e != SysError::Success)
            return map_error(e);
        
        winsz->ws_row = size.rows;
        winsz->ws_col = size.cols;
        winsz->ws_xpixel = size.xpixel;
        winsz->ws_ypixel = size.ypixel;

        return 0;
    }

    return ENOSYS;
}

// ----------------------------------------------------
// 5. helpers
// ----------------------------------------------------

static void ensure_handles() {
    static bool stack_initialized = false;

    // initialize stack-dependent handles once entrystack is populated by the runtime.
    if (!stack_initialized && &entryStack && entryStack) {
        ProcessInitPackage *pkg = find_init_package(entryStack);

        if (pkg) {
            g_init_pkg = pkg;
            g_self_handle = pkg->self_handle;
            g_root_handle = pkg->root_handle;
            g_sink_handle = pkg->sink_handle;
            g_mem_pool = pkg->memory_pool_handle;

            g_fd_table.entries[STDIN_FILENO] = pkg->source_handle;
            g_fd_table.entries[STDOUT_FILENO] = pkg->sink_handle;
            g_fd_table.entries[STDERR_FILENO] = pkg->sink_handle;
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

static HandleID find_capability(CapabilityID capability) {
    if (!g_init_pkg) return 0;
    for (size_t i = 0; i < g_init_pkg->capabilities_len; i++) {
        if (g_init_pkg->capabilities_ptr[i].capability == capability) {
            return g_init_pkg->capabilities_ptr[i].id;
        }
    }
    return 0;
}

static char *find_last_char(char *string, char character) {
  char *last = nullptr;

  for (; *string; ++string) {
      if (*string == character)
          last = string;
  }

  return last;
}

} // namespace mlibc

extern "C" {
float _Complex __mulsc3(float a, float b, float c, float d) { STUB(); }
double _Complex __muldc3(double a, double b, double c, double d) { STUB(); }
long double _Complex __mulxc3(long double a, long double b, long double c, long double d) { STUB(); }
}
