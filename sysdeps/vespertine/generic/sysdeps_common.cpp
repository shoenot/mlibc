#include "sysdeps_shared.hpp"

const ProcessInitPackage *g_init_pkg = nullptr;

HandleID g_root_handle = 0;
HandleID g_cwd_handle = VESPERTINE_HANDLE_CWD;
HandleID g_self_handle = 1;
HandleID g_sink_handle = 3; // Default debug sink
HandleID g_mem_pool = VESPERTINE_HANDLE_MEMORY_POOL;

static HandleID bootstrap_fds[STATIC_FD_BOOTSTRAP_CAP] = {0, 0, 0};
static size_t bootstrap_fd_dir_offsets[STATIC_FD_BOOTSTRAP_CAP] = {0};
size_t bootstrap_fd_ref_storage[STATIC_FD_BOOTSTRAP_CAP] = {0};
static size_t *bootstrap_fd_refs[STATIC_FD_BOOTSTRAP_CAP] = {nullptr};

FdTable g_fd_table = { bootstrap_fds, STATIC_FD_BOOTSTRAP_CAP };
size_t *g_fd_dir_offsets = bootstrap_fd_dir_offsets;
size_t **g_fd_refs = bootstrap_fd_refs;

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

extern "C" [[gnu::weak]] uintptr_t *entryStack;

void ensure_handles() {
    static bool stack_initialized = false;

    // initialize stack-dependent handles once entrystack is populated by the runtime.
    if (!stack_initialized && &entryStack && entryStack) {
        ProcessInitPackage *pkg = find_init_package(entryStack);

        if (pkg) {
            g_init_pkg = pkg;
            g_self_handle = pkg->self_handle;
            g_root_handle = pkg->root_handle;
            g_cwd_handle = pkg->cwd_handle;
            g_sink_handle = pkg->sink_handle;
            g_mem_pool = pkg->memory_pool_handle;

            attach_owned_fd(STDIN_FILENO, pkg->source_handle);
            attach_owned_fd(STDOUT_FILENO, pkg->sink_handle);
            attach_owned_fd(STDERR_FILENO, pkg->sink_handle);
        }

        stack_initialized = true;
  }
}


HandleID find_capability(CapabilityID capability) {
    if (!g_init_pkg) return 0;
    for (size_t i = 0; i < g_init_pkg->capabilities_len; i++) {
        if (g_init_pkg->capabilities_ptr[i].capability == capability) {
            return g_init_pkg->capabilities_ptr[i].id;
        }
    }
    return 0;
}


char *find_last_char(char *string, char character) {
  char *last = nullptr;

  for (; *string; ++string) {
      if (*string == character)
          last = string;
  }

  return last;
}


} // namespace mlibc
