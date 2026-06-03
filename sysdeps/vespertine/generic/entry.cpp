#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <mlibc/sysdeps.hpp>

struct ProcessInitPackage {
    uintptr_t self_handle;
    uintptr_t root_handle;
    uintptr_t source_handle;
    uintptr_t sink_handle;
    void *extra_handles_ptr;
    uintptr_t extra_handles_len;
    uintptr_t argc;
    const char **argv;
    const char **envp;
};

#define STATIC_FD_BOOTSTRAP_CAP 256

struct FdTable {
    uintptr_t *entries;
    size_t capacity;
};

uintptr_t g_self_handle = 1;
uintptr_t g_root_handle = 0;
uintptr_t g_mem_pool = 0;

static uintptr_t bootstrap_fds[STATIC_FD_BOOTSTRAP_CAP] = {0};
FdTable g_fd_table = { bootstrap_fds, STATIC_FD_BOOTSTRAP_CAP };

extern "C" void __mlibc_start_main(int argc, char **argv, char **envp);

extern "C" void __mlibc_entry(ProcessInitPackage *pkg) {
    if (pkg) {
        g_self_handle = pkg->self_handle;
        g_root_handle = pkg->root_handle;

        g_fd_table.entries[0] = pkg->source_handle; // STDIN_FILENO
        g_fd_table.entries[1] = pkg->sink_handle;   // STDOUT_FILENO
        g_fd_table.entries[2] = pkg->sink_handle;   // STDERR_FILENO
    }

    static char *empty_env[] = { nullptr };
    int argc_val = (pkg) ? static_cast<int>(pkg->argc) : 0;
    char **argv_val = (pkg) ? const_cast<char**>(pkg->argv) : nullptr;
    char **envp_val = (pkg && pkg->envp) ? const_cast<char**>(pkg->envp) : empty_env;

    __mlibc_start_main(argc_val, argv_val, envp_val);
}
