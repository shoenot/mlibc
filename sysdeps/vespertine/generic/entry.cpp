#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <mlibc/sysdeps.hpp>
#include <abi/vespertine_abi.hpp> // Includes the massive cbindgen header

struct HandleGrant {
    HandleID id;
    AccessRights rights;
    uintptr_t tag;
};

struct ProcessInitPackage {
    HandleID self_handle;
    HandleID root_handle;
    HandleID source_handle;
    HandleID sink_handle;
    HandleGrant *extra_handles_ptr;
    uintptr_t extra_handles_len;
    uintptr_t argc;
    const char **argv;
    const char **envp;
};

struct SysError; 
struct SyscallResult {
    size_t value;
    size_t error; 
};
extern "C" SyscallResult sys_invoke(HandleID handle, const void *op);

#define STATIC_FD_BOOTSTRAP_CAP 256

struct FdTable {
    HandleID *entries;
    size_t capacity;
};

HandleID g_self_handle = 1;
HandleID g_root_handle = 0;
HandleID g_mem_pool = 0;

static HandleID bootstrap_fds[STATIC_FD_BOOTSTRAP_CAP] = {0};
FdTable g_fd_table = { bootstrap_fds, STATIC_FD_BOOTSTRAP_CAP };

extern "C" void __mlibc_start_main(int argc, char **argv, char **envp);

extern "C" void __mlibc_entry(ProcessInitPackage *pkg) {
    if (pkg) {
        g_self_handle = pkg->self_handle;
        g_root_handle = pkg->root_handle;

        g_fd_table.entries[0] = pkg->source_handle; // STDIN_FILENO
        g_fd_table.entries[1] = pkg->sink_handle;   // STDOUT_FILENO
        g_fd_table.entries[2] = pkg->sink_handle;   // STDERR_FILENO

        // Hunt for the Memory Manager and create a pool
        if (pkg->extra_handles_ptr && pkg->extra_handles_len > 0) {
            for (size_t i = 0; i < pkg->extra_handles_len; i++) {
                if (pkg->extra_handles_ptr[i].tag == TAG_SYS_RES_MAN) { 
                    HandleID res_man = pkg->extra_handles_ptr[i].id;
                    
                    // Create the MemManOp Body
                    MemManOp::MemManOp_CreatePool_Body body;
                    body.limit = 0; // 0 = unlimited or default
                    
                    // Create the MemManOp
                    MemManOp op;
                    op.tag = MemManOp::Tag::MemManOp_CreatePool;
                    op.create_pool = body;

                    // Wrap in Invocation
                    Invocation inv;
                    inv.tag = Invocation::Tag::Invocation_MemoryManager;
                    inv.memory_manager._0 = op;

                    SyscallResult res = sys_invoke(res_man, &inv);
                    if (res.error == 0) { 
                        g_mem_pool = res.value;
                    }
                    break;
                }
            }
        }
    }

    static char *empty_env[] = { nullptr };
    int argc_val = (pkg) ? static_cast<int>(pkg->argc) : 0;
    char **argv_val = (pkg) ? const_cast<char**>(pkg->argv) : nullptr;
    char **envp_val = (pkg && pkg->envp) ? const_cast<char**>(pkg->envp) : empty_env;

    __mlibc_start_main(argc_val, argv_val, envp_val);
}
