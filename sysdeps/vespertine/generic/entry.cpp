#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <mlibc/sysdeps.hpp>
#include <abi/vespertine_abi.hpp>
#include "syscall.hpp"

static SyscallResult sys_write(HandleID handle, const void *buf, size_t count) {
    FileOp::FileOp_Write_Body write_body;
    write_body.offset = 0;
    write_body.buffer_ptr = reinterpret_cast<uintptr_t>(buf);
    write_body.len = count;

    FileOp file_op;
    file_op.tag = FileOp::Tag::FileOp_Write;
    file_op.write = write_body;

    Invocation inv;
    inv.tag = Invocation::Tag::Invocation_File;
    inv.file._0 = file_op;

    return sys_invoke(handle, &inv);
}

static SyscallResult sys_read(HandleID handle, void *buf, size_t count) {
    FileOp::FileOp_Read_Body read_body;
    read_body.offset = 0;
    read_body.buffer_ptr = reinterpret_cast<uintptr_t>(buf);
    read_body.len = count;

    FileOp file_op;
    file_op.tag = FileOp::Tag::FileOp_Read;
    file_op.read = read_body;

    Invocation inv;
    inv.tag = Invocation::Tag::Invocation_File;
    inv.file._0 = file_op;

    return sys_invoke(handle, &inv);
}

static HandleID sys_lookup(HandleID dir, const char *name) {
    size_t len = 0;
    while (name[len]) {
        len++;
    }

    DirectoryOp dir_op;
    dir_op.tag = DirectoryOp::Tag::DirectoryOp_Lookup;
    dir_op.lookup.name = reinterpret_cast<uintptr_t>(name);
    dir_op.lookup.name_len = len;

    Invocation inv;
    inv.tag = Invocation::Tag::Invocation_Directory;
    inv.directory._0 = dir_op;

    SyscallResult res = sys_invoke(dir, &inv);
    if (res.error != SysError::Success) {
        return 0;
    }
    return res.value;
}

struct AuxEntry {
    uintptr_t type;
    uintptr_t val;
};

static ProcessInitPackage *find_init_package(uintptr_t *stack) {
    if (!stack)
        return nullptr;

    size_t argc = stack[0];
    size_t env_idx = 1 + argc + 1;

    while (stack[env_idx])
        env_idx++;

    auto *auxv = reinterpret_cast<AuxEntry *>(&stack[env_idx + 1]);

    for (size_t i = 0; auxv[i].type != 0; i++) {
        if (auxv[i].type == AT_VESPERTINE_INITPKG) {
            return reinterpret_cast<ProcessInitPackage *>(auxv[i].val);
        }
    }

    return nullptr;
}

#define STATIC_FD_BOOTSTRAP_CAP 256

struct FdTable {
    HandleID *entries;
    size_t capacity;
};


extern HandleID g_self_handle;
extern HandleID g_root_handle;
extern HandleID g_cwd_handle;
extern HandleID g_mem_pool;
extern FdTable g_fd_table;

// mlibc internal startup entry point
extern "C" void __dlapi_enter(uintptr_t *entry_stack);

extern "C" uintptr_t *__dlapi_entrystack();

extern "C" int main(int argc, char **argv, char **envp);

extern "C" uintptr_t *entryStack = nullptr;

extern "C" void __mlibc_entry(uintptr_t *stack) {
    // When dynamically linked, ld.so's interpreterMain() already consumed
    // the original kernel-provided stack and saved it internally. The %rsp
    // we received is a stale leftover from ld.so's call frame. Recover the
    // real stack via mlibc's RTLD API.
    //
    // For static builds, __dlapi_entrystack() returns nullptr because
    // interpreterMain hasn't run yet — so we fall through to the original
    // stack parameter, which IS the real kernel stack in that case.
    uintptr_t *original = __dlapi_entrystack();
    if (original) {
        stack = original;
    }

    entryStack = stack;

    ProcessInitPackage *pkg = find_init_package(stack);

    if (stack) {
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
    }

    if (pkg) {
        g_self_handle = pkg->self_handle;
        g_root_handle = pkg->root_handle;
        g_cwd_handle = pkg->cwd_handle;
        g_mem_pool = pkg->memory_pool_handle;

        g_fd_table.entries[0] = pkg->source_handle; // STDIN_FILENO
        g_fd_table.entries[1] = pkg->sink_handle;   // STDOUT_FILENO
        g_fd_table.entries[2] = pkg->sink_handle;   // STDERR_FILENO
    }

    if (!g_mem_pool) {
        __builtin_trap();
    }

    size_t argc = 0;
    size_t envc = 0;
    if (pkg) {
        argc = pkg->argc;
        if (pkg->envp) {
            while (pkg->envp[envc]) {
                envc++;
            }
        }
    }

    size_t fake_stack_len = 1 + argc + 1 + envc + 1 + 4;
    uintptr_t *fake_stack = (uintptr_t *)__builtin_alloca(fake_stack_len * sizeof(uintptr_t));

    size_t cursor = 0;
    fake_stack[cursor++] = argc;

    for (size_t i = 0; i < argc; i++)
        fake_stack[cursor++] = reinterpret_cast<uintptr_t>(pkg->argv[i]);
    fake_stack[cursor++] = 0;

    for (size_t i = 0; i < envc; i++)
        fake_stack[cursor++] = reinterpret_cast<uintptr_t>(pkg->envp[i]);
    fake_stack[cursor++] = 0;

    size_t aux_idx = cursor;

    fake_stack[aux_idx + 0] = AT_VESPERTINE_INITPKG;
    fake_stack[aux_idx + 1] = reinterpret_cast<uintptr_t>(pkg);
    fake_stack[aux_idx + 2] = 0; // AT_NULL
    fake_stack[aux_idx + 3] = 0;

    // call __dlapi_enter to initialize tls and tcb
    __dlapi_enter(fake_stack);

    static char *empty_env[] = { nullptr };
    int argc_val = (pkg) ? static_cast<int>(pkg->argc) : 0;
    char **argv_val = (pkg) ? const_cast<char**>(pkg->argv) : nullptr;
    char **envp_val = (pkg && pkg->envp) ? const_cast<char**>(pkg->envp) : empty_env;

    int result = main(argc_val, argv_val, envp_val);
    exit(result);
}
