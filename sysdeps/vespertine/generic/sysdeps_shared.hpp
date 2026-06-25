#pragma once

#include "mlibc/sysdeps.hpp"
#include <mlibc/all-sysdeps.hpp>
#include <abi/vespertine_abi.hpp>
#include <abi/flags.hpp>
#include <abi-bits/termios.h>
#include <abi-bits/ioctls.h>
#include "helpers.hpp"
#include "mlibc/sysdep-tags.hpp"
#include "syscall.hpp"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <bits/ensure.h>

struct FdTable {
    HandleID *entries;
    size_t capacity;
};

extern const ProcessInitPackage *g_init_pkg;
extern HandleID g_root_handle;
extern HandleID g_cwd_handle;
extern HandleID g_self_handle;
extern HandleID g_sink_handle;
extern HandleID g_mem_pool;
#define STATIC_FD_BOOTSTRAP_CAP 256
extern FdTable g_fd_table;
extern size_t *g_fd_dir_offsets;
extern size_t **g_fd_refs;
extern size_t bootstrap_fd_ref_storage[STATIC_FD_BOOTSTRAP_CAP];

int map_error(SysError err);

namespace mlibc {

void ensure_handles();
int attach_owned_fd(int fd, HandleID handle);
int close_fd_slot(int fd);
int install_fd(HandleID handle, int *fd);
int duplicate_fd_to(int oldfd, int newfd);
int resolve_path(const char *path, AccessRights rights, HandleID *handle);
int resolve_path_from(const char *path, HandleID start, AccessRights rights, HandleID *handle);
int resolve_parent(const char *path, AccessRights rights, HandleID *parent, const char **name, char *storage, size_t storage_size);
HandleID find_capability(CapabilityID capability);
int request_socket_factory(HandleID *factory);
int create_socket_pair(HandleID *read_end, HandleID *write_end);
int stat_handle(HandleID handle, struct stat *statbuf);
int read_exact_handle(HandleID handle, void *buffer, size_t size, bool *eof);
char *find_last_char(char *string, char character);

} // namespace mlibc
