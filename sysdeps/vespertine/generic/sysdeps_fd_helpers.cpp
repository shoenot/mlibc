#include "sysdeps_shared.hpp"

namespace mlibc {

int attach_owned_fd(int fd, HandleID handle) {
    if (fd < 0 || static_cast<size_t>(fd) >= g_fd_table.capacity)
        return EBADF;

    if (g_fd_table.entries[fd] == handle) {
        size_t *refs = g_fd_refs[fd];
        if (!refs) {
            for (size_t i = 0; i < g_fd_table.capacity; i++) {
                if (static_cast<int>(i) == fd)
                    continue;
                if (g_fd_table.entries[i] == handle && g_fd_refs[i]) {
                    refs = g_fd_refs[i];
                    ++*refs;
                    break;
                }
            }

            if (!refs) {
                bootstrap_fd_ref_storage[fd] = 1;
                refs = &bootstrap_fd_ref_storage[fd];
            }

            g_fd_refs[fd] = refs;
        }

        g_fd_dir_offsets[fd] = 0;
        return 0;
    }

    if (g_fd_table.entries[fd]) {
        int error = close_fd_slot(fd);
        if (error)
            return error;
    }

    size_t *refs = nullptr;
    for (size_t i = 0; i < g_fd_table.capacity; i++) {
        if (static_cast<int>(i) == fd)
            continue;
        if (g_fd_table.entries[i] == handle && g_fd_refs[i]) {
            refs = g_fd_refs[i];
            break;
        }
    }

    if (refs) {
        ++*refs;
    } else {
        bootstrap_fd_ref_storage[fd] = 1;
        refs = &bootstrap_fd_ref_storage[fd];
    }

    g_fd_table.entries[fd] = handle;
    g_fd_refs[fd] = refs;
    g_fd_dir_offsets[fd] = 0;
    return 0;
}

int close_fd_slot(int fd) {
    if (fd < 0 || static_cast<size_t>(fd) >= g_fd_table.capacity)
        return EBADF;

    HandleID handle = g_fd_table.entries[fd];
    if (!handle)
        return EBADF;

    size_t *refs = g_fd_refs[fd];
    if (refs && *refs > 1) {
        --*refs;
    } else {
        SyscallResult result = ::sys_close(handle);
        if (result.error != SysError::Success)
            return map_error(result.error);
        if (refs)
            *refs = 0;
    }

    g_fd_table.entries[fd] = 0;
    g_fd_refs[fd] = nullptr;
    g_fd_dir_offsets[fd] = 0;
    return 0;
}

int install_fd(HandleID handle, int *fd) {
    for (size_t candidate = 3; candidate < g_fd_table.capacity; candidate++) {
        if (g_fd_table.entries[candidate] == 0) {
            int error = attach_owned_fd(static_cast<int>(candidate), handle);
            if (error)
                return error;
            *fd = static_cast<int>(candidate);
            return 0;
        }
    }

    ::sys_close(handle);
    return EMFILE;
}

int duplicate_fd_to(int oldfd, int newfd) {
    if (oldfd < 0 || static_cast<size_t>(oldfd) >= g_fd_table.capacity)
        return EBADF;
    if (newfd < 0 || static_cast<size_t>(newfd) >= g_fd_table.capacity)
        return EBADF;

    HandleID handle = g_fd_table.entries[oldfd];
    if (!handle)
        return EBADF;

    if (oldfd == newfd)
        return 0;

    if (g_fd_table.entries[newfd]) {
        int error = close_fd_slot(newfd);
        if (error)
            return error;
    }

    size_t *refs = g_fd_refs[oldfd];
    if (!refs) {
        bootstrap_fd_ref_storage[oldfd] = 1;
        refs = &bootstrap_fd_ref_storage[oldfd];
        g_fd_refs[oldfd] = refs;
    }

    ++*refs;
    g_fd_table.entries[newfd] = handle;
    g_fd_refs[newfd] = refs;
    g_fd_dir_offsets[newfd] = g_fd_dir_offsets[oldfd];
    return 0;
}

HandleID resolve_path_from(const char *path, HandleID start, AccessRights rights) {
    if (!path || *path == '\0') return 0;

    DirectoryOp op{};
    op.tag = DirectoryOp::Tag::DirectoryOp_Resolve;
    op.resolve.start = start;
    op.resolve.path_ptr = reinterpret_cast<uintptr_t>(path);
    op.resolve.path_len = strlen(path);
    op.resolve.rights = rights;

    Invocation invocation{};
    invocation.tag = Invocation::Tag::Invocation_Directory;
    invocation.directory._0 = op;

    SyscallResult result = ::sys_invoke(g_root_handle, &invocation);
    return result.error == SysError::Success ? result.value : 0;
}

int request_socket_factory(HandleID *factory) {
    HandleID handle = find_capability(CAP_SOCKFAC);
    if (handle) {
        *factory = handle;
        return 0;
    }

    HandleID broker = resolve_path("/System/Services/Socket", AccessRights::READ);
    if (!broker)
        return ENOENT;

    BrokerOp broker_op{};
    broker_op.tag = BrokerOp::Tag::BrokerOp_Request;
    broker_op.request.capability = CAP_SOCKFAC;
    broker_op.request.requested_rights = AccessRights::CREATE;

    Invocation invocation{};
    invocation.tag = Invocation::Tag::Invocation_Broker;
    invocation.broker._0 = broker_op;

    SyscallResult result = ::sys_invoke(broker, &invocation);
    ::sys_close(broker);

    if (result.error != SysError::Success)
        return map_error(result.error);

    *factory = result.value;
    return 0;
}

int create_socket_pair(HandleID *read_end, HandleID *write_end) {
    HandleID factory = 0;
    int error = request_socket_factory(&factory);
    if (error)
        return error;

    SocketOp socket_op{};
    socket_op.tag = SocketOp::Tag::SocketOp_Create;
    socket_op.create.sourceproc = g_self_handle;
    socket_op.create.sinkproc = g_self_handle;

    Invocation invocation{};
    invocation.tag = Invocation::Tag::Invocation_Socket;
    invocation.socket._0 = socket_op;

    SyscallResult result = ::sys_invoke(factory, &invocation);

    if (!find_capability(CAP_SOCKFAC))
        ::sys_close(factory);

    if (result.error != SysError::Success)
        return map_error(result.error);

    *read_end = result.value & 0xFFFFFFFFu;
    *write_end = result.value >> 32;
    return 0;
}

int stat_handle(HandleID handle, struct stat *statbuf) {
    FileStat native_stat{};

    FileOp file_op{};
    file_op.tag = FileOp::Tag::FileOp_Stat;
    file_op.stat.stat_ptr = reinterpret_cast<uintptr_t>(&native_stat);

    Invocation invocation{};
    invocation.tag = Invocation::Tag::Invocation_File;
    invocation.file._0 = file_op;

    SyscallResult result = ::sys_invoke(handle, &invocation);
    if (result.error != SysError::Success)
        return map_error(result.error);

    memset(statbuf, 0, sizeof(*statbuf));
    statbuf->st_dev = native_stat.device;
    statbuf->st_ino = native_stat.inode;
    statbuf->st_nlink = native_stat.nlink;
    statbuf->st_mode = native_stat.mode;
    statbuf->st_uid = native_stat.user;
    statbuf->st_gid = native_stat._group;
    statbuf->st_rdev = 0;
    statbuf->st_size = native_stat.size;
    statbuf->st_blksize = native_stat.block_size;
    statbuf->st_blocks = native_stat.blocks;
    statbuf->st_atim.tv_sec = native_stat.atime_sec;
    statbuf->st_atim.tv_nsec = native_stat.atime_nsec;
    statbuf->st_mtim.tv_sec = native_stat.mtime_sec;
    statbuf->st_mtim.tv_nsec = native_stat.mtime_nsec;
    statbuf->st_ctim.tv_sec = native_stat.ctime_sec;
    statbuf->st_ctim.tv_nsec = native_stat.ctime_nsec;

    if ((statbuf->st_mode & S_IFMT) == 0) {
        switch (static_cast<ObjectType>(native_stat.object_type)) {
            case ObjectType::Directory:
                statbuf->st_mode |= S_IFDIR;
                break;
            case ObjectType::File:
                statbuf->st_mode |= S_IFREG;
                break;
            default:
                break;
        }
    }

    return 0;
}

int read_exact_handle(HandleID handle, void *buffer, size_t size, bool *eof) {
    *eof = false;
    size_t total = 0;

    while (total < size) {
        FileOp file_op{};
        file_op.tag = FileOp::Tag::FileOp_Read;
        file_op.read.offset = static_cast<uintptr_t>(-1);
        file_op.read.buffer_ptr = reinterpret_cast<uintptr_t>(buffer) + total;
        file_op.read.len = size - total;

        Invocation invocation{};
        invocation.tag = Invocation::Tag::Invocation_File;
        invocation.file._0 = file_op;

        SyscallResult result = ::sys_invoke(handle, &invocation);
        if (result.error != SysError::Success)
            return map_error(result.error);
        if (result.value == 0) {
            *eof = total == 0;
            return total == 0 ? 0 : EIO;
        }

        total += result.value;
    }

    return 0;
}

HandleID resolve_path(const char *path, AccessRights rights) {
    return resolve_path_from(path, g_cwd_handle, rights);
}

int resolve_parent(const char *path, AccessRights rights, HandleID *parent, const char **name, char *storage, size_t storage_size) {
    size_t length = strlen(path);
    if (!length || length >= storage_size)
        return length ? ENAMETOOLONG : EINVAL;

    memcpy(storage, path, length + 1);
    while (length > 1 && storage[length - 1] == '/')
        storage[--length] = '\0';

    char *slash = find_last_char(storage, '/');
    *name = slash ? slash + 1 : storage;
    if (!**name)
        return EINVAL;

    const char *parent_path = ".";
    if (slash == storage)
        parent_path = "/";
    else if (slash) {
        *slash = '\0';
        parent_path = storage;
    }

    *parent = resolve_path(parent_path, rights);
    return *parent ? 0 : EACCES;
}


} // namespace mlibc
