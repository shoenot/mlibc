#include "sysdeps_shared.hpp"

namespace mlibc {

struct AbiDirEntry {
    uint8_t entry_type;
    uint8_t name_len;
    uint8_t name[254];
};

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

int Sysdeps<Stat>::operator()(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf) {
    ensure_handles();

    if (!statbuf)
        return EINVAL;

    if (flags & ~(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW))
        return EINVAL;

    HandleID handle = 0;
    bool close_handle = false;

    switch (fsfdt) {
        case fsfd_target::fd:
            if (fd < 0 || static_cast<size_t>(fd) >= g_fd_table.capacity)
                return EBADF;
            handle = g_fd_table.entries[fd];
            if (!handle)
                return EBADF;
            break;
        case fsfd_target::path:
            if (!path || !*path)
                return ENOENT;
            handle = resolve_path(path, AccessRights(0));
            close_handle = true;
            break;
        case fsfd_target::fd_path:
            if ((flags & AT_EMPTY_PATH) && (!path || !*path)) {
                if (fd < 0 || static_cast<size_t>(fd) >= g_fd_table.capacity)
                    return EBADF;
                handle = g_fd_table.entries[fd];
                if (!handle)
                    return EBADF;
            } else {
                if (!path || !*path)
                    return ENOENT;

                HandleID start = g_cwd_handle;
                if (fd != AT_FDCWD) {
                    if (fd < 0 || static_cast<size_t>(fd) >= g_fd_table.capacity)
                        return EBADF;
                    start = g_fd_table.entries[fd];
                    if (!start)
                        return EBADF;
                }

                handle = resolve_path_from(path, start, AccessRights(0));
                close_handle = true;
            }
            break;
        default:
            return EINVAL;
    }

    if (!handle)
        return ENOENT;

    int error = stat_handle(handle, statbuf);
    if (close_handle)
        ::sys_close(handle);
    return error;
}

int Sysdeps<OpenDir>::operator()(const char *path, int *handle) {
    ensure_handles();

    if (!path || !*path || !handle)
        return EINVAL;

    HandleID dir = resolve_path(path, AccessRights::LIST | AccessRights::TRAVERSE);
    if (!dir)
        return ENOENT;

    struct stat statbuf{};
    int error = stat_handle(dir, &statbuf);
    if (error) {
        ::sys_close(dir);
        return error;
    }

    if (!S_ISDIR(statbuf.st_mode)) {
        ::sys_close(dir);
        return ENOTDIR;
    }

    return install_fd(dir, handle);
}

int Sysdeps<ReadEntries>::operator()(int fd, void *buffer, size_t max_size, size_t *bytes_read) {
    ensure_handles();

    if (!buffer || !bytes_read)
        return EINVAL;

    *bytes_read = 0;

    if (fd < 0 || static_cast<size_t>(fd) >= g_fd_table.capacity)
        return EBADF;

    HandleID dir = g_fd_table.entries[fd];
    if (!dir)
        return EBADF;

    struct stat statbuf{};
    int error = stat_handle(dir, &statbuf);
    if (error)
        return error;
    if (!S_ISDIR(statbuf.st_mode))
        return ENOTDIR;

    HandleID read_end = 0;
    HandleID write_end = 0;
    error = create_socket_pair(&read_end, &write_end);
    if (error)
        return error;

    DirectoryOp dir_op{};
    dir_op.tag = DirectoryOp::Tag::DirectoryOp_List;
    dir_op.list.offset = 0;
    dir_op.list.sink = write_end;

    Invocation invocation{};
    invocation.tag = Invocation::Tag::Invocation_Directory;
    invocation.directory._0 = dir_op;

    SyscallResult result = ::sys_invoke(dir, &invocation);
    ::sys_close(write_end);

    if (result.error != SysError::Success) {
        ::sys_close(read_end);
        return map_error(result.error);
    }

    size_t emitted = 0;
    size_t seen = 0;
    size_t cursor = g_fd_dir_offsets[fd];

    for (;;) {
        PacketHeader header{};
        bool eof = false;
        error = read_exact_handle(read_end, &header, sizeof(header), &eof);
        if (error) {
            ::sys_close(read_end);
            return error;
        }
        if (eof)
            break;

        if (header.magic != VESPER_MAGIC
                || header.packet_type != static_cast<uint32_t>(PacketType::DirEntry)
                || header.payload_len != sizeof(AbiDirEntry)) {
            ::sys_close(read_end);
            return EIO;
        }

        AbiDirEntry native_entry{};
        error = read_exact_handle(read_end, &native_entry, sizeof(native_entry), &eof);
        if (error) {
            ::sys_close(read_end);
            return error;
        }
        if (eof) {
            ::sys_close(read_end);
            return EIO;
        }

        if (seen++ < cursor) {
            if (!(header.packet_flags & PacketFlags::HAS_NEXT))
                break;
            continue;
        }

        size_t name_len = native_entry.name_len;
        size_t reclen = offsetof(struct dirent, d_name) + name_len + 1;
        size_t align = alignof(struct dirent);
        reclen = (reclen + align - 1) & ~(align - 1);

        if (reclen > max_size) {
            ::sys_close(read_end);
            return EINVAL;
        }

        if (emitted + reclen > max_size)
            break;

        auto *entry = reinterpret_cast<struct dirent *>(static_cast<char *>(buffer) + emitted);
        memset(entry, 0, reclen);
        entry->d_ino = cursor + 1;
        entry->d_off = cursor + 1;
        entry->d_reclen = reclen;

        switch (native_entry.entry_type) {
            case 1:
                entry->d_type = DT_DIR;
                break;
            case 2:
                entry->d_type = DT_REG;
                break;
            default:
                entry->d_type = DT_UNKNOWN;
                break;
        }

        memcpy(entry->d_name, native_entry.name, name_len);
        entry->d_name[name_len] = '\0';

        emitted += reclen;
        cursor++;
        g_fd_dir_offsets[fd] = cursor;

        if (!(header.packet_flags & PacketFlags::HAS_NEXT))
            break;
    }

    ::sys_close(read_end);
    *bytes_read = emitted;
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
    if (res.error == SysError::UnsupportedOperation) {
        if (whence == SEEK_SET && offset >= 0) {
            g_fd_dir_offsets[fd] = static_cast<size_t>(offset);
            if (new_offset)
                *new_offset = offset;
            return 0;
        }
        return ESPIPE;
    }
    if (res.error != SysError::Success) return map_error(res.error);

    if (new_offset) {
        *new_offset = res.value;
    }
    return 0;
}

int Sysdeps<Dup>::operator()(int fd, int flags, int *newfd) {
    if (!newfd)
        return EINVAL;
    if (flags & ~O_CLOEXEC)
        return EINVAL;
    if (fd < 0 || static_cast<size_t>(fd) >= g_fd_table.capacity)
        return EBADF;
    if (!g_fd_table.entries[fd])
        return EBADF;

    for (size_t candidate = 3; candidate < g_fd_table.capacity; candidate++) {
        if (!g_fd_table.entries[candidate]) {
            int error = duplicate_fd_to(fd, static_cast<int>(candidate));
            if (error)
                return error;
            *newfd = static_cast<int>(candidate);
            return 0;
        }
    }

    return EMFILE;
}

int Sysdeps<Dup2>::operator()(int fd, int flags, int newfd) {
    if (flags & ~O_CLOEXEC)
        return EINVAL;
    return duplicate_fd_to(fd, newfd);
}

int Sysdeps<Close>::operator()(int fd) {
    return close_fd_slot(fd);
}
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
    
    AccessRights requested_rights = AccessRights::READ;
    switch (flags & O_ACCMODE) {
        case O_WRONLY:
            requested_rights = AccessRights::WRITE;
            break;
        case O_RDWR:
            requested_rights = AccessRights::READ | AccessRights::WRITE;
            break;
    }
    if (flags & O_DIRECTORY)
        requested_rights = AccessRights::LIST | AccessRights::TRAVERSE;

    HandleID file_handle = resolve_path(local_path, requested_rights);
    
    if (file_handle != 0) {
        // O_CREAT | O_EXCL must fail when the file already exists.
        if ((flags & O_CREAT) && (flags & O_EXCL)) {
            ::sys_close(file_handle);
            return EEXIST;
        }
    } else {
        if (!(flags & O_CREAT))
            return ENOENT;
    
        const char *filename;
        HandleID parent_handle;
        int e = resolve_parent(path, AccessRights::CREATE, &parent_handle, &filename, local_path, sizeof(local_path));
        if (e)
            return e;
    
        DirectoryOp dir_op;
        dir_op.tag = DirectoryOp::Tag::DirectoryOp_CreateFile;
        dir_op.create_file.name =
            reinterpret_cast<uintptr_t>(filename);
        dir_op.create_file.name_len = strlen(filename);
    
        Invocation invocation;
        invocation.tag = Invocation::Tag::Invocation_Directory;
        invocation.directory._0 = dir_op;
    
        SyscallResult result = ::sys_invoke(parent_handle, &invocation);
    
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
    
    return install_fd(file_handle, fd);
}

int Sysdeps<Mkdir>::operator()(const char *path, mode_t mode) {
    (void)mode;
    ensure_handles();

    char storage[4096];
    const char *name;
    HandleID parent;
    int e = resolve_parent(path, AccessRights::CREATE, &parent, &name, storage, sizeof(storage));
    if (e)
        return e;

    DirectoryOp op{};
    op.tag = DirectoryOp::Tag::DirectoryOp_CreateDir;
    op.create_dir.name = reinterpret_cast<uintptr_t>(name);
    op.create_dir.name_len = strlen(name);

    Invocation invocation{};
    invocation.tag = Invocation::Tag::Invocation_Directory;
    invocation.directory._0 = op;

    SyscallResult result = ::sys_invoke(parent, &invocation);
    ::sys_close(parent);
    if (result.error == SysError::Success)
        ::sys_close(result.value);
    if (result.error == SysError::InvalidArgument)
        return EEXIST;
    return map_error(result.error);
}

int Sysdeps<Unlinkat>::operator()(int dirfd, const char *path, int flags) {
    (void)flags;
    ensure_handles();
    if (dirfd != AT_FDCWD)
        return ENOTSUP;

    char storage[4096];
    const char *name;
    HandleID parent;
    int e = resolve_parent(path, AccessRights::REMOVE, &parent, &name, storage, sizeof(storage));
    if (e)
        return e;

    DirectoryOp op{};
    op.tag = DirectoryOp::Tag::DirectoryOp_Unlink;
    op.unlink.name = reinterpret_cast<uintptr_t>(name);
    op.unlink.name_len = strlen(name);

    Invocation invocation{};
    invocation.tag = Invocation::Tag::Invocation_Directory;
    invocation.directory._0 = op;

    SyscallResult result = ::sys_invoke(parent, &invocation);
    ::sys_close(parent);
    return map_error(result.error);
}

int Sysdeps<Rmdir>::operator()(const char *path) {
    return sysdep<Unlinkat>(AT_FDCWD, path, AT_REMOVEDIR);
}

int Sysdeps<Chdir>::operator()(const char *path) {
    ensure_handles();
    HandleID next = resolve_path(path, AccessRights::TRAVERSE);
    if (!next)
        return EACCES;

    if (g_cwd_handle != VESPERTINE_HANDLE_CWD)
        ::sys_close(g_cwd_handle);
    g_cwd_handle = next;
    return 0;
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


} // namespace mlibc
