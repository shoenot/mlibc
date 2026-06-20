#pragma once
#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <abi/flags.hpp>
#include <abi-bits/termios.h>
#include <new>

using HandleID = uintptr_t;
using UserID = uint32_t;

constexpr static const uintptr_t AT_VESPERTINE_INITPKG = 0x6fff0001;

constexpr static const uintptr_t VESPER_MAGIC = 0xc001ca75; // cool cats

constexpr static const uintptr_t TAG_ARG_FILE_0 = 4096;

constexpr static const uintptr_t TAG_ARG_FILE_1 = 4097;

using CapabilityID = uintptr_t;

constexpr static const CapabilityID CAP_LOGGER = 8192;
constexpr static const CapabilityID CAP_CLOCK = 8193;
constexpr static const CapabilityID CAP_PROCMAN = 8194;
constexpr static const CapabilityID CAP_SOCKFAC = 8195;

constexpr static const CapabilityID CAP_APP_TERMCTRL = 12288;

struct CapabilityGrant {
    HandleID id;
    AccessRights rights;
    CapabilityID capability;
};

struct ProcessInitPackage {
    HandleID self_handle;
    HandleID root_handle;
    HandleID source_handle;
    HandleID sink_handle;
    HandleID memory_pool_handle;
    HandleID cwd_handle;
    CapabilityGrant *capabilities_ptr;
    uintptr_t capabilities_len;
    uintptr_t argc;
    const char **argv;
    const char **envp;
};

static_assert(offsetof(CapabilityGrant, capability) == 16);
static_assert(sizeof(CapabilityGrant) == 24);
static_assert(offsetof(ProcessInitPackage, capabilities_ptr) == 48);
static_assert(offsetof(ProcessInitPackage, capabilities_len) == 56);
static_assert(offsetof(ProcessInitPackage, argc) == 64);
static_assert(sizeof(ProcessInitPackage) == 88);

struct alignas(8) PacketHeader {
    uint32_t magic;
    uint16_t version;
    uint16_t packet_flags;
    uint32_t packet_type;
    uint32_t payload_len;
    uint32_t reserved;
    uint32_t _pad;
};

enum class PacketType : uint32_t {
    Error = 0,
    DirEntry = 1,
    ProcessInfo = 2,
    MemoryInfo = 3,
    HandleInfo = 4,
    SystemLog = 5,
    Termios = 201,
    TermSize = 202,
    TermCommand = 203,
    TermCursorPos = 204,
    Value = 1000,
    RecordSchema = 1001,
    RecordPresentation = 1002,
    StreamEnd = 1003,
    ShellError = 1004,
};

enum class SysError : size_t {
    Success = 0,
    InvalidPointer = 1,
    BadAddress = 2,
    OutOfMemory = 3,
    InvalidHandle = 21,
    AccessDenied = 22,
    InvalidArgument = 23,
    UnsupportedOperation = 24,
    BufferFull = 25,
    WouldBlock = 26,
    PoolExhausted = 27,
    NameTooLong = 28,
    InvalidEncoding = 29,
    NotMapped = 30,
    UnknownSyscall = 41,
    ThreadSpawnFail = 50,
};

struct SyscallResult {
    size_t value;
    SysError error;
};

enum class ObjectType : uint32_t {
    File = 1,
    Directory = 2,
    Other = 3,
};

struct FileStat {
    uint32_t object_type;
    uint32_t mode;
    uint32_t user;
    uint32_t _group;
    uint64_t inode;
    uint64_t device;
    uint64_t size;
    uint32_t block_size;
    uint64_t blocks;
    uint32_t nlink;
    int64_t atime_sec;
    int64_t atime_nsec;
    int64_t mtime_sec;
    int64_t mtime_nsec;
    int64_t ctime_sec;
    int64_t ctime_nsec;
};

enum class ProcessExitKind : uint32_t {
    Running = 0,
    Exited = 1,
    Killed = 2,
    Faulted = 3,
};

struct ProcessExitInfo {
    ProcessExitKind kind;
    uint32_t code;
    uint64_t detail;
};

struct ProcStatus {
    uintptr_t pid;
    UserID user;
    uintptr_t active_threads;
    bool is_terminated;
    uintptr_t memory_usage;
};

struct WaitItem {
    HandleID handle;
    Signal signal;
    Signal pending;
};


enum vespertine_std_handle {
    VESPERTINE_HANDLE_ROOT = 0,
    VESPERTINE_HANDLE_SELF = 1,
    VESPERTINE_HANDLE_SOURCE = 2,
    VESPERTINE_HANDLE_SINK = 3,
    VESPERTINE_HANDLE_MEMORY_POOL = 4,
    VESPERTINE_HANDLE_CWD = 5,
};

enum class ThreadOp {
  ThreadOp_Kill,
  ThreadOp_Join,
  ThreadOp_GetID,
};

using HandleID = uintptr_t;

struct ChannelOp {
  enum class Tag {
    ChannelOp_PushSmall,
    ChannelOp_PushLarge,
    ChannelOp_Pull,
  };

  struct ChannelOp_PushSmall_Body {
    uint8_t data[64];
    uint8_t len;
  };

  struct ChannelOp_PushLarge_Body {
    HandleID vmo_handle;
    uintptr_t offset;
    uintptr_t len;
  };

  struct ChannelOp_Pull_Body {
    uintptr_t buffer_ptr;
  };

  Tag tag;
  union {
    ChannelOp_PushSmall_Body push_small;
    ChannelOp_PushLarge_Body push_large;
    ChannelOp_Pull_Body pull;
  };
};

struct DirectoryOp {
  enum class Tag {
    DirectoryOp_Link,
    DirectoryOp_Unlink,
    DirectoryOp_Lookup,
    DirectoryOp_List,
    DirectoryOp_CreateFile,
    DirectoryOp_CreateDir,
    DirectoryOp_Resolve,
  };

  struct DirectoryOp_Link_Body {
    uintptr_t name;
    uintptr_t name_len;
    HandleID handle_id;
  };

  struct DirectoryOp_Unlink_Body {
    uintptr_t name;
    uintptr_t name_len;
  };

  struct DirectoryOp_Lookup_Body {
    uintptr_t name;
    uintptr_t name_len;
  };

  struct DirectoryOp_List_Body {
    uintptr_t offset;
    HandleID sink;
  };

  struct DirectoryOp_CreateFile_Body {
    uintptr_t name;
    uintptr_t name_len;
  };

  struct DirectoryOp_CreateDir_Body {
    uintptr_t name;
    uintptr_t name_len;
  };

  struct DirectoryOp_Resolve_Body {
    HandleID start;
    uintptr_t path_ptr;
    uintptr_t path_len;
    AccessRights rights;
  };

  Tag tag;
  union {
    DirectoryOp_Link_Body link;
    DirectoryOp_Unlink_Body unlink;
    DirectoryOp_Lookup_Body lookup;
    DirectoryOp_List_Body list;
    DirectoryOp_CreateFile_Body create_file;
    DirectoryOp_CreateDir_Body create_dir;
    DirectoryOp_Resolve_Body resolve;
  };
};

struct FileOp {
  enum class Tag {
    FileOp_Read,
    FileOp_Write,
    FileOp_Stat,
    FileOp_GetVmo,
    FileOp_Seek,
    FileOp_Truncate,
  };

  struct FileOp_Read_Body {
    uintptr_t offset;
    uintptr_t buffer_ptr;
    uintptr_t len;
  };

  struct FileOp_Write_Body {
    uintptr_t offset;
    uintptr_t buffer_ptr;
    uintptr_t len;
  };

  struct FileOp_Stat_Body {
    uintptr_t stat_ptr;
  };

  struct FileOp_Seek_Body {
    int64_t offset;
    uint32_t whence;
  };

  struct FileOp_Truncate_Body {
    uintptr_t size;
  };

  Tag tag;
  union {
    FileOp_Read_Body read;
    FileOp_Write_Body write;
    FileOp_Stat_Body stat;
    FileOp_Seek_Body seek;
    FileOp_Truncate_Body truncate;
  };
};

struct VmoOp {
  enum class Tag {
    VmoOp_GetPage,
    VmoOp_Resize,
    VmoOp_Clone,
    VmoOp_MapIntoProc,
  };

  struct VmoOp_GetPage_Body {
    uintptr_t offset;
  };

  struct VmoOp_Resize_Body {
    uintptr_t new_size;
  };

  struct VmoOp_Clone_Body {
    uintptr_t offset;
    uintptr_t len;
  };

  struct VmoOp_MapIntoProc_Body {
    uintptr_t vaddr;
    uintptr_t len;
    uintptr_t vm_flags;
  };

  Tag tag;
  union {
    VmoOp_GetPage_Body get_page;
    VmoOp_Resize_Body resize;
    VmoOp_Clone_Body clone;
    VmoOp_MapIntoProc_Body map_into_proc;
  };
};

struct ProcOp {
  enum class Tag {
    ProcOp_Kill,
    ProcOp_GetStatus,
    ProcOp_GetExitInfo,
    ProcOp_Unmap,
    ProcOp_SpawnThread,
    ProcOp_SetFsBase,
    ProcOp_InsertHandle,
    ProcOp_Mprotect,
  };

  struct ProcOp_GetStatus_Body {
    uintptr_t status_ptr;
  };

  struct ProcOp_GetExitInfo_Body {
    uintptr_t info_ptr;
  };

  struct ProcOp_Unmap_Body {
    uintptr_t vaddr;
    uintptr_t len;
  };

  struct ProcOp_SpawnThread_Body {
    uintptr_t entry;
    uintptr_t stack_top;
    uintptr_t arg;
    uint8_t priority;
  };

  struct ProcOp_SetFsBase_Body {
    uintptr_t fs_base;
  };

  struct ProcOp_InsertHandle_Body {
    HandleID source_handle;
    AccessRights rights;
  };

  struct ProcOp_Mprotect_Body {
    uintptr_t vaddr;
    uintptr_t len;
    uintptr_t prot;
  };

  Tag tag;
  union {
    ProcOp_GetStatus_Body get_status;
    ProcOp_GetExitInfo_Body get_exit_info;
    ProcOp_Unmap_Body unmap;
    ProcOp_SpawnThread_Body spawn_thread;
    ProcOp_SetFsBase_Body set_fs_base;
    ProcOp_InsertHandle_Body insert_handle;
    ProcOp_Mprotect_Body mprotect;
  };
};

struct ProcManOp {
  enum class Tag {
    ProcManOp_Spawn,
  };

  struct ProcManOp_Spawn_Body {
    HandleID exec_handle;
    HandleID root_handle;
    AccessRights root_rights;
    HandleID cwd_handle;
    AccessRights cwd_rights;
    HandleID source;
    HandleID sink;
    uintptr_t capabilities_ptr;
    uintptr_t capabilities_len;
    uintptr_t args_buffer_ptr;
    uintptr_t args_buffer_len;
  };

  Tag tag;
  union {
    ProcManOp_Spawn_Body spawn;
  };
};

struct MemManOp {
  enum class Tag {
    MemManOp_CreatePool,
  };

  struct MemManOp_CreatePool_Body {
    uintptr_t limit;
  };

  Tag tag;
  union {
    MemManOp_CreatePool_Body create_pool;
  };
};

struct BrokerOp {
  enum class Tag {
    BrokerOp_Request,
  };

  struct BrokerOp_Request_Body {
    CapabilityID capability;
    AccessRights requested_rights;
  };

  Tag tag;
  union {
    BrokerOp_Request_Body request;
  };
};

struct MemPoolOp {
  enum class Tag {
    MemPoolOp_AllocateVmo,
    MemPoolOp_CreateSubPool,
    MemPoolOp_RequestExpansion,
  };

  struct MemPoolOp_AllocateVmo_Body {
    uintptr_t size;
  };

  struct MemPoolOp_CreateSubPool_Body {
    uintptr_t limit;
  };

  struct MemPoolOp_RequestExpansion_Body {
    uintptr_t additional_bytes;
  };

  Tag tag;
  union {
    MemPoolOp_AllocateVmo_Body allocate_vmo;
    MemPoolOp_CreateSubPool_Body create_sub_pool;
    MemPoolOp_RequestExpansion_Body request_expansion;
  };
};

struct ClockOp {
  enum class Tag {
    ClockOp_GetTimestamp,
    ClockOp_Sleep,
  };

  struct ClockOp_GetTimestamp_Body {
    uintptr_t s_ptr;
    uintptr_t ns_ptr;
  };

  struct ClockOp_Sleep_Body {
    uintptr_t ns;
  };

  Tag tag;
  union {
    ClockOp_GetTimestamp_Body get_timestamp;
    ClockOp_Sleep_Body sleep;
  };
};

struct SocketOp {
  enum class Tag {
    SocketOp_Create,
    SocketOp_SetNB,
    SocketOp_SetReadPolicy,
  };

  struct SocketOp_Create_Body {
    HandleID sourceproc;
    HandleID sinkproc;
  };

  struct SocketOp_SetNB_Body {
    bool nb;
  };

  struct SocketOp_SetReadPolicy_Body {
    uintptr_t min;
    uintptr_t timeout_ds;
  };

  Tag tag;
  union {
    SocketOp_Create_Body create;
    SocketOp_SetNB_Body set_nb;
    SocketOp_SetReadPolicy_Body set_read_policy;
  };
};

struct WaitOp {
  enum class Tag {
    WaitOp_One,
    WaitOp_Many,
  };

  struct WaitOp_One_Body {
    Signal _0;
  };

  struct WaitOp_Many_Body {
    uintptr_t items_ptr;
    uintptr_t count;
  };

  Tag tag;
  union {
    WaitOp_One_Body one;
    WaitOp_Many_Body many;
  };
};

struct Invocation {
  enum class Tag {
    Invocation_Ping,
    Invocation_GetInfo,
    Invocation_Channel,
    Invocation_Directory,
    Invocation_File,
    Invocation_Vmo,
    Invocation_Proc,
    Invocation_Thread,
    Invocation_ProcessManager,
    Invocation_MemoryManager,
    Invocation_Broker,
    Invocation_MemPool,
    Invocation_Clock,
    Invocation_Socket,
    Invocation_Wait,
  };

  struct Invocation_Channel_Body {
    ChannelOp _0;
  };

  struct Invocation_Directory_Body {
    DirectoryOp _0;
  };

  struct Invocation_File_Body {
    FileOp _0;
  };

  struct Invocation_Vmo_Body {
    VmoOp _0;
  };

  struct Invocation_Proc_Body {
    ProcOp _0;
  };

  struct Invocation_Thread_Body {
    ThreadOp _0;
  };

  struct Invocation_ProcessManager_Body {
    ProcManOp _0;
  };

  struct Invocation_MemoryManager_Body {
    MemManOp _0;
  };

  struct Invocation_Broker_Body {
    BrokerOp _0;
  };

  struct Invocation_MemPool_Body {
    MemPoolOp _0;
  };

  struct Invocation_Clock_Body {
    ClockOp _0;
  };

  struct Invocation_Socket_Body {
    SocketOp _0;
  };

  struct Invocation_Wait_Body {
    WaitOp _0;
  };

  Tag tag;
  union {
    Invocation_Channel_Body channel;
    Invocation_Directory_Body directory;
    Invocation_File_Body file;
    Invocation_Vmo_Body vmo;
    Invocation_Proc_Body proc;
    Invocation_Thread_Body thread;
    Invocation_ProcessManager_Body process_manager;
    Invocation_MemoryManager_Body memory_manager;
    Invocation_Broker_Body broker;
    Invocation_MemPool_Body mem_pool;
    Invocation_Clock_Body clock;
    Invocation_Socket_Body socket;
    Invocation_Wait_Body wait;
  };
};

struct Termios {
  uint32_t c_iflag;
  uint32_t c_oflag;
  uint32_t c_cflag;
  uint32_t c_lflag;
  uint8_t c_line;
  uint8_t c_cc[32];
  uint32_t c_ispeed;
  uint32_t c_ospeed;
};

struct WinSize {
  unsigned short ws_row;
  unsigned short ws_col;
  unsigned short ws_xpixel;
  unsigned short ws_ypixel;
};

struct TermCommand {
  enum class Tag {
    TermCommand_SetTermios,
    TermCommand_GetTermios,
    TermCommand_GetWindowSize,
    TermCommand_GetCursorPosition,
    TermCommand_Clear,
  };

  struct TermCommand_SetTermios_Body {
    Termios _0;
  };

  Tag tag;
  union {
    TermCommand_SetTermios_Body set_termios;
  };
};
