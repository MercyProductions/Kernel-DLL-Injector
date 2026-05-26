#pragma once

//
// AegisDriver2 — Shared Memory Communication Protocol
// This header is shared between the kernel driver and usermode client.
//

// Protocol identity. Bump this and the object names together when struct layouts change.
#define AEGIS2_PROTOCOL_MAGIC   0x32475341u  // 'ASG2'
#define AEGIS2_PROTOCOL_VERSION 12u

// Named objects for shared memory and synchronization
#define AEGIS2_SECTION_NAME     L"\\BaseNamedObjects\\Aegis2V12SharedSection"
#define AEGIS2_REQUEST_EVENT    L"\\BaseNamedObjects\\Aegis2V12RequestEvent"
#define AEGIS2_COMPLETION_EVENT L"\\BaseNamedObjects\\Aegis2V12CompletionEvent"

// Usermode names (no \BaseNamedObjects prefix)
#define AEGIS2_UM_SECTION_NAME     L"Global\\Aegis2V12SharedSection"
#define AEGIS2_UM_REQUEST_EVENT    L"Global\\Aegis2V12RequestEvent"
#define AEGIS2_UM_COMPLETION_EVENT L"Global\\Aegis2V12CompletionEvent"
#define AEGIS2_UM_COMMAND_MUTEX    L"Global\\Aegis2V12CommandMutex"

// Shared memory size
#define AEGIS2_SHARED_SIZE  0x10000  // 64KB
#define AEGIS2_COPY_DATA_SIZE 0xFF00u

// User-mode wait timeout for one driver command.
#define AEGIS2_COMMAND_TIMEOUT_MS 10000u

// Module lookup accepts an empty name for the process executable image.
#define AEGIS2_MODULE_NAME_CHARS 260u
#define AEGIS2_BUILD_TEXT_CHARS 32u
#define AEGIS2_DIAGNOSTIC_ENTRY_COUNT 64u
#define AEGIS2_ALLOCATION_ENTRY_COUNT 128u
#define AEGIS2_COMMAND_BIT(command_id) (1ull << (command_id))

// Command IDs
enum AEGIS2_COMMAND : unsigned int
{
    CMD_NONE = 0,
    CMD_READ_MEMORY = 1,
    CMD_WRITE_MEMORY = 2,
    CMD_ALLOC_MEMORY = 3,
    CMD_FREE_MEMORY = 4,
    CMD_CREATE_THREAD = 5,
    CMD_GET_MODULE_INFORMATION = 6,
    CMD_OPEN_PROCESS = 7,
    CMD_GET_DRIVER_INFO = 8,
    CMD_QUERY_MEMORY = 9,
    CMD_PROTECT_MEMORY = 10,
    CMD_GET_DIAGNOSTICS = 11,
    CMD_REGISTER_CLIENT = 12,
    CMD_RELEASE_CLIENT = 13,
    CMD_CLIENT_HEARTBEAT = 14,
    CMD_BIND_TARGET = 15,
    CMD_GET_ALLOCATIONS = 16,
    CMD_PREPARE_UNLOAD = 17,
    CMD_FREE_ALL_ALLOCATIONS = 18,
    CMD_PING = 0xFF,
};

// Status codes
enum AEGIS2_STATUS : unsigned int
{
    STATUS_AEGIS_SUCCESS = 0,
    STATUS_AEGIS_FAILED = 1,
    STATUS_AEGIS_INVALID_CMD = 2,
    STATUS_AEGIS_PROCESS_NOT_FOUND = 3,
    STATUS_AEGIS_INVALID_PARAMETER = 4,
    STATUS_AEGIS_PARTIAL_COPY = 5,
    STATUS_AEGIS_NOT_FOUND = 6,
    STATUS_AEGIS_ACCESS_DENIED = 7,
    STATUS_AEGIS_TARGET_NOT_BOUND = 8,
    STATUS_AEGIS_TARGET_BLOCKED = 9,
    STATUS_AEGIS_SHUTTING_DOWN = 10,
};

enum AEGIS2_REASON : unsigned int
{
    AEGIS2_REASON_NONE = 0,
    AEGIS2_REASON_BAD_PROTOCOL = 1,
    AEGIS2_REASON_UNAUTHORIZED_CLIENT = 2,
    AEGIS2_REASON_INVALID_PARAMETER = 3,
    AEGIS2_REASON_TARGET_NOT_BOUND = 4,
    AEGIS2_REASON_TARGET_MISMATCH = 5,
    AEGIS2_REASON_TARGET_NOT_FOUND = 6,
    AEGIS2_REASON_TARGET_SYSTEM_PROCESS = 7,
    AEGIS2_REASON_TARGET_PROTECTED_PROCESS = 8,
    AEGIS2_REASON_TARGET_EXITED = 9,
    AEGIS2_REASON_TARGET_CRITICAL_PROCESS = 10,
    AEGIS2_REASON_OPEN_PROCESS_FAILED = 11,
    AEGIS2_REASON_COPY_FAILED = 12,
    AEGIS2_REASON_ALLOC_FAILED = 13,
    AEGIS2_REASON_FREE_FAILED = 14,
    AEGIS2_REASON_QUERY_FAILED = 15,
    AEGIS2_REASON_PROTECT_FAILED = 16,
    AEGIS2_REASON_MODULE_NOT_FOUND = 17,
    AEGIS2_REASON_NOT_IMPLEMENTED = 18,
    AEGIS2_REASON_TARGET_IDENTITY_CHANGED = 19,
    AEGIS2_REASON_MEMORY_NOT_COMMITTED = 20,
    AEGIS2_REASON_MEMORY_GUARD_PAGE = 21,
    AEGIS2_REASON_MEMORY_NOACCESS = 22,
    AEGIS2_REASON_MEMORY_NOT_READABLE = 23,
    AEGIS2_REASON_MEMORY_NOT_WRITABLE = 24,
    AEGIS2_REASON_MEMORY_RANGE_CROSSES_REGION = 25,
    AEGIS2_REASON_ALLOCATION_NOT_TRACKED = 26,
    AEGIS2_REASON_ALLOCATION_LEDGER_FULL = 27,
    AEGIS2_REASON_DRIVER_SHUTTING_DOWN = 28,
    AEGIS2_REASON_FREE_ALL_FAILED = 29,
};

enum AEGIS2_MEMORY_FLAGS : unsigned int
{
    AEGIS2_MEMORY_REQUIRE_COMMIT = 0x00000001u,
    AEGIS2_MEMORY_REJECT_GUARD = 0x00000002u,
    AEGIS2_MEMORY_REJECT_NOACCESS = 0x00000004u,
    AEGIS2_MEMORY_REQUIRE_READ = 0x00000008u,
    AEGIS2_MEMORY_REQUIRE_WRITE = 0x00000010u,
    AEGIS2_MEMORY_FAIL_ON_PARTIAL = 0x00000020u,
    AEGIS2_FREE_REQUIRE_DRIVER_ALLOCATION = 0x00000040u,
};

#define AEGIS2_DEFAULT_READ_FLAGS \
    (AEGIS2_MEMORY_REQUIRE_COMMIT | AEGIS2_MEMORY_REJECT_GUARD | \
     AEGIS2_MEMORY_REJECT_NOACCESS | AEGIS2_MEMORY_REQUIRE_READ | \
     AEGIS2_MEMORY_FAIL_ON_PARTIAL)

#define AEGIS2_DEFAULT_WRITE_FLAGS \
    (AEGIS2_MEMORY_REQUIRE_COMMIT | AEGIS2_MEMORY_REJECT_GUARD | \
     AEGIS2_MEMORY_REJECT_NOACCESS | AEGIS2_MEMORY_REQUIRE_WRITE | \
     AEGIS2_MEMORY_FAIL_ON_PARTIAL)

#define AEGIS2_DEFAULT_PROTECT_FLAGS AEGIS2_MEMORY_REQUIRE_COMMIT

// Request header (always at offset 0 of shared memory)
struct AEGIS2_HEADER
{
    unsigned int          magic;        // AEGIS2_PROTOCOL_MAGIC
    unsigned int          version;      // AEGIS2_PROTOCOL_VERSION
    volatile unsigned int command;      // AEGIS2_COMMAND
    volatile unsigned int status;       // AEGIS2_STATUS (set by driver)
    unsigned int          target_pid;   // Target process ID
    int                   ntstatus;     // Raw NTSTATUS for diagnostics
    unsigned int          request_id;   // User-set sequence for stale completion detection
    volatile unsigned int completed_id; // Driver echoes request_id after processing
    unsigned int          client_pid;   // User-mode client PID for ownership guard
    unsigned int          reason;       // AEGIS2_REASON for diagnostics/logging
    unsigned long long    auth_token;   // Per-client token echoed on every command
};

struct AEGIS2_PROCESS_INFORMATION
{
    unsigned int       process_id;       // Target PID confirmed by the driver
    unsigned int       reserved;
    unsigned long long peb_address;      // PEB address when available
    unsigned long long image_base;       // Main executable image base when available
    unsigned long long start_key;        // Process start key when available
    long long          create_time;      // Process create time fallback identity
};

// CMD_REGISTER_CLIENT
struct AEGIS2_REGISTER_CLIENT
{
    AEGIS2_HEADER header;
    unsigned int owner_pid;             // Result: current owner PID
    unsigned int owner_active;          // Result: nonzero when an owner is active
};

// CMD_RELEASE_CLIENT / CMD_CLIENT_HEARTBEAT
struct AEGIS2_CLIENT_CONTROL
{
    AEGIS2_HEADER header;
    unsigned int owner_pid;             // Result: current owner PID
    unsigned int owner_active;          // Result: nonzero when an owner is active
    unsigned long long heartbeat_time;  // Driver heartbeat timestamp
};

// CMD_BIND_TARGET
struct AEGIS2_TARGET_CONTROL
{
    AEGIS2_HEADER header;                // header.target_pid = PID to bind, 0 = clear binding
    unsigned int target_bound;           // Result: nonzero when a target is bound
    unsigned int reserved;
    AEGIS2_PROCESS_INFORMATION info;     // Result: process metadata for bound target
};

// CMD_READ_MEMORY / CMD_WRITE_MEMORY
struct AEGIS2_COPY_MEMORY
{
    AEGIS2_HEADER header;
    unsigned long long address;         // Target address
    unsigned int       size;            // Number of bytes
    unsigned int       bytes_transferred;// Result: actual bytes copied
    unsigned int       flags;           // AEGIS2_MEMORY_FLAGS
    unsigned int       reserved;
    unsigned char      data[AEGIS2_COPY_DATA_SIZE]; // Data buffer (read into / write from)
};

// CMD_GET_DRIVER_INFO
struct AEGIS2_DRIVER_INFORMATION
{
    unsigned int       protocol_magic;
    unsigned int       protocol_version;
    unsigned int       shared_size;
    unsigned int       header_size;
    unsigned int       max_copy_size;
    unsigned int       pointer_size;
    unsigned long long supported_commands;
    unsigned int       active_allocation_count;
    unsigned int       bound_target_pid;
    unsigned long long bound_target_start_key;
    long long          bound_target_create_time;
    char               build_timestamp[AEGIS2_BUILD_TEXT_CHARS];
};

struct AEGIS2_GET_DRIVER_INFO
{
    AEGIS2_HEADER header;
    AEGIS2_DRIVER_INFORMATION info;
};

// CMD_GET_DIAGNOSTICS
struct AEGIS2_DIAGNOSTIC_ENTRY
{
    unsigned int       sequence;
    unsigned int       request_id;
    unsigned int       command;
    unsigned int       target_pid;
    unsigned int       status;
    int                ntstatus;
    unsigned long long address;
    unsigned long long size;
    unsigned int       bytes_transferred;
    unsigned int       reason;
};

struct AEGIS2_GET_DIAGNOSTICS
{
    AEGIS2_HEADER header;
    unsigned int entry_count;
    unsigned int newest_sequence;
    AEGIS2_DIAGNOSTIC_ENTRY last_error;
    AEGIS2_DIAGNOSTIC_ENTRY entries[AEGIS2_DIAGNOSTIC_ENTRY_COUNT];
};

// CMD_ALLOC_MEMORY
struct AEGIS2_ALLOC_MEMORY
{
    AEGIS2_HEADER header;
    unsigned long long out_address;     // Result: allocated address
    unsigned int       size;            // Requested size; result may be rounded region size
    unsigned int       protect;         // PAGE_* protection
};

// CMD_FREE_MEMORY
struct AEGIS2_FREE_MEMORY
{
    AEGIS2_HEADER header;
    unsigned long long address;         // Address to free
    unsigned int       flags;           // AEGIS2_MEMORY_FLAGS
    unsigned int       reserved;
};

// CMD_QUERY_MEMORY
struct AEGIS2_MEMORY_REGION
{
    unsigned long long base_address;
    unsigned long long allocation_base;
    unsigned long long region_size;
    unsigned int       allocation_protect;
    unsigned int       state;
    unsigned int       protect;
    unsigned int       type;
};

struct AEGIS2_QUERY_MEMORY
{
    AEGIS2_HEADER header;
    unsigned long long address;         // Address to query
    AEGIS2_MEMORY_REGION info;          // Result: memory region metadata
};

// CMD_PROTECT_MEMORY
struct AEGIS2_PROTECT_MEMORY
{
    AEGIS2_HEADER header;
    unsigned long long address;         // Base address to protect
    unsigned long long size;            // Region size
    unsigned int       new_protect;     // PAGE_* protection
    unsigned int       old_protect;     // Result: previous PAGE_* protection
    unsigned int       flags;           // AEGIS2_MEMORY_FLAGS
    unsigned int       reserved;
};

struct AEGIS2_OPEN_PROCESS
{
    AEGIS2_HEADER header;
    unsigned int desired_access;         // PROCESS_* mask used for the driver's open check
    unsigned int reserved;
    AEGIS2_PROCESS_INFORMATION info;     // Result: process metadata
};

// CMD_GET_MODULE_INFORMATION
struct AEGIS2_MODULE_INFORMATION
{
    unsigned long long base_address;     // Result: module/image base
    unsigned long long size_of_image;    // Result: module image size when available
};

struct AEGIS2_GET_MODULE_INFORMATION
{
    AEGIS2_HEADER header;
    wchar_t module_name[AEGIS2_MODULE_NAME_CHARS]; // Empty = executable image
    AEGIS2_MODULE_INFORMATION info;
};

// CMD_CREATE_THREAD
struct AEGIS2_CREATE_THREAD
{
    AEGIS2_HEADER header;
    unsigned long long start_address;   // Thread start routine (e.g. LoadLibraryA)
    unsigned long long parameter;       // Parameter to pass (e.g. DLL path pointer)
    unsigned int       wait_ms;         // How long to wait for completion (0 = don't wait)
    unsigned long long thread_exit_code;// Result: thread exit code
};

struct AEGIS2_ALLOCATION_ENTRY
{
    unsigned long long address;
    unsigned long long size;
    unsigned int       protect;
    unsigned int       process_id;
    unsigned long long start_key;
    long long          create_time;
};

struct AEGIS2_GET_ALLOCATIONS
{
    AEGIS2_HEADER header;
    unsigned int entry_count;
    unsigned int total_active_count;
    AEGIS2_ALLOCATION_ENTRY entries[AEGIS2_ALLOCATION_ENTRY_COUNT];
};

struct AEGIS2_PREPARE_UNLOAD
{
    AEGIS2_HEADER header;
    unsigned int active_allocation_count;
    unsigned int target_bound;
    unsigned int accepting_commands;
    unsigned int reserved;
};

struct AEGIS2_FREE_ALL_ALLOCATIONS
{
    AEGIS2_HEADER header;
    unsigned int freed_count;
    unsigned int failed_count;
    unsigned long long bytes_freed;
};

static_assert(sizeof(AEGIS2_HEADER) == 48, "AEGIS2_HEADER layout changed unexpectedly");
static_assert(sizeof(AEGIS2_DIAGNOSTIC_ENTRY) == 48, "AEGIS2_DIAGNOSTIC_ENTRY layout changed unexpectedly");
static_assert(sizeof(((AEGIS2_COPY_MEMORY*)0)->data) == AEGIS2_COPY_DATA_SIZE, "AEGIS2 copy buffer size mismatch");
static_assert(sizeof(AEGIS2_COPY_MEMORY) <= AEGIS2_SHARED_SIZE, "AEGIS2_COPY_MEMORY exceeds shared memory size");
static_assert(sizeof(AEGIS2_GET_DIAGNOSTICS) <= AEGIS2_SHARED_SIZE, "AEGIS2_GET_DIAGNOSTICS exceeds shared memory size");
static_assert(sizeof(AEGIS2_GET_ALLOCATIONS) <= AEGIS2_SHARED_SIZE, "AEGIS2_GET_ALLOCATIONS exceeds shared memory size");
