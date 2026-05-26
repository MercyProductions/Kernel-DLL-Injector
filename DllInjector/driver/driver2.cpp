#include "driver2.h"
#include <iostream>
#include <iomanip>

static const char* aegis2_status_name(unsigned int status)
{
    switch (status)
    {
    case STATUS_AEGIS_SUCCESS: return "SUCCESS";
    case STATUS_AEGIS_FAILED: return "FAILED";
    case STATUS_AEGIS_INVALID_CMD: return "INVALID_CMD";
    case STATUS_AEGIS_PROCESS_NOT_FOUND: return "PROCESS_NOT_FOUND";
    case STATUS_AEGIS_INVALID_PARAMETER: return "INVALID_PARAMETER";
    case STATUS_AEGIS_PARTIAL_COPY: return "PARTIAL_COPY";
    case STATUS_AEGIS_NOT_FOUND: return "NOT_FOUND";
    case STATUS_AEGIS_ACCESS_DENIED: return "ACCESS_DENIED";
    case STATUS_AEGIS_TARGET_NOT_BOUND: return "TARGET_NOT_BOUND";
    case STATUS_AEGIS_TARGET_BLOCKED: return "TARGET_BLOCKED";
    case STATUS_AEGIS_SHUTTING_DOWN: return "SHUTTING_DOWN";
    default: return "UNKNOWN";
    }
}

static const char* aegis2_reason_name(unsigned int reason)
{
    switch (reason)
    {
    case AEGIS2_REASON_NONE: return "NONE";
    case AEGIS2_REASON_BAD_PROTOCOL: return "BAD_PROTOCOL";
    case AEGIS2_REASON_UNAUTHORIZED_CLIENT: return "UNAUTHORIZED_CLIENT";
    case AEGIS2_REASON_INVALID_PARAMETER: return "INVALID_PARAMETER";
    case AEGIS2_REASON_TARGET_NOT_BOUND: return "TARGET_NOT_BOUND";
    case AEGIS2_REASON_TARGET_MISMATCH: return "TARGET_MISMATCH";
    case AEGIS2_REASON_TARGET_NOT_FOUND: return "TARGET_NOT_FOUND";
    case AEGIS2_REASON_TARGET_SYSTEM_PROCESS: return "TARGET_SYSTEM_PROCESS";
    case AEGIS2_REASON_TARGET_PROTECTED_PROCESS: return "TARGET_PROTECTED_PROCESS";
    case AEGIS2_REASON_TARGET_EXITED: return "TARGET_EXITED";
    case AEGIS2_REASON_TARGET_CRITICAL_PROCESS: return "TARGET_CRITICAL_PROCESS";
    case AEGIS2_REASON_OPEN_PROCESS_FAILED: return "OPEN_PROCESS_FAILED";
    case AEGIS2_REASON_COPY_FAILED: return "COPY_FAILED";
    case AEGIS2_REASON_ALLOC_FAILED: return "ALLOC_FAILED";
    case AEGIS2_REASON_FREE_FAILED: return "FREE_FAILED";
    case AEGIS2_REASON_QUERY_FAILED: return "QUERY_FAILED";
    case AEGIS2_REASON_PROTECT_FAILED: return "PROTECT_FAILED";
    case AEGIS2_REASON_MODULE_NOT_FOUND: return "MODULE_NOT_FOUND";
    case AEGIS2_REASON_NOT_IMPLEMENTED: return "NOT_IMPLEMENTED";
    case AEGIS2_REASON_TARGET_IDENTITY_CHANGED: return "TARGET_IDENTITY_CHANGED";
    case AEGIS2_REASON_MEMORY_NOT_COMMITTED: return "MEMORY_NOT_COMMITTED";
    case AEGIS2_REASON_MEMORY_GUARD_PAGE: return "MEMORY_GUARD_PAGE";
    case AEGIS2_REASON_MEMORY_NOACCESS: return "MEMORY_NOACCESS";
    case AEGIS2_REASON_MEMORY_NOT_READABLE: return "MEMORY_NOT_READABLE";
    case AEGIS2_REASON_MEMORY_NOT_WRITABLE: return "MEMORY_NOT_WRITABLE";
    case AEGIS2_REASON_MEMORY_RANGE_CROSSES_REGION: return "MEMORY_RANGE_CROSSES_REGION";
    case AEGIS2_REASON_ALLOCATION_NOT_TRACKED: return "ALLOCATION_NOT_TRACKED";
    case AEGIS2_REASON_ALLOCATION_LEDGER_FULL: return "ALLOCATION_LEDGER_FULL";
    case AEGIS2_REASON_DRIVER_SHUTTING_DOWN: return "DRIVER_SHUTTING_DOWN";
    case AEGIS2_REASON_FREE_ALL_FAILED: return "FREE_ALL_FAILED";
    default: return "UNKNOWN";
    }
}

static unsigned long long make_aegis2_token()
{
    LARGE_INTEGER counter = {};
    QueryPerformanceCounter(&counter);

    unsigned long long token = (unsigned long long)GetCurrentProcessId();
    token <<= 32;
    token ^= (unsigned long long)GetTickCount64();
    token ^= (unsigned long long)counter.QuadPart;
    token ^= (unsigned long long)(uintptr_t)&counter;

    return token ? token : 0xA2E615D1u;
}

static void log_aegis2_failure(const char* operation, const AEGIS2_HEADER& header)
{
    std::cout << "[-] Driver " << operation << " failed. status=" << header.status
              << " (" << aegis2_status_name(header.status) << ") ntstatus=0x"
              << std::hex << std::uppercase << (unsigned int)header.ntstatus
              << std::nouppercase << std::dec
              << " reason=" << header.reason
              << " (" << aegis2_reason_name(header.reason) << ")" << std::endl;
}

static void prepare_aegis2_header(AEGIS2_HEADER& header, unsigned int command, DWORD target_pid = 0)
{
    header.magic = AEGIS2_PROTOCOL_MAGIC;
    header.version = AEGIS2_PROTOCOL_VERSION;
    header.command = command;
    header.status = STATUS_AEGIS_FAILED;
    header.target_pid = target_pid;
    header.ntstatus = 0;
    header.request_id = 0;
    header.completed_id = 0;
    header.client_pid = 0;
    header.reason = AEGIS2_REASON_NONE;
    header.auth_token = 0;
}

c_driver2::c_driver2()
    : m_section(nullptr), m_request_event(nullptr),
      m_completion_event(nullptr), m_command_mutex(nullptr),
      m_shared(nullptr), m_pid(0), m_next_request_id(1),
      m_client_pid(GetCurrentProcessId()), m_auth_token(make_aegis2_token()),
      m_registered(false)
{
}

c_driver2::~c_driver2()
{
    disconnect();
}

c_driver2& c_driver2::singleton()
{
    static c_driver2 instance;
    return instance;
}

bool c_driver2::connect()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_shared && m_section && m_request_event && m_completion_event && m_command_mutex)
    {
        std::cout << "[+] AegisDriver2 shared memory is already connected. protocol=v"
                  << AEGIS2_PROTOCOL_VERSION << std::endl;
        return true;
    }

    const DWORD pending_pid = m_pid;
    disconnect_unlocked();
    m_pid = pending_pid;

    // Open the shared memory section created by the driver
    m_section = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, AEGIS2_UM_SECTION_NAME);
    if (!m_section)
    {
        std::cout << "[-] Failed to open shared section. Is AegisDriver2 loaded? GetLastError="
                  << GetLastError() << std::endl;
        return false;
    }

    m_shared = MapViewOfFile(m_section, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, AEGIS2_SHARED_SIZE);
    if (!m_shared)
    {
        std::cout << "[-] Failed to map shared memory view. GetLastError="
                  << GetLastError() << std::endl;
        disconnect_unlocked();
        return false;
    }

    // Open synchronization events
    m_request_event = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, AEGIS2_UM_REQUEST_EVENT);
    DWORD request_error = m_request_event ? ERROR_SUCCESS : GetLastError();
    m_completion_event = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, AEGIS2_UM_COMPLETION_EVENT);
    DWORD completion_error = m_completion_event ? ERROR_SUCCESS : GetLastError();
    m_command_mutex = CreateMutexW(nullptr, FALSE, AEGIS2_UM_COMMAND_MUTEX);
    DWORD mutex_error = m_command_mutex ? ERROR_SUCCESS : GetLastError();

    if (!m_request_event || !m_completion_event || !m_command_mutex)
    {
        std::cout << "[-] Failed to open sync events. request_error=" << request_error
                  << " completion_error=" << completion_error
                  << " mutex_error=" << mutex_error << std::endl;
        disconnect_unlocked();
        return false;
    }

    if (!register_client_unlocked())
    {
        disconnect_unlocked();
        return false;
    }

    if (m_pid != 0 && !bind_target_unlocked(m_pid))
    {
        disconnect_unlocked();
        return false;
    }

    std::cout << "[+] Connected to AegisDriver2 via shared memory. protocol=v"
              << AEGIS2_PROTOCOL_VERSION << std::endl;
    return true;
}

void c_driver2::disconnect_unlocked()
{
    if (m_shared) { UnmapViewOfFile(m_shared); m_shared = nullptr; }
    if (m_section) { CloseHandle(m_section); m_section = nullptr; }
    if (m_request_event) { CloseHandle(m_request_event); m_request_event = nullptr; }
    if (m_completion_event) { CloseHandle(m_completion_event); m_completion_event = nullptr; }
    if (m_command_mutex) { CloseHandle(m_command_mutex); m_command_mutex = nullptr; }
    m_pid = 0;
    m_registered = false;
}

void c_driver2::disconnect()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_registered && m_shared && m_request_event && m_completion_event && m_command_mutex)
        release_client_unlocked();
    disconnect_unlocked();
}

void c_driver2::attach_process(DWORD pid)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_pid = pid;

    if (m_shared && m_registered && !bind_target_unlocked(pid))
        m_pid = 0;
}

bool c_driver2::get_driver_info_ex(AEGIS2_DRIVER_INFORMATION* info)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_shared || !info) return false;

    command_lock guard(*this);
    if (!guard.locked()) return false;

    auto* cmd = (AEGIS2_GET_DRIVER_INFO*)m_shared;
    memset(cmd, 0, sizeof(AEGIS2_GET_DRIVER_INFO));
    prepare_aegis2_header(cmd->header, CMD_GET_DRIVER_INFO);

    if (!send_command()) return false;
    if (cmd->header.status != STATUS_AEGIS_SUCCESS)
    {
        log_aegis2_failure("driver-info", cmd->header);
        return false;
    }

    *info = cmd->info;
    return true;
}

bool c_driver2::register_client_unlocked()
{
    if (!m_shared) return false;

    command_lock guard(*this);
    if (!guard.locked()) return false;

    auto* cmd = (AEGIS2_REGISTER_CLIENT*)m_shared;
    memset(cmd, 0, sizeof(AEGIS2_REGISTER_CLIENT));
    prepare_aegis2_header(cmd->header, CMD_REGISTER_CLIENT);

    if (!send_command()) return false;
    if (cmd->header.status != STATUS_AEGIS_SUCCESS)
    {
        log_aegis2_failure("register-client", cmd->header);
        std::cout << "[-] AegisDriver2 owner_pid=" << cmd->owner_pid
                  << " owner_active=" << cmd->owner_active << std::endl;
        return false;
    }

    m_registered = true;
    return true;
}

bool c_driver2::release_client_unlocked()
{
    if (!m_shared) return false;

    command_lock guard(*this);
    if (!guard.locked()) return false;

    auto* cmd = (AEGIS2_CLIENT_CONTROL*)m_shared;
    memset(cmd, 0, sizeof(AEGIS2_CLIENT_CONTROL));
    prepare_aegis2_header(cmd->header, CMD_RELEASE_CLIENT);

    const bool sent = send_command();
    if (!sent || cmd->header.status != STATUS_AEGIS_SUCCESS)
    {
        if (sent)
            log_aegis2_failure("release-client", cmd->header);
        m_registered = false;
        return false;
    }

    m_registered = false;
    return true;
}

bool c_driver2::heartbeat_ex(AEGIS2_CLIENT_CONTROL* heartbeat)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_shared) return false;

    command_lock guard(*this);
    if (!guard.locked()) return false;

    auto* cmd = (AEGIS2_CLIENT_CONTROL*)m_shared;
    memset(cmd, 0, sizeof(AEGIS2_CLIENT_CONTROL));
    prepare_aegis2_header(cmd->header, CMD_CLIENT_HEARTBEAT);

    if (!send_command()) return false;
    if (cmd->header.status != STATUS_AEGIS_SUCCESS)
    {
        log_aegis2_failure("heartbeat", cmd->header);
        return false;
    }

    if (heartbeat)
        *heartbeat = *cmd;

    return true;
}

bool c_driver2::bind_target_unlocked(DWORD pid, AEGIS2_PROCESS_INFORMATION* process)
{
    if (!m_shared) return false;

    command_lock guard(*this);
    if (!guard.locked()) return false;

    auto* cmd = (AEGIS2_TARGET_CONTROL*)m_shared;
    memset(cmd, 0, sizeof(AEGIS2_TARGET_CONTROL));
    prepare_aegis2_header(cmd->header, CMD_BIND_TARGET, pid);

    if (!send_command()) return false;
    if (cmd->header.status != STATUS_AEGIS_SUCCESS)
    {
        log_aegis2_failure("bind-target", cmd->header);
        return false;
    }

    if (process)
        *process = cmd->info;

    return true;
}

bool c_driver2::open_process_ex(DWORD pid, AEGIS2_PROCESS_INFORMATION* process, DWORD desired_access)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_shared) return false;
    if (pid == 0)
    {
        std::cout << "[-] Driver open-process requested with PID 0." << std::endl;
        return false;
    }

    if (!bind_target_unlocked(pid))
        return false;

    command_lock guard(*this);
    if (!guard.locked()) return false;

    auto* cmd = (AEGIS2_OPEN_PROCESS*)m_shared;
    memset(cmd, 0, sizeof(AEGIS2_OPEN_PROCESS));
    prepare_aegis2_header(cmd->header, CMD_OPEN_PROCESS, pid);
    cmd->desired_access = desired_access ? desired_access : PROCESS_QUERY_LIMITED_INFORMATION;

    if (!send_command()) return false;
    if (cmd->header.status != STATUS_AEGIS_SUCCESS)
    {
        log_aegis2_failure("open-process", cmd->header);
        return false;
    }

    m_pid = pid;
    if (process)
        *process = cmd->info;

    return true;
}

bool c_driver2::is_connected() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_shared && m_section && m_request_event && m_completion_event && m_command_mutex;
}

DWORD c_driver2::get_pid() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_pid;
}

c_driver2::command_lock::command_lock(c_driver2& owner)
    : m_owner(owner), m_locked(owner.acquire_command_mutex())
{
}

c_driver2::command_lock::~command_lock()
{
    if (m_locked)
        m_owner.release_command_mutex();
}

bool c_driver2::command_lock::locked() const
{
    return m_locked;
}

bool c_driver2::acquire_command_mutex()
{
    if (!m_command_mutex)
    {
        std::cout << "[-] Driver command requested before command mutex was available." << std::endl;
        return false;
    }

    DWORD result = WaitForSingleObject(m_command_mutex, AEGIS2_COMMAND_TIMEOUT_MS);
    if (result == WAIT_OBJECT_0)
        return true;

    if (result == WAIT_ABANDONED)
    {
        std::cout << "[*] Previous AegisDriver2 client exited while holding the command mutex; recovering." << std::endl;
        return true;
    }

    std::cout << "[-] Timed out waiting for AegisDriver2 command mutex. wait_result=" << result
              << " GetLastError=" << GetLastError() << std::endl;
    return false;
}

void c_driver2::release_command_mutex()
{
    if (m_command_mutex && !ReleaseMutex(m_command_mutex))
    {
        std::cout << "[-] ReleaseMutex(command) failed. GetLastError=" << GetLastError() << std::endl;
    }
}

bool c_driver2::send_command()
{
    if (!m_shared || !m_request_event || !m_completion_event)
    {
        std::cout << "[-] Driver command requested before shared memory/events were connected." << std::endl;
        return false;
    }

    auto* header = (AEGIS2_HEADER*)m_shared;
    header->client_pid = m_client_pid;
    header->auth_token = m_auth_token;

    if (header->request_id == 0)
    {
        header->request_id = m_next_request_id++;
        if (m_next_request_id == 0)
            m_next_request_id = 1;
    }
    header->completed_id = 0;
    const unsigned int request_id = header->request_id;

    // Reset completion event, then signal request
    if (!ResetEvent(m_completion_event))
    {
        std::cout << "[-] ResetEvent(completion) failed. GetLastError=" << GetLastError() << std::endl;
        return false;
    }
    if (!SetEvent(m_request_event))
    {
        std::cout << "[-] SetEvent(request) failed. GetLastError=" << GetLastError() << std::endl;
        return false;
    }

    DWORD result = WaitForSingleObject(m_completion_event, AEGIS2_COMMAND_TIMEOUT_MS);
    if (result != WAIT_OBJECT_0)
    {
        std::cout << "[-] Driver command did not complete. wait_result=" << result
                  << " GetLastError=" << GetLastError() << std::endl;
        return false;
    }

    if (header->completed_id != request_id)
    {
        std::cout << "[-] Driver command completed with a stale request id. expected="
                  << request_id << " completed=" << header->completed_id << std::endl;
        return false;
    }

    return true;
}

bool c_driver2::read_memory_ex(PVOID base, PVOID buffer, DWORD size)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_shared || !base || !buffer) return false;
    if (size == 0) return true;
    if (m_pid == 0)
    {
        std::cout << "[-] Driver read requested without an attached target PID." << std::endl;
        return false;
    }

    DWORD bytes_read = 0;
    while (bytes_read < size)
    {
        DWORD chunk_size = size - bytes_read;
        if (chunk_size > 0xFF00) chunk_size = 0xFF00;

        {
            command_lock guard(*this);
            if (!guard.locked()) return false;

            auto* cmd = (AEGIS2_COPY_MEMORY*)m_shared;
            memset(cmd, 0, sizeof(AEGIS2_COPY_MEMORY));
            prepare_aegis2_header(cmd->header, CMD_READ_MEMORY, m_pid);
            cmd->address = (unsigned long long)base + bytes_read;
            cmd->size = chunk_size;
            cmd->flags = AEGIS2_DEFAULT_READ_FLAGS;

            if (!send_command()) return false;
            if (cmd->header.status != STATUS_AEGIS_SUCCESS && cmd->header.status != STATUS_AEGIS_PARTIAL_COPY)
            {
                log_aegis2_failure("read", cmd->header);
                return false;
            }

            const DWORD transferred = cmd->bytes_transferred;
            if (transferred > chunk_size)
            {
                std::cout << "[-] Driver read returned an invalid byte count. transferred="
                          << transferred << " requested=" << chunk_size << std::endl;
                return false;
            }

            if (transferred > 0)
                memcpy((PUCHAR)buffer + bytes_read, cmd->data, transferred);

            if (transferred != chunk_size)
            {
                log_aegis2_failure("read", cmd->header);
                std::cout << "[-] Driver read transferred " << transferred
                          << " of " << chunk_size << " bytes for this chunk." << std::endl;
                return false;
            }
        }

        bytes_read += chunk_size;
    }
    return true;
}

bool c_driver2::write_memory_ex(PVOID base, PVOID buffer, DWORD size)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_shared || !base || !buffer) return false;
    if (size == 0) return true;
    if (m_pid == 0)
    {
        std::cout << "[-] Driver write requested without an attached target PID." << std::endl;
        return false;
    }

    DWORD bytes_written = 0;
    while (bytes_written < size)
    {
        DWORD chunk_size = size - bytes_written;
        if (chunk_size > 0xFF00) chunk_size = 0xFF00;

        {
            command_lock guard(*this);
            if (!guard.locked()) return false;

            auto* cmd = (AEGIS2_COPY_MEMORY*)m_shared;
            memset(cmd, 0, sizeof(AEGIS2_COPY_MEMORY));
            prepare_aegis2_header(cmd->header, CMD_WRITE_MEMORY, m_pid);
            cmd->address = (unsigned long long)base + bytes_written;
            cmd->size = chunk_size;
            cmd->flags = AEGIS2_DEFAULT_WRITE_FLAGS;
            memcpy(cmd->data, (PUCHAR)buffer + bytes_written, chunk_size);

            if (!send_command()) return false;
            if (cmd->header.status != STATUS_AEGIS_SUCCESS && cmd->header.status != STATUS_AEGIS_PARTIAL_COPY)
            {
                log_aegis2_failure("write", cmd->header);
                return false;
            }

            const DWORD transferred = cmd->bytes_transferred;
            if (transferred != chunk_size)
            {
                log_aegis2_failure("write", cmd->header);
                std::cout << "[-] Driver write transferred " << transferred
                          << " of " << chunk_size << " bytes for this chunk." << std::endl;
                return false;
            }
        }

        bytes_written += chunk_size;
    }
    return true;
}

bool c_driver2::query_memory_ex(PVOID address, AEGIS2_MEMORY_REGION* region)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_shared || !region) return false;
    if (m_pid == 0)
    {
        std::cout << "[-] Driver memory-query requested without an attached target PID." << std::endl;
        return false;
    }

    command_lock guard(*this);
    if (!guard.locked()) return false;

    auto* cmd = (AEGIS2_QUERY_MEMORY*)m_shared;
    memset(cmd, 0, sizeof(AEGIS2_QUERY_MEMORY));
    prepare_aegis2_header(cmd->header, CMD_QUERY_MEMORY, m_pid);
    cmd->address = (unsigned long long)address;

    if (!send_command()) return false;
    if (cmd->header.status != STATUS_AEGIS_SUCCESS)
    {
        log_aegis2_failure("query-memory", cmd->header);
        return false;
    }

    *region = cmd->info;
    return true;
}

bool c_driver2::protect_memory_ex(uint64_t base, uint64_t size, PDWORD protection)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_shared || !base || !size || !protection) return false;
    if (m_pid == 0)
    {
        std::cout << "[-] Driver protect requested without an attached target PID." << std::endl;
        return false;
    }

    command_lock guard(*this);
    if (!guard.locked()) return false;

    auto* cmd = (AEGIS2_PROTECT_MEMORY*)m_shared;
    memset(cmd, 0, sizeof(AEGIS2_PROTECT_MEMORY));
    prepare_aegis2_header(cmd->header, CMD_PROTECT_MEMORY, m_pid);
    cmd->address = base;
    cmd->size = size;
    cmd->new_protect = *protection;
    cmd->flags = AEGIS2_DEFAULT_PROTECT_FLAGS;

    if (!send_command()) return false;
    if (cmd->header.status != STATUS_AEGIS_SUCCESS)
    {
        log_aegis2_failure("protect", cmd->header);
        return false;
    }

    *protection = cmd->old_protect;
    return true;
}

PVOID c_driver2::alloc_memory_ex(DWORD size, DWORD protect)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_shared) return nullptr;
    if (size == 0)
    {
        std::cout << "[-] Driver alloc requested with size 0." << std::endl;
        return nullptr;
    }
    if (m_pid == 0)
    {
        std::cout << "[-] Driver alloc requested without an attached target PID." << std::endl;
        return nullptr;
    }

    command_lock guard(*this);
    if (!guard.locked()) return nullptr;

    auto* cmd = (AEGIS2_ALLOC_MEMORY*)m_shared;
    memset(cmd, 0, sizeof(AEGIS2_ALLOC_MEMORY));
    prepare_aegis2_header(cmd->header, CMD_ALLOC_MEMORY, m_pid);
    cmd->size = size;
    cmd->protect = protect;

    if (!send_command()) return nullptr;
    if (cmd->header.status != STATUS_AEGIS_SUCCESS)
    {
        log_aegis2_failure("alloc", cmd->header);
        return nullptr;
    }

    return (PVOID)cmd->out_address;
}

bool c_driver2::free_memory_ex(PVOID address)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_shared) return false;
    if (!address)
    {
        std::cout << "[-] Driver free requested with a null address." << std::endl;
        return false;
    }
    if (m_pid == 0)
    {
        std::cout << "[-] Driver free requested without an attached target PID." << std::endl;
        return false;
    }

    command_lock guard(*this);
    if (!guard.locked()) return false;

    auto* cmd = (AEGIS2_FREE_MEMORY*)m_shared;
    memset(cmd, 0, sizeof(AEGIS2_FREE_MEMORY));
    prepare_aegis2_header(cmd->header, CMD_FREE_MEMORY, m_pid);
    cmd->address = (unsigned long long)address;
    cmd->flags = AEGIS2_FREE_REQUIRE_DRIVER_ALLOCATION;

    if (!send_command()) return false;
    if (cmd->header.status != STATUS_AEGIS_SUCCESS)
    {
        log_aegis2_failure("free", cmd->header);
        return false;
    }
    return true;
}

bool c_driver2::get_diagnostics_ex(AEGIS2_GET_DIAGNOSTICS* diagnostics)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_shared || !diagnostics) return false;

    command_lock guard(*this);
    if (!guard.locked()) return false;

    auto* cmd = (AEGIS2_GET_DIAGNOSTICS*)m_shared;
    memset(cmd, 0, sizeof(AEGIS2_GET_DIAGNOSTICS));
    prepare_aegis2_header(cmd->header, CMD_GET_DIAGNOSTICS);

    if (!send_command()) return false;
    if (cmd->header.status != STATUS_AEGIS_SUCCESS)
    {
        log_aegis2_failure("diagnostics", cmd->header);
        return false;
    }

    *diagnostics = *cmd;
    return true;
}

bool c_driver2::get_allocations_ex(AEGIS2_GET_ALLOCATIONS* allocations)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_shared || !allocations) return false;

    command_lock guard(*this);
    if (!guard.locked()) return false;

    auto* cmd = (AEGIS2_GET_ALLOCATIONS*)m_shared;
    memset(cmd, 0, sizeof(AEGIS2_GET_ALLOCATIONS));
    prepare_aegis2_header(cmd->header, CMD_GET_ALLOCATIONS, m_pid);

    if (!send_command()) return false;
    if (cmd->header.status != STATUS_AEGIS_SUCCESS)
    {
        log_aegis2_failure("allocations", cmd->header);
        return false;
    }

    *allocations = *cmd;
    return true;
}

bool c_driver2::free_all_allocations_ex(AEGIS2_FREE_ALL_ALLOCATIONS* result)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_shared) return false;
    if (m_pid == 0)
    {
        std::cout << "[-] Driver free-all requested without an attached target PID." << std::endl;
        return false;
    }

    command_lock guard(*this);
    if (!guard.locked()) return false;

    auto* cmd = (AEGIS2_FREE_ALL_ALLOCATIONS*)m_shared;
    memset(cmd, 0, sizeof(AEGIS2_FREE_ALL_ALLOCATIONS));
    prepare_aegis2_header(cmd->header, CMD_FREE_ALL_ALLOCATIONS, m_pid);

    if (!send_command()) return false;
    if (cmd->header.status != STATUS_AEGIS_SUCCESS)
    {
        log_aegis2_failure("free-all", cmd->header);
        if (result)
            *result = *cmd;
        return false;
    }

    if (result)
        *result = *cmd;
    return true;
}

bool c_driver2::prepare_unload_ex(AEGIS2_PREPARE_UNLOAD* result)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_shared) return false;

    command_lock guard(*this);
    if (!guard.locked()) return false;

    auto* cmd = (AEGIS2_PREPARE_UNLOAD*)m_shared;
    memset(cmd, 0, sizeof(AEGIS2_PREPARE_UNLOAD));
    prepare_aegis2_header(cmd->header, CMD_PREPARE_UNLOAD);

    if (!send_command()) return false;
    if (cmd->header.status != STATUS_AEGIS_SUCCESS)
    {
        log_aegis2_failure("prepare-unload", cmd->header);
        if (result)
            *result = *cmd;
        return false;
    }

    if (result)
        *result = *cmd;

    m_registered = false;
    m_pid = 0;
    return true;
}

bool c_driver2::get_module_information_ex(const wchar_t* name, AEGIS2_MODULE_INFORMATION* module)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_shared || !module) return false;
    if (m_pid == 0)
    {
        std::cout << "[-] Driver module lookup requested without an attached target PID." << std::endl;
        return false;
    }

    command_lock guard(*this);
    if (!guard.locked()) return false;

    auto* cmd = (AEGIS2_GET_MODULE_INFORMATION*)m_shared;
    memset(cmd, 0, sizeof(AEGIS2_GET_MODULE_INFORMATION));
    prepare_aegis2_header(cmd->header, CMD_GET_MODULE_INFORMATION, m_pid);

    if (name)
    {
        unsigned int i = 0;
        for (; i + 1 < AEGIS2_MODULE_NAME_CHARS && name[i] != L'\0'; ++i)
            cmd->module_name[i] = name[i];
        cmd->module_name[i] = L'\0';
    }

    if (!send_command()) return false;
    if (cmd->header.status != STATUS_AEGIS_SUCCESS)
    {
        log_aegis2_failure("module lookup", cmd->header);
        return false;
    }

    *module = cmd->info;
    return module->base_address != 0;
}

PVOID c_driver2::get_module_base_ex(const wchar_t* name, unsigned long long* size_of_image)
{
    AEGIS2_MODULE_INFORMATION module = {};
    if (!get_module_information_ex(name, &module))
        return nullptr;

    if (size_of_image)
        *size_of_image = module.size_of_image;

    return (PVOID)module.base_address;
}

PVOID c_driver2::get_process_base_ex(unsigned long long* size_of_image)
{
    return get_module_base_ex(nullptr, size_of_image);
}

bool c_driver2::create_remote_thread_ex(PVOID start_address, PVOID parameter, DWORD wait_ms)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_shared) return false;
    if (!start_address)
    {
        std::cout << "[-] Driver create-thread requested with a null start address." << std::endl;
        return false;
    }
    if (m_pid == 0)
    {
        std::cout << "[-] Driver create-thread requested without an attached target PID." << std::endl;
        return false;
    }

    command_lock guard(*this);
    if (!guard.locked()) return false;

    auto* cmd = (AEGIS2_CREATE_THREAD*)m_shared;
    memset(cmd, 0, sizeof(AEGIS2_CREATE_THREAD));
    prepare_aegis2_header(cmd->header, CMD_CREATE_THREAD, m_pid);
    cmd->start_address = (unsigned long long)start_address;
    cmd->parameter = (unsigned long long)parameter;
    cmd->wait_ms = wait_ms;

    if (!send_command()) return false;
    if (cmd->header.status != STATUS_AEGIS_SUCCESS)
    {
        log_aegis2_failure("create-thread", cmd->header);
        return false;
    }
    return true;
}

bool c_driver2::ping()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_shared) return false;

    command_lock guard(*this);
    if (!guard.locked()) return false;

    auto* cmd = (AEGIS2_HEADER*)m_shared;
    memset(cmd, 0, sizeof(AEGIS2_HEADER));
    prepare_aegis2_header(*cmd, CMD_PING);

    if (!send_command()) return false;
    if (cmd->status != STATUS_AEGIS_SUCCESS)
    {
        log_aegis2_failure("ping", *cmd);
        return false;
    }
    return true;
}
