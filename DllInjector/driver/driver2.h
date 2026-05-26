#pragma once
#include <Windows.h>
#include <mutex>
#include "shared_defs.h"

class c_driver2
{
public:
    c_driver2();
    ~c_driver2();

    static c_driver2& singleton();

    bool     connect();           // Map shared section + open events
    void     disconnect();
    void     attach_process(DWORD pid);
    bool     get_driver_info_ex(AEGIS2_DRIVER_INFORMATION* info);
    bool     open_process_ex(DWORD pid, AEGIS2_PROCESS_INFORMATION* process = nullptr, DWORD desired_access = PROCESS_QUERY_LIMITED_INFORMATION);
    bool     heartbeat_ex(AEGIS2_CLIENT_CONTROL* heartbeat = nullptr);

    // Memory operations (same API as c_driver)
    bool     read_memory_ex(PVOID base, PVOID buffer, DWORD size);
    bool     write_memory_ex(PVOID base, PVOID buffer, DWORD size);
    bool     query_memory_ex(PVOID address, AEGIS2_MEMORY_REGION* region);
    bool     protect_memory_ex(uint64_t base, uint64_t size, PDWORD protection);
    PVOID    alloc_memory_ex(DWORD size, DWORD protect);
    bool     free_memory_ex(PVOID address);
    bool     get_diagnostics_ex(AEGIS2_GET_DIAGNOSTICS* diagnostics);
    bool     get_allocations_ex(AEGIS2_GET_ALLOCATIONS* allocations);
    bool     free_all_allocations_ex(AEGIS2_FREE_ALL_ALLOCATIONS* result = nullptr);
    bool     prepare_unload_ex(AEGIS2_PREPARE_UNLOAD* result = nullptr);
    bool     get_module_information_ex(const wchar_t* name, AEGIS2_MODULE_INFORMATION* module);
    PVOID    get_module_base_ex(const wchar_t* name, unsigned long long* size_of_image = nullptr);
    PVOID    get_process_base_ex(unsigned long long* size_of_image = nullptr);

    // Thread creation (NEW - fully kernel)
    bool     create_remote_thread_ex(PVOID start_address, PVOID parameter, DWORD wait_ms = 5000);

    // Ping to verify driver is alive
    bool     ping();

    bool     is_connected() const;
    DWORD    get_pid() const;

private:
    class command_lock
    {
    public:
        explicit command_lock(c_driver2& owner);
        ~command_lock();
        bool locked() const;

    private:
        c_driver2& m_owner;
        bool m_locked;
    };

    c_driver2(const c_driver2&) = delete;
    c_driver2& operator=(const c_driver2&) = delete;

    bool send_command();  // Signal request, wait for completion
    void disconnect_unlocked();
    bool acquire_command_mutex();
    void release_command_mutex();
    bool register_client_unlocked();
    bool release_client_unlocked();
    bool bind_target_unlocked(DWORD pid, AEGIS2_PROCESS_INFORMATION* process = nullptr);

    mutable std::mutex m_mutex;

    HANDLE  m_section;          // Shared memory section handle
    HANDLE  m_request_event;    // Signal driver to process
    HANDLE  m_completion_event; // Driver signals when done
    HANDLE  m_command_mutex;    // Cross-process shared command buffer guard
    void*   m_shared;           // Mapped view of shared memory
    DWORD   m_pid;              // Current target PID
    unsigned int m_next_request_id;
    DWORD   m_client_pid;
    unsigned long long m_auth_token;
    bool    m_registered;
};

inline c_driver2& driver2()
{
    return c_driver2::singleton();
}
