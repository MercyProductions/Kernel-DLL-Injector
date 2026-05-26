#pragma once
#include <Windows.h>
#include <atomic>
#include "driver/driver.h"
#include "driver/driver2.h"

// Global to track which driver backend is active.
// Keep this behind BackendKind helpers so invalid values fail closed instead of
// silently using EIQDV, and use atomic storage for future threaded callers.
extern std::atomic<int> g_active_driver;

namespace drv {
    enum class BackendKind : int {
        None = 0,
        EiqdvIoctl = 1,
        Aegis2SharedMemory = 2,
    };

    inline BackendKind active_backend() {
        switch (g_active_driver.load(std::memory_order_acquire)) {
        case 1: return BackendKind::EiqdvIoctl;
        case 2: return BackendKind::Aegis2SharedMemory;
        default: return BackendKind::None;
        }
    }

    inline bool set_backend(BackendKind backend) {
        switch (backend) {
        case BackendKind::EiqdvIoctl:
        case BackendKind::Aegis2SharedMemory:
            g_active_driver.store(static_cast<int>(backend), std::memory_order_release);
            return true;
        default:
            g_active_driver.store(static_cast<int>(BackendKind::None), std::memory_order_release);
            return false;
        }
    }

    inline const char* backend_name() {
        switch (active_backend()) {
        case BackendKind::EiqdvIoctl: return "EIQDV IOCTL";
        case BackendKind::Aegis2SharedMemory: return "AegisDriver2 Shared Memory";
        default: return "No valid backend";
        }
    }

    inline void attach(DWORD pid) {
        switch (active_backend()) {
        case BackendKind::Aegis2SharedMemory: driver2().attach_process(pid); break;
        case BackendKind::EiqdvIoctl: driver().attach_process(pid); break;
        default: break;
        }
    }
    inline bool get_driver_info(AEGIS2_DRIVER_INFORMATION* info) {
        if (!info)
            return false;

        switch (active_backend()) {
        case BackendKind::Aegis2SharedMemory:
            return driver2().get_driver_info_ex(info);
        default:
            return false;
        }
    }
    inline bool heartbeat(AEGIS2_CLIENT_CONTROL* heartbeat = nullptr) {
        switch (active_backend()) {
        case BackendKind::Aegis2SharedMemory:
            return driver2().heartbeat_ex(heartbeat);
        default:
            return false;
        }
    }
    inline bool open_process(DWORD pid, AEGIS2_PROCESS_INFORMATION* process = nullptr, DWORD desired_access = PROCESS_QUERY_LIMITED_INFORMATION) {
        switch (active_backend()) {
        case BackendKind::Aegis2SharedMemory:
            return driver2().open_process_ex(pid, process, desired_access);
        case BackendKind::EiqdvIoctl:
            if (pid == 0)
                return false;
            driver().attach_process(pid);
            if (process) {
                process->process_id = pid;
                process->reserved = 0;
                process->peb_address = 0;
                process->image_base = 0;
                process->start_key = 0;
                process->create_time = 0;
            }
            return true;
        default:
            return false;
        }
    }
    inline PVOID alloc(DWORD size, DWORD protect) {
        switch (active_backend()) {
        case BackendKind::Aegis2SharedMemory: return driver2().alloc_memory_ex(size, protect);
        case BackendKind::EiqdvIoctl: return driver().alloc_memory_ex(size, protect);
        default: return nullptr;
        }
    }
    inline bool write(PVOID base, PVOID buffer, DWORD size) {
        switch (active_backend()) {
        case BackendKind::Aegis2SharedMemory: return driver2().write_memory_ex(base, buffer, size);
        case BackendKind::EiqdvIoctl: return driver().write_memory_ex(base, buffer, size) == 0;
        default: return false;
        }
    }
    inline bool read(PVOID base, PVOID buffer, DWORD size) {
        switch (active_backend()) {
        case BackendKind::Aegis2SharedMemory: return driver2().read_memory_ex(base, buffer, size);
        case BackendKind::EiqdvIoctl: return driver().read_memory_ex(base, buffer, size) == 0;
        default: return false;
        }
    }
    inline bool query_memory(PVOID address, AEGIS2_MEMORY_REGION* region) {
        if (!region)
            return false;

        switch (active_backend()) {
        case BackendKind::Aegis2SharedMemory:
            return driver2().query_memory_ex(address, region);
        default:
            return false;
        }
    }
    inline bool protect_memory(uint64_t base, uint64_t size, PDWORD protection) {
        switch (active_backend()) {
        case BackendKind::Aegis2SharedMemory:
            return driver2().protect_memory_ex(base, size, protection);
        case BackendKind::EiqdvIoctl:
            return driver().protect_memory_ex(base, size, protection) == 0;
        default:
            return false;
        }
    }
    inline bool get_diagnostics(AEGIS2_GET_DIAGNOSTICS* diagnostics) {
        if (!diagnostics)
            return false;

        switch (active_backend()) {
        case BackendKind::Aegis2SharedMemory:
            return driver2().get_diagnostics_ex(diagnostics);
        default:
            return false;
        }
    }
    inline bool get_allocations(AEGIS2_GET_ALLOCATIONS* allocations) {
        if (!allocations)
            return false;

        switch (active_backend()) {
        case BackendKind::Aegis2SharedMemory:
            return driver2().get_allocations_ex(allocations);
        default:
            return false;
        }
    }
    inline bool free_all_allocations(AEGIS2_FREE_ALL_ALLOCATIONS* result = nullptr) {
        switch (active_backend()) {
        case BackendKind::Aegis2SharedMemory:
            return driver2().free_all_allocations_ex(result);
        default:
            return false;
        }
    }
    inline bool prepare_unload(AEGIS2_PREPARE_UNLOAD* result = nullptr) {
        switch (active_backend()) {
        case BackendKind::Aegis2SharedMemory:
            return driver2().prepare_unload_ex(result);
        default:
            return false;
        }
    }
    inline bool get_module_information(const wchar_t* name, unsigned long long* base_address, unsigned long long* size_of_image = nullptr) {
        if (base_address) *base_address = 0;
        if (size_of_image) *size_of_image = 0;

        switch (active_backend()) {
        case BackendKind::Aegis2SharedMemory: {
            AEGIS2_MODULE_INFORMATION module = {};
            if (!driver2().get_module_information_ex(name, &module))
                return false;
            if (base_address) *base_address = module.base_address;
            if (size_of_image) *size_of_image = module.size_of_image;
            return module.base_address != 0;
        }
        case BackendKind::EiqdvIoctl: {
            if (!name || name[0] == L'\0')
                return false;
            ::get_module_information module = {};
            if (driver().get_module_information_ex(name, &module) != 0)
                return false;
            if (base_address) *base_address = module.base_image;
            if (size_of_image) *size_of_image = module.size_of_image;
            return module.base_image != 0;
        }
        default: return false;
        }
    }
    inline PVOID get_module_base(const wchar_t* name, unsigned long long* size_of_image = nullptr) {
        unsigned long long base_address = 0;
        if (!get_module_information(name, &base_address, size_of_image))
            return nullptr;
        return reinterpret_cast<PVOID>(base_address);
    }
    inline PVOID get_process_base(unsigned long long* size_of_image = nullptr) {
        return get_module_base(nullptr, size_of_image);
    }
    inline bool free_mem(PVOID address) {
        switch (active_backend()) {
        case BackendKind::Aegis2SharedMemory: return driver2().free_memory_ex(address);
        case BackendKind::EiqdvIoctl: return driver().free_memory_ex(address) == 0;
        default: return false;
        }
    }
    inline bool is_loaded() {
        switch (active_backend()) {
        case BackendKind::Aegis2SharedMemory: return driver2().is_connected();
        case BackendKind::EiqdvIoctl: return driver().is_loaded();
        default: return false;
        }
    }
    inline bool ping() {
        switch (active_backend()) {
        case BackendKind::Aegis2SharedMemory: return driver2().ping();
        case BackendKind::EiqdvIoctl: return driver().is_loaded();
        default: return false;
        }
    }
    inline void disconnect() {
        const BackendKind backend = active_backend();
        if (backend == BackendKind::Aegis2SharedMemory)
            driver2().disconnect();
        else if (backend == BackendKind::EiqdvIoctl)
            driver().disconnect();
    }
}
