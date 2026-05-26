#pragma once

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <type_traits>
#include <vector>

#include "../DllInjector/driver/driver2.h"

namespace aegis2
{
    class Mem
    {
    public:
        bool Connect();
        void Disconnect();

        bool Attach(DWORD pid, const std::wstring& moduleName = L"");
        bool Attach(const std::wstring& processName, const std::wstring& moduleName = L"");
        bool RefreshModule(const std::wstring& moduleName = L"");
        bool DriverInfo(AEGIS2_DRIVER_INFORMATION& info);

        static DWORD FindProcessId(const std::wstring& processName, std::wstring* actualName = nullptr);

        DWORD Pid() const noexcept { return m_pid; }
        std::uintptr_t Base() const noexcept { return m_base; }
        std::uintptr_t ProcessBase() const noexcept { return m_processBase; }
        std::size_t ModuleSize() const noexcept { return m_moduleSize; }
        const std::wstring& ModuleName() const noexcept { return m_moduleName; }
        const std::wstring& LastError() const noexcept { return m_lastError; }

        std::uintptr_t Resolve(std::ptrdiff_t offset) const noexcept
        {
            return offset < 0
                ? m_base - static_cast<std::uintptr_t>(-offset)
                : m_base + static_cast<std::uintptr_t>(offset);
        }

        bool Query(std::uintptr_t address, AEGIS2_MEMORY_REGION& region);
        bool Protect(std::uintptr_t address, std::size_t size, DWORD newProtect, DWORD* oldProtect = nullptr);

        bool ReadBytes(std::uintptr_t address, void* buffer, std::size_t size);
        bool WriteBytes(std::uintptr_t address, const void* buffer, std::size_t size);

        bool ReadArrayOfBytes(std::uintptr_t address, std::size_t count, std::vector<std::uint8_t>& out);
        std::vector<std::uint8_t> ReadArrayOfBytes(std::uintptr_t address, std::size_t count);
        bool WriteArrayOfBytes(std::uintptr_t address, const std::vector<std::uint8_t>& bytes);
        bool WriteArrayOfBytes(std::uintptr_t address, std::initializer_list<std::uint8_t> bytes);

        template <typename T>
        bool ReadValue(std::uintptr_t address, T& out)
        {
            static_assert(std::is_trivially_copyable<T>::value, "ReadValue requires a trivially copyable type.");
            return ReadBytes(address, &out, sizeof(T));
        }

        template <typename T>
        T Read(std::uintptr_t address, T fallback = T{})
        {
            static_assert(std::is_trivially_copyable<T>::value, "Read requires a trivially copyable type.");

            T out{};
            return ReadValue(address, out) ? out : fallback;
        }

        template <typename T>
        bool WriteValue(std::uintptr_t address, const T& value)
        {
            static_assert(std::is_trivially_copyable<T>::value, "WriteValue requires a trivially copyable type.");
            return WriteBytes(address, &value, sizeof(T));
        }

        template <typename T>
        bool Write(std::uintptr_t address, const T& value)
        {
            return WriteValue(address, value);
        }

        std::uint8_t ReadByte(std::uintptr_t address, std::uint8_t fallback = 0);
        bool WriteByte(std::uintptr_t address, std::uint8_t value);

        bool ReadBool(std::uintptr_t address, bool fallback = false);
        bool WriteBool(std::uintptr_t address, bool value);

        std::int16_t ReadShort(std::uintptr_t address, std::int16_t fallback = 0);
        bool WriteShort(std::uintptr_t address, std::int16_t value);

        std::uint16_t ReadUShort(std::uintptr_t address, std::uint16_t fallback = 0);
        bool WriteUShort(std::uintptr_t address, std::uint16_t value);

        std::int32_t ReadInt(std::uintptr_t address, std::int32_t fallback = 0);
        bool WriteInt(std::uintptr_t address, std::int32_t value);

        std::uint32_t ReadUInt(std::uintptr_t address, std::uint32_t fallback = 0);
        bool WriteUInt(std::uintptr_t address, std::uint32_t value);

        std::int64_t ReadInt64(std::uintptr_t address, std::int64_t fallback = 0);
        bool WriteInt64(std::uintptr_t address, std::int64_t value);

        std::uint64_t ReadUInt64(std::uintptr_t address, std::uint64_t fallback = 0);
        bool WriteUInt64(std::uintptr_t address, std::uint64_t value);

        float ReadFloat(std::uintptr_t address, float fallback = 0.0f);
        bool WriteFloat(std::uintptr_t address, float value);

        double ReadDouble(std::uintptr_t address, double fallback = 0.0);
        bool WriteDouble(std::uintptr_t address, double value);

        std::string ReadString(std::uintptr_t address, std::size_t maxLength = 256);
        bool WriteString(std::uintptr_t address, const std::string& value, bool includeNull = true);

        std::wstring ReadWideString(std::uintptr_t address, std::size_t maxChars = 256);
        bool WriteWideString(std::uintptr_t address, const std::wstring& value, bool includeNull = true);

    private:
        bool Fail(const std::wstring& message);
        bool EnsureAttached();
        static bool SizeFitsDriver(std::size_t size);

        DWORD m_pid = 0;
        std::uintptr_t m_base = 0;
        std::uintptr_t m_processBase = 0;
        std::size_t m_moduleSize = 0;
        std::wstring m_moduleName;
        std::wstring m_lastError;
    };
}
