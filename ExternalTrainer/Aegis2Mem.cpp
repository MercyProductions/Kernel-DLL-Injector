#include "Aegis2Mem.h"

#include <TlHelp32.h>

#include <algorithm>
#include <cwctype>
#include <limits>

namespace
{
    std::wstring ToLower(std::wstring value)
    {
        std::transform(value.begin(), value.end(), value.begin(),
            [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
        return value;
    }

    std::wstring StripExtension(const std::wstring& value)
    {
        const std::size_t slash = value.find_last_of(L"\\/");
        const std::size_t dot = value.find_last_of(L'.');

        if (dot == std::wstring::npos)
            return value;
        if (slash != std::wstring::npos && dot < slash)
            return value;

        return value.substr(0, dot);
    }

    bool ProcessNameMatches(const std::wstring& candidate, const std::wstring& requested)
    {
        const std::wstring left = ToLower(candidate);
        const std::wstring right = ToLower(requested);

        if (left == right)
            return true;
        if (right.find(L'.') != std::wstring::npos)
            return false;

        return StripExtension(left) == right;
    }

    std::size_t BoundedStringLength(const char* value, std::size_t maxLength)
    {
        std::size_t length = 0;
        while (length < maxLength && value[length] != '\0')
            ++length;
        return length;
    }

    std::size_t BoundedStringLength(const wchar_t* value, std::size_t maxLength)
    {
        std::size_t length = 0;
        while (length < maxLength && value[length] != L'\0')
            ++length;
        return length;
    }
}

namespace aegis2
{
    bool Mem::Connect()
    {
        m_lastError.clear();

        if (driver2().is_connected())
            return true;

        if (!driver2().connect())
            return Fail(L"Could not connect to AegisDriver2 shared memory. Load the driver first and run this trainer as administrator.");

        return true;
    }

    void Mem::Disconnect()
    {
        driver2().disconnect();
        m_pid = 0;
        m_base = 0;
        m_processBase = 0;
        m_moduleSize = 0;
        m_moduleName.clear();
        m_lastError.clear();
    }

    bool Mem::Attach(DWORD pid, const std::wstring& moduleName)
    {
        if (pid == 0)
            return Fail(L"Attach failed because PID 0 is not a valid target.");
        if (!Connect())
            return false;

        AEGIS2_PROCESS_INFORMATION process = {};
        if (!driver2().open_process_ex(pid, &process, PROCESS_QUERY_LIMITED_INFORMATION))
            return Fail(L"AegisDriver2 rejected the target process. Check driver diagnostics for the specific reason.");

        m_pid = pid;
        m_processBase = static_cast<std::uintptr_t>(process.image_base);
        m_base = m_processBase;
        m_moduleSize = 0;
        m_moduleName.clear();

        if (RefreshModule(moduleName))
            return true;

        if (moduleName.empty() && m_processBase != 0)
        {
            m_base = m_processBase;
            m_moduleSize = 0;
            m_moduleName.clear();
            m_lastError.clear();
            return true;
        }

        return false;
    }

    bool Mem::Attach(const std::wstring& processName, const std::wstring& moduleName)
    {
        std::wstring actualName;
        const DWORD pid = FindProcessId(processName, &actualName);
        if (pid == 0)
            return Fail(L"Could not find a running process named '" + processName + L"'.");

        return Attach(pid, moduleName);
    }

    bool Mem::RefreshModule(const std::wstring& moduleName)
    {
        if (!EnsureAttached())
            return false;

        AEGIS2_MODULE_INFORMATION module = {};
        const wchar_t* requestedModule = moduleName.empty() ? nullptr : moduleName.c_str();

        if (!driver2().get_module_information_ex(requestedModule, &module) || module.base_address == 0)
        {
            const std::wstring label = moduleName.empty() ? L"main executable image" : moduleName;
            return Fail(L"Could not resolve base address for " + label + L".");
        }

        m_base = static_cast<std::uintptr_t>(module.base_address);
        m_moduleSize = static_cast<std::size_t>(module.size_of_image);
        m_moduleName = moduleName;

        if (moduleName.empty())
            m_processBase = m_base;

        m_lastError.clear();
        return true;
    }

    bool Mem::DriverInfo(AEGIS2_DRIVER_INFORMATION& info)
    {
        if (!Connect())
            return false;

        if (!driver2().get_driver_info_ex(&info))
            return Fail(L"Could not query AegisDriver2 driver information.");

        return true;
    }

    DWORD Mem::FindProcessId(const std::wstring& processName, std::wstring* actualName)
    {
        if (processName.empty())
            return 0;

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return 0;

        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);

        DWORD pid = 0;
        if (Process32FirstW(snapshot, &entry))
        {
            do
            {
                if (ProcessNameMatches(entry.szExeFile, processName))
                {
                    pid = entry.th32ProcessID;
                    if (actualName)
                        *actualName = entry.szExeFile;
                    break;
                }
            } while (Process32NextW(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return pid;
    }

    bool Mem::Query(std::uintptr_t address, AEGIS2_MEMORY_REGION& region)
    {
        if (!EnsureAttached())
            return false;
        if (address == 0)
            return Fail(L"Query failed because the address is null.");

        if (!driver2().query_memory_ex(reinterpret_cast<PVOID>(address), &region))
            return Fail(L"AegisDriver2 query-memory command failed.");

        return true;
    }

    bool Mem::Protect(std::uintptr_t address, std::size_t size, DWORD newProtect, DWORD* oldProtect)
    {
        if (!EnsureAttached())
            return false;
        if (address == 0 || size == 0)
            return Fail(L"Protect failed because the address or size is zero.");

        DWORD protection = newProtect;
        if (!driver2().protect_memory_ex(
            static_cast<std::uint64_t>(address),
            static_cast<std::uint64_t>(size),
            &protection))
        {
            return Fail(L"AegisDriver2 protect-memory command failed.");
        }

        if (oldProtect)
            *oldProtect = protection;

        return true;
    }

    bool Mem::ReadBytes(std::uintptr_t address, void* buffer, std::size_t size)
    {
        if (!EnsureAttached())
            return false;
        if (size == 0)
            return true;
        if (address == 0 || buffer == nullptr)
            return Fail(L"Read failed because the address or destination buffer is null.");
        if (!SizeFitsDriver(size))
            return Fail(L"Read failed because the request is larger than the driver wrapper can express.");

        if (!driver2().read_memory_ex(reinterpret_cast<PVOID>(address), buffer, static_cast<DWORD>(size)))
            return Fail(L"AegisDriver2 read-memory command failed.");

        return true;
    }

    bool Mem::WriteBytes(std::uintptr_t address, const void* buffer, std::size_t size)
    {
        if (!EnsureAttached())
            return false;
        if (size == 0)
            return true;
        if (address == 0 || buffer == nullptr)
            return Fail(L"Write failed because the address or source buffer is null.");
        if (!SizeFitsDriver(size))
            return Fail(L"Write failed because the request is larger than the driver wrapper can express.");

        if (!driver2().write_memory_ex(
            reinterpret_cast<PVOID>(address),
            const_cast<void*>(buffer),
            static_cast<DWORD>(size)))
        {
            return Fail(L"AegisDriver2 write-memory command failed.");
        }

        return true;
    }

    bool Mem::ReadArrayOfBytes(std::uintptr_t address, std::size_t count, std::vector<std::uint8_t>& out)
    {
        out.clear();
        if (count == 0)
            return true;

        out.resize(count);
        if (!ReadBytes(address, out.data(), out.size()))
        {
            out.clear();
            return false;
        }

        return true;
    }

    std::vector<std::uint8_t> Mem::ReadArrayOfBytes(std::uintptr_t address, std::size_t count)
    {
        std::vector<std::uint8_t> bytes;
        ReadArrayOfBytes(address, count, bytes);
        return bytes;
    }

    bool Mem::WriteArrayOfBytes(std::uintptr_t address, const std::vector<std::uint8_t>& bytes)
    {
        return bytes.empty() || WriteBytes(address, bytes.data(), bytes.size());
    }

    bool Mem::WriteArrayOfBytes(std::uintptr_t address, std::initializer_list<std::uint8_t> bytes)
    {
        if (bytes.size() == 0)
            return true;

        return WriteBytes(address, bytes.begin(), bytes.size());
    }

    std::uint8_t Mem::ReadByte(std::uintptr_t address, std::uint8_t fallback)
    {
        return Read<std::uint8_t>(address, fallback);
    }

    bool Mem::WriteByte(std::uintptr_t address, std::uint8_t value)
    {
        return WriteValue(address, value);
    }

    bool Mem::ReadBool(std::uintptr_t address, bool fallback)
    {
        return Read<bool>(address, fallback);
    }

    bool Mem::WriteBool(std::uintptr_t address, bool value)
    {
        return WriteValue(address, value);
    }

    std::int16_t Mem::ReadShort(std::uintptr_t address, std::int16_t fallback)
    {
        return Read<std::int16_t>(address, fallback);
    }

    bool Mem::WriteShort(std::uintptr_t address, std::int16_t value)
    {
        return WriteValue(address, value);
    }

    std::uint16_t Mem::ReadUShort(std::uintptr_t address, std::uint16_t fallback)
    {
        return Read<std::uint16_t>(address, fallback);
    }

    bool Mem::WriteUShort(std::uintptr_t address, std::uint16_t value)
    {
        return WriteValue(address, value);
    }

    std::int32_t Mem::ReadInt(std::uintptr_t address, std::int32_t fallback)
    {
        return Read<std::int32_t>(address, fallback);
    }

    bool Mem::WriteInt(std::uintptr_t address, std::int32_t value)
    {
        return WriteValue(address, value);
    }

    std::uint32_t Mem::ReadUInt(std::uintptr_t address, std::uint32_t fallback)
    {
        return Read<std::uint32_t>(address, fallback);
    }

    bool Mem::WriteUInt(std::uintptr_t address, std::uint32_t value)
    {
        return WriteValue(address, value);
    }

    std::int64_t Mem::ReadInt64(std::uintptr_t address, std::int64_t fallback)
    {
        return Read<std::int64_t>(address, fallback);
    }

    bool Mem::WriteInt64(std::uintptr_t address, std::int64_t value)
    {
        return WriteValue(address, value);
    }

    std::uint64_t Mem::ReadUInt64(std::uintptr_t address, std::uint64_t fallback)
    {
        return Read<std::uint64_t>(address, fallback);
    }

    bool Mem::WriteUInt64(std::uintptr_t address, std::uint64_t value)
    {
        return WriteValue(address, value);
    }

    float Mem::ReadFloat(std::uintptr_t address, float fallback)
    {
        return Read<float>(address, fallback);
    }

    bool Mem::WriteFloat(std::uintptr_t address, float value)
    {
        return WriteValue(address, value);
    }

    double Mem::ReadDouble(std::uintptr_t address, double fallback)
    {
        return Read<double>(address, fallback);
    }

    bool Mem::WriteDouble(std::uintptr_t address, double value)
    {
        return WriteValue(address, value);
    }

    std::string Mem::ReadString(std::uintptr_t address, std::size_t maxLength)
    {
        if (maxLength == 0)
            return {};

        std::vector<char> buffer(maxLength + 1, '\0');
        if (!ReadBytes(address, buffer.data(), maxLength))
            return {};

        return std::string(buffer.data(), BoundedStringLength(buffer.data(), maxLength));
    }

    bool Mem::WriteString(std::uintptr_t address, const std::string& value, bool includeNull)
    {
        const std::size_t bytesToWrite = value.size() + (includeNull ? 1u : 0u);
        if (bytesToWrite == 0)
            return true;

        return WriteBytes(address, value.c_str(), bytesToWrite);
    }

    std::wstring Mem::ReadWideString(std::uintptr_t address, std::size_t maxChars)
    {
        if (maxChars == 0)
            return {};

        std::vector<wchar_t> buffer(maxChars + 1, L'\0');
        if (!ReadBytes(address, buffer.data(), maxChars * sizeof(wchar_t)))
            return {};

        return std::wstring(buffer.data(), BoundedStringLength(buffer.data(), maxChars));
    }

    bool Mem::WriteWideString(std::uintptr_t address, const std::wstring& value, bool includeNull)
    {
        const std::size_t charsToWrite = value.size() + (includeNull ? 1u : 0u);
        if (charsToWrite == 0)
            return true;

        return WriteBytes(address, value.c_str(), charsToWrite * sizeof(wchar_t));
    }

    bool Mem::Fail(const std::wstring& message)
    {
        m_lastError = message;
        return false;
    }

    bool Mem::EnsureAttached()
    {
        if (!driver2().is_connected())
            return Fail(L"AegisDriver2 is not connected.");
        if (m_pid == 0)
            return Fail(L"No target process is attached.");
        return true;
    }

    bool Mem::SizeFitsDriver(std::size_t size)
    {
        return size <= static_cast<std::size_t>((std::numeric_limits<DWORD>::max)());
    }
}
