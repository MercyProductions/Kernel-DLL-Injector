#include "Aegis2Mem.h"

#include <Windows.h>

#include <cstdint>
#include <cstdlib>
#include <cwctype>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

namespace
{
    void PrintUsage()
    {
        std::wcout
            << L"Usage:\n"
            << L"  ExternalTrainer.exe <process.exe | pid> [module.dll]\n\n"
            << L"Examples:\n"
            << L"  ExternalTrainer.exe AegisTestTarget.exe\n"
            << L"  ExternalTrainer.exe 1234 client.dll\n";
    }

    bool TryParsePid(const std::wstring& text, DWORD& pid)
    {
        if (text.empty())
            return false;

        for (wchar_t ch : text)
        {
            if (!std::iswdigit(ch))
                return false;
        }

        wchar_t* end = nullptr;
        const unsigned long value = std::wcstoul(text.c_str(), &end, 10);
        if (!end || *end != L'\0' || value == 0 || value > 0xFFFFFFFFul)
            return false;

        pid = static_cast<DWORD>(value);
        return true;
    }

    void PrintAddress(const wchar_t* label, std::uintptr_t value)
    {
        std::wcout << label << L"0x"
            << std::hex << std::uppercase << value
            << std::nouppercase << std::dec << L"\n";
    }

    void TrainerTemplateExamples(aegis2::Mem& mem)
    {
        // Replace these RVAs with offsets for an application you own or have permission to test.
        constexpr std::ptrdiff_t HealthRva = 0x00123456;
        constexpr std::ptrdiff_t SpeedRva = 0x0012345A;
        constexpr std::ptrdiff_t NameRva = 0x00124000;
        constexpr std::ptrdiff_t BytesRva = 0x00125000;

        const std::uintptr_t healthAddress = mem.Resolve(HealthRva);
        const std::uintptr_t speedAddress = mem.Resolve(SpeedRva);
        const std::uintptr_t nameAddress = mem.Resolve(NameRva);
        const std::uintptr_t bytesAddress = mem.Resolve(BytesRva);

        const int health = mem.ReadInt(healthAddress);
        const float speed = mem.ReadFloat(speedAddress);
        const std::string name = mem.ReadString(nameAddress, 64);
        const std::vector<std::uint8_t> bytes = mem.ReadArrayOfBytes(bytesAddress, 16);

        (void)health;
        (void)speed;
        (void)name;
        (void)bytes;

        // Write examples. Keep these disabled until the offsets and target are verified.
        // mem.WriteByte(mem.Resolve(0x00123000), 1);
        // mem.WriteInt(healthAddress, 100);
        // mem.WriteFloat(speedAddress, 1.5f);
        // mem.WriteDouble(mem.Resolve(0x00126000), 42.0);
        // mem.WriteString(nameAddress, "Aegis");
        // mem.WriteArrayOfBytes(bytesAddress, { 0x90, 0x90, 0x90 });
    }
}

int wmain(int argc, wchar_t** argv)
{
    std::wcout << L"AegisDriver2 External Trainer Template\n";
    std::wcout << L"Authorized local targets only.\n\n";

    std::wstring target;
    std::wstring moduleName;

    if (argc >= 2)
    {
        target = argv[1];
        if (argc >= 3)
            moduleName = argv[2];
    }
    else
    {
        PrintUsage();
        std::wcout << L"\nTarget process name or PID: ";
        std::getline(std::wcin, target);
    }

    if (target.empty())
    {
        std::wcerr << L"[-] No target process was provided.\n";
        return 1;
    }

    aegis2::Mem mem;

    AEGIS2_DRIVER_INFORMATION driverInfo = {};
    if (mem.DriverInfo(driverInfo))
    {
        std::wcout << L"[+] Driver protocol v" << driverInfo.protocol_version
            << L" max_copy=0x" << std::hex << driverInfo.max_copy_size
            << std::dec << L" pointer_size=" << driverInfo.pointer_size << L"\n";
    }
    else
    {
        std::wcerr << L"[-] " << mem.LastError() << L"\n";
        return 1;
    }

    DWORD pid = 0;
    const bool attached = TryParsePid(target, pid)
        ? mem.Attach(pid, moduleName)
        : mem.Attach(target, moduleName);

    if (!attached)
    {
        std::wcerr << L"[-] " << mem.LastError() << L"\n";
        return 1;
    }

    std::wcout << L"[+] Attached PID: " << mem.Pid() << L"\n";
    PrintAddress(L"[+] Process base: ", mem.ProcessBase());
    PrintAddress(moduleName.empty() ? L"[+] Image base: " : L"[+] Module base: ", mem.Base());

    if (mem.ModuleSize() != 0)
        std::wcout << L"[+] Module size: 0x" << std::hex << mem.ModuleSize() << std::dec << L"\n";

    std::wcout << L"\nTemplate is connected. Add your offsets in TrainerTemplateExamples() when ready.\n";

    // Call this only after replacing the placeholder RVAs above.
    // TrainerTemplateExamples(mem);

    return 0;
}
