# AegisDriver2 External Trainer Template

This is a standalone user-mode trainer template for authorized local testing with the
`AegisDriver2` shared-memory backend.

The sample executable connects to the driver, attaches to a target process by PID or
process name, resolves the main image base or a requested module base, and exposes a
typed memory helper in `aegis2::Mem`.

## Build

```bat
msbuild ExternalTrainer\ExternalTrainer.vcxproj /p:Configuration=Release /p:Platform=x64
```

Run the trainer as administrator after `AegisDriver2` is loaded:

```bat
ExternalTrainer.exe AegisTestTarget.exe
ExternalTrainer.exe 1234 client.dll
```

## Memory API

```cpp
aegis2::Mem mem;
mem.Attach(L"AegisTestTarget.exe");

auto healthAddress = mem.Resolve(0x00123456);
int health = mem.ReadInt(healthAddress);
mem.WriteInt(healthAddress, 100);

float speed = mem.ReadFloat(mem.Resolve(0x0012345A));
mem.WriteFloat(mem.Resolve(0x0012345A), 1.5f);

std::string name = mem.ReadString(mem.Resolve(0x00124000), 64);
mem.WriteString(mem.Resolve(0x00124000), "Aegis");

auto bytes = mem.ReadArrayOfBytes(mem.Resolve(0x00125000), 16);
mem.WriteArrayOfBytes(mem.Resolve(0x00125000), { 0x90, 0x90, 0x90 });
```

Supported helpers include byte, bool, short, int, unsigned int, int64, uint64,
float, double, narrow strings, wide strings, raw byte buffers, and arrays of bytes.
