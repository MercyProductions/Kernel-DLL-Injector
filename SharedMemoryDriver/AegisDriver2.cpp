#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include "../DllInjector/driver/shared_defs.h"

// Undocumented structures and functions required for APC thread injection
typedef enum _KAPC_ENVIRONMENT {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT, *PKAPC_ENVIRONMENT;

typedef VOID(NTAPI* PKNORMAL_ROUTINE)(
    _In_ PVOID NormalContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2);

typedef VOID KKERNEL_ROUTINE(
    _In_ PRKAPC Apc,
    _Inout_opt_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_opt_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
);
typedef KKERNEL_ROUTINE(NTAPI* PKKERNEL_ROUTINE);
typedef VOID(NTAPI* PKRUNDOWN_ROUTINE)(_In_ PRKAPC Apc);

extern "C" {
    VOID NTAPI KeInitializeApc(
        _Out_ PRKAPC Apc,
        _In_ PRKTHREAD Thread,
        _In_ KAPC_ENVIRONMENT Environment,
        _In_ PKKERNEL_ROUTINE KernelRoutine,
        _In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
        _In_opt_ PKNORMAL_ROUTINE NormalRoutine,
        _In_opt_ KPROCESSOR_MODE ProcessorMode,
        _In_opt_ PVOID NormalContext
    );

    BOOLEAN NTAPI KeInsertQueueApc(
        _Inout_ PRKAPC Apc,
        _In_opt_ PVOID SystemArgument1,
        _In_opt_ PVOID SystemArgument2,
        _In_ KPRIORITY Increment
    );

    NTSTATUS NTAPI MmCopyVirtualMemory(
        PEPROCESS SourceProcess,
        PVOID SourceAddress,
        PEPROCESS TargetProcess,
        PVOID TargetAddress,
        SIZE_T BufferSize,
        KPROCESSOR_MODE PreviousMode,
        PSIZE_T ReturnSize
    );

    PPEB NTAPI PsGetProcessPeb(
        PEPROCESS Process
    );

    PVOID NTAPI PsGetProcessSectionBaseAddress(
        PEPROCESS Process
    );

    NTSTATUS NTAPI ZwProtectVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect
    );
    
    NTSTATUS ZwQuerySystemInformation(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
    );
}

// Global state
HANDLE g_SectionHandle = NULL;
PVOID  g_SectionObject = NULL;
PVOID  g_SharedMemory = NULL;
PKEVENT g_RequestEvent = NULL;
PKEVENT g_CompletionEvent = NULL;
HANDLE  g_ReqEventHandle = NULL;
HANDLE  g_CompEventHandle = NULL;
PVOID   g_WorkerThreadObject = NULL;
volatile LONG g_DriverUnloading = 0;
volatile LONG g_AcceptingCommands = 1;
AEGIS2_DIAGNOSTIC_ENTRY g_Diagnostics[AEGIS2_DIAGNOSTIC_ENTRY_COUNT] = {};
AEGIS2_DIAGNOSTIC_ENTRY g_LastError = {};
AEGIS2_ALLOCATION_ENTRY g_Allocations[AEGIS2_ALLOCATION_ENTRY_COUNT] = {};
volatile LONG g_DiagnosticSequence = 0;
volatile LONG g_ClientRegistered = 0;
volatile LONG g_TargetBound = 0;
ULONG g_OwnerProcessId = 0;
ULONGLONG g_OwnerToken = 0;
ULONGLONG g_OwnerHeartbeatTime = 0;
ULONG g_TargetProcessId = 0;
ULONGLONG g_TargetStartKey = 0;
LONGLONG g_TargetCreateTime = 0;

static const ULONG AEGIS2_POOL_TAG = '2geA';
static const ULONG AEGIS2_COPY_BUFFER_SIZE = sizeof(((AEGIS2_COPY_MEMORY*)0)->data);
static const ULONGLONG AEGIS2_OWNER_STALE_100NS = 60ull * 1000ull * 1000ull * 10ull;

typedef PUCHAR(NTAPI* AEGIS2_PS_GET_PROCESS_IMAGE_FILE_NAME)(PEPROCESS Process);
typedef BOOLEAN(NTAPI* AEGIS2_PS_IS_PROTECTED_PROCESS)(PEPROCESS Process);
typedef ULONGLONG(NTAPI* AEGIS2_PS_GET_PROCESS_START_KEY)(PEPROCESS Process);

static void ClearTarget();

typedef struct _AEGIS2_PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    UCHAR Reserved1[3];
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} AEGIS2_PEB_LDR_DATA, *PAEGIS2_PEB_LDR_DATA;

typedef struct _AEGIS2_PEB
{
    UCHAR Reserved1[2];
    UCHAR BeingDebugged;
    UCHAR Reserved2[1];
    PVOID Reserved3[2];
    PAEGIS2_PEB_LDR_DATA Ldr;
} AEGIS2_PEB, *PAEGIS2_PEB;

typedef struct _AEGIS2_LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} AEGIS2_LDR_DATA_TABLE_ENTRY, *PAEGIS2_LDR_DATA_TABLE_ENTRY;

static NTSTATUS InitializeRestrictedSecurityDescriptor(
    SECURITY_DESCRIPTOR* securityDescriptor,
    PACL acl,
    ULONG aclSize)
{
    NTSTATUS status = RtlCreateSecurityDescriptor(securityDescriptor, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status))
        return status;

    UCHAR systemSidBuffer[SECURITY_MAX_SID_SIZE] = {};
    UCHAR adminSidBuffer[SECURITY_MAX_SID_SIZE] = {};
    PSID systemSid = (PSID)systemSidBuffer;
    PSID adminSid = (PSID)adminSidBuffer;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    status = RtlInitializeSid(systemSid, &ntAuthority, 1);
    if (!NT_SUCCESS(status))
        return status;
    *RtlSubAuthoritySid(systemSid, 0) = SECURITY_LOCAL_SYSTEM_RID;

    status = RtlInitializeSid(adminSid, &ntAuthority, 2);
    if (!NT_SUCCESS(status))
        return status;
    *RtlSubAuthoritySid(adminSid, 0) = SECURITY_BUILTIN_DOMAIN_RID;
    *RtlSubAuthoritySid(adminSid, 1) = DOMAIN_ALIAS_RID_ADMINS;

    const ULONG requiredAclSize =
        sizeof(ACL) +
        (sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG)) * 2 +
        RtlLengthSid(systemSid) +
        RtlLengthSid(adminSid);

    if (aclSize < requiredAclSize)
        return STATUS_BUFFER_TOO_SMALL;

    status = RtlCreateAcl(acl, aclSize, ACL_REVISION);
    if (!NT_SUCCESS(status))
        return status;

    status = RtlAddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, systemSid);
    if (!NT_SUCCESS(status))
        return status;

    status = RtlAddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, adminSid);
    if (!NT_SUCCESS(status))
        return status;

    return RtlSetDaclSecurityDescriptor(securityDescriptor, TRUE, acl, FALSE);
}

static BOOLEAN IsDriverUnloading()
{
    return InterlockedCompareExchange(&g_DriverUnloading, 0, 0) != 0;
}

static BOOLEAN IsAcceptingCommands()
{
    return InterlockedCompareExchange(&g_AcceptingCommands, 0, 0) != 0;
}

static BOOLEAN IsCommandAllowedAfterPrepareUnload(unsigned int command)
{
    return command == CMD_GET_DRIVER_INFO ||
           command == CMD_GET_DIAGNOSTICS ||
           command == CMD_GET_ALLOCATIONS ||
           command == CMD_PING;
}

static BOOLEAN IsValidCopyRequest(const AEGIS2_COPY_MEMORY* cmd)
{
    if (!cmd || cmd->header.target_pid == 0 || cmd->address == 0)
        return FALSE;

    if (cmd->size == 0 || cmd->size > AEGIS2_COPY_BUFFER_SIZE)
        return FALSE;

    return TRUE;
}

static void SetCommandReason(AEGIS2_HEADER* header, unsigned int reason)
{
    if (header)
        header->reason = reason;
}

static BOOLEAN AsciiEqualsInsensitive(const CHAR* left, const CHAR* right)
{
    if (!left || !right)
        return FALSE;

    while (*left && *right)
    {
        CHAR a = *left++;
        CHAR b = *right++;

        if (a >= 'A' && a <= 'Z')
            a = (CHAR)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z')
            b = (CHAR)(b - 'A' + 'a');

        if (a != b)
            return FALSE;
    }

    return *left == '\0' && *right == '\0';
}

static PVOID GetKernelRoutineAddress(const WCHAR* routineName)
{
    UNICODE_STRING name = {};
    RtlInitUnicodeString(&name, routineName);
    return MmGetSystemRoutineAddress(&name);
}

static PUCHAR QueryProcessImageName(PEPROCESS process)
{
    AEGIS2_PS_GET_PROCESS_IMAGE_FILE_NAME getImageName =
        (AEGIS2_PS_GET_PROCESS_IMAGE_FILE_NAME)GetKernelRoutineAddress(L"PsGetProcessImageFileName");

    if (!getImageName || !process)
        return NULL;

    return getImageName(process);
}

static BOOLEAN QueryProcessProtectedState(PEPROCESS process)
{
    if (!process)
        return FALSE;

    AEGIS2_PS_IS_PROTECTED_PROCESS isProtected =
        (AEGIS2_PS_IS_PROTECTED_PROCESS)GetKernelRoutineAddress(L"PsIsProtectedProcess");
    AEGIS2_PS_IS_PROTECTED_PROCESS isProtectedLight =
        (AEGIS2_PS_IS_PROTECTED_PROCESS)GetKernelRoutineAddress(L"PsIsProtectedProcessLight");

    return (isProtected && isProtected(process)) ||
           (isProtectedLight && isProtectedLight(process));
}

static BOOLEAN IsCriticalUserProcessName(const CHAR* imageName)
{
    return AsciiEqualsInsensitive(imageName, "csrss.exe") ||
           AsciiEqualsInsensitive(imageName, "smss.exe") ||
           AsciiEqualsInsensitive(imageName, "wininit.exe") ||
           AsciiEqualsInsensitive(imageName, "winlogon.exe") ||
           AsciiEqualsInsensitive(imageName, "services.exe") ||
           AsciiEqualsInsensitive(imageName, "lsass.exe");
}

static void CaptureProcessIdentity(
    PEPROCESS process,
    ULONGLONG* startKey,
    LONGLONG* createTime)
{
    if (startKey)
        *startKey = 0;
    if (createTime)
        *createTime = 0;

    if (!process)
        return;

    AEGIS2_PS_GET_PROCESS_START_KEY getStartKey =
        (AEGIS2_PS_GET_PROCESS_START_KEY)GetKernelRoutineAddress(L"PsGetProcessStartKey");

    if (getStartKey && startKey)
        *startKey = getStartKey(process);

    if (createTime)
        *createTime = PsGetProcessCreateTimeQuadPart(process);
}

static BOOLEAN ProcessIdentityMatches(PEPROCESS process)
{
    ULONGLONG startKey = 0;
    LONGLONG createTime = 0;
    CaptureProcessIdentity(process, &startKey, &createTime);

    if (g_TargetStartKey != 0 && startKey != 0)
        return startKey == g_TargetStartKey;

    return createTime != 0 && createTime == g_TargetCreateTime;
}

static void FillProcessInformation(PEPROCESS process, ULONG pid, AEGIS2_PROCESS_INFORMATION* info)
{
    if (!info)
        return;

    RtlZeroMemory(info, sizeof(*info));
    info->process_id = pid;
    info->peb_address = (ULONGLONG)PsGetProcessPeb(process);
    info->image_base = (ULONGLONG)PsGetProcessSectionBaseAddress(process);
    CaptureProcessIdentity(process, &info->start_key, &info->create_time);
}

static NTSTATUS ValidateProcessForUse(
    ULONG pid,
    PEPROCESS* outProcess,
    unsigned int* outReason)
{
    if (outProcess)
        *outProcess = NULL;
    if (outReason)
        *outReason = AEGIS2_REASON_NONE;

    if (pid == 0)
    {
        if (outReason) *outReason = AEGIS2_REASON_INVALID_PARAMETER;
        return STATUS_INVALID_PARAMETER;
    }

    if (pid <= 4)
    {
        if (outReason) *outReason = AEGIS2_REASON_TARGET_SYSTEM_PROCESS;
        return STATUS_ACCESS_DENIED;
    }

    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
    if (!NT_SUCCESS(status))
    {
        if (outReason) *outReason = AEGIS2_REASON_TARGET_NOT_FOUND;
        return status;
    }

    status = PsGetProcessExitStatus(process);
    if (status != STATUS_PENDING)
    {
        ObDereferenceObject(process);
        if (outReason) *outReason = AEGIS2_REASON_TARGET_EXITED;
        return STATUS_PROCESS_IS_TERMINATING;
    }

    if (QueryProcessProtectedState(process))
    {
        ObDereferenceObject(process);
        if (outReason) *outReason = AEGIS2_REASON_TARGET_PROTECTED_PROCESS;
        return STATUS_ACCESS_DENIED;
    }

    PUCHAR imageName = QueryProcessImageName(process);
    if (imageName && IsCriticalUserProcessName((const CHAR*)imageName))
    {
        ObDereferenceObject(process);
        if (outReason) *outReason = AEGIS2_REASON_TARGET_CRITICAL_PROCESS;
        return STATUS_ACCESS_DENIED;
    }

    if (outProcess)
    {
        *outProcess = process;
    }
    else
    {
        ObDereferenceObject(process);
    }

    return STATUS_SUCCESS;
}

static unsigned int StatusFromTargetValidation(NTSTATUS status, unsigned int reason)
{
    if (reason == AEGIS2_REASON_TARGET_NOT_FOUND)
        return STATUS_AEGIS_PROCESS_NOT_FOUND;

    if (reason == AEGIS2_REASON_TARGET_SYSTEM_PROCESS ||
        reason == AEGIS2_REASON_TARGET_PROTECTED_PROCESS ||
        reason == AEGIS2_REASON_TARGET_CRITICAL_PROCESS ||
        reason == AEGIS2_REASON_TARGET_EXITED)
    {
        return STATUS_AEGIS_TARGET_BLOCKED;
    }

    if (!NT_SUCCESS(status))
        return STATUS_AEGIS_FAILED;

    return STATUS_AEGIS_SUCCESS;
}

static unsigned int ValidateBoundTargetForCommand(
    AEGIS2_HEADER* header,
    PEPROCESS* outProcess,
    NTSTATUS* outNtStatus)
{
    if (outProcess)
        *outProcess = NULL;
    if (outNtStatus)
        *outNtStatus = STATUS_SUCCESS;

    if (!header || header->target_pid == 0)
    {
        SetCommandReason(header, AEGIS2_REASON_INVALID_PARAMETER);
        if (outNtStatus) *outNtStatus = STATUS_INVALID_PARAMETER;
        return STATUS_AEGIS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&g_TargetBound, 0, 0) == 0)
    {
        SetCommandReason(header, AEGIS2_REASON_TARGET_NOT_BOUND);
        if (outNtStatus) *outNtStatus = STATUS_ACCESS_DENIED;
        return STATUS_AEGIS_TARGET_NOT_BOUND;
    }

    if (header->target_pid != g_TargetProcessId)
    {
        SetCommandReason(header, AEGIS2_REASON_TARGET_MISMATCH);
        if (outNtStatus) *outNtStatus = STATUS_ACCESS_DENIED;
        return STATUS_AEGIS_TARGET_NOT_BOUND;
    }

    unsigned int reason = AEGIS2_REASON_NONE;
    PEPROCESS process = NULL;
    NTSTATUS status = ValidateProcessForUse(header->target_pid, &process, &reason);
    if (!NT_SUCCESS(status))
    {
        SetCommandReason(header, reason);
        if (outNtStatus) *outNtStatus = status;
        return StatusFromTargetValidation(status, reason);
    }

    if (!ProcessIdentityMatches(process))
    {
        ObDereferenceObject(process);
        ClearTarget();
        SetCommandReason(header, AEGIS2_REASON_TARGET_IDENTITY_CHANGED);
        if (outNtStatus) *outNtStatus = STATUS_ACCESS_DENIED;
        return STATUS_AEGIS_TARGET_BLOCKED;
    }

    if (outProcess)
        *outProcess = process;
    else
        ObDereferenceObject(process);

    return STATUS_AEGIS_SUCCESS;
}

static SIZE_T WideStringLengthChars(const WCHAR* value, SIZE_T maxChars)
{
    if (!value)
        return 0;

    SIZE_T length = 0;
    while (length < maxChars && value[length] != L'\0')
        ++length;

    return length;
}

static BOOLEAN ModuleNameMatches(const UNICODE_STRING* candidate, const UNICODE_STRING* requestedName)
{
    if (!candidate || !candidate->Buffer || !requestedName || !requestedName->Buffer)
        return FALSE;

    if (candidate->Length == 0 || requestedName->Length == 0)
        return FALSE;

    return RtlCompareUnicodeString((PUNICODE_STRING)candidate, (PUNICODE_STRING)requestedName, TRUE) == 0;
}

static BOOLEAN IsOwnerProcessAlive()
{
    if (g_OwnerProcessId == 0)
        return FALSE;

    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)g_OwnerProcessId, &process);
    if (NT_SUCCESS(status))
    {
        ObDereferenceObject(process);
        return TRUE;
    }

    return FALSE;
}

static ULONGLONG CurrentInterruptTime()
{
    return KeQueryInterruptTime();
}

static BOOLEAN IsOwnerHeartbeatFresh()
{
    if (g_OwnerHeartbeatTime == 0)
        return FALSE;

    const ULONGLONG now = CurrentInterruptTime();
    return now >= g_OwnerHeartbeatTime &&
           now - g_OwnerHeartbeatTime <= AEGIS2_OWNER_STALE_100NS;
}

static BOOLEAN IsOwnerActive()
{
    return IsOwnerProcessAlive() && IsOwnerHeartbeatFresh();
}

static void ClearTarget()
{
    g_TargetProcessId = 0;
    g_TargetStartKey = 0;
    g_TargetCreateTime = 0;
    InterlockedExchange(&g_TargetBound, 0);
}

static void ClearOwner()
{
    ClearTarget();
    g_OwnerProcessId = 0;
    g_OwnerToken = 0;
    g_OwnerHeartbeatTime = 0;
    InterlockedExchange(&g_ClientRegistered, 0);
}

static BOOLEAN IsAuthorizedCommand(const AEGIS2_HEADER* header)
{
    if (!header)
        return FALSE;

    if (header->command == CMD_REGISTER_CLIENT)
        return TRUE;

    if (InterlockedCompareExchange(&g_ClientRegistered, 0, 0) == 0)
        return FALSE;

    if (header->client_pid == g_OwnerProcessId &&
        header->auth_token != 0 &&
        header->auth_token == g_OwnerToken)
    {
        g_OwnerHeartbeatTime = CurrentInterruptTime();
        return TRUE;
    }

    return FALSE;
}

static unsigned int HandleRegisterClient(AEGIS2_REGISTER_CLIENT* cmd, NTSTATUS* outNtStatus)
{
    if (outNtStatus) *outNtStatus = STATUS_SUCCESS;

    if (!cmd || cmd->header.client_pid == 0 || cmd->header.auth_token == 0)
    {
        if (outNtStatus) *outNtStatus = STATUS_INVALID_PARAMETER;
        return STATUS_AEGIS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&g_ClientRegistered, 0, 0) != 0)
    {
        if (g_OwnerProcessId == cmd->header.client_pid && g_OwnerToken == cmd->header.auth_token)
        {
            g_OwnerHeartbeatTime = CurrentInterruptTime();
            cmd->owner_pid = g_OwnerProcessId;
            cmd->owner_active = 1;
            return STATUS_AEGIS_SUCCESS;
        }

        if (IsOwnerActive())
        {
            cmd->owner_pid = g_OwnerProcessId;
            cmd->owner_active = 1;
            if (outNtStatus) *outNtStatus = STATUS_ACCESS_DENIED;
            return STATUS_AEGIS_ACCESS_DENIED;
        }

        ClearOwner();
    }

    g_OwnerProcessId = cmd->header.client_pid;
    g_OwnerToken = cmd->header.auth_token;
    g_OwnerHeartbeatTime = CurrentInterruptTime();
    InterlockedExchange(&g_ClientRegistered, 1);

    cmd->owner_pid = g_OwnerProcessId;
    cmd->owner_active = 1;
    return STATUS_AEGIS_SUCCESS;
}

static unsigned int HandleReleaseClient(AEGIS2_CLIENT_CONTROL* cmd, NTSTATUS* outNtStatus)
{
    if (outNtStatus) *outNtStatus = STATUS_SUCCESS;

    if (!cmd)
    {
        if (outNtStatus) *outNtStatus = STATUS_INVALID_PARAMETER;
        return STATUS_AEGIS_INVALID_PARAMETER;
    }

    if (!IsAuthorizedCommand(&cmd->header))
    {
        if (outNtStatus) *outNtStatus = STATUS_ACCESS_DENIED;
        return STATUS_AEGIS_ACCESS_DENIED;
    }

    ClearOwner();
    cmd->owner_pid = 0;
    cmd->owner_active = 0;
    cmd->heartbeat_time = 0;
    return STATUS_AEGIS_SUCCESS;
}

static unsigned int HandleClientHeartbeat(AEGIS2_CLIENT_CONTROL* cmd, NTSTATUS* outNtStatus)
{
    if (outNtStatus) *outNtStatus = STATUS_SUCCESS;

    if (!cmd)
    {
        if (outNtStatus) *outNtStatus = STATUS_INVALID_PARAMETER;
        return STATUS_AEGIS_INVALID_PARAMETER;
    }

    if (!IsAuthorizedCommand(&cmd->header))
    {
        if (outNtStatus) *outNtStatus = STATUS_ACCESS_DENIED;
        return STATUS_AEGIS_ACCESS_DENIED;
    }

    g_OwnerHeartbeatTime = CurrentInterruptTime();
    cmd->owner_pid = g_OwnerProcessId;
    cmd->owner_active = 1;
    cmd->heartbeat_time = g_OwnerHeartbeatTime;
    return STATUS_AEGIS_SUCCESS;
}

static unsigned int HandleBindTarget(AEGIS2_TARGET_CONTROL* cmd, NTSTATUS* outNtStatus)
{
    if (outNtStatus) *outNtStatus = STATUS_SUCCESS;

    if (!cmd)
    {
        if (outNtStatus) *outNtStatus = STATUS_INVALID_PARAMETER;
        return STATUS_AEGIS_INVALID_PARAMETER;
    }

    cmd->target_bound = 0;
    RtlZeroMemory(&cmd->info, sizeof(cmd->info));

    if (cmd->header.target_pid == 0)
    {
        ClearTarget();
        return STATUS_AEGIS_SUCCESS;
    }

    PEPROCESS process = NULL;
    unsigned int reason = AEGIS2_REASON_NONE;
    NTSTATUS status = ValidateProcessForUse(cmd->header.target_pid, &process, &reason);
    if (!NT_SUCCESS(status))
    {
        SetCommandReason(&cmd->header, reason);
        if (outNtStatus) *outNtStatus = status;
        return StatusFromTargetValidation(status, reason);
    }

    g_TargetProcessId = cmd->header.target_pid;
    CaptureProcessIdentity(process, &g_TargetStartKey, &g_TargetCreateTime);
    InterlockedExchange(&g_TargetBound, 1);

    cmd->target_bound = 1;
    FillProcessInformation(process, cmd->header.target_pid, &cmd->info);
    ObDereferenceObject(process);

    return STATUS_AEGIS_SUCCESS;
}

static void ExtractDiagnosticFields(
    AEGIS2_HEADER* header,
    unsigned long long* address,
    unsigned long long* size,
    unsigned int* bytesTransferred)
{
    if (address) *address = 0;
    if (size) *size = 0;
    if (bytesTransferred) *bytesTransferred = 0;

    if (!header)
        return;

    switch (header->command)
    {
    case CMD_READ_MEMORY:
    case CMD_WRITE_MEMORY:
    {
        AEGIS2_COPY_MEMORY* cmd = (AEGIS2_COPY_MEMORY*)header;
        if (address) *address = cmd->address;
        if (size) *size = cmd->size;
        if (bytesTransferred) *bytesTransferred = cmd->bytes_transferred;
        break;
    }
    case CMD_ALLOC_MEMORY:
    {
        AEGIS2_ALLOC_MEMORY* cmd = (AEGIS2_ALLOC_MEMORY*)header;
        if (address) *address = cmd->out_address;
        if (size) *size = cmd->size;
        break;
    }
    case CMD_FREE_MEMORY:
    {
        AEGIS2_FREE_MEMORY* cmd = (AEGIS2_FREE_MEMORY*)header;
        if (address) *address = cmd->address;
        break;
    }
    case CMD_QUERY_MEMORY:
    {
        AEGIS2_QUERY_MEMORY* cmd = (AEGIS2_QUERY_MEMORY*)header;
        if (address) *address = cmd->address;
        if (size) *size = cmd->info.region_size;
        break;
    }
    case CMD_PROTECT_MEMORY:
    {
        AEGIS2_PROTECT_MEMORY* cmd = (AEGIS2_PROTECT_MEMORY*)header;
        if (address) *address = cmd->address;
        if (size) *size = cmd->size;
        break;
    }
    case CMD_GET_MODULE_INFORMATION:
    {
        AEGIS2_GET_MODULE_INFORMATION* cmd = (AEGIS2_GET_MODULE_INFORMATION*)header;
        if (address) *address = cmd->info.base_address;
        if (size) *size = cmd->info.size_of_image;
        break;
    }
    case CMD_OPEN_PROCESS:
    {
        AEGIS2_OPEN_PROCESS* cmd = (AEGIS2_OPEN_PROCESS*)header;
        if (address) *address = cmd->info.image_base;
        break;
    }
    case CMD_BIND_TARGET:
    {
        AEGIS2_TARGET_CONTROL* cmd = (AEGIS2_TARGET_CONTROL*)header;
        if (address) *address = cmd->info.image_base;
        break;
    }
    case CMD_PREPARE_UNLOAD:
    {
        AEGIS2_PREPARE_UNLOAD* cmd = (AEGIS2_PREPARE_UNLOAD*)header;
        if (size) *size = cmd->active_allocation_count;
        break;
    }
    case CMD_FREE_ALL_ALLOCATIONS:
    {
        AEGIS2_FREE_ALL_ALLOCATIONS* cmd = (AEGIS2_FREE_ALL_ALLOCATIONS*)header;
        if (size) *size = cmd->bytes_freed;
        if (bytesTransferred) *bytesTransferred = cmd->freed_count;
        break;
    }
    case CMD_CREATE_THREAD:
    {
        AEGIS2_CREATE_THREAD* cmd = (AEGIS2_CREATE_THREAD*)header;
        if (address) *address = cmd->start_address;
        break;
    }
    default:
        break;
    }
}

static void RecordDiagnostic(AEGIS2_HEADER* header)
{
    if (!header)
        return;

    AEGIS2_DIAGNOSTIC_ENTRY entry = {};
    entry.sequence = (unsigned int)InterlockedIncrement(&g_DiagnosticSequence);
    entry.request_id = header->request_id;
    entry.command = header->command;
    entry.target_pid = header->target_pid;
    entry.status = header->status;
    entry.ntstatus = header->ntstatus;
    entry.reason = header->reason;
    ExtractDiagnosticFields(header, &entry.address, &entry.size, &entry.bytes_transferred);

    const ULONG index = (entry.sequence - 1) % AEGIS2_DIAGNOSTIC_ENTRY_COUNT;
    g_Diagnostics[index] = entry;

    if (header->status != STATUS_AEGIS_SUCCESS)
        g_LastError = entry;
}

static void CopyDiagnostics(AEGIS2_GET_DIAGNOSTICS* cmd)
{
    if (!cmd)
        return;

    const unsigned int newest = (unsigned int)InterlockedCompareExchange(&g_DiagnosticSequence, 0, 0);
    const unsigned int count = newest < AEGIS2_DIAGNOSTIC_ENTRY_COUNT ? newest : AEGIS2_DIAGNOSTIC_ENTRY_COUNT;
    const unsigned int first = newest >= count ? newest - count + 1 : 1;

    cmd->entry_count = count;
    cmd->newest_sequence = newest;
    cmd->last_error = g_LastError;
    RtlZeroMemory(cmd->entries, sizeof(cmd->entries));

    for (unsigned int i = 0; i < count; ++i)
    {
        const unsigned int sequence = first + i;
        const unsigned int index = (sequence - 1) % AEGIS2_DIAGNOSTIC_ENTRY_COUNT;
        cmd->entries[i] = g_Diagnostics[index];
    }
}

static unsigned int CopyStatusFromNtStatus(NTSTATUS status, SIZE_T requestedSize, SIZE_T bytesCopied, ULONG flags)
{
    if (bytesCopied == requestedSize && NT_SUCCESS(status))
        return STATUS_AEGIS_SUCCESS;

    if ((flags & AEGIS2_MEMORY_FAIL_ON_PARTIAL) != 0)
        return STATUS_AEGIS_FAILED;

    if (bytesCopied > 0 || NT_SUCCESS(status))
        return STATUS_AEGIS_PARTIAL_COPY;

    if (!NT_SUCCESS(status))
        return STATUS_AEGIS_FAILED;

    return STATUS_AEGIS_PARTIAL_COPY;
}

static NTSTATUS SafeMmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize)
{
    __try
    {
        return MmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess, TargetAddress, BufferSize, PreviousMode, ReturnSize);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        if (ReturnSize)
            *ReturnSize = 0;
        return GetExceptionCode();
    }
}

static BOOLEAN IsReadableProtection(ULONG protect)
{
    const ULONG baseProtect = protect & 0xFFu;
    return baseProtect == PAGE_READONLY ||
           baseProtect == PAGE_READWRITE ||
           baseProtect == PAGE_WRITECOPY ||
           baseProtect == PAGE_EXECUTE_READ ||
           baseProtect == PAGE_EXECUTE_READWRITE ||
           baseProtect == PAGE_EXECUTE_WRITECOPY;
}

static BOOLEAN IsWritableProtection(ULONG protect)
{
    const ULONG baseProtect = protect & 0xFFu;
    return baseProtect == PAGE_READWRITE ||
           baseProtect == PAGE_WRITECOPY ||
           baseProtect == PAGE_EXECUTE_READWRITE ||
           baseProtect == PAGE_EXECUTE_WRITECOPY;
}

static BOOLEAN RangeFitsRegion(ULONGLONG address, ULONGLONG size, const MEMORY_BASIC_INFORMATION* memoryInfo)
{
    if (!memoryInfo || size == 0)
        return FALSE;

    const ULONGLONG end = address + size;
    if (end < address)
        return FALSE;

    const ULONGLONG regionStart = (ULONGLONG)memoryInfo->BaseAddress;
    const ULONGLONG regionEnd = regionStart + (ULONGLONG)memoryInfo->RegionSize;
    if (regionEnd < regionStart)
        return FALSE;

    return address >= regionStart && end <= regionEnd;
}

static unsigned int QueryMemoryRegionForPid(
    ULONG pid,
    ULONGLONG address,
    MEMORY_BASIC_INFORMATION* memoryInfo,
    NTSTATUS* outNtStatus)
{
    if (outNtStatus) *outNtStatus = STATUS_SUCCESS;
    if (!memoryInfo || address == 0)
    {
        if (outNtStatus) *outNtStatus = STATUS_INVALID_PARAMETER;
        return AEGIS2_REASON_INVALID_PARAMETER;
    }

    RtlZeroMemory(memoryInfo, sizeof(*memoryInfo));

    HANDLE processHandle = NULL;
    CLIENT_ID clientId = {};
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    clientId.UniqueThread = NULL;

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    NTSTATUS status = ZwOpenProcess(&processHandle, 0x0400, &objAttr, &clientId); // PROCESS_QUERY_INFORMATION
    if (!NT_SUCCESS(status))
    {
        if (outNtStatus) *outNtStatus = status;
        return AEGIS2_REASON_OPEN_PROCESS_FAILED;
    }

    SIZE_T returnLength = 0;
    status = ZwQueryVirtualMemory(
        processHandle,
        (PVOID)(ULONG_PTR)address,
        MemoryBasicInformation,
        memoryInfo,
        sizeof(*memoryInfo),
        &returnLength);

    ZwClose(processHandle);

    if (outNtStatus) *outNtStatus = status;
    return NT_SUCCESS(status) ? AEGIS2_REASON_NONE : AEGIS2_REASON_QUERY_FAILED;
}

static unsigned int PreflightMemoryAccess(
    ULONG pid,
    ULONGLONG address,
    ULONGLONG size,
    ULONG flags,
    NTSTATUS* outNtStatus)
{
    if (outNtStatus) *outNtStatus = STATUS_SUCCESS;
    if (flags == 0)
        return AEGIS2_REASON_NONE;

    MEMORY_BASIC_INFORMATION memoryInfo = {};
    unsigned int reason = QueryMemoryRegionForPid(pid, address, &memoryInfo, outNtStatus);
    if (reason != AEGIS2_REASON_NONE)
        return reason;

    if (!RangeFitsRegion(address, size, &memoryInfo))
    {
        if (outNtStatus) *outNtStatus = STATUS_ACCESS_VIOLATION;
        return AEGIS2_REASON_MEMORY_RANGE_CROSSES_REGION;
    }

    if ((flags & AEGIS2_MEMORY_REQUIRE_COMMIT) != 0 && memoryInfo.State != MEM_COMMIT)
    {
        if (outNtStatus) *outNtStatus = STATUS_ACCESS_VIOLATION;
        return AEGIS2_REASON_MEMORY_NOT_COMMITTED;
    }

    if ((flags & AEGIS2_MEMORY_REJECT_GUARD) != 0 && (memoryInfo.Protect & PAGE_GUARD) != 0)
    {
        if (outNtStatus) *outNtStatus = STATUS_GUARD_PAGE_VIOLATION;
        return AEGIS2_REASON_MEMORY_GUARD_PAGE;
    }

    if ((flags & AEGIS2_MEMORY_REJECT_NOACCESS) != 0 && ((memoryInfo.Protect & 0xFFu) == PAGE_NOACCESS))
    {
        if (outNtStatus) *outNtStatus = STATUS_ACCESS_VIOLATION;
        return AEGIS2_REASON_MEMORY_NOACCESS;
    }

    if ((flags & AEGIS2_MEMORY_REQUIRE_READ) != 0 && !IsReadableProtection(memoryInfo.Protect))
    {
        if (outNtStatus) *outNtStatus = STATUS_ACCESS_VIOLATION;
        return AEGIS2_REASON_MEMORY_NOT_READABLE;
    }

    if ((flags & AEGIS2_MEMORY_REQUIRE_WRITE) != 0 && !IsWritableProtection(memoryInfo.Protect))
    {
        if (outNtStatus) *outNtStatus = STATUS_ACCESS_VIOLATION;
        return AEGIS2_REASON_MEMORY_NOT_WRITABLE;
    }

    return AEGIS2_REASON_NONE;
}

static ULONG CountActiveAllocations()
{
    ULONG count = 0;
    for (ULONG i = 0; i < AEGIS2_ALLOCATION_ENTRY_COUNT; ++i)
    {
        if (g_Allocations[i].address != 0)
            ++count;
    }
    return count;
}

static BOOLEAN AllocationIdentityMatches(const AEGIS2_ALLOCATION_ENTRY* entry, ULONG pid)
{
    if (!entry || entry->address == 0 || entry->process_id != pid)
        return FALSE;

    if (entry->start_key != 0 && g_TargetStartKey != 0)
        return entry->start_key == g_TargetStartKey;

    return entry->create_time != 0 && entry->create_time == g_TargetCreateTime;
}

static BOOLEAN FindTrackedAllocation(
    ULONG pid,
    ULONGLONG address,
    AEGIS2_ALLOCATION_ENTRY* outEntry,
    ULONG* outIndex)
{
    for (ULONG i = 0; i < AEGIS2_ALLOCATION_ENTRY_COUNT; ++i)
    {
        if (g_Allocations[i].address == address && AllocationIdentityMatches(&g_Allocations[i], pid))
        {
            if (outEntry)
                *outEntry = g_Allocations[i];
            if (outIndex)
                *outIndex = i;
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN TrackAllocation(ULONG pid, ULONGLONG address, ULONGLONG size, ULONG protect)
{
    if (pid == 0 || address == 0 || size == 0)
        return FALSE;

    ULONG slot = AEGIS2_ALLOCATION_ENTRY_COUNT;
    for (ULONG i = 0; i < AEGIS2_ALLOCATION_ENTRY_COUNT; ++i)
    {
        if (g_Allocations[i].address == address && AllocationIdentityMatches(&g_Allocations[i], pid))
        {
            slot = i;
            break;
        }

        if (slot == AEGIS2_ALLOCATION_ENTRY_COUNT && g_Allocations[i].address == 0)
            slot = i;
    }

    if (slot == AEGIS2_ALLOCATION_ENTRY_COUNT)
        return FALSE;

    g_Allocations[slot].address = address;
    g_Allocations[slot].size = size;
    g_Allocations[slot].protect = protect;
    g_Allocations[slot].process_id = pid;
    g_Allocations[slot].start_key = g_TargetStartKey;
    g_Allocations[slot].create_time = g_TargetCreateTime;
    return TRUE;
}

static void RemoveTrackedAllocationByIndex(ULONG index)
{
    if (index < AEGIS2_ALLOCATION_ENTRY_COUNT)
        RtlZeroMemory(&g_Allocations[index], sizeof(g_Allocations[index]));
}

static void CopyAllocationLedger(AEGIS2_GET_ALLOCATIONS* cmd)
{
    if (!cmd)
        return;

    const ULONG filterPid = cmd->header.target_pid;
    ULONG copied = 0;
    ULONG total = 0;
    RtlZeroMemory(cmd->entries, sizeof(cmd->entries));

    for (ULONG i = 0; i < AEGIS2_ALLOCATION_ENTRY_COUNT; ++i)
    {
        if (g_Allocations[i].address == 0)
            continue;

        if (filterPid != 0 && g_Allocations[i].process_id != filterPid)
            continue;

        ++total;
        if (copied < AEGIS2_ALLOCATION_ENTRY_COUNT)
            cmd->entries[copied++] = g_Allocations[i];
    }

    cmd->entry_count = copied;
    cmd->total_active_count = total;
}

static NTSTATUS FreeTrackedAllocationsForPid(
    ULONG pid,
    unsigned int* freedCount,
    unsigned int* failedCount,
    ULONGLONG* bytesFreed)
{
    if (freedCount) *freedCount = 0;
    if (failedCount) *failedCount = 0;
    if (bytesFreed) *bytesFreed = 0;

    HANDLE processHandle = NULL;
    CLIENT_ID clientId = {};
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    clientId.UniqueThread = NULL;

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    NTSTATUS status = ZwOpenProcess(&processHandle, PROCESS_ALL_ACCESS, &objAttr, &clientId);
    if (!NT_SUCCESS(status))
        return status;

    NTSTATUS finalStatus = STATUS_SUCCESS;
    for (ULONG i = 0; i < AEGIS2_ALLOCATION_ENTRY_COUNT; ++i)
    {
        AEGIS2_ALLOCATION_ENTRY entry = g_Allocations[i];
        if (!AllocationIdentityMatches(&entry, pid))
            continue;

        PVOID baseAddress = (PVOID)(ULONG_PTR)entry.address;
        SIZE_T regionSize = 0;
        status = ZwFreeVirtualMemory(processHandle, &baseAddress, &regionSize, MEM_RELEASE);
        if (NT_SUCCESS(status))
        {
            if (freedCount) ++(*freedCount);
            if (bytesFreed) *bytesFreed += entry.size;
            RemoveTrackedAllocationByIndex(i);
        }
        else
        {
            if (failedCount) ++(*failedCount);
            finalStatus = status;
        }
    }

    ZwClose(processHandle);
    return finalStatus;
}

static unsigned int HandleReadMemory(AEGIS2_COPY_MEMORY* cmd, NTSTATUS* outNtStatus)
{
    if (outNtStatus) *outNtStatus = STATUS_SUCCESS;
    if (cmd) cmd->bytes_transferred = 0;

    if (!IsValidCopyRequest(cmd))
    {
        SetCommandReason(cmd ? &cmd->header : NULL, AEGIS2_REASON_INVALID_PARAMETER);
        if (outNtStatus) *outNtStatus = STATUS_INVALID_PARAMETER;
        return STATUS_AEGIS_INVALID_PARAMETER;
    }

    const PVOID targetAddress = (PVOID)(ULONG_PTR)cmd->address;
    const SIZE_T requestedSize = cmd->size;
    const ULONG flags = cmd->flags ? cmd->flags : AEGIS2_DEFAULT_READ_FLAGS;

    PEPROCESS process = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    unsigned int targetStatus = ValidateBoundTargetForCommand(&cmd->header, &process, &status);
    if (targetStatus != STATUS_AEGIS_SUCCESS)
    {
        if (outNtStatus) *outNtStatus = status;
        return targetStatus;
    }

    unsigned int reason = PreflightMemoryAccess(cmd->header.target_pid, cmd->address, requestedSize, flags, &status);
    if (reason != AEGIS2_REASON_NONE)
    {
        ObDereferenceObject(process);
        SetCommandReason(&cmd->header, reason);
        if (outNtStatus) *outNtStatus = status;
        return STATUS_AEGIS_FAILED;
    }

    PVOID scratch = ExAllocatePool2(POOL_FLAG_NON_PAGED, requestedSize, AEGIS2_POOL_TAG);
    if (!scratch)
    {
        ObDereferenceObject(process);
        SetCommandReason(&cmd->header, AEGIS2_REASON_ALLOC_FAILED);
        if (outNtStatus) *outNtStatus = STATUS_INSUFFICIENT_RESOURCES;
        return STATUS_AEGIS_FAILED;
    }

    SIZE_T bytesCopied = 0;
    status = SafeMmCopyVirtualMemory(process, targetAddress, PsGetCurrentProcess(), scratch, requestedSize, KernelMode, &bytesCopied);

    if (bytesCopied > requestedSize)
        bytesCopied = requestedSize;

    cmd->bytes_transferred = (unsigned int)bytesCopied;

    if (bytesCopied > 0)
        RtlCopyMemory(cmd->data, scratch, bytesCopied);

    ObDereferenceObject(process);
    ExFreePoolWithTag(scratch, AEGIS2_POOL_TAG);
    if (outNtStatus) *outNtStatus = status;
    if (!NT_SUCCESS(status) || bytesCopied != requestedSize)
        SetCommandReason(&cmd->header, AEGIS2_REASON_COPY_FAILED);
    return CopyStatusFromNtStatus(status, requestedSize, bytesCopied, flags);
}

static unsigned int HandleWriteMemory(AEGIS2_COPY_MEMORY* cmd, NTSTATUS* outNtStatus)
{
    if (outNtStatus) *outNtStatus = STATUS_SUCCESS;
    if (cmd) cmd->bytes_transferred = 0;

    if (!IsValidCopyRequest(cmd))
    {
        SetCommandReason(cmd ? &cmd->header : NULL, AEGIS2_REASON_INVALID_PARAMETER);
        if (outNtStatus) *outNtStatus = STATUS_INVALID_PARAMETER;
        return STATUS_AEGIS_INVALID_PARAMETER;
    }

    const PVOID targetAddress = (PVOID)(ULONG_PTR)cmd->address;
    const SIZE_T requestedSize = cmd->size;
    const ULONG flags = cmd->flags ? cmd->flags : AEGIS2_DEFAULT_WRITE_FLAGS;

    PEPROCESS process = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    unsigned int targetStatus = ValidateBoundTargetForCommand(&cmd->header, &process, &status);
    if (targetStatus != STATUS_AEGIS_SUCCESS)
    {
        if (outNtStatus) *outNtStatus = status;
        return targetStatus;
    }

    unsigned int reason = PreflightMemoryAccess(cmd->header.target_pid, cmd->address, requestedSize, flags, &status);
    if (reason != AEGIS2_REASON_NONE)
    {
        ObDereferenceObject(process);
        SetCommandReason(&cmd->header, reason);
        if (outNtStatus) *outNtStatus = status;
        return STATUS_AEGIS_FAILED;
    }

    PVOID scratch = ExAllocatePool2(POOL_FLAG_NON_PAGED, requestedSize, AEGIS2_POOL_TAG);
    if (!scratch)
    {
        ObDereferenceObject(process);
        SetCommandReason(&cmd->header, AEGIS2_REASON_ALLOC_FAILED);
        if (outNtStatus) *outNtStatus = STATUS_INSUFFICIENT_RESOURCES;
        return STATUS_AEGIS_FAILED;
    }

    RtlCopyMemory(scratch, cmd->data, requestedSize);

    SIZE_T bytesCopied = 0;
    status = SafeMmCopyVirtualMemory(PsGetCurrentProcess(), scratch, process, targetAddress, requestedSize, KernelMode, &bytesCopied);

    if (bytesCopied > requestedSize)
        bytesCopied = requestedSize;

    cmd->bytes_transferred = (unsigned int)bytesCopied;

    ObDereferenceObject(process);
    ExFreePoolWithTag(scratch, AEGIS2_POOL_TAG);
    if (outNtStatus) *outNtStatus = status;
    if (!NT_SUCCESS(status) || bytesCopied != requestedSize)
        SetCommandReason(&cmd->header, AEGIS2_REASON_COPY_FAILED);
    return CopyStatusFromNtStatus(status, requestedSize, bytesCopied, flags);
}

static unsigned int LookupModuleInProcess(
    PEPROCESS process,
    const WCHAR* moduleName,
    AEGIS2_MODULE_INFORMATION* outInfo,
    NTSTATUS* outNtStatus)
{
    if (outNtStatus) *outNtStatus = STATUS_SUCCESS;

    if (!process || !outInfo || !moduleName)
    {
        if (outNtStatus) *outNtStatus = STATUS_INVALID_PARAMETER;
        return STATUS_AEGIS_INVALID_PARAMETER;
    }

    RtlZeroMemory(outInfo, sizeof(*outInfo));

    const SIZE_T nameLength = WideStringLengthChars(moduleName, AEGIS2_MODULE_NAME_CHARS);
    const BOOLEAN wantsExecutableImage = (nameLength == 0);
    UNICODE_STRING requestedName = {};
    if (!wantsExecutableImage)
    {
        requestedName.Buffer = (PWCH)moduleName;
        requestedName.Length = (USHORT)(nameLength * sizeof(WCHAR));
        requestedName.MaximumLength = requestedName.Length;
    }

    BOOLEAN found = FALSE;
    NTSTATUS status = STATUS_NOT_FOUND;
    KAPC_STATE apcState;

    KeStackAttachProcess(process, &apcState);
    __try
    {
        PAEGIS2_PEB peb = (PAEGIS2_PEB)PsGetProcessPeb(process);
        if (peb && peb->Ldr)
        {
            LIST_ENTRY* head = &peb->Ldr->InLoadOrderModuleList;
            LIST_ENTRY* link = head->Flink;
            ULONG visited = 0;

            while (link && link != head && visited++ < 1024)
            {
                PAEGIS2_LDR_DATA_TABLE_ENTRY entry =
                    CONTAINING_RECORD(link, AEGIS2_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

                if (entry->DllBase &&
                    (wantsExecutableImage ||
                     ModuleNameMatches(&entry->BaseDllName, &requestedName) ||
                     ModuleNameMatches(&entry->FullDllName, &requestedName)))
                {
                    outInfo->base_address = (ULONGLONG)entry->DllBase;
                    outInfo->size_of_image = entry->SizeOfImage;
                    found = TRUE;
                    status = STATUS_SUCCESS;
                    break;
                }

                link = link->Flink;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apcState);

    if (!found && wantsExecutableImage)
    {
        PVOID imageBase = PsGetProcessSectionBaseAddress(process);
        if (imageBase)
        {
            outInfo->base_address = (ULONGLONG)imageBase;
            outInfo->size_of_image = 0;
            found = TRUE;
            status = STATUS_SUCCESS;
        }
    }

    if (outNtStatus) *outNtStatus = status;

    if (found)
        return STATUS_AEGIS_SUCCESS;

    return status == STATUS_NOT_FOUND ? STATUS_AEGIS_NOT_FOUND : STATUS_AEGIS_FAILED;
}

static unsigned int HandleGetModuleInformation(AEGIS2_GET_MODULE_INFORMATION* cmd, NTSTATUS* outNtStatus)
{
    if (outNtStatus) *outNtStatus = STATUS_SUCCESS;

    if (!cmd || cmd->header.target_pid == 0)
    {
        SetCommandReason(cmd ? &cmd->header : NULL, AEGIS2_REASON_INVALID_PARAMETER);
        if (outNtStatus) *outNtStatus = STATUS_INVALID_PARAMETER;
        return STATUS_AEGIS_INVALID_PARAMETER;
    }

    WCHAR moduleName[AEGIS2_MODULE_NAME_CHARS] = {};
    RtlCopyMemory(moduleName, cmd->module_name, sizeof(moduleName));
    moduleName[AEGIS2_MODULE_NAME_CHARS - 1] = L'\0';
    RtlZeroMemory(&cmd->info, sizeof(cmd->info));

    PEPROCESS process = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    unsigned int targetStatus = ValidateBoundTargetForCommand(&cmd->header, &process, &status);
    if (targetStatus != STATUS_AEGIS_SUCCESS)
    {
        if (outNtStatus) *outNtStatus = status;
        return targetStatus;
    }

    unsigned int result = LookupModuleInProcess(process, moduleName, &cmd->info, &status);
    if (result != STATUS_AEGIS_SUCCESS)
        SetCommandReason(&cmd->header, result == STATUS_AEGIS_NOT_FOUND ?
            AEGIS2_REASON_MODULE_NOT_FOUND : AEGIS2_REASON_QUERY_FAILED);

    ObDereferenceObject(process);
    if (outNtStatus) *outNtStatus = status;
    return result;
}

static unsigned int HandleOpenProcess(AEGIS2_OPEN_PROCESS* cmd, NTSTATUS* outNtStatus)
{
    if (outNtStatus) *outNtStatus = STATUS_SUCCESS;

    if (!cmd || cmd->header.target_pid == 0)
    {
        SetCommandReason(cmd ? &cmd->header : NULL, AEGIS2_REASON_INVALID_PARAMETER);
        if (outNtStatus) *outNtStatus = STATUS_INVALID_PARAMETER;
        return STATUS_AEGIS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&cmd->info, sizeof(cmd->info));

    PEPROCESS process = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    unsigned int targetStatus = ValidateBoundTargetForCommand(&cmd->header, &process, &status);
    if (targetStatus != STATUS_AEGIS_SUCCESS)
    {
        if (outNtStatus) *outNtStatus = status;
        return targetStatus;
    }

    HANDLE processHandle = NULL;
    CLIENT_ID clientId = {};
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)cmd->header.target_pid;
    clientId.UniqueThread = NULL;

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    ACCESS_MASK desiredAccess = cmd->desired_access ? cmd->desired_access : 0x0400; // PROCESS_QUERY_INFORMATION
    status = ZwOpenProcess(&processHandle, desiredAccess, &objAttr, &clientId);
    if (!NT_SUCCESS(status))
    {
        SetCommandReason(&cmd->header, AEGIS2_REASON_OPEN_PROCESS_FAILED);
        ObDereferenceObject(process);
        if (outNtStatus) *outNtStatus = status;
        return STATUS_AEGIS_FAILED;
    }

    ZwClose(processHandle);

    FillProcessInformation(process, cmd->header.target_pid, &cmd->info);

    ObDereferenceObject(process);
    if (outNtStatus) *outNtStatus = STATUS_SUCCESS;
    return STATUS_AEGIS_SUCCESS;
}

static unsigned int HandleGetDriverInfo(AEGIS2_GET_DRIVER_INFO* cmd, NTSTATUS* outNtStatus)
{
    if (outNtStatus) *outNtStatus = STATUS_SUCCESS;

    if (!cmd)
    {
        if (outNtStatus) *outNtStatus = STATUS_INVALID_PARAMETER;
        return STATUS_AEGIS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&cmd->info, sizeof(cmd->info));
    cmd->info.protocol_magic = AEGIS2_PROTOCOL_MAGIC;
    cmd->info.protocol_version = AEGIS2_PROTOCOL_VERSION;
    cmd->info.shared_size = AEGIS2_SHARED_SIZE;
    cmd->info.header_size = sizeof(AEGIS2_HEADER);
    cmd->info.max_copy_size = AEGIS2_COPY_BUFFER_SIZE;
    cmd->info.pointer_size = sizeof(PVOID);
    cmd->info.supported_commands =
        AEGIS2_COMMAND_BIT(CMD_READ_MEMORY) |
        AEGIS2_COMMAND_BIT(CMD_WRITE_MEMORY) |
        AEGIS2_COMMAND_BIT(CMD_ALLOC_MEMORY) |
        AEGIS2_COMMAND_BIT(CMD_FREE_MEMORY) |
        AEGIS2_COMMAND_BIT(CMD_GET_MODULE_INFORMATION) |
        AEGIS2_COMMAND_BIT(CMD_OPEN_PROCESS) |
        AEGIS2_COMMAND_BIT(CMD_GET_DRIVER_INFO) |
        AEGIS2_COMMAND_BIT(CMD_QUERY_MEMORY) |
        AEGIS2_COMMAND_BIT(CMD_PROTECT_MEMORY) |
        AEGIS2_COMMAND_BIT(CMD_GET_DIAGNOSTICS) |
        AEGIS2_COMMAND_BIT(CMD_REGISTER_CLIENT) |
        AEGIS2_COMMAND_BIT(CMD_RELEASE_CLIENT) |
        AEGIS2_COMMAND_BIT(CMD_CLIENT_HEARTBEAT) |
        AEGIS2_COMMAND_BIT(CMD_BIND_TARGET) |
        AEGIS2_COMMAND_BIT(CMD_GET_ALLOCATIONS) |
        AEGIS2_COMMAND_BIT(CMD_PREPARE_UNLOAD) |
        AEGIS2_COMMAND_BIT(CMD_FREE_ALL_ALLOCATIONS);
    cmd->info.active_allocation_count = CountActiveAllocations();
    cmd->info.bound_target_pid = InterlockedCompareExchange(&g_TargetBound, 0, 0) ? g_TargetProcessId : 0;
    cmd->info.bound_target_start_key = cmd->info.bound_target_pid ? g_TargetStartKey : 0;
    cmd->info.bound_target_create_time = cmd->info.bound_target_pid ? g_TargetCreateTime : 0;

    static const char buildTimestamp[] = "v12 deterministic";
    const SIZE_T timestampBytes =
        (sizeof(buildTimestamp) - 1 < AEGIS2_BUILD_TEXT_CHARS - 1)
            ? sizeof(buildTimestamp) - 1
            : AEGIS2_BUILD_TEXT_CHARS - 1;
    RtlCopyMemory(cmd->info.build_timestamp, buildTimestamp, timestampBytes);
    cmd->info.build_timestamp[timestampBytes] = '\0';

    return STATUS_AEGIS_SUCCESS;
}

static unsigned int HandleQueryMemory(AEGIS2_QUERY_MEMORY* cmd, NTSTATUS* outNtStatus)
{
    if (outNtStatus) *outNtStatus = STATUS_SUCCESS;

    if (!cmd || cmd->header.target_pid == 0)
    {
        SetCommandReason(cmd ? &cmd->header : NULL, AEGIS2_REASON_INVALID_PARAMETER);
        if (outNtStatus) *outNtStatus = STATUS_INVALID_PARAMETER;
        return STATUS_AEGIS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&cmd->info, sizeof(cmd->info));

    PEPROCESS process = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    unsigned int targetStatus = ValidateBoundTargetForCommand(&cmd->header, &process, &status);
    if (targetStatus != STATUS_AEGIS_SUCCESS)
    {
        if (outNtStatus) *outNtStatus = status;
        return targetStatus;
    }

    HANDLE processHandle = NULL;
    CLIENT_ID clientId = {};
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)cmd->header.target_pid;
    clientId.UniqueThread = NULL;

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenProcess(&processHandle, 0x0400, &objAttr, &clientId); // PROCESS_QUERY_INFORMATION
    if (NT_SUCCESS(status))
    {
        MEMORY_BASIC_INFORMATION memoryInfo = {};
        SIZE_T returnLength = 0;
        status = ZwQueryVirtualMemory(
            processHandle,
            (PVOID)(ULONG_PTR)cmd->address,
            MemoryBasicInformation,
            &memoryInfo,
            sizeof(memoryInfo),
            &returnLength);

        if (NT_SUCCESS(status))
        {
            cmd->info.base_address = (ULONGLONG)memoryInfo.BaseAddress;
            cmd->info.allocation_base = (ULONGLONG)memoryInfo.AllocationBase;
            cmd->info.region_size = (ULONGLONG)memoryInfo.RegionSize;
            cmd->info.allocation_protect = memoryInfo.AllocationProtect;
            cmd->info.state = memoryInfo.State;
            cmd->info.protect = memoryInfo.Protect;
            cmd->info.type = memoryInfo.Type;
        }

        ZwClose(processHandle);
    }

    if (!NT_SUCCESS(status))
        SetCommandReason(&cmd->header, AEGIS2_REASON_QUERY_FAILED);

    ObDereferenceObject(process);
    if (outNtStatus) *outNtStatus = status;
    return NT_SUCCESS(status) ? STATUS_AEGIS_SUCCESS : STATUS_AEGIS_FAILED;
}

static unsigned int HandleProtectMemory(AEGIS2_PROTECT_MEMORY* cmd, NTSTATUS* outNtStatus)
{
    if (outNtStatus) *outNtStatus = STATUS_SUCCESS;

    if (!cmd || cmd->header.target_pid == 0 || cmd->address == 0 || cmd->size == 0)
    {
        SetCommandReason(cmd ? &cmd->header : NULL, AEGIS2_REASON_INVALID_PARAMETER);
        if (outNtStatus) *outNtStatus = STATUS_INVALID_PARAMETER;
        return STATUS_AEGIS_INVALID_PARAMETER;
    }

    cmd->old_protect = 0;
    const ULONG flags = cmd->flags ? cmd->flags : AEGIS2_DEFAULT_PROTECT_FLAGS;

    PEPROCESS process = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    unsigned int targetStatus = ValidateBoundTargetForCommand(&cmd->header, &process, &status);
    if (targetStatus != STATUS_AEGIS_SUCCESS)
    {
        if (outNtStatus) *outNtStatus = status;
        return targetStatus;
    }

    unsigned int reason = PreflightMemoryAccess(cmd->header.target_pid, cmd->address, cmd->size, flags, &status);
    if (reason != AEGIS2_REASON_NONE)
    {
        ObDereferenceObject(process);
        SetCommandReason(&cmd->header, reason);
        if (outNtStatus) *outNtStatus = status;
        return STATUS_AEGIS_FAILED;
    }

    HANDLE processHandle = NULL;
    CLIENT_ID clientId = {};
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)cmd->header.target_pid;
    clientId.UniqueThread = NULL;

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenProcess(&processHandle, PROCESS_ALL_ACCESS, &objAttr, &clientId);
    if (NT_SUCCESS(status))
    {
        PVOID baseAddress = (PVOID)(ULONG_PTR)cmd->address;
        SIZE_T regionSize = (SIZE_T)cmd->size;
        ULONG oldProtect = 0;

        status = ZwProtectVirtualMemory(processHandle, &baseAddress, &regionSize, cmd->new_protect, &oldProtect);
        if (NT_SUCCESS(status))
            cmd->old_protect = oldProtect;

        ZwClose(processHandle);
    }

    if (!NT_SUCCESS(status))
        SetCommandReason(&cmd->header, AEGIS2_REASON_PROTECT_FAILED);

    ObDereferenceObject(process);
    if (outNtStatus) *outNtStatus = status;
    return NT_SUCCESS(status) ? STATUS_AEGIS_SUCCESS : STATUS_AEGIS_FAILED;
}

static unsigned int HandleGetDiagnostics(AEGIS2_GET_DIAGNOSTICS* cmd, NTSTATUS* outNtStatus)
{
    if (outNtStatus) *outNtStatus = STATUS_SUCCESS;

    if (!cmd)
    {
        if (outNtStatus) *outNtStatus = STATUS_INVALID_PARAMETER;
        return STATUS_AEGIS_INVALID_PARAMETER;
    }

    CopyDiagnostics(cmd);
    return STATUS_AEGIS_SUCCESS;
}

static unsigned int HandleGetAllocations(AEGIS2_GET_ALLOCATIONS* cmd, NTSTATUS* outNtStatus)
{
    if (outNtStatus) *outNtStatus = STATUS_SUCCESS;

    if (!cmd)
    {
        if (outNtStatus) *outNtStatus = STATUS_INVALID_PARAMETER;
        return STATUS_AEGIS_INVALID_PARAMETER;
    }

    CopyAllocationLedger(cmd);
    return STATUS_AEGIS_SUCCESS;
}

static unsigned int HandleFreeAllAllocations(AEGIS2_FREE_ALL_ALLOCATIONS* cmd, NTSTATUS* outNtStatus)
{
    if (outNtStatus) *outNtStatus = STATUS_SUCCESS;

    if (!cmd || cmd->header.target_pid == 0)
    {
        SetCommandReason(cmd ? &cmd->header : NULL, AEGIS2_REASON_INVALID_PARAMETER);
        if (outNtStatus) *outNtStatus = STATUS_INVALID_PARAMETER;
        return STATUS_AEGIS_INVALID_PARAMETER;
    }

    cmd->freed_count = 0;
    cmd->failed_count = 0;
    cmd->bytes_freed = 0;

    PEPROCESS process = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    unsigned int targetStatus = ValidateBoundTargetForCommand(&cmd->header, &process, &status);
    if (targetStatus != STATUS_AEGIS_SUCCESS)
    {
        if (outNtStatus) *outNtStatus = status;
        return targetStatus;
    }
    ObDereferenceObject(process);

    status = FreeTrackedAllocationsForPid(
        cmd->header.target_pid,
        &cmd->freed_count,
        &cmd->failed_count,
        &cmd->bytes_freed);

    if (outNtStatus) *outNtStatus = status;
    if (!NT_SUCCESS(status) || cmd->failed_count != 0)
    {
        SetCommandReason(&cmd->header, AEGIS2_REASON_FREE_ALL_FAILED);
        return STATUS_AEGIS_FAILED;
    }

    return STATUS_AEGIS_SUCCESS;
}

static unsigned int HandlePrepareUnload(AEGIS2_PREPARE_UNLOAD* cmd, NTSTATUS* outNtStatus)
{
    if (outNtStatus) *outNtStatus = STATUS_SUCCESS;

    if (!cmd)
    {
        if (outNtStatus) *outNtStatus = STATUS_INVALID_PARAMETER;
        return STATUS_AEGIS_INVALID_PARAMETER;
    }

    cmd->active_allocation_count = CountActiveAllocations();
    cmd->target_bound = InterlockedCompareExchange(&g_TargetBound, 0, 0) ? 1u : 0u;

    InterlockedExchange(&g_AcceptingCommands, 0);
    ClearOwner();

    cmd->accepting_commands = 0;
    return STATUS_AEGIS_SUCCESS;
}

// APC execution kernel routine
VOID ApcKernelRoutine(
    _In_ PRKAPC Apc,
    _Inout_opt_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_opt_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
)
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    ExFreePoolWithTag(Apc, 'CpaA');
}

// CMD_CREATE_THREAD is intentionally not implemented in this shared-memory backend.
// Returning success here would make user mode report a thread creation that never happened.
NTSTATUS HandleCreateThread(AEGIS2_CREATE_THREAD* cmd)
{
    UNREFERENCED_PARAMETER(cmd);
    return STATUS_AEGIS_FAILED;
}

// Worker thread that polls the shared memory
VOID WorkerThread(PVOID StartContext)
{
    UNREFERENCED_PARAMETER(StartContext);

    while (!IsDriverUnloading())
    {
        // Wait for a request
        NTSTATUS status = KeWaitForSingleObject(g_RequestEvent, Executive, KernelMode, FALSE, NULL);
        if (IsDriverUnloading()) break;
        if (status != STATUS_WAIT_0) continue;

        if (!g_SharedMemory)
        {
            KeSetEvent(g_CompletionEvent, 0, FALSE);
            continue;
        }

        AEGIS2_HEADER* header = (AEGIS2_HEADER*)g_SharedMemory;
        header->ntstatus = STATUS_SUCCESS;
        header->reason = AEGIS2_REASON_NONE;
        header->completed_id = 0;

        if (header->magic != AEGIS2_PROTOCOL_MAGIC || header->version != AEGIS2_PROTOCOL_VERSION)
        {
            header->status = STATUS_AEGIS_INVALID_PARAMETER;
            header->ntstatus = STATUS_INVALID_PARAMETER;
            header->reason = AEGIS2_REASON_BAD_PROTOCOL;
            header->completed_id = header->request_id;
            header->command = CMD_NONE;
            KeClearEvent(g_RequestEvent);
            KeSetEvent(g_CompletionEvent, 0, FALSE);
            continue;
        }

        const BOOLEAN unloadPrepared = !IsAcceptingCommands();
        if (unloadPrepared && !IsCommandAllowedAfterPrepareUnload(header->command))
        {
            header->status = STATUS_AEGIS_SHUTTING_DOWN;
            header->ntstatus = STATUS_DELETE_PENDING;
            header->reason = AEGIS2_REASON_DRIVER_SHUTTING_DOWN;
            RecordDiagnostic(header);
            header->completed_id = header->request_id;
            header->command = CMD_NONE;
            KeClearEvent(g_RequestEvent);
            KeSetEvent(g_CompletionEvent, 0, FALSE);
            continue;
        }

        if (!unloadPrepared && !IsAuthorizedCommand(header))
        {
            header->status = STATUS_AEGIS_ACCESS_DENIED;
            header->ntstatus = STATUS_ACCESS_DENIED;
            header->reason = AEGIS2_REASON_UNAUTHORIZED_CLIENT;
            RecordDiagnostic(header);
            header->completed_id = header->request_id;
            header->command = CMD_NONE;
            KeClearEvent(g_RequestEvent);
            KeSetEvent(g_CompletionEvent, 0, FALSE);
            continue;
        }
        
        if (header->command == CMD_REGISTER_CLIENT)
        {
            AEGIS2_REGISTER_CLIENT* cmd = (AEGIS2_REGISTER_CLIENT*)g_SharedMemory;
            NTSTATUS commandStatus = STATUS_SUCCESS;
            header->status = HandleRegisterClient(cmd, &commandStatus);
            header->ntstatus = commandStatus;
        }
        else if (header->command == CMD_RELEASE_CLIENT)
        {
            AEGIS2_CLIENT_CONTROL* cmd = (AEGIS2_CLIENT_CONTROL*)g_SharedMemory;
            NTSTATUS commandStatus = STATUS_SUCCESS;
            header->status = HandleReleaseClient(cmd, &commandStatus);
            header->ntstatus = commandStatus;
        }
        else if (header->command == CMD_CLIENT_HEARTBEAT)
        {
            AEGIS2_CLIENT_CONTROL* cmd = (AEGIS2_CLIENT_CONTROL*)g_SharedMemory;
            NTSTATUS commandStatus = STATUS_SUCCESS;
            header->status = HandleClientHeartbeat(cmd, &commandStatus);
            header->ntstatus = commandStatus;
        }
        else if (header->command == CMD_BIND_TARGET)
        {
            AEGIS2_TARGET_CONTROL* cmd = (AEGIS2_TARGET_CONTROL*)g_SharedMemory;
            NTSTATUS commandStatus = STATUS_SUCCESS;
            header->status = HandleBindTarget(cmd, &commandStatus);
            header->ntstatus = commandStatus;
        }
        else if (header->command == CMD_PREPARE_UNLOAD)
        {
            AEGIS2_PREPARE_UNLOAD* cmd = (AEGIS2_PREPARE_UNLOAD*)g_SharedMemory;
            NTSTATUS commandStatus = STATUS_SUCCESS;
            header->status = HandlePrepareUnload(cmd, &commandStatus);
            header->ntstatus = commandStatus;
        }
        else if (header->command == CMD_PING)
        {
            header->status = STATUS_AEGIS_SUCCESS;
            header->ntstatus = STATUS_SUCCESS;
        }
        else if (header->command == CMD_READ_MEMORY)
        {
            AEGIS2_COPY_MEMORY* cmd = (AEGIS2_COPY_MEMORY*)g_SharedMemory;
            NTSTATUS commandStatus = STATUS_SUCCESS;
            header->status = HandleReadMemory(cmd, &commandStatus);
            header->ntstatus = commandStatus;
        }
        else if (header->command == CMD_WRITE_MEMORY)
        {
            AEGIS2_COPY_MEMORY* cmd = (AEGIS2_COPY_MEMORY*)g_SharedMemory;
            NTSTATUS commandStatus = STATUS_SUCCESS;
            header->status = HandleWriteMemory(cmd, &commandStatus);
            header->ntstatus = commandStatus;
        }
        else if (header->command == CMD_ALLOC_MEMORY)
        {
            AEGIS2_ALLOC_MEMORY* cmd = (AEGIS2_ALLOC_MEMORY*)g_SharedMemory;
            if (cmd->size == 0 || header->target_pid == 0)
            {
                header->status = STATUS_AEGIS_INVALID_PARAMETER;
                header->ntstatus = STATUS_INVALID_PARAMETER;
                header->reason = AEGIS2_REASON_INVALID_PARAMETER;
            }
            else
            {
                PEPROCESS Process = NULL;
                NTSTATUS validationStatus = STATUS_SUCCESS;
                header->status = ValidateBoundTargetForCommand(header, &Process, &validationStatus);
                header->ntstatus = validationStatus;
                if (header->status == STATUS_AEGIS_SUCCESS)
                {
                    SIZE_T RegionSize = cmd->size;
                    ULONG Protect = cmd->protect;
                    PVOID BaseAddress = NULL;

                    HANDLE hProcess = NULL;
                    CLIENT_ID clientId;
                    clientId.UniqueProcess = (HANDLE)header->target_pid;
                    clientId.UniqueThread = NULL;
                    OBJECT_ATTRIBUTES objAttr;
                    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
                
                    NTSTATUS allocStatus = STATUS_UNSUCCESSFUL;
                    NTSTATUS openStatus = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId);
                    if (NT_SUCCESS(openStatus))
                    {
                        allocStatus = ZwAllocateVirtualMemory(hProcess, &BaseAddress, 0, &RegionSize, MEM_COMMIT | MEM_RESERVE, Protect);
                        if (NT_SUCCESS(allocStatus) &&
                            !TrackAllocation(header->target_pid, (ULONGLONG)BaseAddress, (ULONGLONG)RegionSize, Protect))
                        {
                            SIZE_T freeSize = 0;
                            PVOID freeBase = BaseAddress;
                            ZwFreeVirtualMemory(hProcess, &freeBase, &freeSize, MEM_RELEASE);
                            BaseAddress = NULL;
                            allocStatus = STATUS_INSUFFICIENT_RESOURCES;
                            header->reason = AEGIS2_REASON_ALLOCATION_LEDGER_FULL;
                        }
                        ZwClose(hProcess);
                    }
                    else
                    {
                        allocStatus = openStatus;
                        header->reason = AEGIS2_REASON_OPEN_PROCESS_FAILED;
                    }
                
                    if (NT_SUCCESS(allocStatus))
                    {
                        cmd->out_address = (ULONGLONG)BaseAddress;
                        cmd->size = (unsigned int)RegionSize;
                        header->status = STATUS_AEGIS_SUCCESS;
                        header->ntstatus = STATUS_SUCCESS;
                    }
                    else
                    {
                        header->status = STATUS_AEGIS_FAILED;
                        header->ntstatus = allocStatus;
                        if (header->reason == AEGIS2_REASON_NONE)
                            header->reason = AEGIS2_REASON_ALLOC_FAILED;
                    }
                
                    ObDereferenceObject(Process);
                }
            }
        }
        else if (header->command == CMD_FREE_MEMORY)
        {
            AEGIS2_FREE_MEMORY* cmd = (AEGIS2_FREE_MEMORY*)g_SharedMemory;
            if (cmd->address == 0 || header->target_pid == 0)
            {
                header->status = STATUS_AEGIS_INVALID_PARAMETER;
                header->ntstatus = STATUS_INVALID_PARAMETER;
                header->reason = AEGIS2_REASON_INVALID_PARAMETER;
            }
            else
            {
                PEPROCESS Process = NULL;
                NTSTATUS validationStatus = STATUS_SUCCESS;
                header->status = ValidateBoundTargetForCommand(header, &Process, &validationStatus);
                header->ntstatus = validationStatus;
                if (header->status == STATUS_AEGIS_SUCCESS)
                {
                    PVOID BaseAddress = (PVOID)cmd->address;
                    SIZE_T RegionSize = 0; // Must be 0 for MEM_RELEASE
                    AEGIS2_ALLOCATION_ENTRY trackedAllocation = {};
                    ULONG trackedIndex = 0;
                    const BOOLEAN hasTrackedAllocation =
                        FindTrackedAllocation(header->target_pid, cmd->address, &trackedAllocation, &trackedIndex);

                    if ((cmd->flags & AEGIS2_FREE_REQUIRE_DRIVER_ALLOCATION) != 0 && !hasTrackedAllocation)
                    {
                        header->status = STATUS_AEGIS_ACCESS_DENIED;
                        header->ntstatus = STATUS_ACCESS_DENIED;
                        header->reason = AEGIS2_REASON_ALLOCATION_NOT_TRACKED;
                        ObDereferenceObject(Process);
                        RecordDiagnostic(header);
                        header->completed_id = header->request_id;
                        header->command = CMD_NONE;
                        KeClearEvent(g_RequestEvent);
                        KeSetEvent(g_CompletionEvent, 0, FALSE);
                        continue;
                    }

                    HANDLE hProcess = NULL;
                    CLIENT_ID clientId;
                    clientId.UniqueProcess = (HANDLE)header->target_pid;
                    clientId.UniqueThread = NULL;
                    OBJECT_ATTRIBUTES objAttr;
                    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
                
                    NTSTATUS freeStatus = STATUS_UNSUCCESSFUL;
                    NTSTATUS openStatus = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId);
                    if (NT_SUCCESS(openStatus))
                    {
                        freeStatus = ZwFreeVirtualMemory(hProcess, &BaseAddress, &RegionSize, MEM_RELEASE);
                        if (NT_SUCCESS(freeStatus) && hasTrackedAllocation)
                            RemoveTrackedAllocationByIndex(trackedIndex);
                        ZwClose(hProcess);
                    }
                    else
                    {
                        freeStatus = openStatus;
                        header->reason = AEGIS2_REASON_OPEN_PROCESS_FAILED;
                    }
                
                    if (NT_SUCCESS(freeStatus))
                    {
                        header->status = STATUS_AEGIS_SUCCESS;
                        header->ntstatus = STATUS_SUCCESS;
                    }
                    else
                    {
                        header->status = STATUS_AEGIS_FAILED;
                        header->ntstatus = freeStatus;
                        if (header->reason == AEGIS2_REASON_NONE)
                            header->reason = AEGIS2_REASON_FREE_FAILED;
                    }
                
                    ObDereferenceObject(Process);
                }
            }
        }
        else if (header->command == CMD_GET_MODULE_INFORMATION)
        {
            AEGIS2_GET_MODULE_INFORMATION* cmd = (AEGIS2_GET_MODULE_INFORMATION*)g_SharedMemory;
            NTSTATUS commandStatus = STATUS_SUCCESS;
            header->status = HandleGetModuleInformation(cmd, &commandStatus);
            header->ntstatus = commandStatus;
        }
        else if (header->command == CMD_OPEN_PROCESS)
        {
            AEGIS2_OPEN_PROCESS* cmd = (AEGIS2_OPEN_PROCESS*)g_SharedMemory;
            NTSTATUS commandStatus = STATUS_SUCCESS;
            header->status = HandleOpenProcess(cmd, &commandStatus);
            header->ntstatus = commandStatus;
        }
        else if (header->command == CMD_GET_DRIVER_INFO)
        {
            AEGIS2_GET_DRIVER_INFO* cmd = (AEGIS2_GET_DRIVER_INFO*)g_SharedMemory;
            NTSTATUS commandStatus = STATUS_SUCCESS;
            header->status = HandleGetDriverInfo(cmd, &commandStatus);
            header->ntstatus = commandStatus;
        }
        else if (header->command == CMD_QUERY_MEMORY)
        {
            AEGIS2_QUERY_MEMORY* cmd = (AEGIS2_QUERY_MEMORY*)g_SharedMemory;
            NTSTATUS commandStatus = STATUS_SUCCESS;
            header->status = HandleQueryMemory(cmd, &commandStatus);
            header->ntstatus = commandStatus;
        }
        else if (header->command == CMD_PROTECT_MEMORY)
        {
            AEGIS2_PROTECT_MEMORY* cmd = (AEGIS2_PROTECT_MEMORY*)g_SharedMemory;
            NTSTATUS commandStatus = STATUS_SUCCESS;
            header->status = HandleProtectMemory(cmd, &commandStatus);
            header->ntstatus = commandStatus;
        }
        else if (header->command == CMD_GET_DIAGNOSTICS)
        {
            AEGIS2_GET_DIAGNOSTICS* cmd = (AEGIS2_GET_DIAGNOSTICS*)g_SharedMemory;
            NTSTATUS commandStatus = STATUS_SUCCESS;
            header->status = HandleGetDiagnostics(cmd, &commandStatus);
            header->ntstatus = commandStatus;
        }
        else if (header->command == CMD_GET_ALLOCATIONS)
        {
            AEGIS2_GET_ALLOCATIONS* cmd = (AEGIS2_GET_ALLOCATIONS*)g_SharedMemory;
            NTSTATUS commandStatus = STATUS_SUCCESS;
            header->status = HandleGetAllocations(cmd, &commandStatus);
            header->ntstatus = commandStatus;
        }
        else if (header->command == CMD_FREE_ALL_ALLOCATIONS)
        {
            AEGIS2_FREE_ALL_ALLOCATIONS* cmd = (AEGIS2_FREE_ALL_ALLOCATIONS*)g_SharedMemory;
            NTSTATUS commandStatus = STATUS_SUCCESS;
            header->status = HandleFreeAllAllocations(cmd, &commandStatus);
            header->ntstatus = commandStatus;
        }
        else if (header->command == CMD_CREATE_THREAD)
        {
            AEGIS2_CREATE_THREAD* cmd = (AEGIS2_CREATE_THREAD*)g_SharedMemory;
            header->status = HandleCreateThread(cmd);
            header->ntstatus = STATUS_NOT_IMPLEMENTED;
            header->reason = AEGIS2_REASON_NOT_IMPLEMENTED;
        }
        else
        {
            header->status = STATUS_AEGIS_INVALID_CMD;
            header->ntstatus = STATUS_INVALID_DEVICE_REQUEST;
            header->reason = AEGIS2_REASON_INVALID_PARAMETER;
        }

        // Reset command and signal completion
        RecordDiagnostic(header);
        header->completed_id = header->request_id;
        header->command = CMD_NONE;
        KeClearEvent(g_RequestEvent);
        KeSetEvent(g_CompletionEvent, 0, FALSE);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

// Cleanup resources
VOID CleanupResources()
{
    InterlockedExchange(&g_DriverUnloading, 1);
    ClearOwner();

    if (g_RequestEvent) KeSetEvent(g_RequestEvent, 0, FALSE); // Wake thread

    if (g_WorkerThreadObject)
    {
        KeWaitForSingleObject(g_WorkerThreadObject, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(g_WorkerThreadObject);
        g_WorkerThreadObject = NULL;
    }

    if (g_SharedMemory)
    {
        MmUnmapViewInSystemSpace(g_SharedMemory);
        g_SharedMemory = NULL;
    }

    if (g_SectionObject)
    {
        ObDereferenceObject(g_SectionObject);
        g_SectionObject = NULL;
    }

    if (g_ReqEventHandle)
    {
        if (g_RequestEvent)
        {
            ObDereferenceObject(g_RequestEvent);
            g_RequestEvent = NULL;
        }

        ZwClose(g_ReqEventHandle);
        g_ReqEventHandle = NULL;
    }

    if (g_CompEventHandle)
    {
        if (g_CompletionEvent)
        {
            ObDereferenceObject(g_CompletionEvent);
            g_CompletionEvent = NULL;
        }

        ZwClose(g_CompEventHandle);
        g_CompEventHandle = NULL;
    }

    if (g_SectionHandle)
    {
        ZwClose(g_SectionHandle);
        g_SectionHandle = NULL;
    }
}

extern "C" VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    CleanupResources();
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    if (DriverObject)
        DriverObject->DriverUnload = DriverUnload;

    InterlockedExchange(&g_DriverUnloading, 0);
    InterlockedExchange(&g_AcceptingCommands, 1);

    NTSTATUS status;
    UNICODE_STRING sectionName, reqEventName, compEventName;
    OBJECT_ATTRIBUTES objAttrSection, objAttrReq, objAttrComp;
    LARGE_INTEGER sectionSize;
    SECURITY_DESCRIPTOR securityDescriptor;
    UCHAR securityAclBuffer[512] = {};
    PACL securityAcl = (PACL)securityAclBuffer;

    status = InitializeRestrictedSecurityDescriptor(&securityDescriptor, securityAcl, sizeof(securityAclBuffer));
    if (!NT_SUCCESS(status)) return status;

    RtlInitUnicodeString(&sectionName, AEGIS2_SECTION_NAME);
    RtlInitUnicodeString(&reqEventName, AEGIS2_REQUEST_EVENT);
    RtlInitUnicodeString(&compEventName, AEGIS2_COMPLETION_EVENT);

    InitializeObjectAttributes(&objAttrSection, &sectionName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &securityDescriptor);
    InitializeObjectAttributes(&objAttrReq, &reqEventName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &securityDescriptor);
    InitializeObjectAttributes(&objAttrComp, &compEventName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &securityDescriptor);

    // Create shared memory section
    sectionSize.QuadPart = AEGIS2_SHARED_SIZE;
    status = ZwCreateSection(&g_SectionHandle, SECTION_ALL_ACCESS, &objAttrSection, &sectionSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(status)) return status;

    PVOID viewBase = NULL;
    SIZE_T viewSize = AEGIS2_SHARED_SIZE;
    status = ObReferenceObjectByHandle(g_SectionHandle, SECTION_ALL_ACCESS, NULL, KernelMode, &g_SectionObject, NULL);
    if (!NT_SUCCESS(status))
    {
        ZwClose(g_SectionHandle);
        g_SectionHandle = NULL;
        return status;
    }

    status = MmMapViewInSystemSpace(g_SectionObject, &viewBase, &viewSize);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(g_SectionObject);
        g_SectionObject = NULL;
        ZwClose(g_SectionHandle);
        g_SectionHandle = NULL;
        return status;
    }

    g_SharedMemory = viewBase;
    RtlZeroMemory(g_SharedMemory, AEGIS2_SHARED_SIZE);

    // Create events (named events for usermode communication)
    status = ZwCreateEvent(&g_ReqEventHandle, EVENT_ALL_ACCESS, &objAttrReq, NotificationEvent, FALSE);
    if (!NT_SUCCESS(status))
    {
        CleanupResources();
        return status;
    }

    status = ObReferenceObjectByHandle(g_ReqEventHandle, EVENT_ALL_ACCESS, NULL, KernelMode, (PVOID*)&g_RequestEvent, NULL);
    if (!NT_SUCCESS(status))
    {
        CleanupResources();
        return status;
    }

    status = ZwCreateEvent(&g_CompEventHandle, EVENT_ALL_ACCESS, &objAttrComp, NotificationEvent, FALSE);
    if (!NT_SUCCESS(status))
    {
        CleanupResources();
        return status;
    }

    status = ObReferenceObjectByHandle(g_CompEventHandle, EVENT_ALL_ACCESS, NULL, KernelMode, (PVOID*)&g_CompletionEvent, NULL);
    if (!NT_SUCCESS(status))
    {
        CleanupResources();
        return status;
    }

    if (!g_RequestEvent || !g_CompletionEvent)
    {
        CleanupResources();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeClearEvent(g_RequestEvent);
    KeClearEvent(g_CompletionEvent);

    // Start worker thread
    HANDLE threadHandle;
    status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, WorkerThread, NULL);
    if (NT_SUCCESS(status))
    {
        status = ObReferenceObjectByHandle(threadHandle, THREAD_ALL_ACCESS, NULL, KernelMode, &g_WorkerThreadObject, NULL);
        if (!NT_SUCCESS(status))
        {
            InterlockedExchange(&g_DriverUnloading, 1);
            KeSetEvent(g_RequestEvent, 0, FALSE);
            ZwWaitForSingleObject(threadHandle, FALSE, NULL);
            ZwClose(threadHandle);
            CleanupResources();
            return status;
        }
        ZwClose(threadHandle);
    }
    else
    {
        CleanupResources();
        return status;
    }

    return STATUS_SUCCESS;
}
