#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <sddl.h>
#include <mmsystem.h>
#include <dsound.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "bcrypt.lib")

static const wchar_t* kGameName = L"Dead Space.exe";
static const wchar_t* kBypass = L"DEADSPACE4GB_BYPASS";
static const wchar_t* kRequestEnvironment = L"DEADSPACE4GB_REQUEST";
static const wchar_t* kRequestHandleEnvironment = L"DEADSPACE4GB_REQUEST_HANDLE";
static const wchar_t* kReadyEnvironment = L"DEADSPACE4GB_READY_EVENT";
static const wchar_t* kCommitEnvironment = L"DEADSPACE4GB_COMMIT_EVENT";
static const wchar_t* kCancelEnvironment = L"DEADSPACE4GB_CANCEL_EVENT";
static const wchar_t* kAckEnvironment = L"DEADSPACE4GB_ACK_EVENT";
static const wchar_t* kGoEnvironment = L"DEADSPACE4GB_GO_EVENT";
static const wchar_t* kElevatedWorkerEnvironment = L"DEADSPACE4GB_ELEVATED_WORKER";
static const wchar_t* kStateOverride = L"DEADSPACE4GB_STATE_DIRECTORY";
static HMODULE g_self = NULL;
static HMODULE g_real = NULL;
static volatile LONG g_once = 0;
static volatile LONG g_bootstrapBlocked = 0;
// rundll32 loads this DLL in a separate process for the narrow elevated patch
// callback.  Set this before doing any callback work and never clear it in that
// process: logging must fail closed for the full lifetime of the elevated role.
static volatile LONG g_elevatedRole = 0;
static volatile LONG g_logFilesystemAttempts = 0;
static volatile LONG g_elevatedLogCallsSuppressed = 0;
static INIT_ONCE g_dsoundInit = INIT_ONCE_STATIC_INIT;

// The elevated rundll32 process is the authenticated completion channel.  The
// medium-integrity worker retains its exact process HANDLE and accepts success
// only when that process exits with this deliberately unusual status.  No
// user-writable file or named event is trusted as an elevation result.
static const DWORD kElevatedSuccessExitCode = 0xD54A4A01;
static const DWORD kElevatedFailureExitCode = 0xD54A4AFF;
// Kept below MAXLONG so cmd.exe reports the same decimal value on every
// supported Windows version.  Restore.cmd trusts only this process exit status
// and then independently compares target/backup bytes and manifest removal.
static const DWORD kRestoreSuccessExitCode = 0x4D534701;
static const DWORD kRestoreFailureExitCode = 0x4D5347FF;

#define DSOUND_EXPORTS(X) \
    X(DirectSoundCaptureCreate) X(DirectSoundCaptureCreate8) \
    X(DirectSoundCaptureEnumerateA) X(DirectSoundCaptureEnumerateW) \
    X(DirectSoundCreate) X(DirectSoundCreate8) \
    X(DirectSoundEnumerateA) X(DirectSoundEnumerateW) \
    X(DirectSoundFullDuplexCreate) X(DllCanUnloadNow) X(DllGetClassObject) X(GetDeviceID)

#define PTR(name) extern "C" FARPROC g_##name = NULL;
DSOUND_EXPORTS(PTR)

static const wchar_t* BaseName(const wchar_t* path)
{
    const wchar_t* result = path;
    for (const wchar_t* p = path; *p; ++p) if (*p == L'\\' || *p == L'/') result = p + 1;
    return result;
}

static bool Join(wchar_t* out, DWORD cap, const wchar_t* left, const wchar_t* right)
{
    int n = _snwprintf_s(out, cap, _TRUNCATE, L"%s%s%s", left,
        (*left && left[wcslen(left) - 1] != L'\\') ? L"\\" : L"", right);
    return n >= 0;
}

static bool X86Rundll32(wchar_t* output, DWORD capacity)
{
    wchar_t system[4096];
    UINT length = GetSystemWow64DirectoryW(system, ARRAYSIZE(system));
    if (!length || length >= ARRAYSIZE(system)) length = GetSystemDirectoryW(system, ARRAYSIZE(system));
    return length && length < ARRAYSIZE(system) && Join(output, capacity, system, L"rundll32.exe");
}

static bool StateDirectory(wchar_t* out, DWORD cap)
{
    DWORD n = GetEnvironmentVariableW(kStateOverride, out, cap);
    if (n && n < cap) return true;
    n = GetEnvironmentVariableW(L"LOCALAPPDATA", out, cap);
    if (!n || n >= cap) n = GetTempPathW(cap, out);
    if (!n || n >= cap) return false;
    wchar_t tmp[4096];
    if (!Join(tmp, ARRAYSIZE(tmp), out, L"DeadSpace4GBMod")) return false;
    return wcscpy_s(out, cap, tmp) == 0;
}

static void Log(const wchar_t* text)
{
    // This check must remain before StateDirectory, path construction, directory
    // creation, and CreateFile.  Elevated patch helpers call Log too; none of
    // those calls may resolve or open a user-controlled log path across UAC.
    if (InterlockedCompareExchange(&g_elevatedRole, 0, 0))
    {
        InterlockedIncrement(&g_elevatedLogCallsSuppressed);
        return;
    }
    InterlockedIncrement(&g_logFilesystemAttempts);
    wchar_t dir[4096], path[4096];
    if (!StateDirectory(dir, ARRAYSIZE(dir))) return;
    CreateDirectoryW(dir, NULL);
    if (!Join(path, ARRAYSIZE(path), dir, L"one-dll-bootstrap.log")) return;
    HANDLE f = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    SYSTEMTIME t; GetSystemTime(&t);
    wchar_t row[4096];
    int n = _snwprintf_s(row, ARRAYSIZE(row), _TRUNCATE,
        L"%04u-%02u-%02uT%02u:%02u:%02uZ pid=%lu %s\r\n",
        t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond, GetCurrentProcessId(), text);
    if (n > 0) { DWORD wrote = 0; WriteFile(f, row, (DWORD)(n * sizeof(wchar_t)), &wrote, NULL); }
    CloseHandle(f);
}

static bool ReadAt(HANDLE f, LONGLONG offset, void* data, DWORD size)
{
    LARGE_INTEGER at; at.QuadPart = offset;
    DWORD got = 0;
    return SetFilePointerEx(f, at, NULL, FILE_BEGIN) && ReadFile(f, data, size, &got, NULL) && got == size;
}

struct PeInfo
{
    bool laa;
    LONGLONG characteristicsOffset;
    LARGE_INTEGER size;
    FILETIME creation;
    FILETIME access;
    FILETIME write;
};

static bool InspectHandle(HANDLE f, PeInfo* info)
{
    IMAGE_DOS_HEADER dos = {};
    DWORD sig = 0;
    IMAGE_FILE_HEADER coff = {};
    WORD optionalMagic = 0;
    bool ok = GetFileSizeEx(f, &info->size) && info->size.QuadPart >= sizeof(dos) &&
        ReadAt(f, 0, &dos, sizeof(dos)) && dos.e_magic == IMAGE_DOS_SIGNATURE &&
        dos.e_lfanew >= (LONG)sizeof(dos);
    LONGLONG coffOffset = ok ? (LONGLONG)dos.e_lfanew + sizeof(sig) : 0;
    if (ok)
        ok = coffOffset >= 0 && coffOffset + sizeof(coff) <= info->size.QuadPart &&
            ReadAt(f, dos.e_lfanew, &sig, sizeof(sig)) && sig == IMAGE_NT_SIGNATURE &&
            ReadAt(f, coffOffset, &coff, sizeof(coff));
    LONGLONG optionalOffset = coffOffset + sizeof(coff);
    if (ok)
        ok = coff.SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER32) &&
            optionalOffset >= 0 && optionalOffset + coff.SizeOfOptionalHeader <= info->size.QuadPart &&
            ReadAt(f, optionalOffset, &optionalMagic, sizeof(optionalMagic)) &&
            optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
            coff.Machine == IMAGE_FILE_MACHINE_I386 &&
            (coff.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) &&
            !(coff.Characteristics & IMAGE_FILE_DLL) &&
            GetFileTime(f, &info->creation, &info->access, &info->write);
    if (ok)
    {
        info->laa = (coff.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) != 0;
        info->characteristicsOffset = dos.e_lfanew + sizeof(sig) + FIELD_OFFSET(IMAGE_FILE_HEADER, Characteristics);
    }
    return ok;
}

static bool Inspect(const wchar_t* path, PeInfo* info)
{
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return false;
    bool ok = InspectHandle(f, info);
    CloseHandle(f);
    return ok;
}

static bool Sha256HandleWithByte(HANDLE f, LONGLONG substituteOffset, int substituteValue, BYTE digest[32])
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    PUCHAR object = NULL;
    DWORD objectSize = 0, cb = 0;
    bool ok = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) >= 0 &&
        BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objectSize, sizeof(objectSize), &cb, 0) >= 0;
    if (ok) object = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, objectSize);
    if (!object) ok = false;
    if (ok) ok = BCryptCreateHash(alg, &hash, object, objectSize, NULL, 0, 0) >= 0;
    LARGE_INTEGER fileSize = {};
    if (ok) ok = GetFileSizeEx(f, &fileSize) != FALSE;
    BYTE buffer[65536];
    LONGLONG position = 0;
    while (ok)
    {
        if (position >= fileSize.QuadPart) break;
        DWORD read = (DWORD)((fileSize.QuadPart - position) < (LONGLONG)sizeof(buffer) ?
            (fileSize.QuadPart - position) : sizeof(buffer));
        if (!ReadAt(f, position, buffer, read)) { ok = false; break; }
        if (substituteValue >= 0 && substituteOffset >= position && substituteOffset < position + read)
            buffer[substituteOffset - position] = (BYTE)substituteValue;
        if (BCryptHashData(hash, buffer, read, 0) < 0) { ok = false; break; }
        position += read;
    }
    if (ok) ok = BCryptFinishHash(hash, digest, 32, 0) >= 0;
    if (hash) BCryptDestroyHash(hash);
    if (object) HeapFree(GetProcessHeap(), 0, object);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

static bool Sha256Handle(HANDLE f, BYTE digest[32])
{
    return Sha256HandleWithByte(f, -1, -1, digest);
}

static bool Sha256(const wchar_t* path, BYTE digest[32])
{
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (f == INVALID_HANDLE_VALUE) return false;
    bool ok = Sha256Handle(f, digest);
    CloseHandle(f);
    return ok;
}

static bool Sha256Data(const BYTE* data, DWORD size, BYTE digest[32])
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    PUCHAR object = NULL;
    DWORD objectSize = 0, cb = 0;
    bool ok = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) >= 0 &&
        BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objectSize, sizeof(objectSize), &cb, 0) >= 0;
    if (ok) object = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, objectSize);
    if (!object) ok = false;
    if (ok) ok = BCryptCreateHash(alg, &hash, object, objectSize, NULL, 0, 0) >= 0;
    if (ok) ok = BCryptHashData(hash, (PUCHAR)data, size, 0) >= 0 && BCryptFinishHash(hash, digest, 32, 0) >= 0;
    if (hash) BCryptDestroyHash(hash);
    if (object) HeapFree(GetProcessHeap(), 0, object);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

static bool SameHash(const BYTE a[32], const BYTE b[32]) { return memcmp(a, b, 32) == 0; }

static bool IsPermissionError(DWORD error)
{
    return error == ERROR_ACCESS_DENIED || error == ERROR_PRIVILEGE_NOT_HELD ||
        error == ERROR_WRITE_PROTECT || error == ERROR_CANNOT_MAKE;
}

static bool HighIntegrityOrUnknown()
{
    wchar_t forced[8];
    if (GetEnvironmentVariableW(L"DEADSPACE4GB_TEST_FORCE_HIGH_INTEGRITY", forced, ARRAYSIZE(forced)))
        return true;
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return true;
    DWORD bytes = 0;
    GetTokenInformation(token, TokenIntegrityLevel, NULL, 0, &bytes);
    BYTE* buffer = bytes ? (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes) : NULL;
    bool high = true;
    if (buffer && GetTokenInformation(token, TokenIntegrityLevel, buffer, bytes, &bytes))
    {
        TOKEN_MANDATORY_LABEL* label = (TOKEN_MANDATORY_LABEL*)buffer;
        DWORD count = *GetSidSubAuthorityCount(label->Label.Sid);
        if (count) high = *GetSidSubAuthority(label->Label.Sid, count - 1) >= SECURITY_MANDATORY_HIGH_RID;
    }
    if (buffer) HeapFree(GetProcessHeap(), 0, buffer);
    CloseHandle(token);
    return high;
}

static bool HandoffSecurity(SECURITY_ATTRIBUTES* attributes, PSECURITY_DESCRIPTOR* descriptor)
{
    *descriptor = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)", SDDL_REVISION_1, descriptor, NULL)) return false;
    attributes->nLength = sizeof(*attributes);
    attributes->lpSecurityDescriptor = *descriptor;
    attributes->bInheritHandle = FALSE;
    return true;
}

static bool SecureHandoffFile(const wchar_t* path)
{
    SECURITY_ATTRIBUTES attributes = {};
    PSECURITY_DESCRIPTOR descriptor = NULL;
    if (!HandoffSecurity(&attributes, &descriptor)) return false;
    bool ok = SetFileSecurityW(path, DACL_SECURITY_INFORMATION, descriptor) != FALSE;
    LocalFree(descriptor);
    return ok;
}

static void Hex(const BYTE digest[32], wchar_t out[65])
{
    static const wchar_t chars[] = L"0123456789abcdef";
    for (int i = 0; i < 32; ++i) { out[i * 2] = chars[digest[i] >> 4]; out[i * 2 + 1] = chars[digest[i] & 15]; }
    out[64] = 0;
}

static uint64_t StateKey(const wchar_t* path, const PeInfo& info)
{
    uint64_t h = UINT64_C(14695981039346656037);
    for (const wchar_t* p = path; *p; ++p)
    {
        wchar_t c = (*p >= L'A' && *p <= L'Z') ? *p + 32 : *p;
        h = (h ^ (BYTE)c) * UINT64_C(1099511628211);
        h = (h ^ (BYTE)(c >> 8)) * UINT64_C(1099511628211);
    }
    const BYTE* data = (const BYTE*)&info.size.QuadPart;
    for (size_t i = 0; i < sizeof(info.size.QuadPart); ++i) h = (h ^ data[i]) * UINT64_C(1099511628211);
    data = (const BYTE*)&info.write;
    for (size_t i = 0; i < sizeof(info.write); ++i) h = (h ^ data[i]) * UINT64_C(1099511628211);
    return h;
}

static bool MarkerPath(const wchar_t* executable, wchar_t* out, DWORD cap)
{
    PeInfo info = {};
    wchar_t dir[4096], name[128];
    if (!Inspect(executable, &info) || !StateDirectory(dir, ARRAYSIZE(dir))) return false;
    _snwprintf_s(name, ARRAYSIZE(name), _TRUNCATE, L"failure-%016llx.txt", (unsigned long long)StateKey(executable, info));
    return Join(out, cap, dir, name);
}

static void WriteFailureMarker(const wchar_t* executable, const wchar_t* reason)
{
    wchar_t dir[4096], path[4096];
    if (!StateDirectory(dir, ARRAYSIZE(dir)) || !MarkerPath(executable, path, ARRAYSIZE(path))) return;
    CreateDirectoryW(dir, NULL);
    HANDLE f = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD wrote = 0;
    WriteFile(f, reason, (DWORD)(wcslen(reason) * sizeof(wchar_t)), &wrote, NULL);
    FlushFileBuffers(f);
    CloseHandle(f);
}

static void ClearFailureMarker(const wchar_t* executable)
{
    // Privileged callbacks must never resolve or mutate the user-selected state
    // directory.  The original-integrity Bootstrap worker performs cleanup only
    // after it independently verifies the complete patched state.
    if (InterlockedCompareExchange(&g_elevatedRole, 0, 0)) return;
    wchar_t path[4096];
    if (MarkerPath(executable, path, ARRAYSIZE(path))) DeleteFileW(path);
}

static bool ReadTextFile(const wchar_t* path, char* out, DWORD capacity)
{
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (f == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size = {};
    bool ok = GetFileSizeEx(f, &size) && size.QuadPart > 0 && size.QuadPart < capacity;
    DWORD got = 0;
    if (ok) ok = ReadFile(f, out, (DWORD)size.QuadPart, &got, NULL) && got == size.QuadPart;
    if (ok) out[got] = 0;
    CloseHandle(f);
    return ok;
}

static bool ParseHash(const char* json, const char* field, BYTE digest[32])
{
    const char* p = strstr(json, field);
    if (!p) return false;
    p = strchr(p, ':');
    if (!p) return false;
    p = strchr(p, '"');
    if (!p || strlen(++p) < 64) return false;
    for (int i = 0; i < 32; ++i)
    {
        char hi = p[i * 2], lo = p[i * 2 + 1];
        int a = (hi >= '0' && hi <= '9') ? hi - '0' : (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10 : -1;
        int b = (lo >= '0' && lo <= '9') ? lo - '0' : (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10 : -1;
        if (a < 0 || b < 0) return false;
        digest[i] = (BYTE)((a << 4) | b);
    }
    return p[64] == '"';
}

#pragma pack(push, 1)
struct RequestHeader
{
    DWORD magic;
    DWORD version;
    DWORD parentPid;
    DWORD executableChars;
    DWORD commandChars;
    DWORD cwdChars;
    BYTE originalTargetHash[32];
};
#pragma pack(pop)

static bool NormalFileHandle(HANDLE handle);
static bool SameFileIdentity(HANDLE left, HANDLE right);

static bool WriteAll(HANDLE f, const void* data, DWORD bytes)
{
    DWORD wrote = 0;
    return WriteFile(f, data, bytes, &wrote, NULL) && wrote == bytes;
}

// Keep the original File Object (and therefore its share-read-only/no-delete
// lock) while dropping the long-lived handle's write permission.  Retaining
// the writer itself would let another same-integrity process duplicate a
// writable handle across the UAC consent interval.
static bool ReduceToReadOnlyGuard(HANDLE writable, HANDLE* retainedGuard)
{
    *retainedGuard = INVALID_HANDLE_VALUE;
    HANDLE reduced = INVALID_HANDLE_VALUE;
    BOOL duplicated = DuplicateHandle(GetCurrentProcess(), writable, GetCurrentProcess(), &reduced,
        FILE_GENERIC_READ | SYNCHRONIZE, FALSE, 0);
    DWORD error = duplicated ? ERROR_SUCCESS : GetLastError();
    CloseHandle(writable);
    if (!duplicated)
    {
        SetLastError(error);
        return false;
    }
    *retainedGuard = reduced;
    return true;
}

static bool VerifyReadOnlyGuardForTest(HANDLE guard, const wchar_t* label)
{
    wchar_t enabled[8];
    if (!GetEnvironmentVariableW(L"DEADSPACE4GB_TEST_ASSERT_READONLY_GUARDS", enabled, ARRAYSIZE(enabled)))
        return true;
    BYTE value = 0;
    DWORD wrote = 0;
    SetLastError(ERROR_SUCCESS);
    bool denied = !WriteFile(guard, &value, 1, &wrote, NULL) && GetLastError() == ERROR_ACCESS_DENIED;
    wchar_t row[256];
    _snwprintf_s(row, ARRAYSIZE(row), _TRUNCATE, denied ?
        L"%s retained guard verified read-only" : L"%s retained guard unexpectedly allowed write access", label);
    Log(row);
    return denied;
}

static bool CreateRequest(const wchar_t* executable, wchar_t* requestPath, DWORD cap, HANDLE* retainedGuard)
{
    *retainedGuard = INVALID_HANDLE_VALUE;
    wchar_t dir[4096], name[128], cwd[4096];
    if (!StateDirectory(dir, ARRAYSIZE(dir))) return false;
    if (!CreateDirectoryW(dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) return false;
    GUID id;
    if (CoCreateGuid(&id) != S_OK) return false;
    _snwprintf_s(name, ARRAYSIZE(name), _TRUNCATE,
        L"request-%08lx%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x.bin",
        id.Data1, id.Data2, id.Data3, id.Data4[0], id.Data4[1], id.Data4[2], id.Data4[3],
        id.Data4[4], id.Data4[5], id.Data4[6], id.Data4[7]);
    if (!Join(requestPath, cap, dir, name) || !GetCurrentDirectoryW(ARRAYSIZE(cwd), cwd)) return false;
    const wchar_t* command = GetCommandLineW();
    RequestHeader h = { 0x42473444, 2, GetCurrentProcessId(),
        (DWORD)wcslen(executable), (DWORD)wcslen(command), (DWORD)wcslen(cwd), {} };
    if (h.executableChars >= 4096 || h.commandChars >= 32768 || h.cwdChars >= 4096) return false;
    PeInfo originalInfo = {};
    if (!Inspect(executable, &originalInfo) || originalInfo.laa || !Sha256(executable, h.originalTargetHash)) return false;
    SECURITY_ATTRIBUTES security = {};
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    if (!HandoffSecurity(&security, &securityDescriptor)) return false;
    HANDLE f = CreateFileW(requestPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, &security, CREATE_NEW,
        FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_HIDDEN, NULL);
    if (f == INVALID_HANDLE_VALUE) { LocalFree(securityDescriptor); return false; }
    bool ok = WriteAll(f, &h, sizeof(h)) &&
        WriteAll(f, executable, h.executableChars * sizeof(wchar_t)) &&
        WriteAll(f, command, h.commandChars * sizeof(wchar_t)) &&
        WriteAll(f, cwd, h.cwdChars * sizeof(wchar_t)) && FlushFileBuffers(f);
    LocalFree(securityDescriptor);
    if (ok) ok = ReduceToReadOnlyGuard(f, retainedGuard);
    else CloseHandle(f);
    if (ok) ok = VerifyReadOnlyGuardForTest(*retainedGuard, L"request");
    if (!ok)
    {
        if (*retainedGuard != INVALID_HANDLE_VALUE) CloseHandle(*retainedGuard);
        *retainedGuard = INVALID_HANDLE_VALUE;
        DeleteFileW(requestPath);
    }
    return ok;
}

static bool ReadRequest(const wchar_t* path, RequestHeader* h, wchar_t** executable, wchar_t** command,
    wchar_t** cwd, HANDLE* retainedGuard)
{
    *executable = *command = *cwd = NULL;
    *retainedGuard = INVALID_HANDLE_VALUE;
    wchar_t inheritedText[32];
    DWORD inheritedLength = GetEnvironmentVariableW(kRequestHandleEnvironment, inheritedText, ARRAYSIZE(inheritedText));
    HANDLE inherited = INVALID_HANDLE_VALUE;
    if (inheritedLength && inheritedLength < ARRAYSIZE(inheritedText))
        inherited = (HANDLE)(ULONG_PTR)_wcstoui64(inheritedText, NULL, 16);
    if (!NormalFileHandle(inherited)) return false;
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (f == INVALID_HANDLE_VALUE || !SameFileIdentity(inherited, f))
    { if (f != INVALID_HANDLE_VALUE) CloseHandle(f); CloseHandle(inherited); return false; }
    DWORD got = 0;
    bool ok = ReadFile(f, h, sizeof(*h), &got, NULL) && got == sizeof(*h) && h->magic == 0x42473444 &&
        h->version == 2 && h->executableChars && h->executableChars < 4096 &&
        h->commandChars && h->commandChars < 32768 && h->cwdChars < 4096;
    if (ok)
    {
        *executable = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (h->executableChars + 1) * sizeof(wchar_t));
        *command = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (h->commandChars + 1) * sizeof(wchar_t));
        *cwd = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (h->cwdChars + 1) * sizeof(wchar_t));
        ok = *executable && *command && *cwd &&
            ReadFile(f, *executable, h->executableChars * sizeof(wchar_t), &got, NULL) && got == h->executableChars * sizeof(wchar_t) &&
            ReadFile(f, *command, h->commandChars * sizeof(wchar_t), &got, NULL) && got == h->commandChars * sizeof(wchar_t) &&
            ReadFile(f, *cwd, h->cwdChars * sizeof(wchar_t), &got, NULL) && got == h->cwdChars * sizeof(wchar_t);
    }
    FILE_ATTRIBUTE_TAG_INFO tag = {};
    ok = ok && GetFileInformationByHandleEx(f, FileAttributeTagInfo, &tag, sizeof(tag)) &&
        !(tag.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT));
    CloseHandle(f);
    if (ok) *retainedGuard = inherited; else CloseHandle(inherited);
    if (!ok)
    {
        if (*executable) HeapFree(GetProcessHeap(), 0, *executable);
        if (*command) HeapFree(GetProcessHeap(), 0, *command);
        if (*cwd) HeapFree(GetProcessHeap(), 0, *cwd);
        *executable = *command = *cwd = NULL;
    }
    return ok;
}

static bool ReadVerifiedRequest(const wchar_t* path, const BYTE expectedHash[32], RequestHeader* h,
    wchar_t** executable, wchar_t** command, wchar_t** cwd)
{
    *executable = *command = *cwd = NULL;
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (f == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size = {};
    bool ok = NormalFileHandle(f) && GetFileSizeEx(f, &size) &&
        size.QuadPart >= sizeof(RequestHeader) && size.QuadPart <= 100000;
    BYTE* bytes = ok ? (BYTE*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)size.QuadPart) : NULL;
    if (!bytes) ok = false;
    DWORD got = 0;
    if (ok) ok = ReadFile(f, bytes, (DWORD)size.QuadPart, &got, NULL) && got == size.QuadPart;
    BYTE actualHash[32];
    if (ok) ok = Sha256Data(bytes, got, actualHash) && SameHash(actualHash, expectedHash);
    if (ok)
    {
        memcpy(h, bytes, sizeof(*h));
        ok = h->magic == 0x42473444 && h->version == 2 && h->executableChars && h->executableChars < 4096 &&
            h->commandChars && h->commandChars < 32768 && h->cwdChars < 4096;
        ULONGLONG expectedSize = sizeof(*h) +
            ((ULONGLONG)h->executableChars + h->commandChars + h->cwdChars) * sizeof(wchar_t);
        ok = ok && expectedSize == (ULONGLONG)size.QuadPart;
    }
    if (ok)
    {
        *executable = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (h->executableChars + 1) * sizeof(wchar_t));
        *command = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (h->commandChars + 1) * sizeof(wchar_t));
        *cwd = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (h->cwdChars + 1) * sizeof(wchar_t));
        ok = *executable && *command && *cwd;
    }
    if (ok)
    {
        BYTE* cursor = bytes + sizeof(*h);
        memcpy(*executable, cursor, h->executableChars * sizeof(wchar_t)); cursor += h->executableChars * sizeof(wchar_t);
        memcpy(*command, cursor, h->commandChars * sizeof(wchar_t)); cursor += h->commandChars * sizeof(wchar_t);
        memcpy(*cwd, cursor, h->cwdChars * sizeof(wchar_t));
    }
    CloseHandle(f);
    if (bytes) HeapFree(GetProcessHeap(), 0, bytes);
    if (!ok)
    {
        if (*executable) HeapFree(GetProcessHeap(), 0, *executable);
        if (*command) HeapFree(GetProcessHeap(), 0, *command);
        if (*cwd) HeapFree(GetProcessHeap(), 0, *cwd);
        *executable = *command = *cwd = NULL;
    }
    return ok;
}

static bool NormalFileHandle(HANDLE handle)
{
    FILE_ATTRIBUTE_TAG_INFO info = {};
    return handle != INVALID_HANDLE_VALUE &&
        GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &info, sizeof(info)) &&
        !(info.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT));
}

static bool NormalDirectoryHandle(HANDLE handle)
{
    FILE_ATTRIBUTE_TAG_INFO info = {};
    return handle != INVALID_HANDLE_VALUE &&
        GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &info, sizeof(info)) &&
        (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
        !(info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
}

static bool SameFileIdentity(HANDLE left, HANDLE right)
{
    BY_HANDLE_FILE_INFORMATION a = {}, b = {};
    return GetFileInformationByHandle(left, &a) && GetFileInformationByHandle(right, &b) &&
        a.dwVolumeSerialNumber == b.dwVolumeSerialNumber && a.nFileIndexHigh == b.nFileIndexHigh &&
        a.nFileIndexLow == b.nFileIndexLow;
}

static bool ParentDirectoryPath(const wchar_t* path, wchar_t* directory, size_t capacity)
{
    if (wcscpy_s(directory, capacity, path)) return false;
    wchar_t* slash = wcsrchr(directory, L'\\');
    if (!slash || slash == directory) return false;
    *slash = 0;
    return true;
}

static bool OpenPinnedTarget(const wchar_t* target, DWORD access, HANDLE* targetHandle, HANDLE* directoryGuard)
{
    *targetHandle = *directoryGuard = INVALID_HANDLE_VALUE;
    DWORD attributes = GetFileAttributesW(target);
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
    { if (attributes != INVALID_FILE_ATTRIBUTES) SetLastError(ERROR_REPARSE_TAG_MISMATCH); return false; }
    wchar_t directory[4096];
    if (!ParentDirectoryPath(target, directory, ARRAYSIZE(directory))) return false;
    attributes = GetFileAttributesW(directory);
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
    { if (attributes != INVALID_FILE_ATTRIBUTES) SetLastError(ERROR_REPARSE_TAG_MISMATCH); return false; }
    *directoryGuard = CreateFileW(directory, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (!NormalDirectoryHandle(*directoryGuard))
    {
        DWORD error = *directoryGuard == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_REPARSE_TAG_MISMATCH;
        if (*directoryGuard != INVALID_HANDLE_VALUE) CloseHandle(*directoryGuard);
        *directoryGuard = INVALID_HANDLE_VALUE;
        SetLastError(error);
        return false;
    }
    *targetHandle = CreateFileW(target, access, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, NULL);
    if (!NormalFileHandle(*targetHandle))
    {
        DWORD error = *targetHandle == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_REPARSE_TAG_MISMATCH;
        if (*targetHandle != INVALID_HANDLE_VALUE) CloseHandle(*targetHandle);
        CloseHandle(*directoryGuard);
        *targetHandle = *directoryGuard = INVALID_HANDLE_VALUE;
        SetLastError(error);
        return false;
    }
    return true;
}

static bool PathStillNamesPinnedFile(const wchar_t* target, HANDLE pinned)
{
    HANDLE pathHandle = CreateFileW(target, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    bool same = NormalFileHandle(pathHandle) && SameFileIdentity(pinned, pathHandle);
    if (pathHandle != INVALID_HANDLE_VALUE) CloseHandle(pathHandle);
    return same;
}

static bool CopyHandleBytes(HANDLE source, HANDLE destination, const PeInfo& sourceInfo)
{
    LARGE_INTEGER zero = {};
    if (!SetFilePointerEx(destination, zero, NULL, FILE_BEGIN) || !SetEndOfFile(destination)) return false;
    BYTE bytes[65536];
    LONGLONG position = 0;
    while (position < sourceInfo.size.QuadPart)
    {
        DWORD count = (DWORD)((sourceInfo.size.QuadPart - position) < (LONGLONG)sizeof(bytes) ?
            (sourceInfo.size.QuadPart - position) : sizeof(bytes));
        if (!ReadAt(source, position, bytes, count)) return false;
        LARGE_INTEGER at; at.QuadPart = position;
        DWORD wrote = 0;
        if (!SetFilePointerEx(destination, at, NULL, FILE_BEGIN) ||
            !WriteFile(destination, bytes, count, &wrote, NULL) || wrote != count) return false;
        position += count;
    }
    return SetFileTime(destination, &sourceInfo.creation, &sourceInfo.access, &sourceInfo.write) &&
        FlushFileBuffers(destination);
}

static bool OpenVerifiedBackup(const wchar_t* backup, HANDLE target, const PeInfo& targetInfo,
    const BYTE targetHash[32], HANDLE* backupHandle)
{
    *backupHandle = CreateFileW(backup, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, NULL);
    bool created = *backupHandle != INVALID_HANDLE_VALUE;
    if (!created)
    {
        DWORD error = GetLastError();
        if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS) return false;
        *backupHandle = CreateFileW(backup, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    }
    bool ok = NormalFileHandle(*backupHandle);
    if (ok && created) ok = CopyHandleBytes(target, *backupHandle, targetInfo);
    PeInfo backupInfo = {};
    BYTE backupHash[32];
    if (ok) ok = InspectHandle(*backupHandle, &backupInfo) && !backupInfo.laa &&
        Sha256Handle(*backupHandle, backupHash) && SameHash(targetHash, backupHash);
    if (!ok)
    {
        if (*backupHandle != INVALID_HANDLE_VALUE) CloseHandle(*backupHandle);
        *backupHandle = INVALID_HANDLE_VALUE;
        if (created) DeleteFileW(backup);
    }
    return ok;
}

static bool HandlesDifferOnlyByLaa(HANDLE original, const PeInfo& originalInfo,
    HANDLE patched, const PeInfo& patchedInfo)
{
    if (originalInfo.laa || !patchedInfo.laa ||
        originalInfo.size.QuadPart != patchedInfo.size.QuadPart ||
        originalInfo.characteristicsOffset != patchedInfo.characteristicsOffset) return false;
    BYTE a[65536], b[65536];
    LONGLONG position = 0;
    while (position < originalInfo.size.QuadPart)
    {
        DWORD count = (DWORD)((originalInfo.size.QuadPart - position) < (LONGLONG)sizeof(a) ?
            (originalInfo.size.QuadPart - position) : sizeof(a));
        if (!ReadAt(original, position, a, count) || !ReadAt(patched, position, b, count)) return false;
        for (DWORD i = 0; i < count; ++i)
        {
            LONGLONG absolute = position + i;
            BYTE expected = absolute == originalInfo.characteristicsOffset ?
                (BYTE)(a[i] | IMAGE_FILE_LARGE_ADDRESS_AWARE) : a[i];
            if (b[i] != expected) return false;
        }
        position += count;
    }
    return true;
}

static bool WritePinnedLaaByte(HANDLE target, const PeInfo& info, BYTE value)
{
    LARGE_INTEGER at; at.QuadPart = info.characteristicsOffset;
    DWORD wrote = 0;
    if (!SetFilePointerEx(target, at, NULL, FILE_BEGIN)) return false;
    bool writeOk = WriteFile(target, &value, sizeof(value), &wrote, NULL) && wrote == sizeof(value);
    DWORD error = writeOk ? ERROR_SUCCESS : GetLastError();
    if (!writeOk && error == ERROR_SUCCESS) error = ERROR_WRITE_FAULT;
    bool timeOk = SetFileTime(target, &info.creation, &info.access, &info.write) != FALSE;
    if (!timeOk && error == ERROR_SUCCESS) error = GetLastError();
    bool flushOk = FlushFileBuffers(target) != FALSE;
    if (!flushOk && error == ERROR_SUCCESS) error = GetLastError();
    wchar_t forced[8];
    if (writeOk && timeOk && flushOk && GetEnvironmentVariableW(
        L"DEADSPACE4GB_TEST_FORCE_WRITE_FINALIZE_FAILURE", forced, ARRAYSIZE(forced)))
    {
        SetLastError(ERROR_WRITE_FAULT);
        return false;
    }
    if (!writeOk || !timeOk || !flushOk) SetLastError(error);
    return writeOk && timeOk && flushOk;
}

// A failed WriteFile/metadata/flush chain does not prove that the byte remained
// unchanged.  Resolve that uncertainty before releasing the pinned handle by
// verifying the whole expected hash, rewriting the one byte when necessary,
// and requiring a successful flush plus a second same-handle hash.
static bool EnsurePinnedByte(HANDLE target, const PeInfo& info, BYTE value, const BYTE expectedHash[32])
{
    BYTE actual[32];
    bool alreadyExpected = Sha256Handle(target, actual) && SameHash(actual, expectedHash);
    if (!alreadyExpected) WritePinnedLaaByte(target, info, value);
    SetFileTime(target, &info.creation, &info.access, &info.write);
    bool flushed = FlushFileBuffers(target) != FALSE;
    return flushed && Sha256Handle(target, actual) && SameHash(actual, expectedHash);
}

static bool TargetMutexName(const wchar_t* target, wchar_t* name, size_t capacity)
{
    uint64_t hash = UINT64_C(14695981039346656037);
    for (const wchar_t* p = target; *p; ++p)
    {
        wchar_t c = (*p >= L'A' && *p <= L'Z') ? *p + 32 : *p;
        hash = (hash ^ (BYTE)c) * UINT64_C(1099511628211);
        hash = (hash ^ (BYTE)(c >> 8)) * UINT64_C(1099511628211);
    }
    return _snwprintf_s(name, capacity, _TRUNCATE,
        L"Local\\DeadSpace4GBTarget-%016llx", (unsigned long long)hash) >= 0;
}

static void ReleaseTargetMutex(HANDLE mutex)
{
    if (mutex) { ReleaseMutex(mutex); CloseHandle(mutex); }
}

struct ScopedTargetMutex
{
    HANDLE handle;
    ScopedTargetMutex() : handle(NULL) {}
    ~ScopedTargetMutex() { ReleaseTargetMutex(handle); }
    bool Acquire(const wchar_t* target, DWORD timeout)
    {
        wchar_t name[128];
        if (!TargetMutexName(target, name, ARRAYSIZE(name))) return false;
        handle = CreateMutexW(NULL, FALSE, name);
        if (!handle) return false;
        DWORD wait = WaitForSingleObject(handle, timeout);
        if (wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED) return true;
        CloseHandle(handle); handle = NULL; return false;
    }
};

static bool AtomicCopy(const wchar_t* source, const wchar_t* destination, bool replace)
{
    wchar_t temp[4096];
    _snwprintf_s(temp, ARRAYSIZE(temp), _TRUNCATE, L"%s.tmp.%lu.%lu", destination, GetCurrentProcessId(), GetTickCount());
    if (!CopyFileW(source, temp, TRUE)) return false;
    BYTE a[32], b[32];
    bool ok = Sha256(source, a) && Sha256(temp, b) && SameHash(a, b) &&
        MoveFileExW(temp, destination, (replace ? MOVEFILE_REPLACE_EXISTING : 0) | MOVEFILE_WRITE_THROUGH);
    if (!ok) DeleteFileW(temp);
    return ok;
}

static bool EnsureRuntimeWorker(const wchar_t* source, const wchar_t* destination)
{
    if (AtomicCopy(source, destination, true)) return SecureHandoffFile(destination);
    DWORD attributes = GetFileAttributesW(destination);
    BYTE sourceHash[32], destinationHash[32];
    return attributes != INVALID_FILE_ATTRIBUTES &&
        !(attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) &&
        Sha256(source, sourceHash) && Sha256(destination, destinationHash) &&
        SameHash(sourceHash, destinationHash);
}

static bool WriteManifest(const wchar_t* target, const BYTE original[32], const BYTE patched[32])
{
    wchar_t path[4096], originalHex[65], patchedHex[65];
    _snwprintf_s(path, ARRAYSIZE(path), _TRUNCATE, L"%s.deadspace-laa.manifest.json", target);
    Hex(original, originalHex); Hex(patched, patchedHex);
    wchar_t json[1024];
    int chars = _snwprintf_s(json, ARRAYSIZE(json), _TRUNCATE,
        L"{\r\n  \"format\": 1,\r\n  \"target\": \"Dead Space.exe\",\r\n  \"backup\": \"Dead Space.exe.deadspace-laa.bak\",\r\n  \"originalSha256\": \"%s\",\r\n  \"patchedSha256\": \"%s\"\r\n}\r\n",
        originalHex, patchedHex);
    if (chars <= 0) return false;
    // UTF-8 is ASCII for this manifest.
    char utf8[2048];
    int bytes = WideCharToMultiByte(CP_UTF8, 0, json, chars, utf8, sizeof(utf8), NULL, NULL);
    if (bytes <= 0) return false;

    // Never truncate a pre-existing final pathname.  First attempt an exclusive
    // CREATE_NEW.  A planted reparse point or hardlink makes that fail; an
    // existing ordinary manifest is opened read-only and accepted only when it
    // is a single-link exact byte match.  Thus an attacker cannot redirect an
    // elevated write through any pre-created name.
    HANDLE f = CreateFileW(path, GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ, NULL, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, NULL);
    bool created = f != INVALID_HANDLE_VALUE;
    DWORD createError = created ? ERROR_SUCCESS : GetLastError();
    if (!created && (createError == ERROR_FILE_EXISTS || createError == ERROR_ALREADY_EXISTS))
    {
        f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    }
    if (!NormalFileHandle(f))
    {
        DWORD error = f == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_REPARSE_TAG_MISMATCH;
        if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
        SetLastError(error);
        return false;
    }
    BY_HANDLE_FILE_INFORMATION before = {}, after = {};
    LARGE_INTEGER size = {};
    char readback[2048] = {};
    bool ok = GetFileInformationByHandle(f, &before) && before.nNumberOfLinks == 1;
    if (created)
    {
        ok = ok && WriteAll(f, utf8, bytes) && FlushFileBuffers(f) &&
            GetFileSizeEx(f, &size) && size.QuadPart == bytes &&
            ReadAt(f, 0, readback, bytes) && memcmp(readback, utf8, bytes) == 0 &&
            GetFileInformationByHandle(f, &after) && after.nNumberOfLinks == 1 &&
            PathStillNamesPinnedFile(path, f);
    }
    else
    {
        ok = ok && GetFileSizeEx(f, &size) && size.QuadPart == bytes &&
            ReadAt(f, 0, readback, bytes) && memcmp(readback, utf8, bytes) == 0 &&
            GetFileInformationByHandle(f, &after) && after.nNumberOfLinks == 1 &&
            PathStillNamesPinnedFile(path, f);
    }
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok && error == ERROR_SUCCESS) error = ERROR_FILE_INVALID;
    if (!ok && created)
    {
        FILE_DISPOSITION_INFO disposition = { TRUE };
        SetFileInformationByHandle(f, FileDispositionInfo, &disposition, sizeof(disposition));
    }
    CloseHandle(f);
    if (!ok) SetLastError(error);
    return ok;
}

static bool ValidatePatchedState(const wchar_t* target, BYTE patchedHash[32]);
static bool ValidatePatchedStateForOriginal(const wchar_t* target, const BYTE expectedOriginalHash[32],
    BYTE patchedHash[32]);

static bool Restore(const wchar_t* target, wchar_t* reason, size_t reasonCap)
{
    if (_wcsicmp(BaseName(target), kGameName))
    { wcscpy_s(reason, reasonCap, L"Restore target name is not Dead Space.exe."); return false; }
    ScopedTargetMutex restoreMutex;
    if (!restoreMutex.Acquire(target, 30000))
    { wcscpy_s(reason, reasonCap, L"Another patch or restore operation is active; restore was refused."); return false; }
    wchar_t backup[4096], manifest[4096];
    _snwprintf_s(backup, ARRAYSIZE(backup), _TRUNCATE, L"%s.deadspace-laa.bak", target);
    _snwprintf_s(manifest, ARRAYSIZE(manifest), _TRUNCATE, L"%s.deadspace-laa.manifest.json", target);
    HANDLE pinned = INVALID_HANDLE_VALUE, directoryGuard = INVALID_HANDLE_VALUE, backupHandle = INVALID_HANDLE_VALUE;
    if (!OpenPinnedTarget(target, GENERIC_READ | GENERIC_WRITE, &pinned, &directoryGuard))
    { wcscpy_s(reason, reasonCap, L"Could not safely pin Dead Space.exe for restore. Close the game and refuse reparse-point paths."); return false; }
    backupHandle = CreateFileW(backup, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    PeInfo current = {}, original = {};
    BYTE currentHash[32], backupHash[32], expectedCurrent[32], expectedBackup[32];
    char json[4096];
    bool exactBitRecovery = NormalFileHandle(backupHandle) && InspectHandle(pinned, &current) && current.laa &&
        InspectHandle(backupHandle, &original) && !original.laa &&
        Sha256Handle(pinned, currentHash) && Sha256Handle(backupHandle, backupHash) &&
        HandlesDifferOnlyByLaa(backupHandle, original, pinned, current);
    if (!exactBitRecovery)
    {
        if (backupHandle != INVALID_HANDLE_VALUE) CloseHandle(backupHandle);
        CloseHandle(pinned); CloseHandle(directoryGuard);
        wcscpy_s(reason, reasonCap,
            L"Restore refused: the current executable and backup are not an exact one-bit LAA pair. Use EA App Repair or Steam Verify Files.");
        return false;
    }
    bool manifestValid = ReadTextFile(manifest, json, ARRAYSIZE(json)) &&
        ParseHash(json, "\"originalSha256\"", expectedBackup) &&
        ParseHash(json, "\"patchedSha256\"", expectedCurrent) &&
        SameHash(currentHash, expectedCurrent) && SameHash(backupHash, expectedBackup);
    Log(manifestValid ? L"restore: complete manifest validated" :
        L"restore: incomplete manifest state accepted only after exact one-bit backup comparison");
    BYTE originalByte = 0, patchedByte = 0;
    bool ready = ReadAt(backupHandle, original.characteristicsOffset, &originalByte, 1) &&
        ReadAt(pinned, current.characteristicsOffset, &patchedByte, 1) &&
        patchedByte == (BYTE)(originalByte | IMAGE_FILE_LARGE_ADDRESS_AWARE) &&
        PathStillNamesPinnedFile(target, pinned);
    bool writeReported = ready && WritePinnedLaaByte(pinned, current, originalByte);
    if (!ready || (!writeReported && !EnsurePinnedByte(pinned, current, originalByte, backupHash)))
    {
        // If the attempted restore cannot be proven durable, make a best effort
        // to retain the previously verified patched byte before releasing the
        // handle.  Either way the caller receives a failure and repair advice.
        if (ready) EnsurePinnedByte(pinned, current, patchedByte, currentHash);
        CloseHandle(backupHandle); CloseHandle(pinned); CloseHandle(directoryGuard);
        wcscpy_s(reason, reasonCap, L"Restore could not safely clear the pinned LAA byte. Use EA App Repair or Steam Verify Files.");
        return false;
    }
    PeInfo after = {};
    BYTE afterHash[32];
    if (!InspectHandle(pinned, &after) || after.laa || !Sha256Handle(pinned, afterHash) || !SameHash(afterHash, backupHash))
    {
        EnsurePinnedByte(pinned, current, patchedByte, currentHash);
        CloseHandle(backupHandle); CloseHandle(pinned); CloseHandle(directoryGuard);
        wcscpy_s(reason, reasonCap, L"Restore verification failed and the patched byte was retained. Use EA App Repair or Steam Verify Files.");
        return false;
    }
    CloseHandle(backupHandle); CloseHandle(pinned); CloseHandle(directoryGuard);
    if (GetFileAttributesW(manifest) != INVALID_FILE_ATTRIBUTES && !DeleteFileW(manifest))
    {
        wcscpy_s(reason, reasonCap,
            L"The executable was restored and verified, but the stale manifest could not be removed; remove it before reinstalling the mod.");
        return false;
    }
    return true;
}

static bool Patch(const wchar_t* target, const BYTE expectedOriginalHash[32],
    wchar_t* reason, size_t reasonCap, DWORD* errorOut)
{
    *errorOut = ERROR_SUCCESS;
    Log(L"patch: validating target");
    wchar_t elevated[8];
    if (GetEnvironmentVariableW(L"DEADSPACE4GB_TEST_FORCE_ACCESS_DENIED", elevated, ARRAYSIZE(elevated)) &&
        !GetEnvironmentVariableW(kElevatedWorkerEnvironment, elevated, ARRAYSIZE(elevated)))
    { *errorOut = ERROR_ACCESS_DENIED; SetLastError(ERROR_ACCESS_DENIED); wcscpy_s(reason, reasonCap, L"Forced medium-integrity access denial."); return false; }
    if (_wcsicmp(BaseName(target), kGameName))
    { *errorOut = ERROR_BAD_EXE_FORMAT; wcscpy_s(reason, reasonCap, L"Target name is not Dead Space.exe."); return false; }
    HANDLE pinned = INVALID_HANDLE_VALUE, directoryGuard = INVALID_HANDLE_VALUE, backupHandle = INVALID_HANDLE_VALUE;
    if (!OpenPinnedTarget(target, GENERIC_READ | GENERIC_WRITE, &pinned, &directoryGuard))
    { *errorOut = GetLastError(); wcscpy_s(reason, reasonCap, L"Could not safely pin a normal non-reparse Dead Space.exe."); return false; }
    Log(L"patch: target handle and final directory pinned");
    PeInfo info = {};
    if (!InspectHandle(pinned, &info))
    {
        CloseHandle(pinned); CloseHandle(directoryGuard); *errorOut = ERROR_BAD_EXE_FORMAT;
        wcscpy_s(reason, reasonCap, L"Target is not the expected 32-bit Dead Space executable."); return false;
    }
    if (info.laa)
    {
        CloseHandle(pinned); CloseHandle(directoryGuard);
        BYTE existing[32];
        if (ValidatePatchedStateForOriginal(target, expectedOriginalHash, existing)) return true;
        *errorOut = ERROR_INVALID_STATE;
        wcscpy_s(reason, reasonCap, L"Dead Space.exe is LAA but this mod's backup/manifest state is incomplete.");
        return false;
    }
    wchar_t backup[4096];
    _snwprintf_s(backup, ARRAYSIZE(backup), _TRUNCATE, L"%s.deadspace-laa.bak", target);
    BYTE targetHash[32], backupHash[32], patchedHash[32];
    if (!Sha256Handle(pinned, targetHash))
    { CloseHandle(pinned); CloseHandle(directoryGuard); *errorOut = GetLastError(); wcscpy_s(reason, reasonCap, L"Could not hash the pinned target."); return false; }
    if (!SameHash(targetHash, expectedOriginalHash))
    {
        CloseHandle(pinned); CloseHandle(directoryGuard); *errorOut = ERROR_FILE_INVALID;
        wcscpy_s(reason, reasonCap, L"The pinned executable no longer matches the exact original launch request."); return false;
    }
    Log(L"patch: target hash complete");
    if (!OpenVerifiedBackup(backup, pinned, info, targetHash, &backupHandle) ||
        !Sha256Handle(backupHandle, backupHash))
    {
        DWORD backupError = GetLastError();
        if (backupHandle != INVALID_HANDLE_VALUE) CloseHandle(backupHandle);
        CloseHandle(pinned); CloseHandle(directoryGuard); *errorOut = backupError;
        wcscpy_s(reason, reasonCap, L"Could not create or validate an exact pinned backup."); return false;
    }
    Log(L"patch: exact backup pinned and verified");
    BYTE originalByte = 0;
    if (!ReadAt(pinned, info.characteristicsOffset, &originalByte, 1) ||
        (originalByte & IMAGE_FILE_LARGE_ADDRESS_AWARE))
    {
        CloseHandle(backupHandle); CloseHandle(pinned); CloseHandle(directoryGuard); *errorOut = ERROR_BAD_EXE_FORMAT;
        wcscpy_s(reason, reasonCap, L"Pinned PE characteristics byte was invalid."); return false;
    }
    BYTE patchedByte = (BYTE)(originalByte | IMAGE_FILE_LARGE_ADDRESS_AWARE);
    if (!Sha256HandleWithByte(pinned, info.characteristicsOffset, patchedByte, patchedHash))
    {
        CloseHandle(backupHandle); CloseHandle(pinned); CloseHandle(directoryGuard); *errorOut = GetLastError();
        wcscpy_s(reason, reasonCap, L"Could not compute the expected one-byte patched hash."); return false;
    }
    wchar_t forced[8];
    if (GetEnvironmentVariableW(L"DEADSPACE4GB_TEST_FORCE_PATCH_FAILURE", forced, ARRAYSIZE(forced)))
    {
        CloseHandle(backupHandle); CloseHandle(pinned); CloseHandle(directoryGuard); *errorOut = ERROR_GEN_FAILURE;
        wcscpy_s(reason, reasonCap, L"Forced test failure."); return false;
    }
    wchar_t delay[16];
    if (GetEnvironmentVariableW(L"DEADSPACE4GB_TEST_PINNED_DELAY_MS", delay, ARRAYSIZE(delay))) Sleep(_wtoi(delay));
    BYTE lastMomentHash[32];
    if (!PathStillNamesPinnedFile(target, pinned) || !Sha256Handle(pinned, lastMomentHash) ||
        !SameHash(lastMomentHash, targetHash))
    {
        CloseHandle(backupHandle); CloseHandle(pinned); CloseHandle(directoryGuard); *errorOut = ERROR_FILE_INVALID;
        wcscpy_s(reason, reasonCap, L"The target path or pinned file changed while the patch was prepared."); return false;
    }
    if (!WritePinnedLaaByte(pinned, info, patchedByte))
    {
        DWORD writeError = GetLastError();
        bool restored = EnsurePinnedByte(pinned, info, originalByte, targetHash);
        CloseHandle(backupHandle); CloseHandle(pinned); CloseHandle(directoryGuard);
        *errorOut = writeError ? writeError : ERROR_WRITE_FAULT;
        wcscpy_s(reason, reasonCap, restored ?
            L"The pinned LAA write could not be finalized; the exact original was restored." :
            L"The pinned LAA write could not be finalized and same-handle recovery also failed.");
        return false;
    }
    PeInfo after = {};
    BYTE afterHash[32];
    bool forcePostVerifyFailure = GetEnvironmentVariableW(
        L"DEADSPACE4GB_TEST_FORCE_POST_VERIFY_FAILURE", forced, ARRAYSIZE(forced)) != 0;
    if (forcePostVerifyFailure || !InspectHandle(pinned, &after) || !after.laa ||
        !Sha256Handle(pinned, afterHash) || !SameHash(afterHash, patchedHash))
    {
        bool restored = !GetEnvironmentVariableW(L"DEADSPACE4GB_TEST_FORCE_ROLLBACK_FAILURE", forced, ARRAYSIZE(forced)) &&
            EnsurePinnedByte(pinned, info, originalByte, targetHash);
        CloseHandle(backupHandle); CloseHandle(pinned); CloseHandle(directoryGuard);
        *errorOut = ERROR_CRC;
        wcscpy_s(reason, reasonCap, restored ? L"Post-patch verification failed; original restored." : L"Post-patch verification failed; automatic restore also failed.");
        return false;
    }
    if (!WriteManifest(target, backupHash, patchedHash))
    {
        DWORD manifestError = GetLastError();
        bool restored = !GetEnvironmentVariableW(L"DEADSPACE4GB_TEST_FORCE_ROLLBACK_FAILURE", forced, ARRAYSIZE(forced)) &&
            EnsurePinnedByte(pinned, info, originalByte, targetHash);
        CloseHandle(backupHandle); CloseHandle(pinned); CloseHandle(directoryGuard);
        *errorOut = manifestError;
        wcscpy_s(reason, reasonCap, restored ? L"Manifest write failed; original restored." : L"Manifest write failed; automatic restore also failed.");
        return false;
    }
    CloseHandle(backupHandle); CloseHandle(pinned); CloseHandle(directoryGuard);
    return true;
}

static bool ValidatePatchedState(const wchar_t* target, BYTE patchedHash[32])
{
    wchar_t backup[4096], manifest[4096];
    _snwprintf_s(backup, ARRAYSIZE(backup), _TRUNCATE, L"%s.deadspace-laa.bak", target);
    _snwprintf_s(manifest, ARRAYSIZE(manifest), _TRUNCATE, L"%s.deadspace-laa.manifest.json", target);
    PeInfo current = {}, original = {};
    BYTE backupHash[32], expectedCurrent[32], expectedBackup[32];
    char json[4096];
    return _wcsicmp(BaseName(target), kGameName) == 0 && Inspect(target, &current) && current.laa &&
        Inspect(backup, &original) && !original.laa && ReadTextFile(manifest, json, ARRAYSIZE(json)) &&
        ParseHash(json, "\"originalSha256\"", expectedBackup) &&
        ParseHash(json, "\"patchedSha256\"", expectedCurrent) && Sha256(target, patchedHash) &&
        Sha256(backup, backupHash) && SameHash(patchedHash, expectedCurrent) && SameHash(backupHash, expectedBackup);
}

static bool ValidatePatchedStateForOriginal(const wchar_t* target, const BYTE expectedOriginalHash[32],
    BYTE patchedHash[32])
{
    wchar_t backup[4096];
    _snwprintf_s(backup, ARRAYSIZE(backup), _TRUNCATE, L"%s.deadspace-laa.bak", target);
    BYTE backupHash[32];
    return ValidatePatchedState(target, patchedHash) && Sha256(backup, backupHash) &&
        SameHash(backupHash, expectedOriginalHash);
}

enum TargetSafetyState { TargetStateUnsafe, TargetStateOriginal, TargetStatePatched };

static TargetSafetyState ValidateTargetSafety(const wchar_t* target, const BYTE expectedOriginalHash[32])
{
    PeInfo current = {};
    BYTE currentHash[32];
    if (Inspect(target, &current) && !current.laa && Sha256(target, currentHash) &&
        SameHash(currentHash, expectedOriginalHash))
        return TargetStateOriginal;
    return ValidatePatchedStateForOriginal(target, expectedOriginalHash, currentHash) ?
        TargetStatePatched : TargetStateUnsafe;
}

#pragma pack(push, 1)
struct ElevationHeader
{
    DWORD magic;
    DWORD version;
    char token[32];
    BYTE requestHash[32];
    DWORD requestChars;
};
#pragma pack(pop)

static bool ValidToken(const char* token)
{
    if (strlen(token) != 32) return false;
    for (int i = 0; i < 32; ++i)
        if (!((token[i] >= '0' && token[i] <= '9') || (token[i] >= 'a' && token[i] <= 'f'))) return false;
    return true;
}

static bool GenerateToken(char token[33])
{
    GUID id;
    if (CoCreateGuid(&id) != S_OK) return false;
    int n = _snprintf_s(token, 33, _TRUNCATE,
        "%08lx%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x",
        id.Data1, id.Data2, id.Data3, id.Data4[0], id.Data4[1], id.Data4[2], id.Data4[3],
        id.Data4[4], id.Data4[5], id.Data4[6], id.Data4[7]);
    return n == 32;
}

static bool EncodeWideHex(const wchar_t* value, wchar_t* encoded, size_t capacity)
{
    static const wchar_t hex[] = L"0123456789abcdef";
    size_t length = wcslen(value);
    if (!length || length * 4 + 1 > capacity) return false;
    for (size_t i = 0; i < length; ++i)
    {
        WORD c = (WORD)value[i];
        encoded[i * 4] = hex[(c >> 12) & 15]; encoded[i * 4 + 1] = hex[(c >> 8) & 15];
        encoded[i * 4 + 2] = hex[(c >> 4) & 15]; encoded[i * 4 + 3] = hex[c & 15];
    }
    encoded[length * 4] = 0;
    return true;
}

static int HexValue(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static bool DecodeWideHex(const char* encoded, wchar_t* value, size_t capacity)
{
    size_t length = strlen(encoded);
    if (!length || length % 4 || length / 4 + 1 > capacity) return false;
    for (size_t i = 0; i < length / 4; ++i)
    {
        int a = HexValue(encoded[i * 4]), b = HexValue(encoded[i * 4 + 1]);
        int c = HexValue(encoded[i * 4 + 2]), d = HexValue(encoded[i * 4 + 3]);
        if (a < 0 || b < 0 || c < 0 || d < 0) return false;
        value[i] = (wchar_t)((a << 12) | (b << 8) | (c << 4) | d);
    }
    value[length / 4] = 0;
    return true;
}

static bool ElevationDescriptorPath(const char* token, wchar_t* descriptor)
{
    if (!ValidToken(token)) return false;
    wchar_t state[4096], wide[33], name[128];
    if (!StateDirectory(state, ARRAYSIZE(state)) || !MultiByteToWideChar(CP_ACP, 0, token, 32, wide, 32)) return false;
    wide[32] = 0;
    _snwprintf_s(name, ARRAYSIZE(name), _TRUNCATE, L"elevation-%s.bin", wide);
    return Join(descriptor, 4096, state, name);
}

static bool WriteElevationDescriptor(const char* token, const wchar_t* request, wchar_t* descriptor,
    HANDLE* descriptorGuard)
{
    *descriptorGuard = INVALID_HANDLE_VALUE;
    if (!ElevationDescriptorPath(token, descriptor)) return false;
    BYTE requestHash[32];
    if (!Sha256(request, requestHash)) return false;
    ElevationHeader h = {};
    h.magic = 0x45473444; h.version = 3; h.requestChars = (DWORD)wcslen(request);
    memcpy(h.token, token, 32); memcpy(h.requestHash, requestHash, 32);
    if (!h.requestChars || h.requestChars >= 4096) return false;
    SECURITY_ATTRIBUTES security = {};
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    if (!HandoffSecurity(&security, &securityDescriptor)) return false;
    HANDLE descriptorWriter = CreateFileW(descriptor, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
        &security, CREATE_NEW,
        FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, NULL);
    bool ok = NormalFileHandle(descriptorWriter) && WriteAll(descriptorWriter, &h, sizeof(h)) &&
        WriteAll(descriptorWriter, request, h.requestChars * sizeof(wchar_t)) && FlushFileBuffers(descriptorWriter);
    if (ok) ok = ReduceToReadOnlyGuard(descriptorWriter, descriptorGuard);
    else if (descriptorWriter != INVALID_HANDLE_VALUE) CloseHandle(descriptorWriter);
    if (ok) ok = VerifyReadOnlyGuardForTest(*descriptorGuard, L"descriptor");
    LocalFree(securityDescriptor);
    if (!ok)
    {
        if (*descriptorGuard != INVALID_HANDLE_VALUE) CloseHandle(*descriptorGuard);
        *descriptorGuard = INVALID_HANDLE_VALUE;
        DeleteFileW(descriptor);
    }
    return ok;
}

static bool ReadElevationDescriptor(const char* token, const wchar_t* descriptor, wchar_t* request,
    BYTE expectedRequestHash[32])
{
    if (!ValidToken(token) || wcslen(descriptor) >= 4096) return false;
    HANDLE f = CreateFileW(descriptor, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (f == INVALID_HANDLE_VALUE) return false;
    ElevationHeader h = {};
    DWORD got = 0;
    LARGE_INTEGER size = {};
    bool ok = NormalFileHandle(f) && GetFileSizeEx(f, &size) &&
        ReadFile(f, &h, sizeof(h), &got, NULL) && got == sizeof(h) && h.magic == 0x45473444 &&
        h.version == 3 && memcmp(h.token, token, 32) == 0 && h.requestChars && h.requestChars < 4096 &&
        size.QuadPart == sizeof(h) + (LONGLONG)h.requestChars * sizeof(wchar_t) &&
        ReadFile(f, request, h.requestChars * sizeof(wchar_t), &got, NULL) && got == h.requestChars * sizeof(wchar_t);
    if (ok) request[h.requestChars] = 0;
    CloseHandle(f);
    if (ok) memcpy(expectedRequestHash, h.requestHash, 32);
    return ok;
}

__declspec(noreturn) static void FinishElevatedProcess(bool patchSucceeded)
{
    bool audited = InterlockedCompareExchange(&g_elevatedRole, 0, 0) == 1 &&
        InterlockedCompareExchange(&g_elevatedLogCallsSuppressed, 0, 0) > 0 &&
        InterlockedCompareExchange(&g_logFilesystemAttempts, 0, 0) == 0;
    ExitProcess(patchSucceeded && audited ? kElevatedSuccessExitCode : kElevatedFailureExitCode);
}

__declspec(noreturn) static void FinishRestoreProcess(bool restoreSucceeded)
{
    bool audited = InterlockedCompareExchange(&g_elevatedRole, 0, 0) == 1 &&
        InterlockedCompareExchange(&g_elevatedLogCallsSuppressed, 0, 0) > 0 &&
        InterlockedCompareExchange(&g_logFilesystemAttempts, 0, 0) == 0;
    ExitProcess(restoreSucceeded && audited ? kRestoreSuccessExitCode : kRestoreFailureExitCode);
}

static void ShowPatchFailure(const wchar_t* reason, const wchar_t* action)
{
    wchar_t suppressed[8];
    if (GetEnvironmentVariableW(L"DEADSPACE4GB_TEST_SUPPRESS_UI", suppressed, ARRAYSIZE(suppressed)))
    { Log(L"user-visible patch failure suppressed for synthetic test"); return; }
    wchar_t message[1024];
    _snwprintf_s(message, ARRAYSIZE(message), _TRUNCATE,
        L"The Dead Space 4GB Mod could not safely patch Dead Space.exe.\r\n\r\n%s\r\n\r\n%s\r\n"
        L"See the mod log for details.", reason, action);
    MessageBoxW(NULL, message, L"Dead Space (2008) 4GB Mod", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
}

static void ShowRelaunchFailure()
{
    wchar_t suppressed[8];
    if (GetEnvironmentVariableW(L"DEADSPACE4GB_TEST_SUPPRESS_UI", suppressed, ARRAYSIZE(suppressed)))
    { Log(L"user-visible relaunch failure suppressed for synthetic test"); return; }
    MessageBoxW(NULL,
        L"The patch status was verified, but Windows could not restart Dead Space.\r\n\r\n"
        L"Launch Dead Space normally again. The mod will safely re-check the executable.",
        L"Dead Space (2008) 4GB Mod", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
}

static void ShowRecoveryBlocked(const wchar_t* reason)
{
    wchar_t suppressed[8];
    if (GetEnvironmentVariableW(L"DEADSPACE4GB_TEST_SUPPRESS_UI", suppressed, ARRAYSIZE(suppressed)))
    { Log(L"user-visible critical recovery block suppressed for synthetic test"); return; }
    wchar_t message[1200];
    _snwprintf_s(message, ARRAYSIZE(message), _TRUNCATE,
        L"The Dead Space 4GB Mod found an incomplete or invalid patch state and stopped the game for safety.\r\n\r\n"
        L"%s\r\n\r\nRun Restore Dead Space 4GB Mod.cmd from the mod folder. If recovery is refused, use EA App Repair or Steam Verify Files.", reason);
    MessageBoxW(NULL, message, L"Dead Space (2008) 4GB Mod - Recovery Required",
        MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
}

static void ShowHighIntegrityBlocked()
{
    wchar_t suppressed[8];
    if (GetEnvironmentVariableW(L"DEADSPACE4GB_TEST_SUPPRESS_UI", suppressed, ARRAYSIZE(suppressed))) return;
    MessageBoxW(NULL,
        L"The Dead Space 4GB Mod stopped this launch because Dead Space is running as administrator.\r\n\r\n"
        L"Close this copy and launch the game normally through EA App, Steam, or your usual shortcut. "
        L"Do not use Run as administrator for the game.",
        L"Dead Space (2008) 4GB Mod - Normal Launch Required",
        MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
}

static bool LaunchElevatedPatch(const wchar_t* worker, const wchar_t* request, const wchar_t* target,
    const BYTE expectedOriginalHash[32], wchar_t* reason, size_t reasonCap, bool* safeToRelaunch)
{
    *safeToRelaunch = false;
    char token[33];
    wchar_t descriptor[4096];
    HANDLE descriptorGuard = INVALID_HANDLE_VALUE;
    if (!GenerateToken(token) || !WriteElevationDescriptor(token, request, descriptor, &descriptorGuard))
    { *safeToRelaunch = true; wcscpy_s(reason, reasonCap, L"Could not create a verified elevation handoff."); return false; }

    wchar_t handoffDelay[16];
    if (GetEnvironmentVariableW(L"DEADSPACE4GB_TEST_ELEVATION_HANDOFF_DELAY_MS", handoffDelay, ARRAYSIZE(handoffDelay)))
        Sleep(_wtoi(handoffDelay));

    wchar_t rundll[4096], tokenWide[33];
    wchar_t* descriptorHex = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, 16385 * sizeof(wchar_t));
    wchar_t* parameters = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, 24576 * sizeof(wchar_t));
    if (!descriptorHex || !parameters)
    {
        if (descriptorHex) HeapFree(GetProcessHeap(), 0, descriptorHex); if (parameters) HeapFree(GetProcessHeap(), 0, parameters);
        CloseHandle(descriptorGuard); DeleteFileW(descriptor); *safeToRelaunch = true;
        wcscpy_s(reason, reasonCap, L"Not enough memory for the elevation handoff."); return false;
    }
    MultiByteToWideChar(CP_ACP, 0, token, 32, tokenWide, 32); tokenWide[32] = 0;
    bool pathsOk = X86Rundll32(rundll, ARRAYSIZE(rundll)) &&
        EncodeWideHex(descriptor, descriptorHex, 16385) &&
        _snwprintf_s(parameters, 24576, _TRUNCATE, L"\"%s\",Elevated %s %s", worker, tokenWide, descriptorHex) >= 0;
    HANDLE process = NULL;
    DWORD launchError = ERROR_SUCCESS;
    wchar_t seam[8];
    bool simulateCancelledConsent = pathsOk &&
        GetEnvironmentVariableW(L"DEADSPACE4GB_TEST_ELEVATION_CANCEL", seam, ARRAYSIZE(seam)) != 0;
    if (simulateCancelledConsent)
        launchError = ERROR_CANCELLED;
    else if (pathsOk && GetEnvironmentVariableW(L"DEADSPACE4GB_TEST_ELEVATION_NO_UAC", seam, ARRAYSIZE(seam)))
    {
        wchar_t* command = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, 32768 * sizeof(wchar_t));
        if (!command || _snwprintf_s(command, 32768, _TRUNCATE, L"\"%s\" %s", rundll, parameters) < 0)
        { launchError = ERROR_INSUFFICIENT_BUFFER; pathsOk = false; }
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        if (pathsOk && CreateProcessW(rundll, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        { CloseHandle(pi.hThread); process = pi.hProcess; }
        else if (!launchError) launchError = GetLastError();
        if (command) HeapFree(GetProcessHeap(), 0, command);
    }
    else if (pathsOk)
    {
        SHELLEXECUTEINFOW execute = { sizeof(execute) };
        execute.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
        execute.lpVerb = L"runas";
        execute.lpFile = rundll;
        execute.lpParameters = parameters;
        execute.nShow = SW_HIDE;
        if (ShellExecuteExW(&execute)) process = execute.hProcess;
        else launchError = GetLastError();
    }
    else launchError = ERROR_BAD_PATHNAME;
    HeapFree(GetProcessHeap(), 0, descriptorHex);
    HeapFree(GetProcessHeap(), 0, parameters);

    bool valid = false;
    if (process)
    {
        DWORD exitWait = WaitForSingleObject(process, 300000);
        DWORD exitCode = 0;
        if (exitWait == WAIT_OBJECT_0 && GetExitCodeProcess(process, &exitCode))
        {
            *safeToRelaunch = true;
            BYTE patchedHash[32];
            valid = exitCode == kElevatedSuccessExitCode &&
                ValidatePatchedStateForOriginal(target, expectedOriginalHash, patchedHash);
            Log(valid ? L"kernel-authenticated elevated process exit and patched state verified" :
                L"elevated process exit did not prove a complete patched state");
        }
        else
        {
            // The caller is holding the verified worker file and directory guards.  Never
            // release those guards while an elevated rundll32 may still load or execute it.
            // A timed-out worker also leaves patch state uncertain, so no relaunch is allowed.
            Log(L"elevated worker did not exit; containing it before releasing worker guards");
            TerminateProcess(process, ERROR_TIMEOUT);
            *safeToRelaunch = WaitForSingleObject(process, INFINITE) == WAIT_OBJECT_0;
        }
        CloseHandle(process);
    }
    else *safeToRelaunch = true;
    CloseHandle(descriptorGuard);
    DeleteFileW(descriptor);
    if (!valid)
    {
        if (launchError == ERROR_CANCELLED) wcscpy_s(reason, reasonCap, L"Windows administrator permission was declined.");
        else if (launchError) _snwprintf_s(reason, reasonCap, _TRUNCATE, L"The elevated patch worker could not start (Windows error %lu).", launchError);
        else wcscpy_s(reason, reasonCap, L"The elevated patch worker did not return a kernel-authenticated success status and a complete verified patch state.");
    }
    else if (!*safeToRelaunch)
    {
        valid = false;
        wcscpy_s(reason, reasonCap, L"The elevated patch result was valid, but the elevated worker did not exit; relaunch was withheld for safety.");
    }
    return valid;
}

static bool Relaunch(const wchar_t* executable, const wchar_t* command, const wchar_t* cwd)
{
    DWORD oldLength = GetEnvironmentVariableW(kBypass, NULL, 0);
    wchar_t* old = oldLength ? (wchar_t*)HeapAlloc(GetProcessHeap(), 0, oldLength * sizeof(wchar_t)) : NULL;
    if (old) GetEnvironmentVariableW(kBypass, old, oldLength);
    DWORD oldRoleLength = GetEnvironmentVariableW(L"DEADSPACE4GB_RELAUNCH_ROLE", NULL, 0);
    wchar_t* oldRole = oldRoleLength ? (wchar_t*)HeapAlloc(GetProcessHeap(), 0, oldRoleLength * sizeof(wchar_t)) : NULL;
    if (oldRole) GetEnvironmentVariableW(L"DEADSPACE4GB_RELAUNCH_ROLE", oldRole, oldRoleLength);
    SetEnvironmentVariableW(kBypass, L"1");
    wchar_t testRole[8];
    bool markRole = GetEnvironmentVariableW(L"DEADSPACE4GB_TEST_ROLE_MARKER", testRole, ARRAYSIZE(testRole)) != 0;
    if (markRole) SetEnvironmentVariableW(L"DEADSPACE4GB_RELAUNCH_ROLE", L"original-worker");
    wchar_t* mutableCommand = _wcsdup(command);
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    bool launched = mutableCommand && CreateProcessW(executable, mutableCommand, NULL, NULL, FALSE, 0, NULL,
        *cwd ? cwd : NULL, &si, &pi) != FALSE;
    if (launched) { CloseHandle(pi.hThread); CloseHandle(pi.hProcess); Log(L"relaunched target with process-scoped bypass"); }
    else Log(L"relaunch failed; user must launch Dead Space normally again");
    free(mutableCommand);
    if (old) { SetEnvironmentVariableW(kBypass, old); HeapFree(GetProcessHeap(), 0, old); }
    else SetEnvironmentVariableW(kBypass, NULL);
    if (markRole)
    {
        if (oldRole) SetEnvironmentVariableW(L"DEADSPACE4GB_RELAUNCH_ROLE", oldRole);
        else SetEnvironmentVariableW(L"DEADSPACE4GB_RELAUNCH_ROLE", NULL);
    }
    if (oldRole) HeapFree(GetProcessHeap(), 0, oldRole);
    return launched;
}

static bool ValidateWorkerRelationship(const wchar_t* executable)
{
    wchar_t worker[4096], proxy[4096];
    if (!GetModuleFileNameW(g_self, worker, ARRAYSIZE(worker)) ||
        _wcsicmp(BaseName(worker), L"DeadSpace4GBWorker.dll")) return false;
    wcscpy_s(proxy, ARRAYSIZE(proxy), executable);
    wchar_t* slash = wcsrchr(proxy, L'\\');
    if (!slash || wcscpy_s(slash + 1, ARRAYSIZE(proxy) - (slash + 1 - proxy), L"dsound.dll")) return false;
    BYTE workerHash[32], proxyHash[32];
    return Sha256(worker, workerHash) && Sha256(proxy, proxyHash) && SameHash(workerHash, proxyHash);
}

static bool OpenWorkerGuards(const wchar_t* worker, HANDLE* fileGuard, HANDLE* directoryGuard)
{
    *fileGuard = *directoryGuard = INVALID_HANDLE_VALUE;
    DWORD attributes = GetFileAttributesW(worker);
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) return false;
    wchar_t directory[4096];
    wcscpy_s(directory, ARRAYSIZE(directory), worker);
    wchar_t* slash = wcsrchr(directory, L'\\');
    if (!slash) return false;
    *slash = 0;
    attributes = GetFileAttributesW(directory);
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) return false;
    *directoryGuard = CreateFileW(directory, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (*directoryGuard == INVALID_HANDLE_VALUE) return false;
    *fileGuard = CreateFileW(worker, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (*fileGuard == INVALID_HANDLE_VALUE) { CloseHandle(*directoryGuard); *directoryGuard = INVALID_HANDLE_VALUE; return false; }
    FILE_ATTRIBUTE_TAG_INFO fileInfo = {}, directoryInfo = {};
    bool handlesValid = GetFileInformationByHandleEx(*fileGuard, FileAttributeTagInfo, &fileInfo, sizeof(fileInfo)) &&
        GetFileInformationByHandleEx(*directoryGuard, FileAttributeTagInfo, &directoryInfo, sizeof(directoryInfo)) &&
        !(fileInfo.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) &&
        (directoryInfo.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(directoryInfo.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
    if (!handlesValid)
    {
        CloseHandle(*fileGuard); CloseHandle(*directoryGuard);
        *fileGuard = *directoryGuard = INVALID_HANDLE_VALUE;
        return false;
    }
    return true;
}

extern "C" void CALLBACK Elevated(HWND, HINSTANCE, LPSTR commandLine, int)
{
    InterlockedExchange(&g_elevatedRole, 1);
    Log(L"elevated worker entered fail-closed logging role");
    while (*commandLine == ' ' || *commandLine == '\t' || *commandLine == '"') ++commandLine;
    char token[33] = {};
    size_t length = 0;
    while (length < 32 && commandLine[length] && commandLine[length] != ' ' && commandLine[length] != '\t' && commandLine[length] != '"')
    { token[length] = commandLine[length]; ++length; }
    bool tokenValid = length == 32 && ValidToken(token);
    if (!tokenValid) Log(L"elevated worker rejected invalid token");

    const char* encodedStart = commandLine + length;
    while (*encodedStart == ' ' || *encodedStart == '\t' || *encodedStart == '"') ++encodedStart;
    char encoded[16385] = {};
    size_t encodedLength = 0;
    while (encodedLength < 16384 && encodedStart[encodedLength] && encodedStart[encodedLength] != ' ' &&
        encodedStart[encodedLength] != '\t' && encodedStart[encodedLength] != '"')
    { encoded[encodedLength] = encodedStart[encodedLength]; ++encodedLength; }
    wchar_t descriptor[4096] = {}, request[4096] = {};
    bool descriptorPathDecoded = tokenValid && DecodeWideHex(encoded, descriptor, ARRAYSIZE(descriptor));
    if (!descriptorPathDecoded) Log(L"elevated worker rejected descriptor path");
    bool success = false;
    DWORD error = ERROR_INVALID_DATA;
    BYTE patchedHash[32] = {};
    RequestHeader h = {};
    BYTE expectedRequestHash[32] = {};
    wchar_t *executable = NULL, *command = NULL, *cwd = NULL;
    bool descriptorRead = descriptorPathDecoded && ReadElevationDescriptor(token, descriptor, request,
        expectedRequestHash);
    if (descriptorRead) Log(L"elevated worker accepted exact encoded descriptor path");
    if (descriptorRead && ReadVerifiedRequest(request, expectedRequestHash, &h, &executable, &command, &cwd))
    {
        HANDLE parent = OpenProcess(SYNCHRONIZE, FALSE, h.parentPid);
        bool parentEnded = !parent || WaitForSingleObject(parent, 0) == WAIT_OBJECT_0;
        if (parent) CloseHandle(parent);
        wchar_t reason[512] = L"The original game process is still running.";
        if (parentEnded && ValidateWorkerRelationship(executable))
        {
            SetEnvironmentVariableW(kElevatedWorkerEnvironment, L"1");
            wchar_t forced[8];
            bool forceFailure = GetEnvironmentVariableW(L"DEADSPACE4GB_TEST_FORCE_ELEVATED_PATCH_FAILURE",
                forced, ARRAYSIZE(forced)) != 0;
            success = !forceFailure && Patch(executable, h.originalTargetHash, reason, ARRAYSIZE(reason), &error) &&
                ValidatePatchedStateForOriginal(executable, h.originalTargetHash, patchedHash);
            SetEnvironmentVariableW(kElevatedWorkerEnvironment, NULL);
            if (forceFailure) error = ERROR_CANCELLED;
            if (!success && error == ERROR_SUCCESS) error = ERROR_CRC;
            Log(success ? L"elevated patch and independent verification succeeded" : reason);
        }
        else error = parentEnded ? ERROR_INVALID_DATA : ERROR_SHARING_VIOLATION;
    }
    if (executable) HeapFree(GetProcessHeap(), 0, executable);
    if (command) HeapFree(GetProcessHeap(), 0, command);
    if (cwd) HeapFree(GetProcessHeap(), 0, cwd);
    wchar_t forceFailureExit[8];
    if (success && GetEnvironmentVariableW(L"DEADSPACE4GB_TEST_FORCE_ELEVATED_FAILURE_EXIT_AFTER_PATCH",
        forceFailureExit, ARRAYSIZE(forceFailureExit)))
        success = false;
    FinishElevatedProcess(success);
}

extern "C" void CALLBACK Bootstrap(HWND, HINSTANCE, LPSTR, int)
{
    wchar_t request[4096];
    DWORD requestLength = GetEnvironmentVariableW(kRequestEnvironment, request, ARRAYSIZE(request));
    if (!requestLength || requestLength >= ARRAYSIZE(request)) { Log(L"missing bootstrap request environment"); return; }
    RequestHeader h = {};
    wchar_t *executable = NULL, *command = NULL, *cwd = NULL;
    HANDLE requestGuard = INVALID_HANDLE_VALUE;
    if (!ReadRequest(request, &h, &executable, &command, &cwd, &requestGuard))
    { Log(L"invalid request"); DeleteFileW(request); return; }
    Log(L"bootstrap request parsed");
    wchar_t workerPath[4096];
    HANDLE workerGuard = INVALID_HANDLE_VALUE, directoryGuard = INVALID_HANDLE_VALUE;
    if (!GetModuleFileNameW(g_self, workerPath, ARRAYSIZE(workerPath)) ||
        !OpenWorkerGuards(workerPath, &workerGuard, &directoryGuard) || !ValidateWorkerRelationship(executable))
    {
        Log(L"bootstrap could not lock the verified worker path; readiness withheld");
        CloseHandle(requestGuard); DeleteFileW(request);
        HeapFree(GetProcessHeap(), 0, executable); HeapFree(GetProcessHeap(), 0, command); HeapFree(GetProcessHeap(), 0, cwd);
        return;
    }
    HANDLE parent = OpenProcess(SYNCHRONIZE, FALSE, h.parentPid);
    if (!parent)
    {
        Log(L"bootstrap could not retain the original game process handle; readiness withheld");
        CloseHandle(workerGuard); CloseHandle(directoryGuard); CloseHandle(requestGuard); DeleteFileW(request);
        HeapFree(GetProcessHeap(), 0, executable); HeapFree(GetProcessHeap(), 0, command); HeapFree(GetProcessHeap(), 0, cwd);
        return;
    }
    SetEnvironmentVariableW(kRequestEnvironment, NULL);
    SetEnvironmentVariableW(kRequestHandleEnvironment, NULL);
    wchar_t readyName[256], commitName[256], cancelName[256], ackName[256], goName[256];
    DWORD readyLength = GetEnvironmentVariableW(kReadyEnvironment, readyName, ARRAYSIZE(readyName));
    DWORD commitLength = GetEnvironmentVariableW(kCommitEnvironment, commitName, ARRAYSIZE(commitName));
    DWORD cancelLength = GetEnvironmentVariableW(kCancelEnvironment, cancelName, ARRAYSIZE(cancelName));
    DWORD ackLength = GetEnvironmentVariableW(kAckEnvironment, ackName, ARRAYSIZE(ackName));
    DWORD goLength = GetEnvironmentVariableW(kGoEnvironment, goName, ARRAYSIZE(goName));
    HANDLE readyEvent = readyLength && readyLength < ARRAYSIZE(readyName) ? OpenEventW(EVENT_MODIFY_STATE, FALSE, readyName) : NULL;
    HANDLE commitEvent = commitLength && commitLength < ARRAYSIZE(commitName) ? OpenEventW(SYNCHRONIZE, FALSE, commitName) : NULL;
    HANDLE cancelEvent = cancelLength && cancelLength < ARRAYSIZE(cancelName) ? OpenEventW(SYNCHRONIZE, FALSE, cancelName) : NULL;
    HANDLE ackEvent = ackLength && ackLength < ARRAYSIZE(ackName) ? OpenEventW(EVENT_MODIFY_STATE, FALSE, ackName) : NULL;
    HANDLE goEvent = goLength && goLength < ARRAYSIZE(goName) ? OpenEventW(SYNCHRONIZE, FALSE, goName) : NULL;
    if (!readyEvent || !commitEvent || !cancelEvent || !ackEvent || !goEvent)
    {
        if (readyEvent) CloseHandle(readyEvent); if (commitEvent) CloseHandle(commitEvent); if (cancelEvent) CloseHandle(cancelEvent); if (ackEvent) CloseHandle(ackEvent); if (goEvent) CloseHandle(goEvent);
        CloseHandle(parent); CloseHandle(workerGuard); CloseHandle(directoryGuard); CloseHandle(requestGuard); DeleteFileW(request); Log(L"bootstrap handoff events were invalid");
        HeapFree(GetProcessHeap(), 0, executable); HeapFree(GetProcessHeap(), 0, command); HeapFree(GetProcessHeap(), 0, cwd);
        return;
    }
    wchar_t mutexName[128];
    HANDLE targetMutex = TargetMutexName(executable, mutexName, ARRAYSIZE(mutexName)) ?
        CreateMutexW(NULL, FALSE, mutexName) : NULL;
    HANDLE mutexDecision[2] = { targetMutex, cancelEvent };
    DWORD mutexWait = targetMutex ? WaitForMultipleObjects(2, mutexDecision, FALSE, 0) : WAIT_FAILED;
    bool mutexOwned = mutexWait == WAIT_OBJECT_0 || mutexWait == WAIT_ABANDONED_0;
    PeInfo lockedInfo = {};
    BYTE lockedHash[32];
    bool mutexQueued = targetMutex && mutexWait == WAIT_TIMEOUT;
    bool lockedStateValid = mutexQueued || (mutexOwned && Inspect(executable, &lockedInfo) &&
        (lockedInfo.laa || (Sha256(executable, lockedHash) && SameHash(lockedHash, h.originalTargetHash))));
    if (!lockedStateValid)
    {
        Log(mutexOwned ? L"target changed before serialized patch handoff; readiness withheld" :
            L"target patch singleton was cancelled or unavailable; readiness withheld");
        if (mutexOwned) ReleaseTargetMutex(targetMutex); else if (targetMutex) CloseHandle(targetMutex);
        CloseHandle(readyEvent); CloseHandle(commitEvent); CloseHandle(cancelEvent); CloseHandle(ackEvent); CloseHandle(goEvent);
        CloseHandle(parent); CloseHandle(workerGuard); CloseHandle(directoryGuard); CloseHandle(requestGuard); DeleteFileW(request);
        HeapFree(GetProcessHeap(), 0, executable); HeapFree(GetProcessHeap(), 0, command); HeapFree(GetProcessHeap(), 0, cwd);
        return;
    }
    Log(mutexOwned ? L"target patch singleton acquired before readiness" :
        L"target patch singleton busy; this launch will exit before waiting for serialized patch access");
    wchar_t delayText[16];
    if (GetEnvironmentVariableW(L"DEADSPACE4GB_TEST_WORKER_READY_DELAY_MS", delayText, ARRAYSIZE(delayText))) Sleep(_wtoi(delayText));
    SetEvent(readyEvent);
    CloseHandle(readyEvent);
    HANDLE decision[2] = { commitEvent, cancelEvent };
    DWORD decisionResult = WaitForMultipleObjects(2, decision, FALSE, 15000);
    CloseHandle(commitEvent);
    if (decisionResult == WAIT_OBJECT_0)
    {
        wchar_t ackDelay[16];
        if (GetEnvironmentVariableW(L"DEADSPACE4GB_TEST_WORKER_ACK_DELAY_MS", ackDelay, ARRAYSIZE(ackDelay))) Sleep(_wtoi(ackDelay));
        SetEvent(ackEvent);
    }
    DWORD goResult = WAIT_FAILED;
    if (decisionResult == WAIT_OBJECT_0)
    {
        HANDLE finalDecision[2] = { goEvent, cancelEvent };
        goResult = WaitForMultipleObjects(2, finalDecision, FALSE, 15000);
    }
    CloseHandle(cancelEvent); CloseHandle(ackEvent); CloseHandle(goEvent);
    SetEnvironmentVariableW(kReadyEnvironment, NULL);
    SetEnvironmentVariableW(kCommitEnvironment, NULL);
    SetEnvironmentVariableW(kCancelEnvironment, NULL);
    SetEnvironmentVariableW(kAckEnvironment, NULL);
    SetEnvironmentVariableW(kGoEnvironment, NULL);
    if (decisionResult != WAIT_OBJECT_0 || goResult != WAIT_OBJECT_0)
    {
        Log(L"bootstrap handoff cancelled before final GO; no patch or relaunch attempted");
        ReleaseTargetMutex(targetMutex);
        CloseHandle(parent); CloseHandle(workerGuard); CloseHandle(directoryGuard); CloseHandle(requestGuard); DeleteFileW(request);
        HeapFree(GetProcessHeap(), 0, executable); HeapFree(GetProcessHeap(), 0, command); HeapFree(GetProcessHeap(), 0, cwd);
        return;
    }
    bool parentEnded = false;
    bool permissionDenied = false;
    DWORD parentWaitMs = 60000;
    wchar_t waitText[16];
    if (GetEnvironmentVariableW(L"DEADSPACE4GB_TEST_PARENT_WAIT_MS", waitText, ARRAYSIZE(waitText))) parentWaitMs = _wtoi(waitText);
    parentEnded = WaitForSingleObject(parent, parentWaitMs) == WAIT_OBJECT_0;
    CloseHandle(parent);
    if (parentEnded && !mutexOwned)
    {
        DWORD serializedWait = WaitForSingleObject(targetMutex, 60000);
        mutexOwned = serializedWait == WAIT_OBJECT_0 || serializedWait == WAIT_ABANDONED;
        if (mutexOwned) Log(L"queued launch acquired target patch singleton after its parent exited");
    }
    bool locallyWritable = false;
    BYTE serializedPatchedHash[32];
    bool alreadyPatched = parentEnded && mutexOwned &&
        ValidatePatchedStateForOriginal(executable, h.originalTargetHash, serializedPatchedHash);
    if (alreadyPatched) Log(L"serialized launch found a complete patch state; no executable write is needed");
    if (mutexQueued && parentEnded && mutexOwned)
    {
        // This parent deliberately exited after another first-launch worker had
        // already claimed ownership of this target.  The first worker is the
        // sole owner of every outcome: verified relaunch, unchanged fallback,
        // and any elevation prompt.  A queued worker may classify the final
        // serialized state, but it must never write, elevate, or relaunch.
        TargetSafetyState queuedState = ValidateTargetSafety(executable, h.originalTargetHash);
        if (queuedState == TargetStatePatched)
            Log(L"queued duplicate launch suppressed after verified patch completion");
        else if (queuedState == TargetStateOriginal)
            Log(L"queued duplicate launch suppressed after verified unchanged fallback");
        else
        {
            const wchar_t* queuedReason =
                L"The serialized first-launch owner left an incomplete or invalid patch state.";
            Log(L"queued duplicate launch blocked on incomplete serialized patch state; no relaunch attempted");
            ShowRecoveryBlocked(queuedReason);
        }
        CloseHandle(requestGuard); DeleteFileW(request);
        CloseHandle(workerGuard); CloseHandle(directoryGuard);
        ReleaseTargetMutex(targetMutex);
        HeapFree(GetProcessHeap(), 0, executable); HeapFree(GetProcessHeap(), 0, command); HeapFree(GetProcessHeap(), 0, cwd);
        return;
    }
    if (parentEnded && mutexOwned && !alreadyPatched)
    {
        for (int attempt = 0; attempt < 1200; ++attempt)
        {
            HANDLE probe = CreateFileW(executable, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (probe != INVALID_HANDLE_VALUE) { CloseHandle(probe); locallyWritable = true; break; }
            if (IsPermissionError(GetLastError())) { permissionDenied = true; break; }
            Sleep(50);
        }
    }
    if (locallyWritable) Log(L"parent ended and executable is exclusively writable");
    wchar_t reason[512] = L"The original game process did not exit in time.";
    bool patched = alreadyPatched;
    bool safeToRelaunch = true;
    bool elevationAttempted = false;
    DWORD patchError = permissionDenied ? ERROR_ACCESS_DENIED : ERROR_SUCCESS;
    if (locallyWritable)
    {
        patched = Patch(executable, h.originalTargetHash, reason, ARRAYSIZE(reason), &patchError);
    }
    if (!parentEnded || !mutexOwned)
    {
        if (parentEnded && !mutexOwned)
            wcscpy_s(reason, ARRAYSIZE(reason), L"Timed out waiting for the serialized target patch operation.");
        Log(reason);
        WriteFailureMarker(executable, reason);
        ShowPatchFailure(reason, parentEnded ? L"The original process exited, but no replacement copy was started." :
            L"The current game process was left running; no second copy was started.");
        ReleaseTargetMutex(targetMutex);
        CloseHandle(workerGuard); CloseHandle(directoryGuard); CloseHandle(requestGuard); DeleteFileW(request);
        HeapFree(GetProcessHeap(), 0, executable); HeapFree(GetProcessHeap(), 0, command); HeapFree(GetProcessHeap(), 0, cwd);
        return;
    }
    if (!locallyWritable && !permissionDenied)
        wcscpy_s(reason, ARRAYSIZE(reason), L"Dead Space.exe remained locked after the original process exited.");
    if (!patched && (permissionDenied || IsPermissionError(patchError)))
    {
        elevationAttempted = true;
        wchar_t worker[4096];
        if (GetModuleFileNameW(g_self, worker, ARRAYSIZE(worker)))
        {
            Log(L"medium-integrity write was denied; requesting narrow elevated patch worker");
            patched = LaunchElevatedPatch(worker, request, executable, h.originalTargetHash,
                reason, ARRAYSIZE(reason), &safeToRelaunch);
        }
        else wcscpy_s(reason, ARRAYSIZE(reason), L"Could not locate the verified elevation worker DLL.");
    }
    TargetSafetyState targetState = ValidateTargetSafety(executable, h.originalTargetHash);
    if (patched && targetState != TargetStatePatched)
    {
        patched = false;
        safeToRelaunch = false;
        wcscpy_s(reason, ARRAYSIZE(reason),
            L"The patch worker reported success, but the final executable state could not be independently verified.");
    }
    else if (!patched && targetState == TargetStatePatched && !elevationAttempted)
    {
        patched = true;
        Log(L"patch result handoff failed, but complete patched state was independently verified");
    }
    else if (!patched && targetState == TargetStatePatched && elevationAttempted)
    {
        safeToRelaunch = false;
        wcscpy_s(reason, ARRAYSIZE(reason),
            L"The elevated worker did not return its exact authenticated success status, so a patched-looking state was not accepted and restart was withheld.");
    }
    else if (!patched && targetState == TargetStateUnsafe)
    {
        safeToRelaunch = false;
        wcscpy_s(reason, ARRAYSIZE(reason),
            L"Patch recovery did not leave a provably original or complete patched executable; restart was withheld.");
    }
    if (patched)
    {
        ClearFailureMarker(executable);
        Log(L"patch and verification succeeded");
        if (!safeToRelaunch) ShowRelaunchFailure();
    }
    else
    {
        Log(reason);
        WriteFailureMarker(executable, reason);
        ShowPatchFailure(reason, safeToRelaunch ? L"The game will now start unchanged." :
            L"For safety, the game was not restarted. Run Restore Dead Space 4GB Mod.cmd now. If it refuses, use EA App Repair or Steam Verify Files before launching again.");
    }
    CloseHandle(requestGuard); DeleteFileW(request);
    if (!safeToRelaunch)
    {
        ReleaseTargetMutex(targetMutex);
        CloseHandle(workerGuard); CloseHandle(directoryGuard);
        HeapFree(GetProcessHeap(), 0, executable); HeapFree(GetProcessHeap(), 0, command); HeapFree(GetProcessHeap(), 0, cwd);
        return;
    }
    CloseHandle(workerGuard); CloseHandle(directoryGuard);
    bool relaunched = Relaunch(executable, command, cwd);
    ReleaseTargetMutex(targetMutex);
    if (!relaunched)
        ShowRelaunchFailure();
    HeapFree(GetProcessHeap(), 0, executable);
    HeapFree(GetProcessHeap(), 0, command);
    HeapFree(GetProcessHeap(), 0, cwd);
}

extern "C" void CALLBACK Restore(HWND, HINSTANCE, LPSTR commandLine, int)
{
    InterlockedExchange(&g_elevatedRole, 1);
    Log(L"restore worker entered fail-closed logging role");
    wchar_t target[4096];
    DWORD targetLength = GetEnvironmentVariableW(L"DEADSPACE4GB_RESTORE_TARGET", target, ARRAYSIZE(target));
    if (!targetLength || targetLength >= ARRAYSIZE(target))
    {
        while (*commandLine == ' ' || *commandLine == '\t' || *commandLine == '"') ++commandLine;
        size_t n = strlen(commandLine);
        while (n && (commandLine[n - 1] == ' ' || commandLine[n - 1] == '\t' || commandLine[n - 1] == '"')) --n;
        int converted = n ? MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, commandLine, (int)n, target, ARRAYSIZE(target) - 1) : 0;
        if (!converted) FinishRestoreProcess(false);
        target[converted] = 0;
    }
    wchar_t reason[512] = L"restore succeeded";
    bool restored = Restore(target, reason, ARRAYSIZE(reason));
    FinishRestoreProcess(restored);
}

enum BootstrapStartResult { BootstrapNotNeeded, BootstrapStarted, BootstrapFailed, BootstrapBlocked,
    BootstrapHighIntegrityBlocked };

static bool OwnPatchArtifactsPresent(const wchar_t* target)
{
    wchar_t backup[4096], manifest[4096];
    _snwprintf_s(backup, ARRAYSIZE(backup), _TRUNCATE, L"%s.deadspace-laa.bak", target);
    _snwprintf_s(manifest, ARRAYSIZE(manifest), _TRUNCATE, L"%s.deadspace-laa.manifest.json", target);
    return GetFileAttributesW(backup) != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesW(manifest) != INVALID_FILE_ATTRIBUTES;
}

struct EnvironmentSnapshot { const wchar_t* name; wchar_t* value; bool existed; };

static void CaptureEnvironment(EnvironmentSnapshot* snapshot, const wchar_t* name)
{
    snapshot->name = name; snapshot->value = NULL;
    DWORD length = GetEnvironmentVariableW(name, NULL, 0);
    snapshot->existed = length != 0;
    if (length)
    {
        snapshot->value = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, length * sizeof(wchar_t));
        if (snapshot->value) GetEnvironmentVariableW(name, snapshot->value, length);
    }
}

static void RestoreEnvironment(EnvironmentSnapshot* snapshot)
{
    SetEnvironmentVariableW(snapshot->name, snapshot->existed && snapshot->value ? snapshot->value : NULL);
    if (snapshot->value) HeapFree(GetProcessHeap(), 0, snapshot->value);
}

static BootstrapStartResult StartBootstrap(wchar_t* reason, size_t reasonCap)
{
    wchar_t executable[4096], dll[4096], worker[4096], state[4096], rundll[4096], request[4096];
    if (!GetModuleFileNameW(NULL, executable, ARRAYSIZE(executable)))
    { wcscpy_s(reason, reasonCap, L"Could not identify the running executable."); return BootstrapFailed; }
    if (_wcsicmp(BaseName(executable), kGameName)) return BootstrapNotNeeded;
    // A high-integrity game would turn all later state/request/log writes into a
    // cross-integrity surface.  Fail before inspecting artifacts, resolving the
    // state directory, logging, or creating any worker file.
    if (HighIntegrityOrUnknown())
    {
        wcscpy_s(reason, reasonCap, L"Dead Space was launched at high integrity; normal launch is required.");
        return BootstrapHighIntegrityBlocked;
    }
    PeInfo info = {};
    if (!Inspect(executable, &info))
    { wcscpy_s(reason, reasonCap, L"Dead Space.exe is not a valid supported 32-bit executable."); return BootstrapFailed; }
    if (info.laa)
    {
        if (!OwnPatchArtifactsPresent(executable)) return BootstrapNotNeeded;
        BYTE patchedHash[32];
        if (ValidatePatchedState(executable, patchedHash)) return BootstrapNotNeeded;
        wcscpy_s(reason, reasonCap,
            L"Dead Space.exe is LAA, but this mod's backup and manifest do not form a complete verified patch state.");
        return BootstrapBlocked;
    }
    wchar_t bypass[8];
    if (GetEnvironmentVariableW(kBypass, bypass, ARRAYSIZE(bypass))) return BootstrapNotNeeded;
    if (!GetModuleFileNameW(g_self, dll, ARRAYSIZE(dll)) || !StateDirectory(state, ARRAYSIZE(state)))
    { wcscpy_s(reason, reasonCap, L"Could not locate the mod or its private state folder."); return BootstrapFailed; }
    if (!CreateDirectoryW(state, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
    { wcscpy_s(reason, reasonCap, L"Could not create the mod's private state folder."); return BootstrapFailed; }
    if (!Join(worker, ARRAYSIZE(worker), state, L"DeadSpace4GBWorker.dll") ||
        !EnsureRuntimeWorker(dll, worker))
    { wcscpy_s(reason, reasonCap, L"Could not create and verify the private patch worker handoff."); return BootstrapFailed; }
    HANDLE workerGuard = INVALID_HANDLE_VALUE, directoryGuard = INVALID_HANDLE_VALUE;
    HANDLE requestGuard = INVALID_HANDLE_VALUE;
    BYTE deployedHash[32], workerHash[32];
    if (!OpenWorkerGuards(worker, &workerGuard, &directoryGuard) || !Sha256(dll, deployedHash) ||
        !Sha256(worker, workerHash) || !SameHash(deployedHash, workerHash) ||
        !CreateRequest(executable, request, ARRAYSIZE(request), &requestGuard))
    {
        if (workerGuard != INVALID_HANDLE_VALUE) CloseHandle(workerGuard);
        if (directoryGuard != INVALID_HANDLE_VALUE) CloseHandle(directoryGuard);
        if (requestGuard != INVALID_HANDLE_VALUE) CloseHandle(requestGuard);
        wcscpy_s(reason, reasonCap, L"Could not lock and create the private patch worker handoff."); return BootstrapFailed;
    }
    if (!X86Rundll32(rundll, ARRAYSIZE(rundll)))
    { CloseHandle(workerGuard); CloseHandle(directoryGuard); CloseHandle(requestGuard); DeleteFileW(request); wcscpy_s(reason, reasonCap, L"Could not locate the 32-bit Windows patch-worker host."); return BootstrapFailed; }
    wchar_t command[32768];
    if (_snwprintf_s(command, ARRAYSIZE(command), _TRUNCATE, L"\"%s\" \"%s\",Bootstrap", rundll, worker) < 0)
    { CloseHandle(workerGuard); CloseHandle(directoryGuard); CloseHandle(requestGuard); DeleteFileW(request); wcscpy_s(reason, reasonCap, L"The patch-worker launch command was too long."); return BootstrapFailed; }
    char eventToken[33];
    wchar_t eventTokenWide[33], readyName[256], commitName[256], cancelName[256], ackName[256], goName[256];
    if (!GenerateToken(eventToken) || !MultiByteToWideChar(CP_ACP, 0, eventToken, 32, eventTokenWide, 32))
    { CloseHandle(workerGuard); CloseHandle(directoryGuard); CloseHandle(requestGuard); DeleteFileW(request); wcscpy_s(reason, reasonCap, L"Could not generate an unpredictable patch handshake."); return BootstrapFailed; }
    eventTokenWide[32] = 0;
    _snwprintf_s(readyName, ARRAYSIZE(readyName), _TRUNCATE, L"Local\\DeadSpace4GBReady-%s", eventTokenWide);
    _snwprintf_s(commitName, ARRAYSIZE(commitName), _TRUNCATE, L"Local\\DeadSpace4GBCommit-%s", eventTokenWide);
    _snwprintf_s(cancelName, ARRAYSIZE(cancelName), _TRUNCATE, L"Local\\DeadSpace4GBCancel-%s", eventTokenWide);
    _snwprintf_s(ackName, ARRAYSIZE(ackName), _TRUNCATE, L"Local\\DeadSpace4GBAck-%s", eventTokenWide);
    _snwprintf_s(goName, ARRAYSIZE(goName), _TRUNCATE, L"Local\\DeadSpace4GBGo-%s", eventTokenWide);
    SetLastError(ERROR_SUCCESS); HANDLE readyEvent = CreateEventW(NULL, TRUE, FALSE, readyName); bool collision = GetLastError() == ERROR_ALREADY_EXISTS;
    SetLastError(ERROR_SUCCESS); HANDLE commitEvent = CreateEventW(NULL, TRUE, FALSE, commitName); collision = collision || GetLastError() == ERROR_ALREADY_EXISTS;
    SetLastError(ERROR_SUCCESS); HANDLE cancelEvent = CreateEventW(NULL, TRUE, FALSE, cancelName); collision = collision || GetLastError() == ERROR_ALREADY_EXISTS;
    SetLastError(ERROR_SUCCESS); HANDLE ackEvent = CreateEventW(NULL, TRUE, FALSE, ackName); collision = collision || GetLastError() == ERROR_ALREADY_EXISTS;
    SetLastError(ERROR_SUCCESS); HANDLE goEvent = CreateEventW(NULL, TRUE, FALSE, goName); collision = collision || GetLastError() == ERROR_ALREADY_EXISTS;
    if (!readyEvent || !commitEvent || !cancelEvent || !ackEvent || !goEvent || collision)
    {
        if (readyEvent) CloseHandle(readyEvent); if (commitEvent) CloseHandle(commitEvent); if (cancelEvent) CloseHandle(cancelEvent); if (ackEvent) CloseHandle(ackEvent); if (goEvent) CloseHandle(goEvent);
        CloseHandle(workerGuard); CloseHandle(directoryGuard); CloseHandle(requestGuard); DeleteFileW(request); wcscpy_s(reason, reasonCap, L"Could not create a unique safe patch-worker handshake."); return BootstrapFailed;
    }
    STARTUPINFOEXW si = {};
    si.StartupInfo.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    SIZE_T attributeBytes = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeBytes);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeBytes);
    bool inheritReady = si.lpAttributeList &&
        InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeBytes) &&
        SetHandleInformation(requestGuard, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) &&
        UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            &requestGuard, sizeof(requestGuard), NULL, NULL);
    EnvironmentSnapshot snapshots[7];
    CaptureEnvironment(&snapshots[0], kRequestEnvironment); CaptureEnvironment(&snapshots[1], kReadyEnvironment);
    CaptureEnvironment(&snapshots[2], kCommitEnvironment); CaptureEnvironment(&snapshots[3], kCancelEnvironment);
    CaptureEnvironment(&snapshots[4], kAckEnvironment);
    CaptureEnvironment(&snapshots[5], kGoEnvironment);
    CaptureEnvironment(&snapshots[6], kRequestHandleEnvironment);
    wchar_t requestHandleText[32];
    _snwprintf_s(requestHandleText, ARRAYSIZE(requestHandleText), _TRUNCATE, L"%llx",
        (unsigned long long)(ULONG_PTR)requestGuard);
    SetEnvironmentVariableW(kRequestEnvironment, request);
    SetEnvironmentVariableW(kRequestHandleEnvironment, requestHandleText);
    SetEnvironmentVariableW(kReadyEnvironment, readyName);
    SetEnvironmentVariableW(kCommitEnvironment, commitName);
    SetEnvironmentVariableW(kCancelEnvironment, cancelName);
    SetEnvironmentVariableW(kAckEnvironment, ackName);
    SetEnvironmentVariableW(kGoEnvironment, goName);
    bool launched = inheritReady && CreateProcessW(rundll, command, NULL, NULL, TRUE,
        CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi) != FALSE;
    SetHandleInformation(requestGuard, HANDLE_FLAG_INHERIT, 0);
    if (si.lpAttributeList) { DeleteProcThreadAttributeList(si.lpAttributeList); HeapFree(GetProcessHeap(), 0, si.lpAttributeList); }
    for (int i = 0; i < 7; ++i) RestoreEnvironment(&snapshots[i]);
    if (!launched)
    {
        CloseHandle(readyEvent); CloseHandle(commitEvent); CloseHandle(cancelEvent); CloseHandle(ackEvent); CloseHandle(goEvent);
        CloseHandle(workerGuard); CloseHandle(directoryGuard); CloseHandle(requestGuard); DeleteFileW(request);
        wcscpy_s(reason, reasonCap, L"Windows could not start the private patch worker."); return BootstrapFailed;
    }
    CloseHandle(pi.hThread);
    DWORD readyTimeout = 30000;
    wchar_t readyTimeoutText[16];
    if (GetEnvironmentVariableW(L"DEADSPACE4GB_TEST_READY_TIMEOUT_MS", readyTimeoutText, ARRAYSIZE(readyTimeoutText)))
        readyTimeout = _wtoi(readyTimeoutText);
    bool ready = WaitForSingleObject(readyEvent, readyTimeout) == WAIT_OBJECT_0;
    bool committed = ready && SetEvent(commitEvent) != FALSE;
    bool acknowledged = committed && WaitForSingleObject(ackEvent, 5000) == WAIT_OBJECT_0;
    bool goSent = acknowledged && SetEvent(goEvent) != FALSE;
    if (!goSent)
    {
        SetEvent(cancelEvent);
        if (WaitForSingleObject(pi.hProcess, 5000) != WAIT_OBJECT_0) TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(readyEvent); CloseHandle(commitEvent); CloseHandle(cancelEvent); CloseHandle(ackEvent); CloseHandle(goEvent);
        CloseHandle(workerGuard); CloseHandle(directoryGuard); CloseHandle(requestGuard);
        DeleteFileW(request);
        wcscpy_s(reason, reasonCap, !ready ? L"The patch worker did not become ready; it was cancelled without patching." :
            !committed ? L"The patch worker could not be committed safely." :
            !acknowledged ? L"The patch worker did not acknowledge commit and was stopped before the game was changed." :
            L"The final patch-worker GO signal failed; the worker was cancelled before the game was changed.");
        return BootstrapFailed;
    }
    CloseHandle(readyEvent); CloseHandle(commitEvent); CloseHandle(cancelEvent); CloseHandle(ackEvent); CloseHandle(goEvent);
    CloseHandle(pi.hProcess);
    CloseHandle(workerGuard); CloseHandle(directoryGuard); CloseHandle(requestGuard);
    Log(L"out-of-process bootstrap launched; ending unpatched first process");
    wchar_t keepParent[8];
    if (GetEnvironmentVariableW(L"DEADSPACE4GB_TEST_DO_NOT_END_PARENT", keepParent, ARRAYSIZE(keepParent))) return BootstrapStarted;
    TerminateProcess(GetCurrentProcess(), 0);
    return BootstrapStarted;
}

static bool EnsureBootstrap()
{
    if (InterlockedCompareExchange(&g_once, 1, 0) == 0)
    {
        wchar_t reason[512] = L"Unknown patch-worker startup failure.";
        BootstrapStartResult result = StartBootstrap(reason, ARRAYSIZE(reason));
        if (result == BootstrapFailed)
        { Log(reason); ShowPatchFailure(reason, L"The current game launch will continue unchanged."); }
        else if (result == BootstrapBlocked)
        {
            InterlockedExchange(&g_bootstrapBlocked, 1);
            Log(reason);
            ShowRecoveryBlocked(reason);
            ExitProcess(ERROR_INVALID_STATE);
        }
        else if (result == BootstrapHighIntegrityBlocked)
        {
            InterlockedExchange(&g_bootstrapBlocked, 1);
            ShowHighIntegrityBlocked();
            ExitProcess(ERROR_ELEVATION_REQUIRED);
        }
    }
    return InterlockedCompareExchange(&g_bootstrapBlocked, 0, 0) == 0;
}

static BOOL CALLBACK LoadRealOnce(PINIT_ONCE, PVOID, PVOID*)
{
    wchar_t system[4096], path[4096];
    if (!GetSystemDirectoryW(system, ARRAYSIZE(system)) || !Join(path, ARRAYSIZE(path), system, L"dsound.dll")) return FALSE;
    HMODULE real = LoadLibraryW(path);
    if (!real) return FALSE;
#define LOCAL(name) FARPROC local_##name = NULL;
    DSOUND_EXPORTS(LOCAL)
#undef LOCAL
#define RESOLVE(name) local_##name = GetProcAddress(real, #name);
    DSOUND_EXPORTS(RESOLVE)
#undef RESOLVE
    bool complete = true;
#define CHECK(name) complete = complete && local_##name != NULL;
    DSOUND_EXPORTS(CHECK)
#undef CHECK
    if (!complete) { FreeLibrary(real); return FALSE; }
    g_real = real;
#define PUBLISH(name) g_##name = local_##name;
    DSOUND_EXPORTS(PUBLISH)
#undef PUBLISH
    return TRUE;
}

static bool EnsureReal()
{
    return InitOnceExecuteOnce(&g_dsoundInit, LoadRealOnce, NULL, NULL) != FALSE;
}

extern "C" HRESULT WINAPI proxy_DirectSoundCaptureCreate(LPCGUID a, LPDIRECTSOUNDCAPTURE* b, LPUNKNOWN c)
{ typedef HRESULT (WINAPI* Fn)(LPCGUID, LPDIRECTSOUNDCAPTURE*, LPUNKNOWN); return EnsureReal() ? ((Fn)g_DirectSoundCaptureCreate)(a,b,c) : E_FAIL; }

extern "C" HRESULT WINAPI proxy_DirectSoundCaptureCreate8(LPCGUID a, LPDIRECTSOUNDCAPTURE8* b, LPUNKNOWN c)
{ typedef HRESULT (WINAPI* Fn)(LPCGUID, LPDIRECTSOUNDCAPTURE8*, LPUNKNOWN); return EnsureReal() ? ((Fn)g_DirectSoundCaptureCreate8)(a,b,c) : E_FAIL; }

extern "C" HRESULT WINAPI proxy_DirectSoundCaptureEnumerateA(LPDSENUMCALLBACKA a, LPVOID b)
{ typedef HRESULT (WINAPI* Fn)(LPDSENUMCALLBACKA, LPVOID); return EnsureReal() ? ((Fn)g_DirectSoundCaptureEnumerateA)(a,b) : E_FAIL; }

extern "C" HRESULT WINAPI proxy_DirectSoundCaptureEnumerateW(LPDSENUMCALLBACKW a, LPVOID b)
{ typedef HRESULT (WINAPI* Fn)(LPDSENUMCALLBACKW, LPVOID); return EnsureReal() ? ((Fn)g_DirectSoundCaptureEnumerateW)(a,b) : E_FAIL; }

extern "C" HRESULT WINAPI proxy_DirectSoundCreate(LPCGUID a, LPDIRECTSOUND* b, LPUNKNOWN c)
{
    if (!EnsureBootstrap()) return E_FAIL;
    typedef HRESULT (WINAPI* Fn)(LPCGUID, LPDIRECTSOUND*, LPUNKNOWN);
    return EnsureReal() ? ((Fn)g_DirectSoundCreate)(a,b,c) : E_FAIL;
}

extern "C" HRESULT WINAPI proxy_DirectSoundCreate8(LPCGUID a, LPDIRECTSOUND8* b, LPUNKNOWN c)
{ typedef HRESULT (WINAPI* Fn)(LPCGUID, LPDIRECTSOUND8*, LPUNKNOWN); return EnsureReal() ? ((Fn)g_DirectSoundCreate8)(a,b,c) : E_FAIL; }

extern "C" HRESULT WINAPI proxy_DirectSoundEnumerateA(LPDSENUMCALLBACKA a, LPVOID b)
{ typedef HRESULT (WINAPI* Fn)(LPDSENUMCALLBACKA, LPVOID); return EnsureReal() ? ((Fn)g_DirectSoundEnumerateA)(a,b) : E_FAIL; }

extern "C" HRESULT WINAPI proxy_DirectSoundEnumerateW(LPDSENUMCALLBACKW a, LPVOID b)
{ typedef HRESULT (WINAPI* Fn)(LPDSENUMCALLBACKW, LPVOID); return EnsureReal() ? ((Fn)g_DirectSoundEnumerateW)(a,b) : E_FAIL; }

extern "C" HRESULT WINAPI proxy_DirectSoundFullDuplexCreate(LPCGUID a, LPCGUID b, LPCDSCBUFFERDESC c,
    LPCDSBUFFERDESC d, HWND e, DWORD f, LPDIRECTSOUNDFULLDUPLEX* g,
    LPDIRECTSOUNDCAPTUREBUFFER8* h, LPDIRECTSOUNDBUFFER8* i, LPUNKNOWN j)
{
    typedef HRESULT (WINAPI* Fn)(LPCGUID,LPCGUID,LPCDSCBUFFERDESC,LPCDSBUFFERDESC,HWND,DWORD,
        LPDIRECTSOUNDFULLDUPLEX*,LPDIRECTSOUNDCAPTUREBUFFER8*,LPDIRECTSOUNDBUFFER8*,LPUNKNOWN);
    return EnsureReal() ? ((Fn)g_DirectSoundFullDuplexCreate)(a,b,c,d,e,f,g,h,i,j) : E_FAIL;
}

extern "C" HRESULT WINAPI proxy_DllCanUnloadNow()
{ typedef HRESULT (WINAPI* Fn)(); return EnsureReal() ? ((Fn)g_DllCanUnloadNow)() : E_FAIL; }

extern "C" HRESULT WINAPI proxy_DllGetClassObject(REFCLSID a, REFIID b, LPVOID* c)
{ typedef HRESULT (WINAPI* Fn)(REFCLSID,REFIID,LPVOID*); return EnsureReal() ? ((Fn)g_DllGetClassObject)(a,b,c) : E_FAIL; }

extern "C" HRESULT WINAPI proxy_GetDeviceID(LPCGUID a, LPGUID b)
{
    if (!EnsureBootstrap()) return E_FAIL;
    typedef HRESULT (WINAPI* Fn)(LPCGUID, LPGUID);
    return EnsureReal() ? ((Fn)g_GetDeviceID)(a,b) : E_FAIL;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        g_self = instance;
    }
    return TRUE;
}
