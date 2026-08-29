// WINDOWS USER-MODE SOCD / NULL BIND / SNAP TAP
//
// Build: rc /nologo /fo bin/null_bind.res null_bind.rc && cl main.cpp /O2 /DNDEBUG /std:c++20 /nologo /W4 /GS- /Zl /GL /Gw /FA /Fabin/ /Fobin/ /Febin/null_bind.exe bin/null_bind.res /link /LTCG /OPT:REF /OPT:ICF /MERGE:.pdata=.rdata
// Run:   bin/null_bind.exe

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <avrt.h>
#include <stdarg.h>
#include <string.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "avrt.lib")
#pragma comment(linker, "/SUBSYSTEM:CONSOLE")

// Build with /DSHORT_CIRCUIT=1 to pass HC_ACTION events without notifying later hooks.
// Not recommended.
#ifndef SHORT_CIRCUIT
    #define SHORT_CIRCUIT 0
#endif
#if SHORT_CIRCUIT
    #define PASS_HC_ACTION(wp, lp) 0
#else
    #define PASS_HC_ACTION(wp, lp) CallNextHookEx(NULL, HC_ACTION, (wp), (lp))
#endif

// Each key may only be in a single pair because a later entry would overwrite its earlier relationship.
// https://learn.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes
// Extended virtual keys are unsupported.
#define PAIRS(X) \
    X('A', 'D')  \
    X('W', 'S')

#define PAIR_DATA(a, b) { a, b },
#define PAIR_TEXT(a, b) " " #a "/" #b

static BYTE const PAIRS[][2] = {
    PAIRS(PAIR_DATA)
};

static char const BANNER[] =
    "  /\\_/\\\n"
    " ( o.o )\n"
    "  > ^ <\n"
    " /|   |\\\n"
    "(_|   |_)\n"
    "\n"
    "null_bind active:"
    PAIRS(PAIR_TEXT)
    ". Press Ctrl+C to exit.\n";

#undef PAIR_TEXT
#undef PAIR_DATA
#undef PAIRS

#define INJECTION_TAG ((ULONG_PTR)0 - 0x284) // imm12
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread()  ((HANDLE)(LONG_PTR)-2)

static_assert(KEYEVENTF_KEYUP == 2);
enum KeyState : BYTE {
    UP = 0,                   // in up,   out up
    DOWN = 1,                 // in down, out down
    MASKED = KEYEVENTF_KEYUP, // in down, out up; KEYEVENTF_KEYUP conveniently happens to be 2
};

typedef UINT WINAPI NtUserSendInputFn(UINT, INPUT *, int);

template<typename T> using Dummy = T[1]; // scuffed compound literal

#pragma warning(push)
#pragma warning(disable: 4201) // nameless struct/union
#if defined(_M_ARM64)
    static union {
        struct { // SoA because LDRB can't scale its register offset.
            KeyState states[256];
            BYTE counterparts[256];
            WORD scans[256];
            NtUserSendInputFn *send_input;
            INPUT input;
            DWORD main_tid;
        };
    } __declspec(align(64));
    #define VK_COUNTERPART(vk) (counterparts[(vk)])
    #define VK_STATE(vk) (states[(vk)])
    #define VK_SCAN(vk) (scans[(vk)])
#else
    static union {
        struct {
            struct {
                KeyState state;
                BYTE counterpart;
                WORD scan;
            } keys[256];
            #if !defined(_M_X64)
                NtUserSendInputFn *send_input;
            #endif
            INPUT input;
            DWORD main_tid;
        };
    } __declspec(align(64));
    #define VK_COUNTERPART(vk) (keys[(vk)].counterpart)
    #define VK_STATE(vk) (keys[(vk)].state)
    #define VK_SCAN(vk) (keys[(vk)].scan)
#endif
#pragma warning(pop)

void
WriteStd(DWORD std_handle, char const *str, DWORD len)
{
    WriteFile(GetStdHandle(std_handle), str, len, Dummy<DWORD>{}, NULL);
}

[[noreturn]] void
Fatal(char const *format, ...)
{
    char text[1024];
    va_list args;
    va_start(args, format);
    WriteStd(STD_ERROR_HANDLE, text, wvsprintfA(text, format, args));
    va_end(args);
    ExitProcess(1);
}

FARPROC
ResolveNtUserSendInput(void)
{
    HMODULE win32u = GetModuleHandleW(L"win32u.dll");
    if (!win32u) {
        Fatal("Couldn't find win32u (%lu)\n", GetLastError());
    }

    FARPROC proc = GetProcAddress(win32u, "NtUserSendInput");
    if (!proc) {
        Fatal("Couldn't find NtUserSendInput (%lu)\n", GetLastError());
    }
    return proc;
}

#if defined(_M_X64)
    #pragma section(".stub", read, execute)
    extern "C" {
        alignas(64) __declspec(allocate(".stub"))
        BYTE syscall_stub[11] = {
            0x4C, 0x8B, 0xD1,             // mov r10, rcx
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, <service number>
            0x0F, 0x05,                   // syscall
            0xC3                          // ret
        };
        NtUserSendInputFn NtUserSendInput;
    }
    #pragma comment(linker, "/alternatename:NtUserSendInput=syscall_stub")

    __declspec(noinline) void
    InitSendInputStub(void)
    {
        BYTE *source = (BYTE *)ResolveNtUserSendInput();

        if (memcmp(syscall_stub, source, 4) != 0) {
            Fatal("Unexpected NtUserSendInput stub prefix\n");
        }

        DWORD protection;
        if (!VirtualProtect(syscall_stub, sizeof(syscall_stub), PAGE_READWRITE, &protection)) {
            Fatal("Couldn't make syscall stub writable (%lu)\n", GetLastError());
        }

        memcpy(syscall_stub + 4, source + 4, 4);

        if (!VirtualProtect(syscall_stub, sizeof(syscall_stub), protection, Dummy<DWORD>{})) {
            Fatal("Couldn't restore syscall stub protection (%lu)\n", GetLastError());
        }
        if (!FlushInstructionCache(NtCurrentProcess(), syscall_stub, sizeof(syscall_stub))) {
            Fatal("Couldn't flush syscall stub instruction cache (%lu)\n", GetLastError());
        }
    }
#else
    #define NtUserSendInput send_input
#endif

__declspec(noinline) void
RollbackInjection(void)
{
    VK_STATE((BYTE)input.ki.wVk) = (input.ki.dwFlags & KEYEVENTF_KEYUP) ? DOWN : MASKED;
}

__declspec(noinline) __declspec(code_seg(".text$hot1")) LRESULT __stdcall
AttemptInjectionThenPass(KeyState state, WPARAM wp, LPARAM lp, UINT vk)
{
    #if SHORT_CIRCUIT
        (void)wp;
        (void)lp;
    #else
        // Store wp/lp in the shadow space across NtUserSendInput to avoid saving/restoring nonvolatiles.
        volatile WPARAM v_wp = wp;
        volatile LPARAM v_lp = lp;
    #endif

    VK_STATE(vk) = state;
    *(BYTE *)&input.ki.wVk = (BYTE)vk;
    input.ki.wScan = VK_SCAN(vk);
    input.ki.dwFlags = state & KEYEVENTF_KEYUP; // assumes non-extended keys
    if (!NtUserSendInput(1, &input, sizeof(input))) {
        RollbackInjection();
    }

    #if SHORT_CIRCUIT
        return 0;
    #else
        // Owning the continuation lets OnKeyboardEvent remain frameless.
        return PASS_HC_ACTION(v_wp, v_lp);
    #endif
}

__declspec(code_seg(".text$hot0")) LRESULT CALLBACK
OnKeyboardEvent(int code, WPARAM wp, LPARAM lp)
{
    if (code != HC_ACTION) [[unlikely]] {
        return CallNextHookEx(NULL, code, wp, lp);
    }

    KBDLLHOOKSTRUCT *event = (KBDLLHOOKSTRUCT *)lp;
    BYTE vk = (BYTE)event->vkCode;
    BYTE counterpart = VK_COUNTERPART(vk);
    if (!counterpart) {
        return PASS_HC_ACTION(wp, lp);
    }

    if ((event->flags & LLKHF_INJECTED) && event->dwExtraInfo == INJECTION_TAG) {
        return PASS_HC_ACTION(wp, lp);
    }

    BYTE llkhf_up = ((BYTE)event->flags & LLKHF_UP) != 0;
    if (!llkhf_up && VK_STATE(vk) != UP) [[unlikely]] {
        return (VK_STATE(vk) == MASKED) ? 1 : PASS_HC_ACTION(wp, lp);
    }

    VK_STATE(vk) = (KeyState)(llkhf_up ^ DOWN);
    if (VK_STATE(counterpart) == (KeyState)(DOWN + llkhf_up)) {
        return AttemptInjectionThenPass((KeyState)(MASKED - llkhf_up), wp, lp, counterpart);
    }
    return PASS_HC_ACTION(wp, lp);
}

BOOL WINAPI
OnConsoleCtrl(DWORD type)
{
    (void)type;
    PostThreadMessageW(main_tid, WM_QUIT, 0, 0);
    return TRUE;
}

extern "C" void
mainCRTStartup(void)
{
    if (!CreateMutexW(NULL, FALSE, L"null_bind_single") || GetLastError() == ERROR_ALREADY_EXISTS) {
        ExitProcess(1);
    }

    #if defined(_M_X64)
        InitSendInputStub();
    #else
        // Just skip user32!SendInput's forwarding thunk.
        NtUserSendInput = (NtUserSendInputFn *)ResolveNtUserSendInput();
    #endif

    input.type = INPUT_KEYBOARD;
    input.ki.dwExtraInfo = INJECTION_TAG;

    for (size_t i = 0; i < ARRAYSIZE(PAIRS); i++) {
        BYTE a = PAIRS[i][0];
        BYTE b = PAIRS[i][1];
        VK_COUNTERPART(a) = b;
        VK_COUNTERPART(b) = a;
        VK_SCAN(a) = (WORD)MapVirtualKeyW(a, MAPVK_VK_TO_VSC);
        VK_SCAN(b) = (WORD)MapVirtualKeyW(b, MAPVK_VK_TO_VSC);
    }

    HANDLE process = NtCurrentProcess();

    PROCESS_POWER_THROTTLING_STATE power = {
        .Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION,
        .ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
    };
    SetProcessInformation(process, ProcessPowerThrottling, &power, sizeof(power));

    SetPriorityClass(process, REALTIME_PRIORITY_CLASS);
    SetThreadPriority(NtCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    HANDLE mmcss = NULL;
    if (GetPriorityClass(process) != REALTIME_PRIORITY_CLASS) {
        SetPriorityClass(process, HIGH_PRIORITY_CLASS);
        mmcss = AvSetMmThreadCharacteristicsW(L"Pro Audio", Dummy<DWORD>{});
        if (mmcss && !AvSetMmThreadPriority(mmcss, AVRT_PRIORITY_CRITICAL)) {
            AvRevertMmThreadCharacteristics(mmcss);
            mmcss = NULL;
        }
    }

    MSG msg;
    main_tid = GetCurrentThreadId();
    PeekMessageW(&msg, NULL, 0, 0, PM_NOREMOVE);
    SetConsoleCtrlHandler(OnConsoleCtrl, TRUE);

    HHOOK hook = SetWindowsHookExW(WH_KEYBOARD_LL, OnKeyboardEvent, GetModuleHandleW(NULL), 0);
    if (!hook) {
        Fatal("SetWindowsHookEx failed (%lu)\n", GetLastError());
    }

    ShowWindow(GetConsoleWindow(), SW_MINIMIZE);
    WriteStd(STD_OUTPUT_HANDLE, BANNER, sizeof(BANNER) - 1);

    while (GetMessageW(&msg, NULL, 0, 0) > 0);

    // Masked keys aren't restored on the way out. I don't care because it's self-healing.
    UnhookWindowsHookEx(hook);

    if (mmcss) {
        AvRevertMmThreadCharacteristics(mmcss);
    }
    ExitProcess(0);
}