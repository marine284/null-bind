// WINDOWS USER-MODE SOCD / NULL BIND / SNAP TAP
//
// Build: rc /nologo /fo bin/null_bind.res null_bind.rc && cl main.cpp /O2 /std:c++20 /nologo /W4 /GS- /Zl /GL /Gy /Gw /FA /Fabin/ /Fobin/ /Febin/null_bind.exe bin/null_bind.res /link /LTCG /OPT:REF /OPT:ICF /MERGE:.pdata=.rdata
// Run:   bin/null_bind.exe

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <avrt.h>
#include <stdarg.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "avrt.lib")
#pragma comment(linker, "/SUBSYSTEM:CONSOLE")

extern "C" {
    void *__cdecl memcpy(void *, const void *, size_t);
    int   __cdecl memcmp(const void *, const void *, size_t);
}
#pragma intrinsic(memcpy, memcmp)

// Build with /DSHORT_CIRCUIT=1 to pass HC_ACTION events without notifying later hooks.
// Not recommended.
#ifndef SHORT_CIRCUIT
    #define SHORT_CIRCUIT 0
#endif
#if SHORT_CIRCUIT
    #define PASS_HC_ACTION(wp, lp) ((LRESULT)0)
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

static const BYTE pairs[][2] = {
    PAIRS(PAIR_DATA)
};

static const char banner[] =
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

enum : BYTE {
    UP = 0,                   // in up,   out up
    DOWN = 1,                 // in down, out down
    MASKED = KEYEVENTF_KEYUP, // in down, out up; KEYEVENTF_KEYUP conveniently happens to be 2
}; // key states

#if defined(_M_ARM64)
    alignas(64) static struct { // SoA because LDRB can't scale its register offset.
        BYTE states[256];
        BYTE counterparts[256];
        WORD scans[256];
    } keys;
    #define VK_COUNTERPART(vk) (keys.counterparts[(vk)])
    #define VK_STATE(vk)       (keys.states[(vk)])
    #define VK_SCAN(vk)        (keys.scans[(vk)])
#else
    alignas(64) static struct {
        BYTE state;
        BYTE counterpart;
        WORD scan;
    } keys[256];
    #define VK_COUNTERPART(vk) (keys[(vk)].counterpart)
    #define VK_STATE(vk)       (keys[(vk)].state)
    #define VK_SCAN(vk)        (keys[(vk)].scan)
#endif

static DWORD main_tid;
static INPUT input = {
    .type = INPUT_KEYBOARD,
    .ki = { .dwExtraInfo = INJECTION_TAG }
};

static void
write_std(DWORD std, const char *str, DWORD len)
{
    DWORD written;
    WriteFile(GetStdHandle(std), str, len, &written, NULL);
}

[[noreturn]] static void 
fatal(const char *format, ...)
{
    char text[128];
    va_list args;
    va_start(args, format);
    write_std(STD_ERROR_HANDLE, text, wvsprintfA(text, format, args));
    va_end(args);
    ExitProcess(1);
}

#if defined(_M_X64)
    // The linker alias gives calls function-symbol semantics (E8 rel32).
    #pragma section(".stub", read, execute)
    extern "C" {
        alignas(64) __declspec(allocate(".stub"))
        BYTE sys_send_input_slot[11] = {
            0x4C, 0x8B, 0xD1,             // mov r10, rcx
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, <service number>
            0x0F, 0x05,                   // syscall
            0xC3                          // ret
        };
        UINT WINAPI sys_send_input(UINT, const INPUT *, int);
    }
    #pragma comment(linker, "/alternatename:sys_send_input=sys_send_input_slot")
    #define NtUserSendInput sys_send_input

    static __declspec(noinline) void
    init_sys_send_input(void)
    {
        const HMODULE win32u = GetModuleHandleW(L"win32u.dll");
        if (!win32u) {
            fatal("Couldn't find win32u (%lu)\n", GetLastError());
        }

        const BYTE *const src = (const BYTE *)GetProcAddress(win32u, "NtUserSendInput");
        if (!src) {
            fatal("Couldn't find NtUserSendInput (%lu)\n", GetLastError());
        }

        if (memcmp(src, sys_send_input_slot, 4) != 0) {
            fatal("Unexpected NtUserSendInput prefix\n");
        }

        DWORD old_protection;
        if (!VirtualProtect(sys_send_input_slot, sizeof(sys_send_input_slot), PAGE_READWRITE, &old_protection)) {
            fatal("Couldn't make syscall stub writable (%lu)\n", GetLastError());
        }

        memcpy(sys_send_input_slot + 4, src + 4, 4);

        DWORD ignored;
        const BOOL restored = VirtualProtect(sys_send_input_slot, sizeof(sys_send_input_slot), old_protection, &ignored);
        const DWORD restore_error = restored ? ERROR_SUCCESS : GetLastError();
        const BOOL flushed = FlushInstructionCache(GetCurrentProcess(), sys_send_input_slot, sizeof(sys_send_input_slot));
        if (!restored) {
            fatal("Couldn't restore syscall stub protection (%lu)\n", restore_error);
        }
        if (!flushed) {
            fatal("Couldn't flush syscall stub instruction cache (%lu)\n", GetLastError());
        }
    }
#else
    typedef UINT (WINAPI *nt_user_send_input_fn)(UINT, const INPUT *, int);
    static nt_user_send_input_fn NtUserSendInput;
#endif

static __declspec(noinline) void
rollback_injection(void)
{
    VK_STATE((BYTE)input.ki.wVk) = (BYTE)((input.ki.dwFlags & KEYEVENTF_KEYUP) ? DOWN : MASKED);
}

static __declspec(noinline) __declspec(code_seg(".text$hot1")) LRESULT __stdcall
attempt_injection_then_pass(UINT vk, WPARAM wp, LPARAM lp, BYTE state)
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
    input.ki.wVk = (WORD)vk;
    input.ki.wScan = VK_SCAN(vk);
    input.ki.dwFlags = state & KEYEVENTF_KEYUP; // assumes non-extended keys
    if (!NtUserSendInput(1, &input, sizeof(input))) {
        rollback_injection();
    }

#if SHORT_CIRCUIT
    return 0;
#else
    // Owning the continuation lets on_keyboard_event remain frameless.
    return PASS_HC_ACTION(v_wp, v_lp);
#endif
}

static __declspec(code_seg(".text$hot0")) LRESULT CALLBACK
on_keyboard_event(int code, WPARAM wp, LPARAM lp)
{
    if (code != HC_ACTION) [[unlikely]] {
        return CallNextHookEx(NULL, code, wp, lp);
    }

    const KBDLLHOOKSTRUCT *const event = (const KBDLLHOOKSTRUCT *)lp;
    const BYTE vk = (BYTE)event->vkCode;
    const BYTE counterpart = VK_COUNTERPART(vk);
    if (!counterpart) {
        return PASS_HC_ACTION(wp, lp);
    }

    if ((event->flags & LLKHF_INJECTED) && event->dwExtraInfo == INJECTION_TAG) {
        return PASS_HC_ACTION(wp, lp);
    }

    const BYTE llkhf_up = (BYTE)((BYTE)event->flags >> 7);
    if (!llkhf_up && VK_STATE(vk) != UP) [[unlikely]] {
        return (VK_STATE(vk) == MASKED) ? 1 : PASS_HC_ACTION(wp, lp);
    }

    VK_STATE(vk) = (BYTE)(llkhf_up ^ DOWN);
    if (VK_STATE(counterpart) == (BYTE)(DOWN + llkhf_up)) {
        return attempt_injection_then_pass(counterpart, wp, lp, (BYTE)(MASKED - llkhf_up));
    }
    return PASS_HC_ACTION(wp, lp);
}

static BOOL WINAPI
on_console_ctrl(DWORD type)
{
    (void)type;
    PostThreadMessageW(main_tid, WM_QUIT, 0, 0);
    return TRUE;
}

extern "C" void
mainCRTStartup(void)
{
    HANDLE mutex = CreateMutexW(NULL, FALSE, L"null_bind_single");
    if (!mutex || GetLastError() == ERROR_ALREADY_EXISTS) {
        ExitProcess(1);
    }

#if defined(_M_X64)
    init_sys_send_input();
#else
    // Just skip user32!SendInput's forwarding thunk.
    NtUserSendInput = (nt_user_send_input_fn)GetProcAddress(GetModuleHandleW(L"win32u.dll"), "NtUserSendInput");
#endif

    for (size_t i = 0; i < ARRAYSIZE(pairs); i++) {
        const BYTE a = pairs[i][0];
        const BYTE b = pairs[i][1];
        VK_COUNTERPART(a) = b;
        VK_COUNTERPART(b) = a;
        VK_SCAN(a) = (WORD)MapVirtualKeyW(a, MAPVK_VK_TO_VSC);
        VK_SCAN(b) = (WORD)MapVirtualKeyW(b, MAPVK_VK_TO_VSC);
    }

    const HANDLE process = GetCurrentProcess();

    PROCESS_POWER_THROTTLING_STATE power = {
        .Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION,
        .ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
    };
    SetProcessInformation(process, ProcessPowerThrottling, &power, sizeof(power));

    SetPriorityClass(process, REALTIME_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    HANDLE mmcss = NULL;
    if (GetPriorityClass(process) != REALTIME_PRIORITY_CLASS) {
        DWORD task_index = 0;
        SetPriorityClass(process, HIGH_PRIORITY_CLASS);
        mmcss = AvSetMmThreadCharacteristicsW(L"Pro Audio", &task_index);
        if (mmcss && !AvSetMmThreadPriority(mmcss, AVRT_PRIORITY_CRITICAL)) {
            AvRevertMmThreadCharacteristics(mmcss);
            mmcss = NULL;
        }
    }

    MSG msg;
    main_tid = GetCurrentThreadId();
    PeekMessageW(&msg, NULL, 0, 0, PM_NOREMOVE);
    SetConsoleCtrlHandler(on_console_ctrl, TRUE);

    HHOOK hook = SetWindowsHookExW(WH_KEYBOARD_LL, on_keyboard_event, GetModuleHandleW(NULL), 0);
    if (!hook) {
        fatal("SetWindowsHookEx failed (%lu)\n", GetLastError());
    }

    ShowWindow(GetConsoleWindow(), SW_MINIMIZE);
    write_std(STD_OUTPUT_HANDLE, banner, sizeof(banner) - 1);

    while (GetMessageW(&msg, NULL, 0, 0) > 0);

    // Masked keys aren't restored on the way out. I don't care because it's self-healing.
    UnhookWindowsHookEx(hook);

    if (mmcss) {
        AvRevertMmThreadCharacteristics(mmcss);
    }
    ExitProcess(0);
}
