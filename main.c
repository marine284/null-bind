// WINDOWS USER-MODE SOCD / NULL BIND / SNAP TAP
//
// Please note that anti-injection software can see LLKHF_INJECTED.
//
// Build: cl /std:c11 /nologo /W4 /O2 /GL /Gy /GS- /FA /Fabin/ /Fobin/ /Febin/null_bind.exe main.c /link /NODEFAULTLIB /ENTRY:main /LTCG /OPT:REF /OPT:ICF /MERGE:.pdata=.rdata kernel32.lib user32.lib avrt.lib
// Run:   bin/null_bind.exe

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <avrt.h>

// Each key may only be in a single pair because a later entry would overwrite its earlier relationship.
// https://learn.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes
// Cursor & Navigation (0x21–0x2E), Right Modifiers (0xA1, 0xA3, 0xA5), Browser & Media (0xA6–0xB7), and Gamepad (0xC3–0xDA) are unsupported.
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

#define INJECTION_TAG ((ULONG_PTR)0x4E424E42) // "NBNB"

enum {
    KEY_RELEASED = 0,
    KEY_ACTIVE = 1,
    KEY_NULLED = KEYEVENTF_KEYUP, // 0x0002
}; // keys[].state

static struct {
    BYTE opp;
    BYTE state;
    WORD scan;
} __declspec(align(64)) keys[256]; // indexed by virtual-key code

#define OPPOSITE_VK(vk) (keys[(BYTE)(vk)].opp)
#define KEY_STATE(vk)   (keys[(BYTE)(vk)].state)
#define KEY_SCAN(vk)    (keys[(BYTE)(vk)].scan)

static DWORD main_tid;
static INPUT input = {
    .type = INPUT_KEYBOARD,
    .ki.dwExtraInfo = INJECTION_TAG
};

static __declspec(noinline) void rollback_injection(void)
{
    KEY_STATE(input.ki.wVk) = (BYTE)((input.ki.dwFlags & KEYEVENTF_KEYUP) ? KEY_ACTIVE : KEY_NULLED);
}

// Owning the pass continuation lets `on_keyboard_event` remain frameless.
static __declspec(noinline) LRESULT attempt_injection_then_pass(WPARAM wp, LPARAM lp, BYTE vk, BYTE state)
{
    KEY_STATE(vk) = state;
    input.ki.wVk = vk;
    input.ki.wScan = KEY_SCAN(vk);
    input.ki.dwFlags = state & KEYEVENTF_KEYUP; // assumes non-extended keys
    if (SendInput(1, &input, sizeof input) != 1) {
        rollback_injection();
    }
    return CallNextHookEx(NULL, HC_ACTION, wp, lp);
}

// Dispatch
static LRESULT CALLBACK on_keyboard_event(int code, WPARAM wp, LPARAM lp)
{
    // Is it a valid event?
    if (code != HC_ACTION) {
        return CallNextHookEx(NULL, code, wp, lp);
    }

    const KBDLLHOOKSTRUCT *const event = (const KBDLLHOOKSTRUCT *)lp;
    const BYTE vk = (BYTE)event->vkCode;
    const BYTE opp = OPPOSITE_VK(vk);

    // Is it managed?
    if (!opp) {
        return CallNextHookEx(NULL, HC_ACTION, wp, lp);
    }

    // Is it ours?
    if ((event->flags & LLKHF_INJECTED) && event->dwExtraInfo == INJECTION_TAG) {
        return CallNextHookEx(NULL, HC_ACTION, wp, lp);
    }

    const BYTE is_up = (BYTE)((event->flags & LLKHF_UP) >> 7); // true 50/50

    // Is it a repeated key-down?
    if (!is_up && KEY_STATE(vk) != KEY_RELEASED) {
        return (KEY_STATE(vk) == KEY_NULLED) ? 1 : CallNextHookEx(NULL, HC_ACTION, wp, lp);
    }

    KEY_STATE(vk) = (BYTE)(is_up ^ KEY_ACTIVE);

    // So it's a fresh key-down, but must the opposite be flipped?
    if (KEY_STATE(opp) == (BYTE)(KEY_ACTIVE + is_up)) {
        return attempt_injection_then_pass(wp, lp, opp, (BYTE)(KEY_NULLED - is_up));
    }

    return CallNextHookEx(NULL, HC_ACTION, wp, lp);
}

static BOOL WINAPI on_console_ctrl(DWORD type)
{
    (void)type;
    PostThreadMessageW(main_tid, WM_QUIT, 0, 0);
    return TRUE;
}

static void write_std(DWORD std, const char *str, DWORD len)
{
    DWORD written;
    WriteFile(GetStdHandle(std), str, len, &written, NULL);
}

void main(void)
{
    CreateMutexW(NULL, FALSE, L"null_bind_single");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        ExitProcess(1);
    }

    for (size_t i = 0; i < ARRAYSIZE(pairs); i++) {
        const BYTE a = pairs[i][0];
        const BYTE b = pairs[i][1];
        OPPOSITE_VK(a) = b;
        OPPOSITE_VK(b) = a;
        KEY_SCAN(a) = (WORD)MapVirtualKeyW(a, MAPVK_VK_TO_VSC);
        KEY_SCAN(b) = (WORD)MapVirtualKeyW(b, MAPVK_VK_TO_VSC);
    }

    DWORD task_index = 0;
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    HANDLE mmcss = AvSetMmThreadCharacteristicsW(L"Pro Audio", &task_index);
    if (!mmcss || !AvSetMmThreadPriority(mmcss, AVRT_PRIORITY_CRITICAL)) {
        if (mmcss) {
            AvRevertMmThreadCharacteristics(mmcss);
            mmcss = NULL;
        }
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    }

    PROCESS_POWER_THROTTLING_STATE power = {
        .Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION,
        .ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
    };
    SetProcessInformation(GetCurrentProcess(), ProcessPowerThrottling, &power, sizeof power);

    MSG msg;
    main_tid = GetCurrentThreadId();
    PeekMessageW(&msg, NULL, 0, 0, PM_NOREMOVE);
    SetConsoleCtrlHandler(on_console_ctrl, TRUE);

    HHOOK hook = SetWindowsHookExW(WH_KEYBOARD_LL, on_keyboard_event, GetModuleHandleW(NULL), 0);
    if (!hook) {
        char err[64];
        const DWORD len = (DWORD)wsprintfA(err, "SetWindowsHookEx failed (%lu)\n", GetLastError());
        write_std(STD_ERROR_HANDLE, err, len);
        ExitProcess(1);
    }

    write_std(STD_OUTPUT_HANDLE, banner, sizeof banner - 1);

    while (GetMessageW(&msg, NULL, 0, 0) > 0);

    // Nulled-but-held keys aren't restored on the way out because the repress can only be injected
    // after the unhook, and by then there is no way to know the state is still held.
    // I don't care because it's self-healing.
    UnhookWindowsHookEx(hook);

    if (mmcss) {
        AvRevertMmThreadCharacteristics(mmcss);
    }
    ExitProcess(0);
}