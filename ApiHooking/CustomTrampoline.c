#include <stdio.h>
#include <Windows.h>
#include <stdint.h>

// If compiling as x64
#ifdef _M_X64
#define TRAMPOLINE_SIZE 13 // _M_X64
#endif

// If compiling as x32
#ifdef _M_IX86
#define TRAMPOLINE_SIZE 7 // _M_X32
#endif

int (WINAPI MyMessageBoxA)(HWND   hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT   uType) {
	// log Original parameters
	printf("[+] Original Parameters \n");
	printf("\t - lpText : %s\n", lpText);
	printf("\t - lpCaption : %s \n", lpCaption);

	// Due to the trampoline-based hook, it is impossible to have a global original function pointer be called to resume execution. Therefore, the MessageBoxW WinAPI will be called.
	return MessageBoxW(hWnd, L"Different lpText", L"Different lpCaption", uType);
}

// contains info needed for hook & unhook function.
typedef struct _HookSt {

	PVOID pFunctionToHook; // address of the function to hook.
	PVOID pFunctionToRun; // address of the function to run instead.
	BYTE pOriginalBytes[TRAMPOLINE_SIZE]; // buffer to keep some original bytes.
	DWORD dwOldProtection; // hold the old memory protection of the "function to hook"

}HookSt, * PHookSt;

BOOL InitializeHookStruct(IN PVOID pFunctionToHook, IN PVOID pFunctionToRun, OUT PHookSt Hook) {

	// Filling up the struct
	Hook->pFunctionToHook = pFunctionToHook;
	Hook->pFunctionToRun = pFunctionToRun;

	// Save original bytes of the same size that we will overwrite (that is TRAMPOLINE_SIZE)
	// This is done to be able to do cleanups when done
	memcpy(Hook->pOriginalBytes, pFunctionToHook, TRAMPOLINE_SIZE);

	// Changing the protection to RWX so that we can modify the bytes
	// We are saving the old protection to the struct (to re-place it at cleanup)
	if (!VirtualProtect(pFunctionToHook, TRAMPOLINE_SIZE, PAGE_EXECUTE_READWRITE, &Hook->dwOldProtection)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}


BOOL InstallHook(IN PHookSt Hook) {

#ifdef _M_X64// 64-bit trampoline
	uint8_t	uTrampoline[] = {
			0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, pFunctionToRun //   Pointer is  8-byte in x64-bit // pAddress is represented as NULL.
			0x41, 0xFF, 0xE2                                            // jmp r10
	};

	// pAddress is the address.The uint32_t and uint64_t data types are used to ensure that the address is the correct number of bytes.uint32_t is of size 4 bytes, and uint64_t is of size 8 bytes.
	// Patching the shellcode with the address to jump to (pFunctionToRun)
	uint64_t uPatch = (uint64_t)(Hook->pFunctionToRun);
	// Copying the address of the function to jump to, to the offset '2' in uTrampoline
	memcpy(&uTrampoline[2], &uPatch, sizeof(uPatch));
#endif // _M_X64

#ifdef _M_IX86// 32-bit trampoline
	uint8_t	uTrampoline[] = {
	   0xB8, 0x00, 0x00, 0x00, 0x00,     // mov eax, pFunctionToRun
	   0xFF, 0xE0                        // jmp eax
	};

	// Patching the shellcode with the address to jump to (pFunctionToRun)
	uint32_t uPatch = (uint32_t)(Hook->pFunctionToRun);
	// Copying the address of the function to jump to, to the offset '1' in uTrampoline
	memcpy(&uTrampoline[1], &uPatch, sizeof(uPatch));
#endif // _M_IX86


	// Placing the trampoline function - installing the hook
	memcpy(Hook->pFunctionToHook, uTrampoline, sizeof(uTrampoline));

	return TRUE;
}

BOOL RemoveHook(IN PHookSt Hook) {

	DWORD	dwOldProtection = NULL;

	// Copying the original bytes over
	memcpy(Hook->pFunctionToHook, Hook->pOriginalBytes, TRAMPOLINE_SIZE);
	// Cleaning up our buffer
	memset(Hook->pOriginalBytes, '\0', TRAMPOLINE_SIZE);
	// Setting the old memory protection back to what it was before hooking
	if (!VirtualProtect(Hook->pFunctionToHook, TRAMPOLINE_SIZE, Hook->dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Setting all to null
	Hook->pFunctionToHook = NULL;
	Hook->pFunctionToRun = NULL;
	Hook->dwOldProtection = NULL;

	return TRUE;
}

int main() {

	// Initializing the structure (needed before installing/removing the hook)
	HookSt st = { 0 };

	if (!InitializeHookStruct(&MessageBoxA, &MyMessageBoxA, &st)) {
		return -1;
	}

	// will run
	MessageBoxA(NULL, "Is Malware Development  ?", "Original MsgBox", MB_OK | MB_ICONQUESTION);

	//  hooking
	if (!InstallHook(&st)) {
		return -1;
	}

	//  wont run - hooked
	MessageBoxA(NULL, "Malware Development Is Bad", "Original MsgBox", MB_OK | MB_ICONWARNING);


	//  unhooking
	if (!RemoveHook(&st)) {
		return -1;
	}


	//  will run - hook disabled
	MessageBoxA(NULL, "Normal MsgBox Again", "Original MsgBox", MB_OK | MB_ICONINFORMATION);


	return 0;
}
