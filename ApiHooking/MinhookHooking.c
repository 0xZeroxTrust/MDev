#include<stdio.h>
#include<Windows.h>
#include<Minhook.h>

typedef INT(WINAPI *fnMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
fnMessageBoxA g_pMessageBoxA = NULL; //set to NULL because the Minhook MH_CreateHook API call is the one that initializes it for use

int (WINAPI MyMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {

	// log Original Parameters
	printf("[+] Original Parameters : \n");
	printf("\t - lpText : %s\n", lpText);
	printf("\t - lpCaption : %s \n", lpCaption);

	// show different text and caption.
	return g_pMessageBoxA(hWnd, "Different lpText", "Different lpCaption", uType);
}

BOOL InstallHook() {

	DWORD dwMinHookErr = NULL;

	if ((dwMinHookErr = MH_Initialize()) != MH_OK) {
		printf("[!] MH_Initialize Failed with Error : %d \n", dwMinHookErr);
		return FALSE;
	}

	// Installing the hook on MesssageBoxA, to run MyMessageBoxA instead
	// g_pMessageBoxA will be a pointer to the original MessageBoxA function
	if ((dwMinHookErr = MH_CreateHook(&MessageBoxA, &MyMessageBoxA, &(LPVOID&)g_pMessageBoxA)) != MH_OK) {
		printf("[!] MH_CreateHook Failed with Error : %d \n", dwMinHookErr);
		return FALSE;
	}

	// Enabling the hook on MessageBoxA
	if ((dwMinHookErr = MH_EnableHook(&MessageBoxA)) != MH_OK) {
		printf("[!] MH_EnableHook Failed with Error : %d \n", dwMinHookErr);
		return FALSE;
	}

	return TRUE;
}

BOOL Unhook() {

	DWORD 	dwMinHookErr = NULL;

	if ((dwMinHookErr = MH_DisableHook(&MessageBoxA)) != MH_OK) {
		printf("[!] MH_DisableHook Failed With Error : %d \n", dwMinHookErr);
		return -1;
	}

	if ((dwMinHookErr = MH_Uninitialize()) != MH_OK) {
		printf("[!] MH_Uninitialize Failed With Error : %d \n", dwMinHookErr);
		return -1;
	}

	return TRUE;
}

int main() {

	//  will run
	MessageBoxA(NULL, " Malware Development ", "Original MsgBox", MB_OK | MB_ICONQUESTION);

//-----------------------------------------------------------------
	//  hooking
	printf("[i] Installing the Hook ...");
	if (!InstallHook()) {
		return -1;
	}
	printf("[+] DONE \n");

//------------------------------------------------------------------------
	//  wont run - hooked
	MessageBoxA(NULL, "Malware  Is Bad for health", "Original MsgBox", MB_OK | MB_ICONWARNING);

//-----------------------------------------------------------------------
	//  unhooking
	printf("[i] Removing The Hook ...");
	if (!Unhook())
		return -1;

	printf("[+] DONE \n");

//---------------------------------------------------------------	 
	//  will run - hook disabled

	MessageBoxA(NULL, "Normal MsgBox Again", "Original MsgBox", MB_OK | MB_ICONINFORMATION);

	printf("[#] Press <Enter> To quit ...");
	getchar();
	return 0;
}

