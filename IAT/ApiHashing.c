#include <stdio.h>
#include <windows.h>
#include <winternl.h>

#pragma warning( disable : 4146)
#define USER32DLL_HASH 0x81E3778E
#define MessageBoxA_HASH 0xF10E27CA
#define INITIAL_SEED	7	// RANDOM HASH

typedef int (WINAPI* fnMessageBoxA)(HWND   hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT  uType);

// Generate JenkinsOneAtATime32Bit hashes from Ascii input string
DWORD HASHA(_In_ CONST CHAR* String)
{
	SIZE_T Index = 0;
	DWORD Hash = 0;
	SIZE_T Length = lstrlenA(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}


HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {

	if (dwModuleNameHash == NULL)
		return NULL;

#ifdef _WIN64
	PPEB      pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB      pPeb = (PEB*)(__readfsdword(0x30));
#endif

	PPEB_LDR_DATA            pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {

		if (pDte->FullDllName.Length != NULL && pDte->FullDllName.Length < MAX_PATH) {

			// Converting `FullDllName.Buffer` to upper case string
			CHAR UpperCaseDllName[MAX_PATH];
			
			DWORD i = 0;
			while (pDte->FullDllName.Buffer[i]) {
				UpperCaseDllName[i] = (CHAR)toupper(pDte->FullDllName.Buffer[i]);
				i++;
			}
			UpperCaseDllName[i] = '\0';
			// hashing `UpperCaseDllName` and comparing the hash value to that's of the input `dwModuleNameHash`
			if (HASHA(UpperCaseDllName) == dwModuleNameHash) {
				printf("Hash of USER32.dll 0x%0.8X \n", HASHA(UpperCaseDllName));
				return (HMODULE)pDte->Reserved2[0];
			}
		}
		else {
			break;
		}

		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
	}

	return NULL;
}

FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {

	if (hModule == NULL || dwApiNameHash == NULL) {
		return NULL;
	}

	PBYTE pBase = (PBYTE)hModule;

	PIMAGE_DOS_HEADER         pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}

	PIMAGE_NT_HEADERS         pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	IMAGE_OPTIONAL_HEADER     ImgOptHdr = pImgNtHdrs->OptionalHeader;

	PIMAGE_EXPORT_DIRECTORY   pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);


	PDWORD  FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	PDWORD  FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	PWORD   FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
		PVOID	pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

		// Hashing every function name pFunctionName
		// If both hashes are equal then we found the function we want
		if (dwApiNameHash == HASHA(pFunctionName)) {
			//printf("0x%0.8X functionname : 0x%p \n", dwApiNameHash, pFunctionName); //%X: Specifies that the argument (in this case, the hash value) should be formatted as an uppercase hexadecimal number. // 0: The leading zero specifies that if the hexadecimal value has fewer than 8 digits, it should be padded with zeros on the left to make it 8 digits long
			return (FARPROC)pFunctionAddress;
		}
	}

	return NULL;
}

int main() {

	// Load User32.dll to the current process so that GetModuleHandleH will work
	if (LoadLibraryA("USER32.DLL") == NULL) {
		printf("[!] LoadLibraryA Failed With Error : %d \n", GetLastError());
		return 0;
	}

	// Getting the handle of user32.dll using GetModuleHandleH
	HMODULE hUser32Module = GetModuleHandleH(USER32DLL_HASH);

	if (hUser32Module == NULL) {
		printf("[!] Cound'nt Get Handle To User32.dll \n");
		return -1;
	}


	// Getting the address of MessageBoxA function using GetProcAddressH

	fnMessageBoxA pMessageBoxA = (fnMessageBoxA)GetProcAddressH(hUser32Module, MessageBoxA_HASH);
	if (pMessageBoxA == NULL) {
		printf("[!] Cound'nt Find Address Of Specified Function \n");
		return -1;
	}

	// Calling MessageBoxA
	pMessageBoxA(NULL, "Learning Malware ", "Wow", MB_OK | MB_ICONEXCLAMATION);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}
