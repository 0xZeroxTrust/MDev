#include <stdio.h>
#include <windows.h>

FARPROC GetProcAddressReplacement(IN HMODULE hModule, IN LPCSTR lpApiName) {

	// We do this to avoid casting at each time we use 'hModule'
	PBYTE pBase = (PBYTE)hModule;

	// Getting the dos header and doing a signature check
	PIMAGE_DOS_HEADER	pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	// Getting the nt headers and doing a signature check
	PIMAGE_NT_HEADERS	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// Getting the optional header
	IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;

	// Getting the image export table
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	// Getting the function's names array pointer
	PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);

	// Getting the function's addresses array pointer
	PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);

	// Getting the function's ordinal array pointer
	PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);


	// Looping through all the exported functions
	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {

		// Getting the name of the function
		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);

		// Getting the address of the function through its ordinal
		PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

		// Searching for the function specified
		if (strcmp(lpApiName, pFunctionName) == 0) {
			printf("[ %0.4d ] FOUND API -\t NAME: %s -\t ADDRESS: 0x%p  -\t ORDINAL: %d\n", i, pFunctionName, pFunctionAddress, FunctionOrdinalArray[i]);
			return (FARPROC)pFunctionAddress;
		}
	}

	return NULL;
}

int main() {

	PVOID pAddress = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
	printf("Orinianl GetProcAddress : 0x%p \n", pAddress);

	PVOID pReplacementAddress = GetProcAddressReplacement(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
	printf("GetProcAddress Replacement : 0x%p \n", pReplacementAddress);
	return 0;
}
