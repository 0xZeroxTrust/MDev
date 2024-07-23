#include <stdio.h>
#include <windows.h>
#pragma warning(disable:4996)

void parsePE(const char* filePath) {
    // Open the file
    FILE* file = fopen(filePath, "rb");
    if (!file) {
        printf("Failed to open file.\n");
        return;
    }

    // Get the file size
    fseek(file, 0, SEEK_END);
    size_t fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Read the file into memory
    BYTE* pPE = (BYTE*)malloc(fileSize);
    if (!pPE) {
        printf("Memory allocation failed.\n");
        fclose(file);
        return;
    }
    fread(pPE, 1, fileSize, file);
    fclose(file);

    // Pointer to the DOS header
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pPE;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Invalid DOS signature.\n");
        free(pPE);
        return;
    }
    printf("******* DOS HEADER *******\n");
    printf("\t0x%x\t\tMagic number\n", pImgDosHdr->e_magic);
    printf("\t0x%x\t\tBytes on last page of file\n", pImgDosHdr->e_cblp);
    printf("\t0x%x\t\tPages in file\n", pImgDosHdr->e_cp);
    printf("\t0x%x\t\tRelocations\n", pImgDosHdr->e_crlc);
    printf("\t0x%x\t\tSize of header in paragraphs\n", pImgDosHdr->e_cparhdr);
    printf("\t0x%x\t\tMinimum extra paragraphs needed\n", pImgDosHdr->e_minalloc);
    printf("\t0x%x\t\tMaximum extra paragraphs needed\n", pImgDosHdr->e_maxalloc);
    printf("\t0x%x\t\tInitial (relative) SS value\n", pImgDosHdr->e_ss);
    printf("\t0x%x\t\tInitial SP value\n", pImgDosHdr->e_sp);
    printf("\t0x%x\t\tInitial SP value\n", pImgDosHdr->e_sp);
    printf("\t0x%x\t\tChecksum\n", pImgDosHdr->e_csum);
    printf("\t0x%x\t\tInitial IP value\n", pImgDosHdr->e_ip);
    printf("\t0x%x\t\tInitial (relative) CS value\n", pImgDosHdr->e_cs);
    printf("\t0x%x\t\tFile address of relocation table\n", pImgDosHdr->e_lfarlc);
    printf("\t0x%x\t\tOverlay number\n", pImgDosHdr->e_ovno);
    printf("\t0x%x\t\tOEM identifier (for e_oeminfo)\n", pImgDosHdr->e_oemid);
    printf("\t0x%x\t\tOEM information; e_oemid specific\n", pImgDosHdr->e_oeminfo);
    printf("\t0x%x\t\tFile address of new exe header\n", pImgDosHdr->e_lfanew);




    // Pointer to the NT headers
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pPE + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
        printf("Invalid NT signature.\n");
        free(pPE);
        return;
    }

    IMAGE_FILE_HEADER ImgFileHdr = pImgNtHdrs->FileHeader;
    printf("\n******* FILE HEADER *******\n");
    printf("\t0x%x\t\tMachine\n", pImgNtHdrs->FileHeader.Machine);
    printf("\t0x%x\t\tNumberofSections\n", pImgNtHdrs->FileHeader.NumberOfSections);
    printf("\t0x%x\t\tSizeOfOptionalHeader\n", pImgNtHdrs->FileHeader.SizeOfOptionalHeader);

    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
    if (ImgOptHdr.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
        printf("Invalid Optional header magic.\n");
        free(pPE);
        return;
    }
    printf("\t0x%x\t\tMagic\n", pImgNtHdrs->OptionalHeader.Magic);
    printf("\t0x%x\t\tMajor Linker Version\n", pImgNtHdrs->OptionalHeader.MajorLinkerVersion);
    printf("\t0x%x\t\tMinor Linker Version\n", pImgNtHdrs->OptionalHeader.MinorLinkerVersion);
    printf("\t0x%x\t\tSize Of Code\n", pImgNtHdrs->OptionalHeader.SizeOfCode);
    printf("\t0x%x\t\tSize Of Initialized Data\n", pImgNtHdrs->OptionalHeader.SizeOfInitializedData);
    printf("\t0x%x\t\tSize Of UnInitialized Data\n", pImgNtHdrs->OptionalHeader.SizeOfUninitializedData);
    printf("\t0x%x\t\tAddress Of Entry Point (.text)\n", pImgNtHdrs->OptionalHeader.AddressOfEntryPoint);
    printf("\t0x%x\t\tBase Of Code\n", pImgNtHdrs->OptionalHeader.BaseOfCode);
    //printf("\t0x%x\t\tBase Of Data\n", pImgNtHdrs->OptionalHeader.BaseOfData);
    printf("\t0x%x\t\tImage Base\n", pImgNtHdrs->OptionalHeader.ImageBase);
    printf("\t0x%x\t\tSection Alignment\n", pImgNtHdrs->OptionalHeader.SectionAlignment);
    printf("\t0x%x\t\tFile Alignment\n", pImgNtHdrs->OptionalHeader.FileAlignment);
    printf("\t0x%x\t\tMajor Operating System Version\n", pImgNtHdrs->OptionalHeader.MajorOperatingSystemVersion);
    printf("\t0x%x\t\tMinor Operating System Version\n", pImgNtHdrs->OptionalHeader.MinorOperatingSystemVersion);
    printf("\t0x%x\t\tMajor Image Version\n", pImgNtHdrs->OptionalHeader.MajorImageVersion);
    printf("\t0x%x\t\tMinor Image Version\n", pImgNtHdrs->OptionalHeader.MinorImageVersion);
    printf("\t0x%x\t\tMajor Subsystem Version\n", pImgNtHdrs->OptionalHeader.MajorSubsystemVersion);
    printf("\t0x%x\t\tMinor Subsystem Version\n", pImgNtHdrs->OptionalHeader.MinorSubsystemVersion);
    printf("\t0x%x\t\tWin32 Version Value\n", pImgNtHdrs->OptionalHeader.Win32VersionValue);
    printf("\t0x%x\t\tSize Of Image\n", pImgNtHdrs->OptionalHeader.SizeOfImage);
    printf("\t0x%x\t\tSize Of Headers\n", pImgNtHdrs->OptionalHeader.SizeOfHeaders);
    printf("\t0x%x\t\tCheckSum\n", pImgNtHdrs->OptionalHeader.CheckSum);
    printf("\t0x%x\t\tSubsystem\n", pImgNtHdrs->OptionalHeader.Subsystem);
    printf("\t0x%x\t\tDllCharacteristics\n", pImgNtHdrs->OptionalHeader.DllCharacteristics);
    printf("\t0x%x\t\tSize Of Stack Reserve\n", pImgNtHdrs->OptionalHeader.SizeOfStackReserve);
    printf("\t0x%x\t\tSize Of Stack Commit\n", pImgNtHdrs->OptionalHeader.SizeOfStackCommit);
    printf("\t0x%x\t\tSize Of Heap Reserve\n", pImgNtHdrs->OptionalHeader.SizeOfHeapReserve);
    printf("\t0x%x\t\tSize Of Heap Commit\n", pImgNtHdrs->OptionalHeader.SizeOfHeapCommit);
    printf("\t0x%x\t\tLoader Flags\n", pImgNtHdrs->OptionalHeader.LoaderFlags);
    printf("\t0x%x\t\tNumber Of Rva And Sizes\n", pImgNtHdrs->OptionalHeader.NumberOfRvaAndSizes);



    IMAGE_DATA_DIRECTORY DataDir = ImgOptHdr.DataDirectory[0]; // Example for index 0
    IMAGE_DATA_DIRECTORY ExpDataDir = ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    printf("\n******* DATA DIRECTORIES *******\n");
    printf("\tExport Directory Address: 0x%x; Size: 0x%x\n", ImgOptHdr.DataDirectory[0].VirtualAddress, ImgOptHdr.DataDirectory[0].Size);
    printf("\tImport Directory Address: 0x%x; Size: 0x%x\n", ImgOptHdr.DataDirectory[1].VirtualAddress, ImgOptHdr.DataDirectory[1].Size);
    printf("\tResource Directory Address: 0x%x; Size: 0x%x\n", ImgOptHdr.DataDirectory[2].VirtualAddress, ImgOptHdr.DataDirectory[2].Size);
    printf("\tException Directory Address: 0x%x; Size: 0x%x\n", ImgOptHdr.DataDirectory[3].VirtualAddress, ImgOptHdr.DataDirectory[3].Size);
    printf("\tBase Relocation Table At: 0x%x; Size: 0x%x\n", ImgOptHdr.DataDirectory[5].VirtualAddress, ImgOptHdr.DataDirectory[5].Size);
    printf("\tTLS Directory At: 0x%x; Size: 0x%x\n", ImgOptHdr.DataDirectory[9].VirtualAddress, ImgOptHdr.DataDirectory[9].Size);
    printf("\tImport Address Table: 0x%x; Size: 0x%x\n", ImgOptHdr.DataDirectory[12].VirtualAddress, ImgOptHdr.DataDirectory[12].Size);


    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PIMAGE_IMPORT_DESCRIPTOR* pImgImpDesc = (PIMAGE_IMPORT_DESCRIPTOR*)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    PIMAGE_TLS_DIRECTORY pImgTlsDir = (PIMAGE_TLS_DIRECTORY)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
    PIMAGE_RUNTIME_FUNCTION_ENTRY pImgRunFuncEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
    PIMAGE_BASE_RELOCATION pImgBaseReloc = (PIMAGE_BASE_RELOCATION)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    // Pointer to the section headers
    PIMAGE_SECTION_HEADER pImgSectionHdr = (PIMAGE_SECTION_HEADER)(((PBYTE)pImgNtHdrs) + sizeof(IMAGE_NT_HEADERS));

    printf("Number of sections: %d\n", pImgNtHdrs->FileHeader.NumberOfSections);

    for (size_t i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
        printf("Section %zu: %s\n", i + 1, pImgSectionHdr->Name);
        printf("\t%s\n", pImgSectionHdr->Name);
        printf("\t\t0x%x\t\tVirtual Size\n", pImgSectionHdr->Misc.VirtualSize);
        printf("\t\t0x%x\t\tVirtual Address\n", pImgSectionHdr->VirtualAddress);
        printf("\t\t0x%x\t\tSize Of Raw Data\n", pImgSectionHdr->SizeOfRawData);
        printf("\t\t0x%x\t\tPointer To Raw Data\n", pImgSectionHdr->PointerToRawData);
        printf("\t\t0x%x\t\tPointer To Relocations\n", pImgSectionHdr->PointerToRelocations);
        printf("\t\t0x%x\t\tPointer To Line Numbers\n", pImgSectionHdr->PointerToLinenumbers);
        printf("\t\t0x%x\t\tNumber Of Relocations\n", pImgSectionHdr->NumberOfRelocations);
        printf("\t\t0x%x\t\tNumber Of Line Numbers\n", pImgSectionHdr->NumberOfLinenumbers);
        printf("\t\t0x%x\tCharacteristics\n", pImgSectionHdr->Characteristics);

        pImgSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)pImgSectionHdr + (DWORD)sizeof(IMAGE_SECTION_HEADER));
    }

    free(pPE);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <PE file path>\n", argv[0]);
        return -1;
    }

    parsePE(argv[1]);
    return 0;
}
