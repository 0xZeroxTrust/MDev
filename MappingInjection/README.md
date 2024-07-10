Mapping injection is a process injection technique that avoids using common monitored syscalls like VirtualAllocEx and WriteProcessMemory. Instead, it leverages the Syscall MapViewOfFile2() and some preliminary steps to prepare memory with the required shellcode.

