The use of PEB->ProcessParameters.CommandLine.Buffer to overwrite the payload can be exposed by Process Hacker and other tools such as Process Explorer because these tools use NtQueryInformationProcess to read the command line arguments of a process at runtime. Since this occurs at runtime, they can see what is currently inside PEB->ProcessParameters.CommandLine.Buffer

### Solution
These Tools read the CommandLine.Buffer up until the length specified by CommandLine.Length . They don’t rely on CommandLine.Buffer being null-terminated bcaz Microsoft states that UNICODE_STRING.Buffer might not be null-terminated.

limit the number of bytes read from CommandLine.Buffer to be equal to CommandLine.Length in order to prevent reading additional unnecessary bytes
