#include <windows.h>
#include <stdio.h>
#pragma warning( push )
#pragma warning( disable : 4146)
#pragma warning( push )

#define INITIAL_HASH 3731 
#define INITIAL_SEED 7  // Added to randomize the hash

// Generate Djb2 hashes from ASCII input string
DWORD HashStringDjb2A(_In_ const char* String) {
    ULONG Hash = INITIAL_HASH;
    INT c;

    while (c = *String++)
        Hash = ((Hash << INITIAL_SEED) + Hash) + c;

    return Hash;
}

// Generate Djb2 hashes from wide-character input string
DWORD HashStringDjb2W(_In_ const wchar_t* String) {
    ULONG Hash = INITIAL_HASH;
    INT c;

    while (c = *String++)
        Hash = ((Hash << INITIAL_SEED) + Hash) + c;

    return Hash;
}

// -----------------------------------------------------------
// JenkinsOneAtTime32BitA
UINT32 HashStringJenkinsOneAtATime32BitA(_In_ const char* String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
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

	UINT32 HashJA = Hash;
	return HashJA;
}

// Generate JenkinsOneAtATime32Bit hashes from wide-character input string
UINT32 HashStringJenkinsOneAtATime32BitW(_In_  const wchar_t* String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenW(String);

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

// ---------------------------------------------------------------

// loselose Hashing Algo
DWORD HashStringLoseLoseA(_In_ const char* String)
{
	ULONG Hash = 0;
	INT c;

	while (c = *String++) {
		Hash += c;
		Hash *= c + INITIAL_SEED;	// update
	}
	return Hash;
}

// Generate LoseLose hashes from wide-character input string
DWORD HashStringLoseLoseW(_In_ const wchar_t* String)
{
	ULONG Hash = 0;
	INT c;

	while (c = *String++) {
		Hash += c;
		Hash *= c + INITIAL_SEED;	// update
	}

	return Hash;
}

// ------------------------------------------------------------
// Rotr32
UINT32 HashStringRotr32Sub(UINT32 Value, UINT Count) {
	DWORD Mask = (CHAR_BIT * sizeof(Value) - 1);
	Count &= Mask;
	return (Value >> Count) | (Value << ((-Count) & Mask));

}

	// Generate Rotr32 hashes from Ascii input string
	INT HashStringRotr32A(_In_ const char* String)
	{
		INT Value = 0;

		for (INT Index = 0; Index < lstrlenA(String); Index++)
			Value = String[Index] + HashStringRotr32Sub(Value, INITIAL_SEED);

		return Value;
	}

	// Generate Rotr32 hashes from wide-character input string
	INT HashStringRotr32W(_In_ const wchar_t* String)
	{
		INT Value = 0;

		for (INT Index = 0; Index < lstrlenW(String); Index++)
			Value = String[Index] + HashStringRotr32Sub(Value, INITIAL_SEED);

		return Value;
	}

int main() {
    // Test the ASCII string hash function
    const char* testStringA = "Hello, World!";
    // Test the wide-character string hash function
    const wchar_t testStringW[] = L"Hello, World!";

    printf("[i] Djb2 Hashing \n");
    DWORD hashA = HashStringDjb2A(testStringA);
    printf("Hash of '%s': %lu\n", testStringA, hashA);
    DWORD hashW = HashStringDjb2W(testStringW);
    wprintf(L"Hash of '%s': %lu\n", testStringW, hashW);
	printf("\n");

	printf("[i] JenkinsOneAtATime32Bit Hashing \n");
	UINT32 hashJA = HashStringJenkinsOneAtATime32BitA(testStringA);
	printf("Hash of '%s': %lu\n", testStringA, hashJA);
	UINT32 hashJW = HashStringJenkinsOneAtATime32BitW(testStringW);
	wprintf(L"Hash of '%s': %lu\n", testStringW, hashJW);
	printf("\n");

	printf("[i] LoseLose Hashing \n");
	DWORD hashLA = HashStringDjb2A(testStringA);
	printf("Hash of '%s': %lu\n", testStringA, hashLA);
	DWORD hashLW = HashStringDjb2W(testStringW);
	wprintf(L"Hash of '%s': %lu\n", testStringW, hashLW);
	printf("\n");

	printf("[i] Rotr Hashing \n");
	int hashRA = HashStringDjb2A(testStringA);
	printf("Hash of '%s': %lu\n", testStringA, hashRA);
	int hashRW = HashStringDjb2W(testStringW);
	wprintf(L"Hash of '%s': %lu\n", testStringW, hashRW);
	printf("\n");


    return 0;
}
