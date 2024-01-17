//
// based on https://www.x86matthew.com/view_post?id=import_dll_injection greate post
//
#include <iostream>
#include <windows.h>
#include "ntdll.h"
#include <memory>
#include "wil\resource.h"

// The dll need to have at least 1 imported function in order for the loader to load the dll.
// We tell the loader to look for a function by its ordinal number - 1.
// To make the loader look by ordinal numbert, we set the highest bit to 1.
// (https://learn.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2)
#ifdef _WIN64
uint64_t ordinal = 0x8000000000000001;
#else
uint32_t ordinal = 0x80000001;
#endif

typedef NTSTATUS
(NTAPI* pNtQueryInformationProcess)(
	_In_ HANDLE ProcessHandle,
	_In_ PROCESSINFOCLASS ProcessInformationClass,
	_Out_ PVOID ProcessInformation,
	_In_ ULONG ProcessInformationLength,
	_Out_opt_ PULONG ReturnLength
	);

enum ImportDescriptorPosition {
	FIRST = 0,
	LAST
};

pNtQueryInformationProcess NtQIP = nullptr;

// taken from MSDetours
//https://github.com/microsoft/Detours/tree/4b8c659f549b0ab21cf649377c7a84eb708f5e68

#define MM_ALLOCATION_GRANULARITY 0x10000
/// <summary>
/// Tries to allocate memory near the module specified by the pbModule param
/// </summary>
/// <param name="hProcess">Handle to the remote process</param>
/// <param name="pbModule"Base address of the module to with we want to change the imports></param>
/// <param name="size">allocation size</param>
/// <returns></returns>
static PBYTE FindAndAllocateNearBase(HANDLE hProcess, PBYTE pbModule, DWORD size, const char* allocationName)
{
	MEMORY_BASIC_INFORMATION mbi;
	ZeroMemory(&mbi, sizeof(mbi));

	PBYTE pbLast = pbModule;
	for (;; pbLast = (PBYTE)mbi.BaseAddress + mbi.RegionSize) {

		ZeroMemory(&mbi, sizeof(mbi));
		if (VirtualQueryEx(hProcess, (PVOID)pbLast, &mbi, sizeof(mbi)) == 0) {
			if (GetLastError() == ERROR_INVALID_PARAMETER) {
				break;
			}
			printf("VirtualQueryEx(%p) failed: %lu\n",
				pbLast, GetLastError());
			break;
		}
		// Usermode address space has such an unaligned region size always at the
		// end and only at the end.
		//
		if ((mbi.RegionSize & 0xfff) == 0xfff) {
			break;
		}

		// Skip anything other than a pure free region.
		//
		if (mbi.State != MEM_FREE) {
			continue;
		}

		// Use the max of mbi.BaseAddress and pbBase, in case mbi.BaseAddress < pbBase.
		PBYTE pbAddress = (PBYTE)mbi.BaseAddress > pbModule ? (PBYTE)mbi.BaseAddress : pbModule;

		// Round pbAddress up to the nearest MM allocation boundary.
		const DWORD_PTR mmGranularityMinusOne = (DWORD_PTR)(MM_ALLOCATION_GRANULARITY - 1);
		pbAddress = (PBYTE)(((DWORD_PTR)pbAddress + mmGranularityMinusOne) & ~mmGranularityMinusOne);

#ifdef _WIN64
		// The offset from pbModule to any replacement import must fit into 32 bits.
		// For simplicity, we check that the offset to the last byte fits into 32 bits,
		// instead of the largest offset we'll actually use. The values are very similar.
		const size_t GB4 = ((((size_t)1) << 32) - 1);
		if ((size_t)(pbAddress + size - 1 - pbModule) > GB4) {
			printf("FindAndAllocateNearBase(1) failing due to distance >4GB %p\n", pbAddress);
			return NULL;
		}
#else
		UNREFERENCED_PARAMETER(pbModule);
#endif

		printf("Free region %p..%p\n",
			mbi.BaseAddress,
			(PBYTE)mbi.BaseAddress + mbi.RegionSize);

		for (; pbAddress < (PBYTE)mbi.BaseAddress + mbi.RegionSize; pbAddress += MM_ALLOCATION_GRANULARITY) {
			PBYTE pbAlloc = (PBYTE)VirtualAllocEx(hProcess, pbAddress, size,
				MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
			if (pbAlloc == NULL) {
				printf("VirtualAllocEx(%p) failed: %lu\n", pbAddress, GetLastError());
				continue;
			}
#ifdef _WIN64
			// The offset from pbModule to any replacement import must fit into 32 bits.
			if ((size_t)(pbAddress + size - 1 - pbModule) > GB4) {
				printf("FindAndAllocateNearBase(2) failing due to distance >4GB %p\n", pbAddress);
				return NULL;
			}
#endif
			printf("[%p..%p] Allocated for %s.\n",
				pbAlloc, pbAlloc + size, allocationName);
			return pbAlloc;
		}
	}
	return NULL;
}

// Allocate and write buffer into hProcess's memory
// If that is a 64 bit process, we need to alocate memory near the base address of the module so the (DWORD) relative address pointers will work properly.
void* WriteToRemoteProcess(HANDLE hProcess, PBYTE pbase, LPCVOID buffer, SIZE_T size, const char* allocationName) {

#ifdef _WIN64
	auto allocatedBuffer = FindAndAllocateNearBase(hProcess, pbase, size, allocationName);
#else
	auto allocatedBuffer = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#endif


	//auto allocatedBuffer = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (allocatedBuffer == NULL)
	{
		printf("VirtualAllocEx failed. Error: %d\n", GetLastError());
		return nullptr;
	}

	// write import lookup table to remote process buffer
	if (WriteProcessMemory(hProcess, (void*)allocatedBuffer, (void*)buffer, size, NULL) == 0)
	{
		printf("WriteProcessMemory failed. Error: %d\n", GetLastError());
	}
	return allocatedBuffer;
}

/// <summary>
/// launches a process in suspended mode
/// </summary>
/// <param name="pExePath">- path to the exe file</param>
/// <returns>A tuple with two wil::unique_handle values - {process handle, main thread handle}</returns>
std::tuple<wil::unique_handle, wil::unique_handle> LaunchTargetProcess(const char* pExePath)
{
	PROCESS_INFORMATION ProcessInfo;
	STARTUPINFOA StartupInfo;

	// initialise startup data
	memset((void*)&StartupInfo, 0, sizeof(StartupInfo));
	StartupInfo.cb = sizeof(StartupInfo);

	printf("Launching target process...\n");

	// create target process (suspended)
	memset((void*)&ProcessInfo, 0, sizeof(ProcessInfo));
	if (CreateProcessA(NULL, (LPSTR)pExePath, NULL, NULL, 0, CREATE_SUSPENDED, NULL, NULL, &StartupInfo, &ProcessInfo) == 0)
	{
		return std::make_tuple(nullptr, nullptr);
	}

	return std::make_tuple(wil::unique_handle(ProcessInfo.hProcess), wil::unique_handle(ProcessInfo.hThread));;
}

/// <summary>
/// Create a new IMAGE_IMPORT_DESCRIPTOR for the dll we want to load. 
/// </summary>
/// <param name="pRemoteAlloc_ImportLookupTable">adress of the import lookup table allocated in the target process</param>
/// <param name="dwExeBaseAddr"></param>
/// <param name="pRemoteAlloc_DllPath"adress of the dll path allocated in the target process</param>
/// <param name="pRemoteAlloc_ImportAddressTable">adress of the import address table allocated in the target process</param>
/// <param name="ImageNtHeader"></param>
/// <param name="pos">ImportDescriptorPosition value: FIRST - add our descriptor on index 0. LAST - add it last in the descriptors list</param>
/// <returns>a tuple of {shared_ptr to the new ImportDescriptorList, the ImportDescriptorList length}</returns>
std::tuple<std::shared_ptr<void>, DWORD> CreateNewImportDescriptor(wil::unique_handle& hProcess, void* pRemoteAlloc_ImportLookupTable, void* dwExeBaseAddr, void* pRemoteAlloc_DllPath, void* pRemoteAlloc_ImportAddressTable, const IMAGE_NT_HEADERS& ImageNtHeader, ImportDescriptorPosition pos) {

	IMAGE_IMPORT_DESCRIPTOR NewDllImportDescriptors[2];

	NewDllImportDescriptors[0].OriginalFirstThunk = (PBYTE)pRemoteAlloc_ImportLookupTable - dwExeBaseAddr;
	NewDllImportDescriptors[0].TimeDateStamp = 0;
	NewDllImportDescriptors[0].ForwarderChain = 0;
	NewDllImportDescriptors[0].Name = (PBYTE)pRemoteAlloc_DllPath - dwExeBaseAddr;
	NewDllImportDescriptors[0].FirstThunk = (PBYTE)pRemoteAlloc_ImportAddressTable - dwExeBaseAddr;

	// end of import descriptor chain (only in use if we add the new import descriptor at the end of the list)
	NewDllImportDescriptors[1].OriginalFirstThunk = 0;
	NewDllImportDescriptors[1].TimeDateStamp = 0;
	NewDllImportDescriptors[1].ForwarderChain = 0;
	NewDllImportDescriptors[1].Name = 0;
	NewDllImportDescriptors[1].FirstThunk = 0;

	// calculate existing number of imported dll modules
	DWORD dwExistingImportDescriptorEntryCount = ImageNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	DWORD dwNewImportDescriptorEntryCount = 0;

	if (dwExistingImportDescriptorEntryCount == 0)
	{
		// the target process doesn't have any imported dll entries - this is highly unusual but not impossible
		dwNewImportDescriptorEntryCount = 2;
	}
	else
	{
		// add one extra dll entry
		dwNewImportDescriptorEntryCount = dwExistingImportDescriptorEntryCount + 1;
	}

	// allocate new import description list (local)
	DWORD dwNewImportDescriptorListDataLength = dwNewImportDescriptorEntryCount * sizeof(IMAGE_IMPORT_DESCRIPTOR);
	std::shared_ptr<void> pNewImportDescriptorList(malloc(dwNewImportDescriptorListDataLength), free);
	if (pNewImportDescriptorList == nullptr)
	{
		return std::make_tuple(nullptr, 0);
	}

	if (dwExistingImportDescriptorEntryCount != 0)
	{
		// read existing import descriptor entries
		void* newDescriptorPos = nullptr;
		void* oldDescriptorsPos = nullptr;
		size_t sizeOfNewImportDescriptors = 0;

		switch (pos) {
		case(ImportDescriptorPosition::FIRST):
			// our injected module's import descriptor goes first, the original list after it.
			// we should ignor the null terminating descriptor in that case. the original list have the null terminating descriptor at the end.
			sizeOfNewImportDescriptors = sizeof(IMAGE_IMPORT_DESCRIPTOR);
			newDescriptorPos = pNewImportDescriptorList.get(); // raw shared pointer! make sure not dangling
			oldDescriptorsPos = (PBYTE)newDescriptorPos + sizeof(IMAGE_IMPORT_DESCRIPTOR);
			break;

		case(ImportDescriptorPosition::LAST):
			//  the original list goes first, our injected module's import descriptor after it, including the null terminating descriptor
			sizeOfNewImportDescriptors = sizeof(NewDllImportDescriptors);
			oldDescriptorsPos = pNewImportDescriptorList.get();// raw shared pointer! make sure not dangling
			newDescriptorPos = (PBYTE)oldDescriptorsPos + dwNewImportDescriptorListDataLength - sizeof(NewDllImportDescriptors);
			break;

		default:
			printf("Descriptor position not valid (%d)", pos);
			return std::make_tuple(nullptr, 0);
			break;
		}

		

		void* dwExistingImportDescriptorAddr = (PBYTE)dwExeBaseAddr + ImageNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

		if (ReadProcessMemory(hProcess.get(), (void*)dwExistingImportDescriptorAddr, oldDescriptorsPos, dwExistingImportDescriptorEntryCount * sizeof(IMAGE_IMPORT_DESCRIPTOR), NULL) == 0)
		{
			return std::make_tuple(nullptr, 0);
		}

		memcpy(newDescriptorPos, NewDllImportDescriptors, sizeOfNewImportDescriptors);

	}
	else {
		// no imports for that exe we add only our descriptor and the null terminating descriptor.
		memcpy(pNewImportDescriptorList.get(), NewDllImportDescriptors, sizeof(NewDllImportDescriptors));
	}

	return std::make_tuple(pNewImportDescriptorList, dwNewImportDescriptorListDataLength);
}

DWORD InjectDll(wil::unique_handle& hProcess, wil::unique_handle& hProcessMainThread, const char* pDllPath)
{

	printf("Reading image base address from PEB...\n");

	// get process info
	PROCESS_BASIC_INFORMATION ProcessBasicInfo;
	memset(&ProcessBasicInfo, 0, sizeof(ProcessBasicInfo));
	auto status = NtQIP(hProcess.get(), ProcessBasicInformation, &ProcessBasicInfo, sizeof(ProcessBasicInfo), NULL);
	if (status != 0)
	{
		return 1;
	}

	PEB remoteExePeb;
	void* dwRemotePebPtr = 0;
	// get target exe PEB address
	dwRemotePebPtr = ProcessBasicInfo.PebBaseAddress;
	if (auto ret = ReadProcessMemory(hProcess.get(), dwRemotePebPtr, (void*)&remoteExePeb, sizeof(remoteExePeb), NULL); ret == 0)
	{
		auto err = GetLastError();
		return 1;
	}

	// get target exe base address
	IMAGE_DOS_HEADER ImageDosHeader;
	void* dwExeBaseAddr = remoteExePeb.ImageBaseAddress;
	if (auto ret = ReadProcessMemory(hProcess.get(), dwExeBaseAddr, (void*)&ImageDosHeader, sizeof(ImageDosHeader), NULL); ret == 0)
	{
		auto err = GetLastError();
		return 1;
	}

	// read NT header from target process
	IMAGE_NT_HEADERS ImageNtHeader;
	void* dwNtHeaderAddr = (PBYTE)dwExeBaseAddr + ImageDosHeader.e_lfanew;
	memset((void*)&ImageNtHeader, 0, sizeof(ImageNtHeader));
	if (ReadProcessMemory(hProcess.get(), (void*)dwNtHeaderAddr, (void*)&ImageNtHeader, sizeof(ImageNtHeader), NULL) == 0)
	{
		return 1;
	}

	// save a copy of the original NT header
	IMAGE_NT_HEADERS ImageNtHeader_Original;
	memcpy((void*)&ImageNtHeader_Original, (void*)&ImageNtHeader, sizeof(ImageNtHeader_Original));

	// calculate dll path length
	DWORD dwDllPathLength = strlen(pDllPath) + 1;

	// allocate buffer for the dll path in the remote process
	void* pRemoteAlloc_DllPath = NULL;
	if (pRemoteAlloc_DllPath = WriteToRemoteProcess(hProcess.get(), (PBYTE)dwExeBaseAddr, pDllPath, dwDllPathLength, "dll path"); !pRemoteAlloc_DllPath) {
		return 1;
	}

	// set import lookup table values (import ordinal #1)
	IMAGE_THUNK_DATA dwImportLookupTable[2];
	dwImportLookupTable[0].u1.Ordinal = ordinal;
	dwImportLookupTable[1].u1.Ordinal = 0;

	// allocate buffer for the new import lookup table in the remote process
	void* pRemoteAlloc_ImportLookupTable = NULL;
	if (pRemoteAlloc_ImportLookupTable = WriteToRemoteProcess(hProcess.get(), (PBYTE)dwExeBaseAddr, dwImportLookupTable, sizeof(dwImportLookupTable), "lookup table"); !pRemoteAlloc_ImportLookupTable) {
		return 1;
	}


	// allocate buffer for the new import address table in the remote process
	void* pRemoteAlloc_ImportAddressTable = NULL;
	if (pRemoteAlloc_ImportAddressTable = WriteToRemoteProcess(hProcess.get(), (PBYTE)dwExeBaseAddr, dwImportLookupTable, sizeof(dwImportLookupTable), "address table"); !pRemoteAlloc_ImportAddressTable) {
		return 1;
	}

	// create new import descriptor for injected dll
	auto [pNewImportDescriptorList, dwNewImportDescriptorListDataLength] = CreateNewImportDescriptor(hProcess, pRemoteAlloc_ImportLookupTable, dwExeBaseAddr, pRemoteAlloc_DllPath, pRemoteAlloc_ImportAddressTable, ImageNtHeader, ImportDescriptorPosition::LAST);

	if (!pNewImportDescriptorList || dwNewImportDescriptorListDataLength == 0) {
		return 1;
	}

	//auto pNewNearImports =  FindAndAllocateNearBase(hProcess, (PBYTE)dwExeBaseAddr, dwNewImportDescriptorListDataLength);
	void* pNewNearImports = WriteToRemoteProcess(hProcess.get(), (PBYTE)dwExeBaseAddr, pNewImportDescriptorList.get(), dwNewImportDescriptorListDataLength, "import descriptor list");
	if (!pNewNearImports) {
		return 1;
	}

	printf("Updating PE headers...\n");

	// change the import descriptor address in the remote NT header to point to the new list
	ImageNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = (PBYTE)pNewNearImports - dwExeBaseAddr;
	ImageNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = dwNewImportDescriptorListDataLength;

	// make NT header writable
	DWORD dwOriginalProtection = 0;
	if (VirtualProtectEx(hProcess.get(), (LPVOID)dwNtHeaderAddr, sizeof(ImageNtHeader), PAGE_EXECUTE_READWRITE, &dwOriginalProtection) == 0)
	{
		return 1;
	}

	// write updated NT header to remote process
	if (WriteProcessMemory(hProcess.get(), (void*)dwNtHeaderAddr, (void*)&ImageNtHeader, sizeof(ImageNtHeader), NULL) == 0)
	{
		return 1;
	}

	printf("Resuming process...\n");

	// resume target process execution
	ResumeThread(hProcessMainThread.get());

	printf("Waiting for target DLL...\n");

	// wait for the target process to load the DLL
	for (;;)
	{
		// read the IAT table for the injected DLL
		IMAGE_THUNK_DATA dwCurrentImportAddressTable[2];

		memset((void*)dwCurrentImportAddressTable, 0, sizeof(dwCurrentImportAddressTable));
		if (ReadProcessMemory(hProcess.get(), (void*)pRemoteAlloc_ImportAddressTable, (void*)dwCurrentImportAddressTable, sizeof(dwCurrentImportAddressTable), NULL) == 0)
		{
			return 1;
		}

		// check if the IAT table has been processed
		if (dwCurrentImportAddressTable[0].u1.Function == dwImportLookupTable[0].u1.Function)
		{
			// IAT table for injected DLL not yet processed - try again in 100ms
			Sleep(100);

			continue;
		}

		// DLL has been loaded by target process
		break;
	}

	printf("Restoring original PE headers...\n");

	// restore original NT headers in target process
	if (WriteProcessMemory(hProcess.get(), (void*)dwNtHeaderAddr, (void*)&ImageNtHeader_Original, sizeof(ImageNtHeader), NULL) == 0)
	{
		return 1;
	}

	// restore original protection value for remote NT headers
	DWORD dwOriginalProtection2 = 0;
	if (VirtualProtectEx(hProcess.get(), (LPVOID)dwNtHeaderAddr, sizeof(ImageNtHeader), dwOriginalProtection, &dwOriginalProtection2) == 0)
	{
		return 1;
	}

	// free temporary memory in remote process
	VirtualFreeEx(hProcess.get(), pRemoteAlloc_DllPath, 0, MEM_RELEASE);
	VirtualFreeEx(hProcess.get(), pRemoteAlloc_ImportLookupTable, 0, MEM_RELEASE);
	VirtualFreeEx(hProcess.get(), pRemoteAlloc_ImportAddressTable, 0, MEM_RELEASE);
	VirtualFreeEx(hProcess.get(), (LPVOID)pNewNearImports, 0, MEM_RELEASE);

	return 0;
}


int main(int argc, char* argv[])
{

	char szInjectDllFullPath[512];
	char* pInjectDllPath = NULL;
	char* pExePath = NULL;

	if (argc != 3)
	{
		printf("Usage: %s [exe_path] [inject_dll_path]\n\n", argv[0]);

		return 1;
	}

	// get params
	try {
		pExePath = argv[1];
		pInjectDllPath = argv[2];
	}
	catch (...) {
		printf("Error getting command line args. Terminating\n");
		return 1;
	}

	// get full path from dll filename
	memset(szInjectDllFullPath, 0, sizeof(szInjectDllFullPath));
	if (GetFullPathNameA(pInjectDllPath, sizeof(szInjectDllFullPath) - 1, szInjectDllFullPath, NULL) == 0)
	{
		printf("Invalid DLL path\n");

		return 1;
	}

	////get full path from dll filename
	memset(szInjectDllFullPath, 0, sizeof(szInjectDllFullPath));
	if (GetFullPathNameA(pInjectDllPath, sizeof(szInjectDllFullPath) - 1, szInjectDllFullPath, NULL) == 0)
	{
		printf("Invalid DLL path\n");

		return 1;
	}

	// get NtQueryInformationProcess function ptr
	NtQIP = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	if (NtQIP == NULL)
	{
		printf("Failed to find NtQueryInformationProcess function\n");

		return 1;
	}

	// launch target process
	auto [hProc, hThread] = LaunchTargetProcess(pExePath);
	if (!hProc.is_valid() || !hThread.is_valid())
	{
		printf("Failed to launch target process\n");

		return 1;
	}

	if (InjectDll(hProc, hThread, szInjectDllFullPath) != 0)
	{
		printf("Failed to inject DLL\n");

		TerminateProcess(hProc.get(), 0);

		return 1;
	}
}
