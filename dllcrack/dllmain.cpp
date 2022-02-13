#include<iostream>
#include<string>
#include <sstream>
#include <Windows.h>
#include"MinHook/MinHook.h"
#include <TlHelp32.h>
#include "hwd.h"
#ifdef _DEBUG
#pragma comment(lib,"MinHook/Debug/MinHook.lib")
#else
#pragma comment(lib,"MinHook/Release/MinHook.lib")
#endif
using namespace std;
void* NtProtectVirtualMemory = NULL;
HMODULE hm;

DWORD GetPID(const char* procName) {															// Itterates through every process and looks for a process who's executable name matches the char array passed to this function,
																						// then returns the process ID of that process
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	DWORD pID = NULL;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);				// Creates a snapshot of the currently running processes to itterate over
	//int i = 0; // To skip the first PUBG lite exe.
	if (Process32First(snapshot, &entry)) {												// Grabs the first process' information
		do {
			if (_stricmp(entry.szExeFile, procName) == 0) { 								// Compare the process file name to the only argument passed into the function																	
				pID = entry.th32ProcessID;												// If they are the same set the pID value to that process pID
				break;																	// and break out of the do while loop
			}
		} while (Process32Next(snapshot, &entry));										// Continue scanning the next process in the snapshot
	}

	CloseHandle(snapshot);																// Close the handle since we're done with it

	return pID;																			// Returns the pID

}

DWORD_PTR GetModuleBaseAddress(DWORD pID, const char* moduleName) {								// Itterates through the process with the provided process ID and returns the base address of the module provided

	MODULEENTRY32 entry;
	entry.dwSize = sizeof(MODULEENTRY32);
	DWORD_PTR baseAddress = 0;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pID);					// Creates a snapshot of the process with the provided process ID

	if (Module32First(snapshot, &entry)) {												// Grabs the first modules information
		do {
			if (_stricmp(entry.szModule, moduleName) == 0) {							// Compares the module name to the argument passed into the function
				baseAddress = (DWORD_PTR)entry.modBaseAddr;									// if they are the same set the baseAddress variable to the base address of the module
				break;																	// and break out of the do while loop
			}
		} while (Module32Next(snapshot, &entry));										// continue scanning the next module in the snapshot
	}

	CloseHandle(snapshot);																// Close the handle since we're done with it
	return baseAddress;																	// Return the base Address
}

DWORD WINAPI crack(LPVOID)
{
	if (AllocConsole()) {
		freopen_s(reinterpret_cast<FILE**>(stdout), "CONOUT$", "w", stdout);
		SetConsoleCP(CP_UTF8);
		SetConsoleOutputCP(CP_UTF8);
	}
	/*cout << "您的HWID为:" << get_hwid() << endl;
	cout << "请在C:\\hwdCrack\\key.ini中的key字段中填写key后按任意键继续,如果已经填写过,则无需再次填写"  << endl;
	system("pause");

	char buf[1024];
	GetPrivateProfileStringA("key", "key", "", buf, sizeof(buf), "C:\\hwdCrack\\key.ini");
	initKV();*/
	//if (strcmp(buf, encrypt(get_hwid()).c_str()) == 0)
	if(true)
	{
		cout << "欢迎使用 作者:荒陌" << endl;
		cout << "QQ群:260873883" << endl;
		MH_STATUS status = MH_Initialize();
		cout << "MH_Initialize:" << MH_StatusToString(status) << endl;
		cout << "等待注入待破解dll" << endl;
		DWORD pid = GetPID("gta5.exe");

		uint64_t base_addr = NULL;
		while (base_addr == NULL)
		{
			base_addr = GetModuleBaseAddress(pid, "hwd.dll");
			Sleep(200);
		}

		Sleep(2000);

		//patch vmp的hook的NtProtectVirtualMemory函数
		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		NtProtectVirtualMemory = GetProcAddress(ntdll, "NtProtectVirtualMemory");
		byte newBytes[] = { 0x4C,0x8B,0xD1,0xB8,0x50 };
		PDWORD O;

		if (VirtualProtect(NtProtectVirtualMemory, sizeof(newBytes) + 1, PAGE_EXECUTE_READWRITE, (PDWORD)&O) != 0)
		{
			cout << "VirtualProtect:OK" << endl;
			if (memcmp(NtProtectVirtualMemory, newBytes, sizeof(newBytes)) != 0)
			{
				memcpy(NtProtectVirtualMemory, newBytes, sizeof(newBytes));
				cout << "NtProtectVirtualMemory Patch:OK" << endl;
			}
		}

		//HookApi
		status = MH_CreateHookApi(L"hwd.dll", "hwd_getUserInfo", &hwd_getUserInfo, (LPVOID*)&hwd_getUserInfo_o);
		cout << "hwd_getUserInfo:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_deductBalance", &hwd_deductBalance, (LPVOID*)&hwd_deductBalance_o);
		cout << "hwd_deductBalance:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_login", &hwd_login, (LPVOID*)&hwd_login_o);
		cout << "hwd_login:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_getVersion", &hwd_getVersion, (LPVOID*)&hwd_getVersion_o);
		cout << "hwd_getVersion:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_getLastErrorMsg", &hwd_getLastErrorMsg, (LPVOID*)&hwd_getLastErrorMsg_o);
		cout << "hwd_getLastErrorMsg:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_getLastErrorCode", &hwd_getLastErrorCode, (LPVOID*)&hwd_getLastErrorCode_o);
		cout << "hwd_getLastErrorCode:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_loadSkinByByte", &hwd_loadSkinByByte, (LPVOID*)&hwd_loadSkinByByte_o);
		cout << "hwd_loadSkinByByte:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_loadSkinByFile", &hwd_loadSkinByFile, (LPVOID*)&hwd_loadSkinByFile_o);
		cout << "hwd_loadSkinByFile:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_init", &hwd_init, (LPVOID*)&hwd_init_o);
		cout << "hwd_init:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_getSoftInfo", &hwd_getSoftInfo, (LPVOID*)&hwd_getSoftInfo_o);
		cout << "hwd_getSoftInfo:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_getSoftVersionInfo", &hwd_getSoftVersionInfo, (LPVOID*)&hwd_getSoftVersionInfo_o);
		cout << "hwd_getSoftVersionInfo:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_getSoftPara", &hwd_getSoftPara, (LPVOID*)&hwd_getSoftPara_o);
		cout << "hwd_getSoftPara:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_getCaptchaImg", &hwd_getCaptchaImg, (LPVOID*)&hwd_getCaptchaImg_o);
		cout << "hwd_getCaptchaImg:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_getCaptchaImgFile", &hwd_getCaptchaImgFile, (LPVOID*)&hwd_getCaptchaImgFile_o);
		cout << "hwd_getCaptchaImgFile:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_getMachineCode", &hwd_getMachineCode, (LPVOID*)&hwd_getMachineCode_o);
		cout << "hwd_getMachineCode:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_reg", &hwd_reg, (LPVOID*)&hwd_reg_o);
		cout << "hwd_reg:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_sendMail", &hwd_sendMail, (LPVOID*)&hwd_sendMail_o);
		cout << "hwd_sendMail:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_resetPwd", &hwd_resetPwd, (LPVOID*)&hwd_resetPwd_o);
		cout << "hwd_resetPwd:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_recharge", &hwd_recharge, (LPVOID*)&hwd_recharge_o);
		cout << "hwd_recharge:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_addBlackList", &hwd_addBlackList, (LPVOID*)&hwd_addBlackList_o);
		cout << "hwd_addBlackList:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_getUserPara", &hwd_getUserPara, (LPVOID*)&hwd_getUserPara_o);
		cout << "hwd_getUserPara:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_deductPoint", &hwd_deductPoint, (LPVOID*)&hwd_deductPoint_o);
		cout << "hwd_deductPoint:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_deductTime", &hwd_deductTime, (LPVOID*)&hwd_deductTime_o);
		cout << "hwd_deductTime:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_setUserbind", &hwd_setUserbind, (LPVOID*)&hwd_setUserbind_o);
		cout << "hwd_setUserbind:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_bindMachineCode", &hwd_bindMachineCode, (LPVOID*)&hwd_bindMachineCode_o);
		cout << "hwd_bindMachineCode:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_logout", &hwd_logout, (LPVOID*)&hwd_logout_o);
		cout << "hwd_logout:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_callPHP", &hwd_callPHP, (LPVOID*)&hwd_callPHP_o);
		cout << "hwd_callPHP:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_getParam", &hwd_getParam, (LPVOID*)&hwd_getParam_o);
		cout << "hwd_getParam:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_getPcMsg", &hwd_getPcMsg, (LPVOID*)&hwd_getPcMsg_o);
		cout << "hwd_getPcMsg:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_heartbeat", &hwd_heartbeat, (LPVOID*)&hwd_heartbeat_o);
		cout << "hwd_heartbeat:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_loadLoginWindow", &hwd_loadLoginWindow, (LPVOID*)&hwd_loadLoginWindow_o);
		cout << "hwd_loadLoginWindow:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_loadRegWindow", &hwd_loadRegWindow, (LPVOID*)&hwd_loadRegWindow_o);
		cout << "hwd_loadRegWindow:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_loadRepwdWindow", &hwd_loadRepwdWindow, (LPVOID*)&hwd_loadRepwdWindow_o);
		cout << "hwd_loadRepwdWindow:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_loadRechargeWindow", &hwd_loadRechargeWindow, (LPVOID*)&hwd_loadRechargeWindow_o);
		cout << "hwd_loadRechargeWindow:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_save", &hwd_save, (LPVOID*)&hwd_save_o);
		cout << "hwd_save:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_read", &hwd_read, (LPVOID*)&hwd_read_o);
		cout << "hwd_read:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_htmlFilter", &hwd_htmlFilter, (LPVOID*)&hwd_htmlFilter_o);
		cout << "hwd_htmlFilter:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_fastCheck", &hwd_fastCheck, (LPVOID*)&hwd_fastCheck_o);
		cout << "hwd_fastCheck:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_getFastInfo", &hwd_getFastInfo, (LPVOID*)&hwd_getFastInfo_o);
		cout << "hwd_getFastInfo:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_getFastPara", &hwd_getFastPara, (LPVOID*)&hwd_getFastPara_o);
		cout << "hwd_getFastPara:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_blueSky", &hwd_blueSky, (LPVOID*)&hwd_blueSky_o);
		cout << "hwd_blueSky:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_getFileMD5", &hwd_getFileMD5, (LPVOID*)&hwd_getFileMD5_o);
		cout << "hwd_getFileMD5:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_getStrMD5", &hwd_getStrMD5, (LPVOID*)&hwd_getStrMD5_o);
		cout << "hwd_getStrMD5:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_getRuningPath", &hwd_getRuningPath, (LPVOID*)&hwd_getRuningPath_o);
		cout << "hwd_getRuningPath:" << MH_StatusToString(status) << endl;

		status = MH_CreateHookApi(L"hwd.dll", "hwd_getModulePath", &hwd_getModulePath, (LPVOID*)&hwd_getModulePath_o);
		cout << "hwd_getModulePath:" << MH_StatusToString(status) << endl;

		status = MH_EnableHook(MH_ALL_HOOKS);
		cout << "MH_EnableHook:" << MH_StatusToString(status) << endl;



		//普通Hook
		//uint64_t getUserInfo = base_addr + 0x0001dd10;	//hwd_getUserInfo

		//status = MH_CreateHook((LPVOID)getUserInfo, &hwd_getUserInfo, (LPVOID*)&hwd_getUserInfo_o);
		//MessageBoxA(0, MH_StatusToString(status), "MH_CreateHook", MB_OK);

		//status = MH_EnableHook((LPVOID)getUserInfo);
		//MessageBoxA(0, MH_StatusToString(status), "MH_EnableHook", MB_OK);

		//WindowsApiHook
		//status = MH_CreateHook(exit, &exit_h, (LPVOID*)&exit_o);
		//MessageBoxA(0, MH_StatusToString(status), "MH_CreateHook", MB_OK);

		//status = MH_EnableHook(exit);
		//MessageBoxA(0, MH_StatusToString(status), "MH_EnableHook", MB_OK);
	}
	else
	{
	FreeConsole();
	FreeLibraryAndExitThread(hm, 0);
	}



	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		hm = hModule;
		CreateThread(nullptr, 0, crack, nullptr, 0, NULL);
		// crack();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		//MH_Uninitialize();
		break;
	}
	return TRUE;
}

