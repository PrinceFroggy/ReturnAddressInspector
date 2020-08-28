#include <Windows.h>
#include <algorithm>
#include <vector>
#include <stdio.h>
#include <tchar.h>
#include <intrin.h>

#pragma intrinsic(_ReturnAddress)

typedef LONG (WINAPI *pfnInterlockedIncrement)(_Inout_ LONG volatile *Addend);
const pfnInterlockedIncrement __InterlockedIncrement = reinterpret_cast<pfnInterlockedIncrement>(GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), TEXT("InterlockedIncrement")));

__declspec(naked) LONG WINAPI InterlockedIncrementTrampoline(_Inout_ LONG volatile *Addend)
{
	static const DWORD OriginalInterlockedIncrement = reinterpret_cast<DWORD>(__InterlockedIncrement) + 5;
	__asm
	{
		push ebp
		mov ebp, esp
		jmp dword ptr [OriginalInterlockedIncrement]
	}
}

std::vector<DWORD> vReturnAddresses;

__declspec(noinline) LONG WINAPI InterlockedIncrementHook(_Inout_ LONG volatile *Addend)
{
	DWORD dwReturnAddress = 0;// reinterpret_cast<DWORD>(_ReturnAddress());
	__try
	{
		__asm
		{
			push eax
			mov eax, dword ptr [ebp]
			mov eax, dword ptr [eax+4]
			mov dword ptr [dwReturnAddress], eax
			pop eax
		}
	}
	__finally
	{
		HMODULE hModule;
		GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)dwReturnAddress, &hModule);
		if (hModule == GetModuleHandle(NULL))
		{
			if (std::find(vReturnAddresses.begin(), vReturnAddresses.end(), dwReturnAddress) == vReturnAddresses.end())
			{
				vReturnAddresses.push_back(dwReturnAddress);
				TCHAR szBuffer[100];
				_stprintf_s(szBuffer, TEXT("Return Address: %X"), dwReturnAddress);
				OutputDebugString(szBuffer);
			}
		}
	}
	return InterlockedIncrementTrampoline(Addend);
}

bool Hook(bool bEnable)
{
	if (bEnable)
	{
		__try
		{
			DWORD dwOldProtect;
			VirtualProtect(__InterlockedIncrement, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			*(BYTE *)__InterlockedIncrement = 0xE9;
			*(DWORD *)((DWORD)__InterlockedIncrement + 1) = (DWORD)InterlockedIncrementHook - (DWORD)__InterlockedIncrement - 5;
			VirtualProtect(__InterlockedIncrement, 5, dwOldProtect, &dwOldProtect);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			OutputDebugString(TEXT("ENABLE - fail"));
			return false;
		}
		OutputDebugString(TEXT("ENABLE"));
	}
	else
	{
		__try
		{
			DWORD dwOldProtect;
			VirtualProtect(__InterlockedIncrement, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			*(BYTE *)__InterlockedIncrement = 0x8B;
			*(DWORD *)((DWORD)__InterlockedIncrement + 1) = 0xEC8B55FF;
			VirtualProtect(__InterlockedIncrement, 5, dwOldProtect, &dwOldProtect);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			OutputDebugString(TEXT("DISABLE - fail"));
			return false;
		}
		OutputDebugString(TEXT("DISABLE"));
	}
	return true;
}

BOOL APIENTRY DllMain(_In_ HMODULE hModule, _In_ DWORD dwReason, _In_ PVOID pReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		OutputDebugString(TEXT("DLL_PROCESS_ATTACH"));
		DisableThreadLibraryCalls(hModule);
		Hook(true);
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		OutputDebugString(TEXT("DLL_PROCESS_DETACH"));
		Hook(false);
	}
	return TRUE;
}