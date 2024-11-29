#include <Windows.h>
#include <Psapi.h>
#include <iostream>
#include <tuple>

std::tuple<DWORD,DWORD> GetSectionAddr(void * baseAddr,const char *sectionName) {

	// 检查DOS头
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)baseAddr;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return { 0,0 };
	}

	// 跳到PE头
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD64)baseAddr + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return { 0,0 };
	}

	// 获取节表
	PIMAGE_SECTION_HEADER pSectionHeaders = IMAGE_FIRST_SECTION(pNtHeaders);

	// 遍历节表寻找指定节
	for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i) {
		if (memcmp(pSectionHeaders[i].Name, sectionName, 8) == 0) {
			DWORD sectionAddr = pSectionHeaders[i].VirtualAddress;
			DWORD size = pSectionHeaders[i].SizeOfRawData;
			return { sectionAddr, size };
		}
	}

	return { 0,0 };
}


DWORD GetAddrByMachineCode(const wchar_t* modulePath, const BYTE machineCodePattern[],const unsigned int & patternSize) {

	// 获取模块基址
	HANDLE hProcess = GetCurrentProcess();
	HMODULE hNtoskrnl = LoadLibrary(modulePath);

	MODULEINFO moduleInfo = { 0 };
	if (!GetModuleInformation(GetCurrentProcess(), hNtoskrnl, &moduleInfo, sizeof(MODULEINFO))) {
		std::cerr << "GetModuleInformation failed." << std::endl;
		return 0;
	}

	auto tup = GetSectionAddr(moduleInfo.lpBaseOfDll, "PAGE");

	DWORD64 startAddr = (DWORD64)hNtoskrnl+ std::get<0>(tup);
	DWORD64 sizeAddr = std::get<1>(tup);

	SIZE_T bytesRead;
	BYTE buffer[4096] = { 0 }; // 每次读取一个页（4kb）大小的内存
	for (SIZE_T offset = 0; offset < sizeAddr; offset += sizeof(buffer)) {

		if (!ReadProcessMemory(hProcess, (LPCVOID)(startAddr + offset), buffer, sizeof(buffer), &bytesRead)) {
			std::cerr << "ReadProcessMemory failed: " << GetLastError() << std::endl;
			break;
		}

		// match
		for (SIZE_T i = 0; i < bytesRead - patternSize; ++i) {
			bool found = true;
			for (SIZE_T j = 0; j < patternSize; ++j) {
				if (buffer[i + j] != machineCodePattern[j]) {
					found = false;
					break;
				}
			}
			if (found) {
				std::cout << "Pattern found at offset: " << std::hex << "0x" << (startAddr + offset + i) << std::endl;
				return DWORD(startAddr + offset + i);
			}
		}
	}

	return 0;
}

int main(int argc, char* argv[]) {

	const wchar_t* module_path = L"C:\\Windows\system32\\ntoskrnl.exe";

	// 要搜索的机器码
	BYTE machineCodePattern[] = {
		0x48, 0x89, 0x5C, 0x24, 0x08,
		0x48, 0x89, 0x74, 0x24, 0x10,
		0x57,
		0x48, 0x83, 0xEC, 0x30,
		0x8B, 0xFA,
		0x48, 0x8B, 0xD9
	};

	auto addr = GetAddrByMachineCode(module_path, machineCodePattern,sizeof(machineCodePattern));

	return 0;
}