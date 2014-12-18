//AntiServerFull (spoofed ip) fix by BartekDVD & Gamer_Z
//Thanks to Kurta999 and GWMPT for help

#include <set>
#include <time.h>

#ifdef _WIN32
#define THISCALL __thiscall
#define STDCALL __stdcall

#include <Windows.h>
#include <Psapi.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Psapi.lib")
#else
#define THISCALL
#define STDCALL
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef unsigned long DWORD;
typedef int SOCKET;
typedef unsigned char BYTE;
#endif

#include "sampgdk.h"

typedef int(THISCALL *FPTR_SocketLayerSendTo)(void* pSocketLayerObj, SOCKET s, const char *data, int length, unsigned int binaryAddress, unsigned short port);
typedef void(STDCALL *FPTR_ProcessNetworkPacket)(const unsigned int binaryAddress, const unsigned short port, const char *data, const int length, void *rakPeer);//0x00456EF0

int SendTo(SOCKET s, const char *data, int length, char ip[16], unsigned short port); 

FPTR_ProcessNetworkPacket RealProcessNetworkPacket;
FPTR_SocketLayerSendTo RealSocketLayerSendTo;

DWORD iRealProcessNetworkPacket;
DWORD iSocketLayerSendTo;
SOCKET* pRakServerSocket;
void* pSocketLayerObject;

static const size_t MAX_OFFLINE_DATA_LENGTH = 400;

void *pRakServer = NULL;

bool inline IsGoodPongLength(size_t length)
{
	return
		length >= sizeof(unsigned char) + 4 &&
		length < sizeof(unsigned char) + 4 + MAX_OFFLINE_DATA_LENGTH;
}

std::set<unsigned long long> ip_whitelist;
std::set<unsigned long long> ip_whitelist_online;
unsigned long long PlayerIPSET[MAX_PLAYERS];

size_t MyMagicNumber;
#define MAGIC 0								//change this to a random number between 0 and 4!

int MySecretReturnCode(const unsigned int binaryAddress, const unsigned short port)
{
#if MAGIC == 0
	return (MyMagicNumber ^ binaryAddress) ^ ~port;
#elif MAGIC == 1
	return (MyMagicNumber ^ binaryAddress) ^ port;
#elif MAGIC == 2
	return (MyMagicNumber ^ ~binaryAddress) ^ port;
#elif MAGIC == 3
	return (MyMagicNumber ^ ~binaryAddress) ^ ~port;
#endif
}

//|Step 1. Hook |Step 2. Challenge |Step 3. PassThrough.
void STDCALL DetouredProcessNetworkPacket(const unsigned int binaryAddress, const unsigned short port, const char *data, const int length, void *rakPeer)
{
	static char ping[5] = { 8/*ID_PING*/, 0, 0, 0, 0 };
	unsigned int ip_data[2] = { binaryAddress, port };
	if (ip_whitelist.find(*(unsigned long long*)ip_data) == ip_whitelist.end())
	{
		if (data[0] == 40/*ID_PONG*/ && IsGoodPongLength(length) && (*(int*)(data + 1)) == MySecretReturnCode(binaryAddress, port))
			ip_whitelist.insert(*(unsigned long long*)ip_data);
		else
		{
			(*(int*)(ping + 1)) = MySecretReturnCode(binaryAddress, port);
			RealSocketLayerSendTo(pSocketLayerObject, *pRakServerSocket, (const char*)ping, 5, binaryAddress, port);
		}
	}
	else RealProcessNetworkPacket(binaryAddress, port, data, length, rakPeer);
}

static const size_t PLUGIN_DATA_RAKSERVER = 0xE2; // RakServerInterface* PluginGetRakServer()

void* Detour(unsigned char* src, unsigned char* dst, int num)
{
	if (src == (unsigned char*)0)
		return (void*)0;
	if (dst == (unsigned char*)0)
		return (void*)0;
	if (num < 5)
		return (void*)0;

	unsigned char *all = new unsigned char[5 + num];

#ifndef _WIN32
	size_t pagesize = sysconf(_SC_PAGESIZE);
	size_t addr1 = ((size_t)all / pagesize)*pagesize;
	size_t addr2 = ((size_t)src / pagesize)*pagesize;
	mprotect((void*)addr1, pagesize + num + 5, PROT_READ | PROT_WRITE | PROT_EXEC);
	mprotect((void*)addr2, pagesize + num, PROT_READ | PROT_WRITE | PROT_EXEC);
#else
	unsigned long dwProtect;
	VirtualProtect(all, 5 + num, PAGE_EXECUTE_READWRITE, &dwProtect);
	VirtualProtect(src, num, PAGE_EXECUTE_READWRITE, &dwProtect);
#endif

	memcpy(all, src, num);

	if (all[0] == 0xE9 || all[0] == 0xE8)
	{
		unsigned long val = *(unsigned long*)(&all[1]);
		*(unsigned long*)(&all[1]) = val + src - all;
	}

	all += num;
	unsigned long jmp1 = (unsigned long)((src + num) - (all + 5));

	all[0] = 0xE9;
	*(unsigned long*)(all + 1) = jmp1;

	unsigned long jmp2 = (unsigned long)(dst - src) - 5;

	all -= num;

	src[0] = 0xE9;
	*(unsigned long*)(src + 1) = jmp2;

	return (void*)all;
}

void Retour(unsigned char* src, unsigned char** all, int num)
{
	if (all == (unsigned char**)0)
		return;
	if (*all == (unsigned char*)0)
		return;
	if (src == (unsigned char*)0)
		return;
	if (num < 5)
		return;

#ifndef _WIN32
	size_t pagesize = sysconf(_SC_PAGESIZE);
	size_t addr = ((size_t)src / pagesize)*pagesize;
	mprotect((void*)addr, pagesize + num, PROT_READ | PROT_WRITE | PROT_EXEC);
#else
	unsigned long dwProtect;
	VirtualProtect(src, num, PAGE_EXECUTE_READWRITE, &dwProtect);
#endif

	memcpy(src, *all, num);

	if (src[0] == 0xE9 || src[0] == 0xE8)
	{
		unsigned long val = *(unsigned long*)(&src[1]);
		*(unsigned long*)(&src[1]) = val + (*all) - src;
	}

	delete[](*all);
	*all = (unsigned char*)0;
}

//run each minut to perform some unused memory cleanup
void CleanupUnusedWhitelistSlots(int timerid, void * param)
{
	MyMagicNumber = 0x22222222 + (rand() % (0xAAAAAAAA - 0x22222222));
	for (auto i = ip_whitelist.begin(); i != ip_whitelist.end();)
		if (ip_whitelist_online.find(*i) == ip_whitelist_online.end())
			i = ip_whitelist.erase(i);
		else ++i;
}

bool memory_compare(const BYTE *data, const BYTE *pattern, const char *mask)
{
	for (; *mask; ++mask, ++data, ++pattern)
	{
		if (*mask == 'x' && *data != *pattern)
			return false;
	}
	return (*mask) == NULL;
}

DWORD FindPattern(char *pattern, char *mask)
{
	DWORD i;
	DWORD size;
	DWORD address;
#ifdef _WIN32
	MODULEINFO info = { 0 };

	address = (DWORD)GetModuleHandle(NULL);
	GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), &info, sizeof(MODULEINFO));
	size = (DWORD)info.SizeOfImage;
#else
	address = 0x804b480; // around the elf base
	size = 0x8128B80 - address;
#endif
	for (i = 0; i < size; ++i)
	{
		if (memory_compare((BYTE *)(address + i), (BYTE *)pattern, mask))
			return (DWORD)(address + i);
	}
	return 0;
}

extern void * pAMXFunctions;

PLUGIN_EXPORT unsigned int PLUGIN_CALL Supports()
{
	return sampgdk::Supports() | SUPPORTS_PROCESS_TICK;
}

PLUGIN_EXPORT bool PLUGIN_CALL Load(void **ppData)
{
	pAMXFunctions = ppData[PLUGIN_DATA_AMX_EXPORTS];
	bool load = sampgdk::Load(ppData);

	srand((unsigned int)time(NULL));
	MyMagicNumber = 0x22222222 + (rand() % (0xAAAAAAAA - 0x22222222));
	sampgdk_SetTimer(60000, true, CleanupUnusedWhitelistSlots, 0);

	int(*pfn_GetRakServer)(void) = (int(*)(void))ppData[PLUGIN_DATA_RAKSERVER];
	pRakServer = (void*)pfn_GetRakServer();

#ifdef _WIN32

	int iRealProcessNetworkPacket = FindPattern("\x6A\xFF\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x64\x89\x25\x00\x00\x00\x00\x81\xEC\x5C", "xxx????xxxxxxxxxxxxxxxxx");//0x00456EF0;
	int iSocketLayerSendTo = FindPattern("\x83\xEC\x10\x55\x8B\x6C\x24\x18\x83\xFD\xFF", "xxxxxxxxxxx");//0x004633A0;
	pRakServerSocket = (SOCKET*)((char*)pRakServer + 0xC20);
	pSocketLayerObject = (void*)0x004EDA71;
	RealProcessNetworkPacket = reinterpret_cast<FPTR_ProcessNetworkPacket>(Detour((unsigned char*)iRealProcessNetworkPacket, (unsigned char*)DetouredProcessNetworkPacket, 7));
	RealSocketLayerSendTo = reinterpret_cast<FPTR_SocketLayerSendTo>(iSocketLayerSendTo);

#else
	if (*((char*)(0x8150D2F + 0x07) == 0)
	{//500p
		int iRealProcessNetworkPacket = 0x8073080;
		int iSocketLayerSendTo = 0x808EB80;
		pRakServerSocket = (SOCKET*)((char*)pRakServer + 0xC12);
		pSocketLayerObject = (void*)0x08194A00;
		RealProcessNetworkPacket = reinterpret_cast<FPTR_ProcessNetworkPacket>(Detour((unsigned char*)iRealProcessNetworkPacket, (unsigned char*)DetouredProcessNetworkPacket, 6));//or 5?
		RealSocketLayerSendTo = reinterpret_cast<FPTR_SocketLayerSendTo>(iSocketLayerSendTo);
	}
	else
	{//1000p
		int iRealProcessNetworkPacket = 0x8073080;
		int iSocketLayerSendTo = 0x808EB80;
		pRakServerSocket = (SOCKET*)((char*)pRakServer + 0xC12);
		pSocketLayerObject = (void*)0x08194420;
		RealProcessNetworkPacket = reinterpret_cast<FPTR_ProcessNetworkPacket>(Detour((unsigned char*)iRealProcessNetworkPacket, (unsigned char*)DetouredProcessNetworkPacket, 6));//or 5?
		RealSocketLayerSendTo = reinterpret_cast<FPTR_SocketLayerSendTo>(iSocketLayerSendTo);
	}
#endif

	return load;
}

PLUGIN_EXPORT void PLUGIN_CALL ProcessTick()
{
	sampgdk::ProcessTick();
}

SAMPGDK_CALLBACK(bool, OnIncomingConnection(int playerid, const char * ip_address, int port))
{
	unsigned int ip_data[2] = { inet_addr(ip_address), port };
	if (PlayerIPSET[playerid] != 0)
		ip_whitelist.erase(PlayerIPSET[playerid]);
	PlayerIPSET[playerid] = *(unsigned long long*)ip_data;
	return true;
}

SAMPGDK_CALLBACK(bool, OnPlayerConnect(int playerid))
{
	ip_whitelist_online.insert(PlayerIPSET[playerid]);
	return true;
}

SAMPGDK_CALLBACK(bool, OnPlayerDisconnect(int playerid, int reason))
{
	ip_whitelist_online.erase(PlayerIPSET[playerid]);
	ip_whitelist.erase(PlayerIPSET[playerid]);
	PlayerIPSET[playerid] = 0;
	return true;
}

PLUGIN_EXPORT void PLUGIN_CALL Unload()
{
	sampgdk::Unload();
}
