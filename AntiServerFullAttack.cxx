//AntiServerFull (spoofed ip) fix by BartekDVD & Gamer_Z
//Thanks to Kurta999 and GWMPT for help
//Works ONLY on SA-MP 0.3z-R4 (windows & linux 500p & linux 1000p)
#include <set>
#include <time.h>
#include <vector>
#include <string>

#ifdef _WIN32

#define THISCALL __thiscall
#define STDCALL __stdcall

#include <Windows.h>
#include <Psapi.h>
#include <intrin.h>

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
#include <stdlib.h>

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

static const size_t PLUGIN_DATA_RAKSERVER = 0xE2;	// RakServerInterface* PluginGetRakServer()
static const size_t MAX_OFFLINE_DATA_LENGTH = 400;

void *pRakServer = NULL;
extern void * pAMXFunctions;
void **gppData = 0;

std::set<unsigned long long> ip_whitelist;
std::set<unsigned long long> ip_whitelist_online;
unsigned long long PlayerIPSET[MAX_PLAYERS];

typedef unsigned long Fnv32_t;


/*
* 32 bit magic FNV-1a prime
*/
#define FNV_32_PRIME ((Fnv32_t)0x01000193)


/*
* fnv_32a_buf - perform a 32 bit Fowler/Noll/Vo FNV-1a hash on a buffer
*
* input:
*	buf	- start of buffer to hash
*	len	- length of buffer in octets
*	hval	- previous hash value or 0 if first call
*
* returns:
*	32 bit hash as a static hash type
*
* NOTE: To use the recommended 32 bit FNV-1a hash, use FNV1_32A_INIT as the
* 	 hval arg on the first call to either fnv_32a_buf() or fnv_32a_str().
*/
Fnv32_t
fnv_32a_buf(void *buf, size_t len, Fnv32_t hval)
{
	unsigned char *bp = (unsigned char *)buf;	/* start of buffer */
	unsigned char *be = bp + len;		/* beyond end of buffer */

	/*
	* FNV-1a hash each octet in the buffer
	*/
	while (bp < be) {

		/* xor the bottom with the current octet */
		hval ^= (Fnv32_t)*bp++;

		/* multiply by the 32 bit FNV magic prime mod 2^32 */
#if defined(NO_FNV_GCC_OPTIMIZATION)
		hval *= FNV_32_PRIME;
#else
		hval += (hval << 1) + (hval << 4) + (hval << 7) + (hval << 8) + (hval << 24);
#endif
	}

	/* return our new hash value */
	return hval;
}


/*
* fnv_32a_str - perform a 32 bit Fowler/Noll/Vo FNV-1a hash on a string
*
* input:
*	str	- string to hash
*	hval	- previous hash value or 0 if first call
*
* returns:
*	32 bit hash as a static hash type
*
* NOTE: To use the recommended 32 bit FNV-1a hash, use FNV1_32A_INIT as the
*  	 hval arg on the first call to either fnv_32a_buf() or fnv_32a_str().
*/
Fnv32_t
fnv_32a_str(char *str, Fnv32_t hval)
{
	unsigned char *s = (unsigned char *)str;	/* unsigned string */

	/*
	* FNV-1a hash each octet in the buffer
	*/
	while (*s) {

		/* xor the bottom with the current octet */
		hval ^= (Fnv32_t)*s++;

		/* multiply by the 32 bit FNV magic prime mod 2^32 */
#if defined(NO_FNV_GCC_OPTIMIZATION)
		hval *= FNV_32_PRIME;
#else
		hval += (hval << 1) + (hval << 4) + (hval << 7) + (hval << 8) + (hval << 24);
#endif
	}

	/* return our new hash value */
	return hval;
}
///////////////////////////////////
size_t MyMagicNumber;

size_t shuffle[9];

size_t get_vec_remove_num(std::vector<size_t>& vec)
{
	size_t num = rand() % vec.size();
	size_t retval = vec[num];
	vec.erase(vec.begin() + num);
	return retval;
}

void generate_shuffles(int timerid, void * param)
{
	MyMagicNumber = (rand() % 0xFFFF) << 16 | (rand() % 0xFFFF);

	std::vector<size_t> vec;

	for (size_t i = 0; i < 16; ++i)
		vec.push_back((size_t)(rand() % 6));

	for (size_t i = 0; i < 8; ++i)
		shuffle[i] = (get_vec_remove_num(vec)) + (get_vec_remove_num(vec));

	shuffle[7] = rand() % 3;
}

unsigned long MySecretReturnCode(const unsigned int binaryAddress, const unsigned short port)
{
	unsigned long long _a = MyMagicNumber << shuffle[0];
	unsigned long long _b = binaryAddress << shuffle[1];
	unsigned long long _c = port << shuffle[2];

	unsigned long long _d = (_a + _b) >> shuffle[3];
	unsigned long long _e = (_c + _d) >> shuffle[4];

	unsigned long long _f = (_a - _d) << shuffle[5];
	unsigned long long _g = (_c - _b) << shuffle[6];

	return (unsigned long)((_a*_b | _c * _d | _f * _g * _e) ^ shuffle[7]);
}

unsigned long _final_security_code(unsigned long ulong_ip, unsigned short port)
{
	char ip_sz[5];
	char magic_sz[5];
	char port_sz[3];

	*(unsigned long*)ip_sz = ulong_ip;
	*(unsigned long*)magic_sz = MyMagicNumber;
	*(unsigned short*)port_sz = port;

	ip_sz[4] = 0;
	port_sz[2] = 0;

	return fnv_32a_str(magic_sz, (fnv_32a_str(port_sz, fnv_32a_str(ip_sz, MySecretReturnCode(ulong_ip, port))));
}

bool inline IsGoodPongLength(size_t length)
{
	return
		length >= sizeof(unsigned char) + 4 &&
		length < sizeof(unsigned char) + 4 + MAX_OFFLINE_DATA_LENGTH;
}

#if _WIN32
	#define REQUIRE_BYTESWAP//define or undefine if players timout after installing this plugin
#endif

#if __linux
	//#define REQUIRE_BYTESWAP//define or undefine if players timout after installing this plugin
#endif

unsigned long inline asfa_swapbytes(unsigned long bytes)
{
#ifdef REQUIRE_BYTESWAP
	#ifdef _WIN32
		return _byteswap_ulong(bytes);
	#else
	return __builtin_bswap32(bytes);
	#endif
#else
	return bytes;
#endif
}

void STDCALL DetouredProcessNetworkPacket(const unsigned int binaryAddress, const unsigned short port, const char *data, const int length, void *rakPeer)
{
	static char ping[5] = { 8/*ID_PING*/, 0, 0, 0, 0 };
	unsigned int ip_data[2] = {
		asfa_swapbytes(binaryAddress),
		(unsigned int)port
	};

	if (ip_whitelist.find(*(unsigned long long*)ip_data) == ip_whitelist.end())
	{
		if (data[0] == 40/*ID_PONG*/ && IsGoodPongLength(length) && (*(int*)(data + 1)) == MySecretReturnCode(ip_data[0], port))
			ip_whitelist.insert(*(unsigned long long*)ip_data);
		else
		{
			(*(int*)(ping + 1)) = _final_security_code(ip_data[0], port);
			RealSocketLayerSendTo(pSocketLayerObject, *pRakServerSocket, (const char*)ping, 5, binaryAddress, port);
		}
	}
	else RealProcessNetworkPacket(binaryAddress, port, data, length, rakPeer);
}

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
	return (*mask) == 0;
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

PLUGIN_EXPORT unsigned int PLUGIN_CALL Supports()
{
	return sampgdk::Supports() | SUPPORTS_PROCESS_TICK;
}


PLUGIN_EXPORT bool PLUGIN_CALL Load(void **ppData)
{
	pAMXFunctions = ppData[PLUGIN_DATA_AMX_EXPORTS];
	gppData = ppData;
	return sampgdk::Load(ppData);
}

PLUGIN_EXPORT void PLUGIN_CALL ProcessTick()
{
	sampgdk::ProcessTick();
}

SAMPGDK_CALLBACK(bool, OnGameModeInit())
{
	static bool doubleinitprotection = true;
	if (doubleinitprotection)
	{
		doubleinitprotection = false;

		srand((unsigned int)time(NULL));

		generate_shuffles(0,0);

		sampgdk_SetTimer(15000, true, generate_shuffles, 0);

		sampgdk_SetTimer(60000, true, CleanupUnusedWhitelistSlots, 0);

		int(*pfn_GetRakServer)(void) = (int(*)(void))gppData[PLUGIN_DATA_RAKSERVER];
		pRakServer = (void*)pfn_GetRakServer();

#ifdef _WIN32

		int iRealProcessNetworkPacket = FindPattern("\x6A\xFF\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x64\x89\x25\x00\x00\x00\x00\x81\xEC\x5C", "xxx????xxxxxxxxxxxxxxxxx");//0x00456EF0;
		int iSocketLayerSendTo = FindPattern("\x83\xEC\x10\x55\x8B\x6C\x24\x18\x83\xFD\xFF", "xxxxxxxxxxx");//0x004633A0;
		
		RealProcessNetworkPacket = reinterpret_cast<FPTR_ProcessNetworkPacket>(Detour((unsigned char*)iRealProcessNetworkPacket, (unsigned char*)DetouredProcessNetworkPacket, 7));
		RealSocketLayerSendTo = reinterpret_cast<FPTR_SocketLayerSendTo>(iSocketLayerSendTo);

		pRakServerSocket = (SOCKET*)((char*)pRakServer + 0xC20);
		pSocketLayerObject = (void*)0x004EDA71;		

#else

		int iSocketLayerSendTo = 0x808EB80;
		int iRealProcessNetworkPacket = 0x8073080;
		
		RealSocketLayerSendTo = reinterpret_cast<FPTR_SocketLayerSendTo>(iSocketLayerSendTo);
		RealProcessNetworkPacket = reinterpret_cast<FPTR_ProcessNetworkPacket>(Detour((unsigned char*)iRealProcessNetworkPacket, (unsigned char*)DetouredProcessNetworkPacket, 6));//or 5?
		
		pRakServerSocket = (SOCKET*)((char*)pRakServer + 0xC0E);

		if (*((char*)(0x8150D2F + 0x07)) == 0)
			pSocketLayerObject = (void*)0x08194A00;//500p	
		else
			pSocketLayerObject = (void*)0x08194420;//1000p

#endif
	}

	return true;
}

SAMPGDK_CALLBACK(bool, OnIncomingConnection(int playerid, const char * ip_address, int port))
{
	unsigned int ip_data[2] = 
	{ 
		inet_addr(ip_address), 
		(unsigned int)port
	};

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
