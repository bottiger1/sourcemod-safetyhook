#include "detours.h"

#include <iostream>
#include <iomanip>


#include <amtl/os/am-system-errors.h>
#if defined PLATFORM_POSIX
#include <sys/mman.h>
#define	PAGE_EXECUTE_READWRITE	PROT_READ|PROT_WRITE|PROT_EXEC
#endif

ISourcePawnEngine *CDetourManager::spengine = NULL;
IGameConfig *CDetourManager::gameconf = NULL;

static void ProtectMemory(void *addr, int length, int prot)
{
	char error[256];
#if defined PLATFORM_POSIX
	long pageSize = sysconf(_SC_PAGESIZE);
	void *startPage = ke::AlignedBase(addr, pageSize);
	void *endPage = ke::AlignedBase((void *)((intptr_t)addr + length), pageSize);
	if (mprotect(startPage, ((intptr_t)endPage - (intptr_t)startPage) + pageSize, prot) == -1) {
		ke::FormatSystemError(error, sizeof(error));
		fprintf(stderr, "mprotect: %s\n", error);
	}
#elif defined PLATFORM_WINDOWS
	DWORD old_prot;
	if (!VirtualProtect(addr, length, prot, &old_prot)) {
		ke::FormatSystemError(error, sizeof(error));
		fprintf(stderr, "VirtualProtect: %s\n", error);
	}
#endif
}

static void SetMemPatchable(void *address, size_t size)
{
	ProtectMemory(address, (int)size, PAGE_EXECUTE_READWRITE);
}

static uint8_t* RoundDownPageSize(uint8_t* addr)
{
#if defined PLATFORM_POSIX
	uintptr_t iAddr = (uintptr_t) addr;
	uintptr_t mask = sysconf(_SC_PAGESIZE) - 1;
	return (uint8_t*)(iAddr & ~mask);
#else
	return addr; // not needed in windows
#endif
}

// utility function
static void PrintBytes(const char* name, void* ptr, size_t len) {
	uint8_t* bytes = (uint8_t*)ptr;
	std::cout << name << " ";
    for (size_t i = 0; i < len; ++i) {
        // Print each byte as a two-character wide hex value, padded with zeros if necessary
        char hex[8];
        sprintf(hex, "%x ", bytes[i]);
        std::cout << std::hex << hex;
    }
    std::cout << std::endl;
}

void CDetourManager::Init(ISourcePawnEngine *spengine, IGameConfig *gameconf)
{
	CDetourManager::spengine = spengine;
	CDetourManager::gameconf = gameconf;
}

CDetour *CDetourManager::CreateDetour(void *callbackfunction, void **trampoline, const char *signame)
{
	void* pAddress;
	if (!gameconf->GetMemSig(signame, &pAddress))
	{
		g_pSM->LogError(myself, "Signature for %s not found in gamedata", signame);
		return NULL;
	}

	if (!pAddress)
	{
		g_pSM->LogError(myself, "Sigscan for %s failed", signame);
		return NULL;
	}

	return CreateDetour(callbackfunction, trampoline, pAddress);
}

CDetour *CDetourManager::CreateDetour(void *callbackFunction, void **trampoline, void *pAddress)
{
	CDetour* detour = new CDetour(callbackFunction, trampoline, pAddress);

	auto result = safetyhook::InlineHook::create(pAddress, callbackFunction, safetyhook::InlineHook::Flags::StartDisabled);
	if(result)
	{
		detour->m_hook = std::move(result.value());
		*trampoline = detour->m_hook.original<void*>();
	}
	else
	{
		auto err = result.error();
		g_pSM->LogError(myself, "safetyhook::InlineHook::Error: %i address %p\n", err.type, pAddress);
		// TODO: print details
		//if(err.type == safetyhook::InlineHook::Error::)
		
		delete detour;
		return NULL;		
	}

	return detour;
}

CDetour::CDetour(void* callbackFunction, void **trampoline, void *pAddress)
{
}

CDetour::~CDetour()
{
}

bool CDetour::IsEnabled()
{
	return m_hook.enabled();
}

void CDetour::EnableDetour()
{
	m_hook.enable();
}

void CDetour::DisableDetour()
{
	m_hook.disable();
}

void CDetour::Destroy()
{
	delete this;
}