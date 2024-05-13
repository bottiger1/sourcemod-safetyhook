#include "detours.h"

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

	auto result = safetyhook::InlineHook::create(pAddress, callbackFunction);
	if(result)
	{
		detour->m_hook = std::move(result.value());
		*trampoline = detour->m_hook.original<void*>();
		detour->Init();
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
	free(m_detoured_bytes);
}

void CDetour::Init()
{
	// copy detoured bytes as safety hook doesn't save it and we need it for fast enable/disable
	size_t prologue_bytes = m_hook.original_bytes().size();
	m_detoured_bytes = malloc(prologue_bytes);
	memcpy(m_detoured_bytes, (void*)m_hook.target(), prologue_bytes);

	// start disabled like original cdetour
	m_enabled = true;
	DisableDetour();
}

bool CDetour::IsEnabled()
{
	return m_enabled;
}

void CDetour::EnableDetour()
{
	if(m_enabled)
		return;
	m_enabled = true;

	size_t bytes = m_hook.original_bytes().size();
	//safetyhook::unprotect(m_hook.target(), bytes); // not working...
	SetMemPatchable(m_hook.target(), bytes);
	memcpy(m_hook.target(), m_detoured_bytes, bytes);
}

void CDetour::DisableDetour()
{
	if(!m_enabled)
		return;
	m_enabled = false;

	size_t bytes = m_hook.original_bytes().size();
	//Msg("target %p original bytes %p size %i\n", m_hook.target(), m_hook.original_bytes().data(), m_hook.original_bytes().size());
	//safetyhook::unprotect(m_hook.target(), bytes); // not working...
	SetMemPatchable(m_hook.target(), bytes);
	memcpy(m_hook.target(), m_hook.original_bytes().data(), bytes);
}

void CDetour::Destroy()
{
	delete this;
}