#include "detours.h"

ISourcePawnEngine *CDetourManager::spengine = NULL;
IGameConfig *CDetourManager::gameconf = NULL;

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
	m_enabled = false;

	// copy detoured bytes as safety hook doesn't save it and we need it for fast enable/disable
	size_t prologue_bytes = m_hook.original_bytes().size();
	m_detoured_bytes.resize(prologue_bytes);
	memcpy(m_detoured_bytes.data(), pAddress, prologue_bytes);

	// start disabled like original cdetour
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

	// safetyhook doesn't reprotect the address so we shouldn't have to unprotect
	memcpy((void*)m_hook.target_address(), m_detoured_bytes.data(), m_detoured_bytes.size());
}

void CDetour::DisableDetour()
{
	if(!m_enabled)
		return;

	// safetyhook doesn't reprotect the address so we shouldn't have to unprotect
	memcpy((void*)m_hook.target_address(), m_hook.original_bytes().data(), m_detoured_bytes.size());
}

void CDetour::Destroy()
{
	//hook.reset(); // called in destructor already
	delete this;
}