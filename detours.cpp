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