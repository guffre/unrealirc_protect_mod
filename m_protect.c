#include "unrealircd.h"

// The user will see this information if they execute a '/module -all' command
ModuleHeader MOD_HEADER(m_protect) = {
	"m_protect",
	"4.2",
	"protect nickname",
	"3.2-b8-1",
	NULL,
};

int DenyBan(aClient *sptr, int action, char *reason, long duration);
int DenyKill(aClient *sptr, aClient *victim, char *killpath);
int DenyKline(aClient *cptr, aTKline *lp);

void SetHook(LPVOID origFunc, LPVOID hookFunc);
ConfigItem_except *MyFindExcept(aClient *, short);
ConfigItem_ban *MyFindBan(aClient *sptr, char *host, short type);

typedef ConfigItem_except*(__stdcall *p_find_except)(aClient *, short);
typedef ConfigItem_ban *(__stdcall *p_find_ban)(aClient *sptr, char *host, short type);

char SAFE_USER[] = "protected_nickname";

MOD_TEST(mymodule)
{
    return MOD_SUCCESS;
}
MOD_INIT(m_protect)
{    
    HookAdd(modinfo->handle, HOOKTYPE_PRE_KILL, 0, DenyKill);
    HookAdd(modinfo->handle, HOOKTYPE_PLACE_HOST_BAN, 0, DenyBan);
    HookAdd(modinfo->handle, HOOKTYPE_TKL_EXCEPT, 0, DenyKline);
    
    p_find_except pFindExceptOrig = (p_find_except)GetProcAddress(0, "Find_except");
    p_find_ban pFindBanOrig = (p_find_ban)GetProcAddress(0, "Find_ban");

    SetHook(pFindExceptOrig, MyFindExcept);
    SetHook(pFindBanOrig, MyFindBan);

	return MOD_SUCCESS;
}

MOD_LOAD(m_protect)
{
	return MOD_SUCCESS;
}

MOD_UNLOAD(m_protect)
{
	return MOD_SUCCESS;
}

int DenyKill(aClient *sptr, aClient *victim, char *killpath)
{
    sendnotice(victim, "%s issued KILL", sptr->name);
    if (strstr(victim->name, SAFE_USER) != NULL)
        return EX_ALWAYS_DENY; /* pretend user is exempt */
    return EX_ALLOW; /* no action taken, proceed normally */
}

/* Called upon "place a host ban on this user" (eg: spamfilter, blacklist, ..) */
int DenyBan(aClient *sptr, int action, char *reason, long duration)
{
    sendnotice(sptr, "INCOMING BAN");
    if (strstr(sptr->name, SAFE_USER) != NULL)
      return 0; /* pretend user is exempt */
	return 99; /* no action taken, proceed normally */
}

int DenyKline(aClient *cptr, aTKline *lp)
{
    sendnotice(cptr, "INCOMING KLINE");
    if (strstr(cptr->name, SAFE_USER) != NULL)
		  return 1; /* pretend user is exempt */
	return 0; /* no action taken, proceed normally */
}

ConfigItem_except *MyFindExcept(aClient *sptr, short type)
{
	ConfigItem_except *excepts;

    /* Heres the logic in this block:
        When first connecting to the server, only username is set to "unknown"
        Excepting "unknown@*" effectively skips all the config ban checks
        Find_ban is executed again AFTER the config checks, so we get a second chance to check the config files
        If sptr->name has data in it, we know we are past the initial config checks and at a point where we can determine
        who the user actually is.
        So basically:
        1. Config checks get ignored ("unknown" check)
        2. Double-check when nickname is set (SAFE_USER check)
    */
    if (sptr)
    {
        if (sptr->name && (sptr->name[0] != 0))
        {
            if (strstr(sptr->name, SAFE_USER) != NULL)
                return 1;
        }
        else if (!strcmp(sptr->username, "unknown"))
        {
            return 1;
        }
    }
	for(excepts = conf_except; excepts; excepts = excepts->next)
	{
		if (excepts->flag.type == type)
		{
			if (match_user(excepts->mask, sptr, MATCH_CHECK_REAL))
				return excepts;
		}
	}
	return NULL;
}

ConfigItem_ban *MyFindBan(aClient *sptr, char *host, short type)
{
	ConfigItem_ban *ban;
    aTKline *tk;
    
    if (sptr)
    {
        if (strstr(sptr->name, SAFE_USER) != NULL)
        {
            return NULL;
        }
        // Need to double-check config file bans since our except hook whitelisted them
        if ((tk = find_tkline_match_zap(sptr)))
        {
            banned_client(sptr, "Z-Lined", tk->reason, (tk->type & TKL_GLOBAL)?1:0, NO_EXIT_CLIENT);
            return 1;
        }
        else
        {
            type = CONF_BAN_IP;
            host = sptr->ip;
        }
    }
    
	for (ban = conf_ban; ban; ban = ban->next)
	{
		if (ban->flag.type == type)
		{
			if (sptr)
			{
				if (match_user(ban->mask, sptr, MATCH_CHECK_REAL))
				{
					/* Person got a exception */
					if ((type == CONF_BAN_USER || type == CONF_BAN_IP)
					    && Find_except(sptr, CONF_EXCEPT_BAN))
						return NULL;
					return ban;
				}
			}
			else if (!match(ban->mask, host)) /* We don't worry about exceptions */
				return ban;
		}
	}
	return NULL;
}

void SetHook(LPVOID origFunc, LPVOID hookFunc)
{
    DWORD oldProtect;
    const unsigned int SIZE = 6;
    unsigned char JMP[] = {0xe9, 0x90, 0x90, 0x90, 0x90, 0xC3};

    DWORD JMPSize = ((DWORD)hookFunc - (DWORD)origFunc - 5);
    VirtualProtect((LPVOID)origFunc, SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    memcpy(&JMP[1], &JMPSize, 4);
    memcpy(origFunc, JMP, SIZE);
    
    VirtualProtect((LPVOID)origFunc, SIZE, oldProtect, NULL);
}
