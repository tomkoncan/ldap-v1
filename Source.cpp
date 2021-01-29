#include "windows.h"
#include "stdio.h"
#include "winldap.h"
#include "winber.h"

#pragma comment (lib, "Wldap32.lib")
void winErrCodeToStr(DWORD, wchar_t*, DWORD);
void ldapErrCodeToStr(DWORD, wchar_t*, DWORD);

int wmain(int argc, wchar_t** argv)
{
	LDAP ldapStruct;
	LDAP* pldapStruct = &ldapStruct;
	wchar_t szErrBuff[256] = {0};
	DWORD dwLdapVer = LDAP_VERSION3;
	DWORD sts = 0;
	wchar_t szMyHostname[256] = L"";
	wchar_t szMyDnsName[256] = L"";
	DWORD dwSize = 256;

	//------------------------------------------------------------------------------------------------
	//	pridobim svoj computername - hostname part
	//	fetching my hostname - hostname part
	//------------------------------------------------------------------------------------------------
	sts = GetComputerNameEx(ComputerNameDnsHostname, szMyHostname, &dwSize);
	if (sts == 0)
	{
		winErrCodeToStr(GetLastError(), szErrBuff, 256);
		wprintf(L"GetComputerNameEx() returns error: %d (%s)\n", GetLastError(), szErrBuff);
		return GetLastError();
	}

	//------------------------------------------------------------------------------------------------
	//	pridobim svoj computername - dns domain name part
	//	fetching my hostname - domain name part
	//------------------------------------------------------------------------------------------------
	dwSize = 256;	//	buffer size reset - the previous API call sets this value to hostname length
	sts = GetComputerNameEx(ComputerNameDnsDomain, szMyDnsName, &dwSize);
	if (sts == 0)
	{
		winErrCodeToStr(GetLastError(), szErrBuff, 256);
		wprintf(L"GetComputerNameEx() returns error: %d (%s)\n", GetLastError(), szErrBuff);
		return GetLastError();
	}
	
	wprintf(L"\nLDAP-tk v1.1\tmyHostName='%s', myDNSname='%s'\n\n", szMyHostname, szMyDnsName);
	//------------------------------------------------------------------------------------------------
	//	sestavim DN, distinguished name iz dnshostname-a
	//	DN composition out of dnshostname
	//------------------------------------------------------------------------------------------------
	wchar_t* token = NULL;
	wchar_t* ctx = NULL;
	wchar_t szDNbuf[256] = { 0 };
	token = wcstok_s(szMyDnsName, L".", &ctx);
	while (token != NULL)
	{
		// While there are tokens in "string"
		swprintf_s(szDNbuf, 256, L"%sdc=%s,", szDNbuf,token);
		// Get next token:
		token = wcstok_s(NULL, L".", &ctx);
	}

	wchar_t tmp = szDNbuf[wcslen(szDNbuf)-1];
	if (szDNbuf[wcslen(szDNbuf)-1] == L',')
	{
		szDNbuf[wcslen(szDNbuf) - 1] = L'\0';
	}
	else
	{
		wprintf(L"Internal error (DN='%s')\n", szDNbuf);
	}

	//------------------------------------------------------------------------------------------------
	//	Init LDAP strukture
	//	LDAP strukcture init
	//------------------------------------------------------------------------------------------------
	pldapStruct = ldap_init(szMyDnsName, 389);
	if (pldapStruct == NULL)
	{
		//	neuspesen klic ldap_init - koncamo / unsuccessful call; terminate the program
		wprintf(L"ldap_init() failed with error %d.\n", GetLastError());
		return GetLastError();
	}
	wprintf(L"ldap_init() succeeded.\n");

	//------------------------------------------------------------------------------------------------
	//	nastavim option ldapv3 ker je default v2
	//	option default is v2 - need to set it to ldapv3
	//------------------------------------------------------------------------------------------------
	sts = ldap_set_option(pldapStruct, LDAP_OPT_PROTOCOL_VERSION, (void*)&dwLdapVer);
	if (sts == LDAP_SUCCESS)
		wprintf(L"ldap_set_option() succeeded - version set to 3\n");
	else
	{
		wprintf(L"ldap_set_option() failed with error %d\n", sts);
		return sts;
	}

	//------------------------------------------------------------------------------------------------
	//	server connect
	//------------------------------------------------------------------------------------------------
	sts = ldap_connect(pldapStruct, NULL);
	if (sts == LDAP_SUCCESS)
		wprintf(L"ldap_connect() succeeded.\n");
	else
	{
		ldapErrCodeToStr(sts, szErrBuff, 256);
		wprintf(L"ldap_connect() failed with error %d (%s).\n", sts, szErrBuff);
		return sts;
	}

	//------------------------------------------------------------------------------------------------
	//	bind s trenutnimi credentiali
	//	bind with credentials of currently logged on user
	//------------------------------------------------------------------------------------------------
	sts = ldap_bind_s(pldapStruct, NULL, NULL, LDAP_AUTH_NEGOTIATE);
	if (sts == LDAP_SUCCESS)
		wprintf(L"ldap_bind_s() succeeded.\n");
	else
	{
		ldapErrCodeToStr(sts, szErrBuff, 256);
		wprintf(L"ldap_bind_s() failed with error %d (%s)\n", sts, szErrBuff);
		return sts;
	}

	//------------------------------------------------------------------------------------------------
	//	izvedem dejansko iskanje - sinhrono
	//	executing a synchronous search
	//------------------------------------------------------------------------------------------------
	LDAPMessage* pSearchResult;
	wchar_t pMyFilter[256] = L"";
	swprintf_s(pMyFilter, 256, L"(samaccountname=%s$)", szMyHostname);  //construct LDAP filter from hostname
	const wchar_t* pMyAttributes[2];

	pMyAttributes[0] = L"canonicalname";
	pMyAttributes[1] = NULL;
	wprintf(L"Attempting LDAP query with parameters:\n");
	wprintf(L"\tLDAPfilter ............... '%s'\n", pMyFilter);
	wprintf(L"\tLDAP-DN .................. '%s'\n", szDNbuf);
	wprintf(L"\tattributes to retrieve ... '%s'\n\n", pMyAttributes[0]);

	sts = ldap_search_s(
		pldapStruct,			// Session handle
		(const PWSTR)szDNbuf,	// DN to start search
		LDAP_SCOPE_SUBTREE,		// Scope
		(const PWSTR)pMyFilter,	// Filter
		(PZPWSTR)pMyAttributes,	// Retrieve list of attributes
		0,						// Get both attributes and values
		&pSearchResult);		// [out] Search results

	if (sts != LDAP_SUCCESS)
	{
		ldapErrCodeToStr(sts, szErrBuff, 256);
		wprintf(L"ldap_search_s() failed with %d (%s)\n", sts, szErrBuff);
		ldap_unbind_s(pldapStruct);
		if (pSearchResult != NULL) ldap_msgfree(pSearchResult);
		return sts;
	}
	else
		wprintf(L"ldap_search() succeeded \n");

	//------------------------------------------------------------------------------------------------
	//	Kolk entryjev je vrnjenih?
	//	number of entries returned
	//------------------------------------------------------------------------------------------------
	DWORD dwEntries = ldap_count_entries(
		pldapStruct,	// Session handle
		pSearchResult);	// Search result
	if (dwEntries == NULL)
	{
		wprintf(L"ldap_count_entries() failed with %d\n", sts);
		ldap_unbind_s(pldapStruct);
		if (pSearchResult != NULL)
			ldap_msgfree(pSearchResult);
		return sts;
	}
	else
		wprintf(L"ldap_count_entries() succeeded.\n");
	wprintf(L"The number of entries is: %d \n", dwEntries);

	//------------------------------------------------------------------------------------------------
	// Sprehodi se skozi entryje, getaj jih, izpisi in requestaj seznam atributov in valueov
	//	walk through the entry structure, get them, display them and request a list of 
	//	attribute/value pairs
	//------------------------------------------------------------------------------------------------
	LDAPMessage* pEntry = NULL;
	PWCHAR pEntryDN = NULL;
	ULONG iCnt = 0;
	BerElement* pBer = NULL;
	PWCHAR pAttribute = NULL;
	PWCHAR* ppValue = NULL;
	ULONG iValue = 0;
	wchar_t* sMsg;

	for (iCnt = 0; iCnt < dwEntries; iCnt++)
	{
		// Get the first/next entry.
		if (!iCnt)
			pEntry = ldap_first_entry(pldapStruct, pSearchResult);
		else
			pEntry = ldap_next_entry(pldapStruct, pEntry);

		// Output a status message.
		sMsg = (!iCnt ? L"ldap_first_entry" : L"ldap_next_entry");
		if (pEntry == NULL)
		{
			wprintf(L"%s failed with 0x%0lx \n", sMsg, LdapGetLastError());
			ldap_unbind_s(pldapStruct);
			ldap_msgfree(pSearchResult);
			return -1;
		}
		else
			wprintf(L"%s succeeded\n", sMsg);

		// Output the entry number.
		wprintf(L"ENTRY NUMBER %i \n", iCnt);

		// Get the first attribute name.
		pAttribute = ldap_first_attribute(
			pldapStruct,   // Session handle
			pEntry,            // Current entry
			&pBer);            // [out] Current BerElement

		// Output the attribute names for the current object
		// and output values.
		while (pAttribute != NULL)
		{
			// Output the attribute name.
			wprintf(L"     ATTR: %s", pAttribute);

			// Get the string values.

			ppValue = ldap_get_values(
				pldapStruct,  // Session Handle
				pEntry,           // Current entry
				pAttribute);      // Current attribute

			// Print status if no values are returned (NULL ptr)
			if (ppValue == NULL)
			{
				wprintf(L": [NO ATTRIBUTE VALUE RETURNED]");
			}

			// Output the attribute values
			else
			{
				iValue = ldap_count_values(ppValue);
				if (!iValue)
				{
					wprintf(L": [BAD VALUE LIST]");
				}
				else
				{
					// Output the first attribute value
					wprintf(L": %s", *ppValue);

					// Output more values if available
					ULONG z;
					for (z = 1; z < iValue; z++)
					{
						wprintf(L", %s", ppValue[z]);
					}
				}
			}

			// Free memory.
			if (ppValue != NULL)
				ldap_value_free(ppValue);
			ppValue = NULL;
			ldap_memfree(pAttribute);

			// Get next attribute name.
			pAttribute = ldap_next_attribute(
				pldapStruct,   // Session Handle
				pEntry,            // Current entry
				pBer);             // Current BerElement
			wprintf(L"\n");
		}

		if (pBer != NULL)
			wprintf(L"ber_free().\n");
			ber_free(pBer, 0);
		pBer = NULL;

		//----------------------------------------------------------
		// Normal cleanup and exit.
		//----------------------------------------------------------
		wprintf(L"ldap_unbind().\n");
		ldap_unbind(pldapStruct);

		wprintf(L"ldap_msgfree().\n");
		ldap_msgfree(pSearchResult);

		wprintf(L"ldap_value_free().\n");
		ldap_value_free(ppValue);

		return 0;
	}

}

//----------------------------------------------------------
//	funkcija vraca windows system error message kot string
//	input parameter = windows status error code
//	this function returns a win sys err message as a string
//	input: windows status error code
//----------------------------------------------------------
void winErrCodeToStr(DWORD dwSysErrCode, wchar_t* szErrBuf, DWORD dwChars)
{
	dwChars = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dwSysErrCode,
		0,
		szErrBuf,
		dwChars,
		NULL);

	if (0 == dwChars)
	{
		swprintf_s(szErrBuf, 256, L"***ErrMsgNotFound***");
		return;
	}
	//
	//	odstranim carriage returne in line feede na koncu
	//
	wchar_t* pTmp = szErrBuf;
	for (DWORD i = 0; pTmp[i] != 0; i++)
	{
		if ((pTmp[i] == L'\n') || (pTmp[i] == L'\r')) pTmp[i] = 0;
	}
}

//----------------------------------------------------------
//	funkcija vraca ldap error message kot string
//	input parameter = ldap error code
//	this function returns an ldap err message as a string
//	input: ldap error code
//----------------------------------------------------------
void ldapErrCodeToStr(DWORD dwLdapErrCode, wchar_t* szErrBuf, DWORD dwChars)
{
	static const wchar_t* szLdapStr[113] = { L"SUCCESS", L"OPERATIONS_ERROR", L"PROTOCOL_ERROR",
	L"TIMELIMIT_EXCEEDED", L"SIZELIMIT_EXCEEDED", L"COMPARE_FALSE", L"COMPARE_TRUE",
	L"AUTH_METHOD_NOT_SUPPORTED", L"STRONG_AUTH_REQUIRED", L"REFERRAL_V2/PARTIAL_RESULTS",
	L"REFERRAL", L"ADMIN_LIMIT_EXCEEDED", L"UNAVAILABLE_CRIT_EXTENSION", L"CONFIDENTIALITY_REQUIRED",
	L"SASL_BIND_IN_PROGRESS", L"---Undefined-LDAP-Error---", L"NO_SUCH_ATTRIBUTE", 	L"UNDEFINED_TYPE",
	L"INAPPROPRIATE_MATCHING", 	L"CONSTRAINT_VIOLATION", L"ATTRIBUTE_OR_VALUE_EXISTS",
	L"INVALID_SYNTAX", 	L"---Undefined-LDAP-Error---", 	L"---Undefined-LDAP-Error---",
	L"---Undefined-LDAP-Error---", 	L"---Undefined-LDAP-Error---", 	L"---Undefined-LDAP-Error---",
	L"---Undefined-LDAP-Error---", 	L"---Undefined-LDAP-Error---", 	L"---Undefined-LDAP-Error---",
	L"---Undefined-LDAP-Error---", 	L"---Undefined-LDAP-Error---", 	L"NO_SUCH_OBJECT",
	L"ALIAS_PROBLEM", L"INVALID_DN_SYNTAX", L"IS_LEAF", L"ALIAS_DEREF_PROBLEM",
	L"---Undefined-LDAP-Error---", 	L"---Undefined-LDAP-Error---", L"---Undefined-LDAP-Error---",
	L"---Undefined-LDAP-Error---", 	L"---Undefined-LDAP-Error---", L"---Undefined-LDAP-Error---",
	L"---Undefined-LDAP-Error---", 	L"---Undefined-LDAP-Error---", 	L"---Undefined-LDAP-Error---",
	L"---Undefined-LDAP-Error---",	L"---Undefined-LDAP-Error---", 	L"INAPPROPRIATE_AUTH",
	L"INVALID_CREDENTIALS", L"INSUFFICIENT_RIGHTS", L"BUSY", L"UNAVAILABLE", L"UNWILLING_TO_PERFORM",
	L"LOOP_DETECT", L"---Undefined-LDAP-Error---", L"---Undefined-LDAP-Error---",
	L"---Undefined-LDAP-Error---", L"---Undefined-LDAP-Error---", L"---Undefined-LDAP-Error---",
	L"SORT_CONTROL_MISSING", L"OFFSET_RANGE_ERROR", L"---Undefined-LDAP-Error---",
		L"---Undefined-LDAP-Error---", L"NAMING_VIOLATION", L"OBJECT_CLASS_VIOLATION",
		L"NOT_ALLOWED_ON_NONLEAF", L"NOT_ALLOWED_ON_RDN", L"ALREADY_EXISTS", L"NO_OBJECT_CLASS_MODS",
		L"RESULTS_TOO_LARGE", L"AFFECTS_MULTIPLE_DSAS", L"---Undefined-LDAP-Error---",
		L"---Undefined-LDAP-Error---", L"---Undefined-LDAP-Error---", L"---Undefined-LDAP-Error---",
		L"VIRTUAL_LIST_VIEW_ERROR", L"---Undefined-LDAP-Error---", L"---Undefined-LDAP-Error---",
		L"---Undefined-LDAP-Error---", L"OTHER", L"SERVER_DOWN", L"LOCAL_ERROR", L"ENCODING_ERROR",
		L"DECODING_ERROR", L"TIMEOUT", L"AUTH_UNKNOWN", L"FILTER_ERROR", L"USER_CANCELLED",
	L"PARAM_ERROR", L"NO_MEMORY", L"CONNECT_ERROR", L"NOT_SUPPORTED", L"CONTROL_NOT_FOUND",
	L"NO_RESULTS_RETURNED", L"MORE_RESULTS_TO_RETURN", L"CLIENT_LOOP", L"REFERRAL_LIMIT_EXCEEDED",
	L"---Undefined-LDAP-Error---", L"---Undefined-LDAP-Error---", L"INVALID_RESPONSE",
	L"AMBIGIOUS_RESPONSE", L"---Undefined-LDAP-Error---", L"---Undefined-LDAP-Error---",
	L"---Undefined-LDAP-Error---", L"---Undefined-LDAP-Error---", L"---Undefined-LDAP-Error---",
	L"---Undefined-LDAP-Error---", L"---Undefined-LDAP-Error---", L"---Undefined-LDAP-Error---",
	L"---Undefined-LDAP-Error---", L"---Undefined-LDAP-Error---", L"TLS_NOT_SUPPORTED" };

	if ((dwLdapErrCode < 0) || (dwLdapErrCode > 112))
	{
		wcsncpy_s(szErrBuf, 27, L"---Undefined-LDAP-Error---", 27);
		return;
	}

	wcsncpy_s(szErrBuf, 27, szLdapStr[dwLdapErrCode], 27);
	return;
}