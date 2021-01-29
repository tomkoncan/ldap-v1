#include "windows.h"
#include "stdio.h"
#include "winldap.h"
#include "winber.h"

#pragma comment (lib, "Wldap32.lib")

int wmain(int argc, wchar_t** argv)
{
	LDAP ldapStruct;
	LDAP* pldapStruct = &ldapStruct;
	DWORD dwLdapVer = LDAP_VERSION3;
	DWORD sts = 0;
	wchar_t szMyHostname[256];
	wchar_t szMyDomainname[256];
	DWORD dwSize = 256;
	//
	//	pridobim svoj computername
	//
	sts = GetComputerNameEx(ComputerNameDnsHostname, szMyHostname, &dwSize);
	if (sts == 0)
	{
		wprintf(L"GetComputerNameEx() returns error for OwnHostname: %d\n", GetLastError());
		return sts;
	}
	wprintf(L"MyHostname = '%s'\n", szMyHostname);
	dwSize = 256;
	wprintf(L"dwSize=%d\n", dwSize);

	sts = GetComputerNameEx(ComputerNameDnsDomain, szMyDomainname, &dwSize);
	if (sts == 0)
	{
		wprintf(L"GetComputerNameEx() returns error for OwnHostname: %d\n", GetLastError());
		return sts;
	}
	wprintf(L"MyDomainName = '%s'\n", szMyDomainname);

	//------------------------------------------------------------------------------------------------
	//	Init LDAP strukture
	//------------------------------------------------------------------------------------------------
	pldapStruct = ldap_init(szMyDomainname, 389);
	if (pldapStruct == NULL)
	{
		//	neuspesen klic ldap_init - koncamo
		wprintf(L"ldap_init() failed with error %d.\n", GetLastError());
		return GetLastError();
	}
	wprintf(L"ldap_init() succeeded.\n");

	//------------------------------------------------------------------------------------------------
	//	nastavim option ldapv3, default je v2
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
	//	connect na server
	//------------------------------------------------------------------------------------------------
	sts = ldap_connect(pldapStruct, NULL);
	if (sts == LDAP_SUCCESS)
		wprintf(L"ldap_connect() succeeded.\n");
	else
	{
		wprintf(L"ldap_connect() failed with error %d.\n", sts);
		return sts;
	}

	//------------------------------------------------------------------------------------------------
	//	bind s trenutnimi credentiali
	//------------------------------------------------------------------------------------------------
	sts = ldap_bind_s(pldapStruct, NULL, NULL, LDAP_AUTH_NEGOTIATE);
	if (sts == LDAP_SUCCESS)
		wprintf(L"ldap_bind_s() succeeded.\n");
	else
	{
		wprintf(L"ldap_bind_s() failed with error %d\n", sts);
		return sts;
	}

	//------------------------------------------------------------------------------------------------
	//	izvedem dejansko iskanje - sinhrono
	//------------------------------------------------------------------------------------------------
	LDAPMessage* pSearchResult;
	wchar_t pMyFilter[256] = L"";
	swprintf_s(pMyFilter, 256, L"(samaccountname=%s$)", szMyHostname);  //construct LDAP filter from hostname
	wprintf(L"LDAP filter = '%s'\n", pMyFilter);
	const wchar_t* pMyAttributes[2];
	const wchar_t* pMyDN = L"dc=pod,dc=loc";

	pMyAttributes[0] = L"canonicalname";
	pMyAttributes[1] = NULL;

	sts = ldap_search_s(
		pldapStruct,			// Session handle
		(const PWSTR)pMyDN,		// DN to start search
		LDAP_SCOPE_SUBTREE,		// Scope
		(const PWSTR)pMyFilter,	// Filter
		(PZPWSTR)pMyAttributes,	// Retrieve list of attributes
		0,						// Get both attributes and values
		&pSearchResult);		// [out] Search results

	if (sts != LDAP_SUCCESS)
	{
		wprintf(L"ldap_search_s() failed with %d\n", sts);
		ldap_unbind_s(pldapStruct);
		if (pSearchResult != NULL) ldap_msgfree(pSearchResult);
		return sts;
	}
	else
		wprintf(L"ldap_search() succeeded \n");

	//------------------------------------------------------------------------------------------------
	//	Kolk entryjev je vrnjenih?
	//------------------------------------------------------------------------------------------------
	DWORD dwEntries;

	dwEntries = ldap_count_entries(
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
	// Loop through the search entries, get, and output the
	// requested list of attributes and values.
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