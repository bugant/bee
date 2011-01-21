/*
 *   Copyright (c) 2010 Matteo Centenaro
 *   
 *   Permission is hereby granted, free of charge, to any person obtaining a copy
 *   of this software and associated documentation files (the "Software"), to deal
 *   in the Software without restriction, including without limitation the rights
 *   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *   copies of the Software, and to permit persons to whom the Software is
 *   furnished to do so, subject to the following conditions:
 *   
 *   The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 *   
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *   THE SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <atoken.h>

void atoken_quit(atoken *t)
{
    if (!t)
	return;

    if (t->fun)
	(*t->fun->C_Finalize)(NULL_PTR);

    if (t->module != 0)
	DLCLOSE(t->module);
}

/* atoken_load_module tries to load the specified module and
 * gets the C_GetFunctionList symbol to check that the
 * module is a valid PKCS#11 one.
 * It returns 0 on success, -1 on failure
 */
int atoken_load_module(atoken *t, const char *module_name)
{
    CK_RV(*funC_GetFunctionList) (CK_FUNCTION_LIST_PTR_PTR);
    CK_RV rv;

    /* Load dynamically library (so or DLL) */
    if ((t->module = DLOPEN(module_name)) == 0)
    {
	printf("Could not open the module\n");
	return -1;
    }

    /* Get the pointer to the C_GetFunctionList, this is a test to see if the
     * given module implements PKCS#11 */
    if ((funC_GetFunctionList = (CK_RV (*) (CK_FUNCTION_LIST_PTR_PTR))DLSYM(t->module, "C_GetFunctionList")) == NULL)
    {
	printf("Not a valid PKCS#11 module\n");
	return -1;
    }

    /* Cryptoki library standard initialization */
    if ((rv = funC_GetFunctionList(&(t->fun))) != CKR_OK)
    {
	CKRLOG("C_GetFunctionList", rv);
	return -1;
    }

    return 0;
}

CK_RV atoken_init(atoken *t, const char *module_name)
{
    CK_ULONG count = 0;
    CK_SLOT_ID_PTR pSlotList;
    CK_RV rv;

    if (atoken_load_module(t, module_name) == -1)
    {
	CKRLOG("Cannot load module", (CK_ULONG) CKR_GENERAL_ERROR);
	return CKR_GENERAL_ERROR;
    }

    rv = (*t->fun->C_Initialize)(NULL_PTR);
    if (rv != CKR_OK)
    {
	CKRLOG("C_Initialize", rv);
	return rv;
    }

    rv = (*t->fun->C_GetSlotList)(TRUE, NULL, &count);
    if (rv != CKR_OK)
    {
	CKRLOG("C_GetSlotList", rv);
	atoken_quit(t);
	return rv;
    }

    if (count == 0)
    {
	CKRLOG("No slot found", (CK_ULONG) CKR_GENERAL_ERROR);
	atoken_quit(t);
	return CKR_GENERAL_ERROR;
    }

    pSlotList = calloc(count, sizeof(CK_SLOT_ID));
    pSlotList[0] = 42;
    // Get First Slot ID, with Token if possible
    rv = (*t->fun->C_GetSlotList)(TRUE, pSlotList, &count);
    if (rv != CKR_OK)
    {
	CKRLOG("C_GetSlotList", rv);
	free(pSlotList);
	atoken_quit(t);
	return rv;
    }

    if (count == 0)
    {
	CKRLOG("No slot found", (CK_ULONG) CKR_GENERAL_ERROR);
	atoken_quit(t);
	return CKR_GENERAL_ERROR;
	exit(0);
    }

    t->slot = pSlotList[0];
    free(pSlotList);

    return CKR_OK;
}

CK_RV atoken_login(atoken *t, CK_USER_TYPE user, CK_CHAR *pin)
{
    CK_RV rv;

    rv = (*t->fun->C_OpenSession)(t->slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &(t->session));
    if (rv != CKR_OK)
    {
	CKRLOG("C_OpenSession", rv);
	return rv;
    }

    if (strlen((char *)pin))
    {
	rv = (*t->fun->C_Login)(t->session, user, pin,(CK_ULONG) strlen((char *) pin));
	if (rv != CKR_OK)
	    CKRLOG("C_Login", rv);
    } else {
	printf("Please provide a valid PIN\n");
	(*t->fun->C_CloseSession)(t->session);
	rv = CKR_PIN_INVALID;
    }

    return rv;
}

CK_RV atoken_logout(atoken t)
{
    CK_RV rv = (*t.fun->C_CloseSession)(t.session);
    if (rv != CKR_OK)
	CKRLOG("C_CloseSession", rv);
    return rv;
}

CK_RV atoken_get_mechanisms(atoken t, CK_MECHANISM_TYPE_PTR m, CK_ULONG_PTR len)
{
    return (*t.fun->C_GetMechanismList)(t.slot, m, len);
}

CK_RV atoken_get_info(atoken t, CK_TOKEN_INFO_PTR info)
{
    return (*t.fun->C_GetTokenInfo)(t.slot, info);
}
