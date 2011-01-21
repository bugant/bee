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

CK_RV atoken_new_key(atoken t,
	CK_MECHANISM_PTR m,
	CK_ATTRIBUTE_PTR attrs,
	CK_ULONG attrs_len,
	CK_OBJECT_HANDLE_PTR key)
{
    CK_RV r = (*t.fun->C_GenerateKey)(t.session, m, attrs, attrs_len, key);
    if (r != CKR_OK)
	CKRLOG("C_GenerateKey", r);

    return r;
}

CK_RV atoken_new_key_pair(atoken t,
	CK_MECHANISM_PTR m,
	CK_ATTRIBUTE_PTR pub_attrs,
	CK_ULONG pub_len,
	CK_ATTRIBUTE_PTR priv_attrs,
	CK_ULONG priv_len,
	CK_OBJECT_HANDLE_PTR pub,
	CK_OBJECT_HANDLE_PTR priv)
{
    CK_RV r = (*t.fun->C_GenerateKeyPair)(t.session, m, pub_attrs, pub_len, priv_attrs, priv_len, pub, priv);
    if (r != CKR_OK)
	CKRLOG("C_GenerateKeyPair", r);

    return r;
}

CK_RV atoken_get_attributes(atoken t,
	CK_OBJECT_HANDLE o,
	CK_ATTRIBUTE_PTR attrs,
	CK_ULONG len)
{
    if (attrs == NULL_PTR || o == NULL_PTR || t.session == NULL_PTR)
	return CKR_GENERAL_ERROR;

    CK_RV r = (*t.fun->C_GetAttributeValue)(t.session, o, attrs, len);
    if (r != CKR_OK)
	CKRLOG("C_GetAttributeValue", r);

    return r;
}

CK_RV atoken_set_attributes(atoken t,
	CK_OBJECT_HANDLE o,
	CK_ATTRIBUTE_PTR attrs,
	CK_ULONG len)
{
    CK_RV r = (*t.fun->C_SetAttributeValue)(t.session, o, attrs, len);
    if (r != CKR_OK)
	CKRLOG("C_SetAttributeValue", r);

    return r;
}

CK_RV atoken_find_objects(atoken t,
	CK_ATTRIBUTE_PTR search,
	CK_ULONG len,
	CK_OBJECT_HANDLE_PTR *found,
	CK_ULONG_PTR found_len)
{
    CK_OBJECT_HANDLE_PTR one_by_one = NULL_PTR;
    CK_ULONG found_it = 0;
    CK_ULONG how_many = 0;
    CK_ULONG error = CKR_GENERAL_ERROR;
    CK_RV r;
    int loop = 1;

    *found = NULL_PTR;
    *found_len = how_many;

    how_many = 100;
    while(loop)
    {
	// printf("getting %lu objects", how_many);
	one_by_one = calloc(how_many, sizeof(CK_OBJECT_HANDLE));
	if (!one_by_one)
	{
	    CKRLOG("Cannot allocate memory for the searching operation", error);
	    r = error;
	    break;
	}

	// printf("FindObjectsInit\n");
	r = (*t.fun->C_FindObjectsInit)(t.session, search, len);
	if (r != CKR_OK)
	{
	    CKRLOG("C_FindObjectsInit", r);
	    r = error;
	    break;
	}

	// printf("getting objects\n");
	if ((r = (*t.fun->C_FindObjects)(t.session, one_by_one, how_many, &found_it)) != CKR_OK)
	{
	    CKRLOG("C_FindObject", r);
	    break;
	}

	// printf("FindObjectsFinal\n");
	(*t.fun->C_FindObjectsFinal)(t.session);

	printf("found %lu objects\n", found_it);
	if (found_it == how_many)
	    how_many += how_many;
	else
	    loop = 0;
    }

    if (r != CKR_OK)
    {
	*found_len = 0;
	if (one_by_one)
	    free(one_by_one);
	return r;
    }

    if (found_it > 0)
    {
        *found = one_by_one;
	*found_len = found_it;
    }
    else
	*found_len = 0;

    return CKR_OK;
}

CK_RV atoken_create_object(atoken t, CK_ATTRIBUTE_PTR attrs, CK_ULONG len, CK_OBJECT_HANDLE_PTR o)
{
    CK_RV r = (*t.fun->C_CreateObject)(t.session, attrs, len, o);
    if (r != CKR_OK)
	CKRLOG("C_CreateObject", r);

    return r;
}

CK_RV atoken_copy_object(atoken t, CK_OBJECT_HANDLE o, CK_ATTRIBUTE_PTR attrs, CK_ULONG len, CK_OBJECT_HANDLE_PTR copy)
{
    CK_RV r = (*t.fun->C_CopyObject)(t.session, o, attrs, len, copy);
    if (r != CKR_OK)
	CKRLOG("C_CopyObject", r);

    return r;
}

CK_RV atoken_destroy_object(atoken t, CK_OBJECT_HANDLE o)
{
    return (*t.fun->C_DestroyObject)(t.session, o);
}

CK_RV atoken_gen_mechanism(CK_MECHANISM_PTR m, CK_MECHANISM_PTR gen)
{
    int found = 0;
    if (!m || !gen)
    {
	CKRLOG("Invalid (NULL) mechanism", (CK_ULONG) CKR_MECHANISM_INVALID);
	return CKR_MECHANISM_INVALID;
    }

    switch (m->mechanism)
    {
	case CKM_AES_ECB:
	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
	case CKM_AES_ECB_ENCRYPT_DATA:
	case CKM_AES_CBC_ENCRYPT_DATA:
	case CKM_AES_MAC:
	case CKM_AES_MAC_GENERAL:
	    gen->mechanism = CKM_AES_KEY_GEN;
	    found = 1;
	    break;

	case CKM_DES_ECB:
	case CKM_DES_CBC:
	case CKM_DES_CBC_PAD:
	case CKM_DES_ECB_ENCRYPT_DATA:
	case CKM_DES_CBC_ENCRYPT_DATA:
	case CKM_DES_MAC:
	case CKM_DES_MAC_GENERAL:
	    gen->mechanism = CKM_DES_KEY_GEN;
	    found = 1;
	    break;

	case CKM_DES3_ECB:
	case CKM_DES3_CBC:
	case CKM_DES3_CBC_PAD:
	case CKM_DES3_ECB_ENCRYPT_DATA:
	case CKM_DES3_CBC_ENCRYPT_DATA:
	case CKM_DES3_MAC:
	case CKM_DES3_MAC_GENERAL:
	    gen->mechanism = CKM_DES3_KEY_GEN;
	    found = 1;
	    break;

	case CKM_RSA_PKCS:
	case CKM_RSA_9796:
	case CKM_RSA_X_509:
	case CKM_MD2_RSA_PKCS:
	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA224_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
	case CKM_RIPEMD128_RSA_PKCS:
	case CKM_RIPEMD160_RSA_PKCS:
	case CKM_RSA_PKCS_OAEP:
	case CKM_RSA_PKCS_PSS:
	case CKM_SHA1_RSA_PKCS_PSS:
	case CKM_SHA224_RSA_PKCS_PSS:
	case CKM_SHA256_RSA_PKCS_PSS:
	case CKM_SHA512_RSA_PKCS_PSS:
	case CKM_SHA384_RSA_PKCS_PSS:
	    gen->mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
	    found = 1;
	    break;

	case CKM_RSA_X9_31:
	case CKM_SHA1_RSA_X9_31:
	    gen->mechanism = CKM_RSA_X9_31_KEY_PAIR_GEN;
	    found = 1;
	    break;
    }

    if (!found)
    {
	CKRLOG("Unsupported mechanism", (CK_ULONG) CKR_MECHANISM_INVALID);
	return CKR_MECHANISM_INVALID;
    }

    gen->pParameter = m->pParameter;
    gen->ulParameterLen = m->ulParameterLen;
    return CKR_OK;
}
