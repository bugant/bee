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
#include <bee.h>

// this is for debugging
void my_free(void * p) {
    // printf("Freeing %p\n",p);
    free(p);
}

void init_attrs(attrs *a)
{
    a->as = (CK_ATTRIBUTE_PTR) NULL_PTR;
    a->len = 0;
}

attrs* copy_attrs_with_static_bools(attrs a, CK_VOID_PTR yes, CK_VOID_PTR no)
{
    int i;
    attrs *copy;
    CK_ATTRIBUTE_PTR as;

    copy = malloc (sizeof(attrs));
    if (!copy)
	return NULL_PTR;

    if (a.len == 0)
    {
	init_attrs(copy);
	return copy;
    }

    as = calloc(a.len, sizeof(CK_ATTRIBUTE));
    if (!as)
    {
	my_free(copy);
	return NULL_PTR;
    }

    copy->len = a.len;
    copy->as = as;

    memcpy(as, a.as, a.len * sizeof(CK_ATTRIBUTE));
    for (i = 0; i < copy->len; i++)
    {
	if (as[i].pValue != NULL_PTR && as[i].pValue != yes && as[i].pValue != no)
	{
	    CK_VOID_PTR new_val = malloc(as[i].ulValueLen);
	    if (!new_val)
	    {
		my_free(as);
		my_free(copy);
		return NULL_PTR;
	    }

	    as[i].pValue = new_val;
	    memcpy(new_val, a.as[i].pValue, as[i].ulValueLen);
	}
    }

    return copy;
}

attrs* copy_attrs(attrs a)
{
    return copy_attrs_with_static_bools(a, NULL_PTR, NULL_PTR);
}

void deep_free_attrs(attrs *a, CK_VOID_PTR yes, CK_VOID_PTR no)
{
    CK_ULONG i;
    CK_VOID_PTR pVal;

    if (!a)
	return;

    for (i = 0; i < a->len; i++)
    {
	pVal = a->as[i].pValue;
	if (pVal != yes && pVal != no && pVal != NULL_PTR)
	{
	    //printf("freeing %lX\n", a->as[i].type);
	    my_free(pVal);
	}
    }

    free_attrs(a);
}

void soft_free_attrs(attrs *a)
{
    if (!a)
	return;

    if (a->as)
	my_free(a->as);
}

void free_attrs(attrs *a)
{
    if (!a)
	return;

    soft_free_attrs(a);
    my_free(a);
}

int add_bool_attr(attrs *as, CK_ATTRIBUTE_TYPE a, CK_BBOOL *b)
{
    return add_attribute(as, a, (CK_VOID_PTR) b, sizeof(CK_BBOOL));
}

int add_attribute(attrs *as, CK_ATTRIBUTE_TYPE a, CK_VOID_PTR val, CK_ULONG len)
{
    CK_ATTRIBUTE_PTR new_val;
    CK_ATTRIBUTE_PTR new;
    CK_ATTRIBUTE_PTR old;

    new_val = (CK_ATTRIBUTE_PTR) find_attribute(*as, a);
    if (new_val == NULL_PTR)
    {
	new = (CK_ATTRIBUTE_PTR) calloc(as->len + 1, sizeof(CK_ATTRIBUTE));
	if (!new)
	    return -1;

	if (as->as)
	    memcpy(new, as->as, as->len * sizeof(CK_ATTRIBUTE));
	new_val = &(new[as->len]);
	new_val->type = a;
	old = as->as;
	as->as = new;
	as->len = as->len + 1;
	my_free(old);
    }
    new_val->pValue = val;
    new_val->ulValueLen = len;

    return 0;
}

CK_ATTRIBUTE_PTR find_attribute(attrs a, CK_ATTRIBUTE_TYPE t)
{
    int i;

    for (i = 0; i < a.len; i++)
	if (a.as[i].type == t)
	    return &(a.as[i]);

    return (CK_ATTRIBUTE_PTR) NULL_PTR;
}

void add_gen_key_attributes(attrs *as, CK_MECHANISM_PTR m)
{
    CK_OBJECT_CLASS *class;
    CK_KEY_TYPE *type;
    CK_ULONG *len;
    int found = 0;

    class = (CK_OBJECT_CLASS *) malloc(sizeof(CK_OBJECT_CLASS));
    type = (CK_KEY_TYPE *) malloc(sizeof(CK_KEY_TYPE));
    if (!as || !class || !type)
	return;

    *class =  CKO_SECRET_KEY;
    add_attribute(as, CKA_CLASS, class, sizeof(CK_OBJECT_CLASS));

    switch (m->mechanism)
    {
	case CKM_AES_ECB:
	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
	case CKM_AES_ECB_ENCRYPT_DATA:
	case CKM_AES_CBC_ENCRYPT_DATA:
	case CKM_AES_MAC:
	case CKM_AES_MAC_GENERAL:
	    *type = CKK_AES;
	    found = 1;
	    break;

	case CKM_DES_ECB:
	case CKM_DES_CBC:
	case CKM_DES_CBC_PAD:
	case CKM_DES_ECB_ENCRYPT_DATA:
	case CKM_DES_CBC_ENCRYPT_DATA:
	case CKM_DES_MAC:
	case CKM_DES_MAC_GENERAL:
	    *type = CKK_DES;
	    found = 1;
	    break;

	case CKM_DES3_ECB:
	case CKM_DES3_CBC:
	case CKM_DES3_CBC_PAD:
	case CKM_DES3_ECB_ENCRYPT_DATA:
	case CKM_DES3_CBC_ENCRYPT_DATA:
	case CKM_DES3_MAC:
	case CKM_DES3_MAC_GENERAL:
	    *type = CKK_DES3;
	    found = 1;
	    break;
    }

    if (found)
	add_attribute(as, CKA_KEY_TYPE, type, sizeof(CK_KEY_TYPE));

    // AES keys need to have the CKA_VALUE_LEN attribute set, by default
    // it will be set to the minimun length, i.e., 16 Bytes (128 bits)
    if (found && *type == CKK_AES && find_attribute(*as, CKA_VALUE_LEN) == NULL_PTR)
    {
	len = (CK_ULONG*) malloc(sizeof(CK_ULONG));
	if (!len)
	    return;
	*len = 16;
	add_attribute(as, CKA_VALUE_LEN, len, sizeof(CK_ULONG));
    }
}

void add_gen_key_pair_attributes_1024bits(attrs *pub, attrs *priv, CK_MECHANISM_PTR m)
{
    add_gen_key_pair_attributes(pub, priv, 1024, m);
}

void add_gen_key_pair_attributes(attrs *pub, attrs *priv, CK_ULONG len, CK_MECHANISM_PTR m)
{
    CK_OBJECT_CLASS *pub_class;
    CK_OBJECT_CLASS *priv_class;
    CK_KEY_TYPE *type_priv, *type_pub;
    CK_ULONG *klen;
    CK_BYTE *exp;
    int found = 0;
 
    pub_class = (CK_OBJECT_CLASS *) malloc(sizeof(CK_OBJECT_CLASS));
    priv_class = (CK_OBJECT_CLASS *) malloc(sizeof(CK_OBJECT_CLASS));
    type_priv = (CK_KEY_TYPE *) malloc(sizeof(CK_KEY_TYPE));
    type_pub = (CK_KEY_TYPE *) malloc(sizeof(CK_KEY_TYPE));
    klen = (CK_ULONG *) malloc(sizeof(CK_ULONG));
    exp = (CK_BYTE *) malloc(sizeof(CK_BYTE) * 3);
    if (!pub || !priv || !pub_class || !priv_class || !type_priv || !type_pub || !klen || !exp)
	return;

    *pub_class = CKO_PUBLIC_KEY;
    *priv_class = CKO_PRIVATE_KEY;
    *klen = len;
    exp[0] = '\x01';
    exp[1] = '\x00';
    exp[2] = '\x01';

    switch (m->mechanism)
    {
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
	case CKM_RSA_X9_31:
	case CKM_SHA1_RSA_X9_31:
	case CKM_RSA_PKCS_PSS:
	case CKM_SHA1_RSA_PKCS_PSS:
	case CKM_SHA224_RSA_PKCS_PSS:
	case CKM_SHA256_RSA_PKCS_PSS:
	case CKM_SHA512_RSA_PKCS_PSS:
	case CKM_SHA384_RSA_PKCS_PSS:
	    *type_priv = CKK_RSA;
	    *type_pub = CKK_RSA;
	    found = 1;
	    break;
    }

    if (found)
    {
	add_attribute(pub, CKA_CLASS, pub_class, sizeof(pub_class));
	add_attribute(priv, CKA_CLASS, priv_class, sizeof(priv_class));
	add_attribute(pub, CKA_MODULUS_BITS, klen, sizeof(CK_ULONG));
	add_attribute(pub, CKA_PUBLIC_EXPONENT, exp, 3);
	add_attribute(pub, CKA_KEY_TYPE, type_pub, sizeof(CK_KEY_TYPE));
	add_attribute(priv, CKA_KEY_TYPE, type_priv, sizeof(CK_KEY_TYPE));
    }
}
