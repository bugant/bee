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

CK_RV generate_key(bee b, CK_OBJECT_HANDLE_PTR key)
{
    return generate_key_with_mechanism(b, b.default_sym_m, key);
}

CK_RV generate_named_key(bee b, const char *name, CK_OBJECT_HANDLE_PTR key)
{
    attrs *a;
    CK_RV r;

    a = copy_attrs(*(b.default_sym_attrs));
    if (a == NULL_PTR)
    {
	CKRLOG("generate_named_key: Cannot copy default symmetric attributes", (CK_RV) CKR_GENERAL_ERROR);
	return (CK_RV) CKR_GENERAL_ERROR;
    }

    add_attribute(a, CKA_LABEL, (CK_VOID_PTR) name, strlen(name));
    add_gen_key_attributes(a, b.default_sym_m);
    r = generate_key_with_attrs(b, *a, key);
    deep_free_attrs(a, (CK_VOID_PTR) name, NULL_PTR);
    return r;
}

CK_RV generate_key_with_attrs(bee b, attrs a, CK_OBJECT_HANDLE_PTR key)
{
    return generate_key_with_attrs_and_mechanism(b, a, b.default_sym_m, key);
}

CK_RV generate_key_with_mechanism(bee b, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE_PTR key)
{
    attrs *a;
    CK_RV r;

    a = copy_attrs(*(b.default_sym_attrs));
    if (a == NULL_PTR)
    {
	CKRLOG("generate_key_with_mechanism: Cannot copy default symmetric attributes", (CK_RV) CKR_GENERAL_ERROR);
	return (CK_RV) CKR_GENERAL_ERROR;
    }

    add_gen_key_attributes(a, m);
    r = generate_key_with_attrs_and_mechanism(b, *a, m, key);
    deep_free_attrs(a, NULL_PTR, NULL_PTR);
    return r;
}

CK_RV generate_key_with_attrs_and_mechanism(bee b, attrs a, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE_PTR key)
{
    CK_MECHANISM_PTR gen = (CK_MECHANISM_PTR) malloc(sizeof(CK_MECHANISM));
    CK_RV r;
    if ((r = atoken_gen_mechanism(m, gen)) != CKR_OK)
	return r;

    return atoken_new_key(b.t, gen, a.as, a.len, key);
}

/* KEY PAIR SECTION */

CK_RV generate_key_pair(bee b, CK_ULONG len, CK_OBJECT_HANDLE_PTR pub_key, CK_OBJECT_HANDLE_PTR priv_key)
{
    return generate_key_pair_with_mechanism(b, len, b.default_asym_m, pub_key, priv_key);
}

CK_RV generate_named_key_pair(bee b, CK_ULONG len, const char *name, CK_OBJECT_HANDLE_PTR pub_key, CK_OBJECT_HANDLE_PTR priv_key)
{
    CK_RV r;
    attrs *pub, *priv;
    pub = copy_attrs(*(b.default_pub_attrs));
    priv = copy_attrs(*(b.default_priv_attrs));

    if (pub == NULL_PTR || priv == NULL_PTR)
    {
	CKRLOG("generate_key_pair_with_mechanism: Cannot copy default asym attributes", (CK_RV) CKR_GENERAL_ERROR);
	return (CK_RV) CKR_GENERAL_ERROR;
    }

    add_attribute(pub, CKA_LABEL, (CK_VOID_PTR) name, strlen(name));
    add_attribute(priv, CKA_LABEL, (CK_VOID_PTR) name, strlen(name));
    add_gen_key_pair_attributes(pub, priv, len, b.default_asym_m);
    r = generate_key_pair_with_attrs(b, *pub, *priv, pub_key, priv_key);
    deep_free_attrs(pub, (CK_VOID_PTR) name, NULL_PTR);
    deep_free_attrs(priv, (CK_VOID_PTR) name, NULL_PTR);
    return r;
}

CK_RV generate_key_pair_with_attrs(bee b,
	attrs pub,
	attrs priv,
	CK_OBJECT_HANDLE_PTR pub_key,
	CK_OBJECT_HANDLE_PTR priv_key)
{
    return generate_key_pair_with_attrs_and_mechanism(b, pub, priv, b.default_asym_m, pub_key, priv_key);
}

CK_RV generate_key_pair_with_mechanism(bee b,
	CK_ULONG len,
	CK_MECHANISM_PTR m,
	CK_OBJECT_HANDLE_PTR pub_key,
	CK_OBJECT_HANDLE_PTR priv_key)
{
    attrs *pub, *priv;
    pub = copy_attrs(*(b.default_pub_attrs));
    priv = copy_attrs(*(b.default_priv_attrs));
    CK_RV r;

    if (pub == NULL_PTR || priv == NULL_PTR)
    {
	CKRLOG("generate_key_pair_with_mechanism: Cannot copy default asym attributes", (CK_RV) CKR_GENERAL_ERROR);
	return (CK_RV) CKR_GENERAL_ERROR;
    }

    add_gen_key_pair_attributes(pub, priv, len, b.default_asym_m);
    r = generate_key_pair_with_attrs_and_mechanism(b, *pub, *priv, m, pub_key, priv_key);
    deep_free_attrs(pub, NULL_PTR, NULL_PTR);
    deep_free_attrs(priv, NULL_PTR, NULL_PTR);
    return r;
}

CK_RV generate_key_pair_with_attrs_and_mechanism(bee b,
	attrs pub,
	attrs priv,
	CK_MECHANISM_PTR m,
	CK_OBJECT_HANDLE_PTR pub_key,
	CK_OBJECT_HANDLE_PTR priv_key)
{
    CK_MECHANISM_PTR gen = (CK_MECHANISM_PTR) malloc(sizeof(CK_MECHANISM));
    CK_RV r;
    if ((r = atoken_gen_mechanism(m, gen)) != CKR_OK)
	return r;

    return atoken_new_key_pair(b.t, gen, pub.as, pub.len, priv.as, priv.len, pub_key, priv_key);
}
