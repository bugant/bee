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

CK_BYTE_PTR iv8 = NULL_PTR;
CK_BYTE_PTR iv16 = NULL_PTR;
CK_MAC_GENERAL_PARAMS_PTR macp = NULL_PTR;

CK_RV init(const char *module, const unsigned char *pin, bee *b)
{
    return init_user(module, CKU_USER, pin, b);
}

CK_RV init_user(const char *module, CK_USER_TYPE user, const unsigned char *pin, bee *b)
{
    CK_RV error = CKR_GENERAL_ERROR;
    CK_MECHANISM_PTR sym, asym;
    attrs *a_sym, *a_pub, *a_priv;

    sym = (CK_MECHANISM_PTR) malloc(sizeof(CK_MECHANISM));
    asym = (CK_MECHANISM_PTR) malloc(sizeof(CK_MECHANISM));
    a_sym = (attrs*) malloc(sizeof(attrs));
    a_pub = (attrs*) malloc(sizeof(attrs));
    a_priv = (attrs*) malloc(sizeof(attrs));
    if (!sym || !asym || !a_sym || !a_pub || !a_priv)
    {
	CKRLOG("bee cannot allocate memory for default mechanisms", error);
	return error;
    }

    sym->mechanism = DEFAULT_SYM_M;
    sym->pParameter = NULL_PTR;
    sym->ulParameterLen = 0;

    asym->mechanism = DEFAULT_ASYM_M;
    asym->pParameter = NULL_PTR;
    asym->ulParameterLen = 0;

    init_attrs(a_sym);
    init_attrs(a_pub);
    init_attrs(a_priv);

    return init_and_configure(module, user, pin, sym, asym, a_sym, a_pub, a_priv, b);
}

CK_RV init_and_configure(const char *module,
	CK_USER_TYPE user,
	const unsigned char *pin,
	CK_MECHANISM_PTR sym,
	CK_MECHANISM_PTR asym,
	attrs *a_sym,
	attrs *a_pub,
	attrs *a_priv,
	bee *b)
{
    CK_RV r = atoken_init(&(b->t), module);
    if (r != CKR_OK)
	return r;

    r = atoken_login(&(b->t), user, (CK_CHAR *)pin);
    if (r != CKR_OK)
	return r;

    b->default_sym_m = sym;
    b->default_asym_m = asym;
    b->default_sym_attrs = a_sym;
    b->default_pub_attrs = a_pub;
    b->default_priv_attrs = a_priv;

    malloc_sym_mechanism_parameters();
    init_mechanism_parameter(sym);
    return CKR_OK;
}

CK_RV logout(bee *b)
{
    CK_RV r = atoken_logout(b->t);
    atoken_quit(&(b->t));
    return r;
}

void malloc_sym_mechanism_parameters()
{
    CK_RV error = CKR_GENERAL_ERROR;
    iv8 = (CK_BYTE_PTR) malloc(sizeof(CK_BYTE) * 8);
    iv16 = (CK_BYTE_PTR) malloc(sizeof(CK_BYTE) * 16);
    macp = (CK_MAC_GENERAL_PARAMS_PTR) malloc(sizeof(CK_MAC_GENERAL_PARAMS));

    if (!iv8 || !iv16 || !macp)
    {
	CKRLOG("bee cannot allocate memory for mechanism parameters", error);
	return;
    }

    memset(iv8, 0, 8);
    memset(iv16, 0, 16);
    *macp = (CK_MAC_GENERAL_PARAMS) 16;
}

void init_mechanism_parameter(CK_MECHANISM_PTR m)
{
    // CK_RV error = CKR_GENERAL_ERROR;
    // CK_BYTE_PTR iv8;
    // CK_BYTE_PTR iv16;
    // CK_MAC_GENERAL_PARAMS_PTR macp;

    // iv8 = (CK_BYTE_PTR) malloc(sizeof(CK_BYTE) * 8);
    // iv16 = (CK_BYTE_PTR) malloc(sizeof(CK_BYTE) * 16);
    // macp = (CK_MAC_GENERAL_PARAMS_PTR) malloc(sizeof(CK_MAC_GENERAL_PARAMS));

    // if (!iv8 || !iv16 || !macp)
    // {
    //     CKRLOG("bee cannot allocate memory for mechanism parameters", error);
    //     return;
    // }

    // memset(iv8, 0, 8);
    // memset(iv16, 0, 16);

    switch (m->mechanism)
    {
	case CKM_DES_CBC:
	case CKM_DES_CBC_PAD:
	case CKM_DES3_CBC:
	case CKM_DES3_CBC_PAD:
	    m->pParameter = iv8;
	    m->ulParameterLen = 8;
	    return;
	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
	    m->pParameter = iv16;
	    m->ulParameterLen = 16;
	    return;
	case CKM_AES_MAC_GENERAL:
	    m->pParameter = macp;
	    m->ulParameterLen = sizeof(CK_MAC_GENERAL_PARAMS);
	    return;
    }
}

void set_default_sym_mechanism(bee *b, CK_MECHANISM_PTR m)
{
    init_mechanism_parameter(m);
    b->default_sym_m = m;
}

void set_default_asym_mechanism(bee *b, CK_MECHANISM_PTR m)
{
    b->default_asym_m = m;
}

void copy_as_default_template(bee *b, attrs **old, attrs *new, int is_a_copy, CK_VOID_PTR yes, CK_VOID_PTR no)
{
    attrs *copy = copy_attrs_with_static_bools(*new, yes, no);
    if (is_a_copy && old && *old)
	deep_free_attrs(*old, yes, no);
    *old = copy;
}

void set_default_sym_template(bee *b, attrs *a)
{
    b->default_sym_attrs = a;
}

void copy_as_default_sym_template(bee *b, attrs *a, int is_a_copy, CK_VOID_PTR yes, CK_VOID_PTR no)
{
    copy_as_default_template(b, &(b->default_sym_attrs), a, is_a_copy, yes, no);
}

void set_default_pub_template(bee *b, attrs *a)
{
    b->default_pub_attrs = a;
}

void copy_as_default_pub_template(bee *b, attrs *a, int is_a_copy, CK_VOID_PTR yes, CK_VOID_PTR no)
{
    copy_as_default_template(b, &(b->default_pub_attrs), a, is_a_copy, yes, no);
}

void set_default_priv_template(bee *b, attrs *a)
{
    b->default_priv_attrs = a;
}

void copy_as_default_priv_template(bee *b, attrs *a, int is_a_copy, CK_VOID_PTR yes, CK_VOID_PTR no)
{
    copy_as_default_template(b, &(b->default_priv_attrs), a, is_a_copy, yes, no);
}
