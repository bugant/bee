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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <oo-bee.h>

CK_BBOOL yes = TRUE;
CK_BBOOL no = FALSE;
long last_error;

void fill_mechanism(CK_MECHANISM_PTR m, long t)
{
    if (!m)
	return;

    m->mechanism = (CK_ULONG) t;
    m->pParameter = NULL_PTR;
    m->ulParameterLen = 0;
}

void bee_free_mem(void *p)
{
    if (!p)
	return;

    free(p);
}

long bee_get_last_error()
{
    return last_error;
}

void bee_reset_error()
{
    last_error = 0;
}

void* bee_new(const char *module, const unsigned char *pin)
{
    CK_RV r;
    bee *b = (bee*) malloc(sizeof(bee));
    if (!b)
    {
	last_error = BEE_ERR_MEM;
    }

    if ((r = init(module, pin, b)) != CKR_OK)
    {
	last_error = r;
	return NULL;
    }

    return (void *) b;
}

void* bee_new_and_configure(const char *module,
	long user,
	const unsigned char *pin,
	long sym_m,
	long asym_m,
	void *a_sym,
	void *a_pub,
	void *a_priv)
{
    CK_RV r;
    bee *b;
    CK_MECHANISM_PTR sym, asym;

    b = (bee*) malloc(sizeof(bee));
    sym = (CK_MECHANISM_PTR) malloc(sizeof(CK_MECHANISM));
    asym = (CK_MECHANISM_PTR) malloc(sizeof(CK_MECHANISM));
    if (!b || !sym || !asym)
    {
	last_error = BEE_ERR_MEM;
    }

    fill_mechanism(sym, sym_m);
    fill_mechanism(asym, asym_m);
    if ((r = init_and_configure(module, (CK_USER_TYPE) user, pin, sym, asym, (attrs*) a_sym, (attrs*) a_pub, (attrs*) a_priv, b)) != CKR_OK)
    {
	last_error = r;
	return NULL;
    }

    return (void *) b;
}

void bee_logout(void *b)
{
    bee *theb = (bee*) b;
    free(theb->default_sym_m);
    free(theb->default_asym_m);
    // Template has to take care about freeing themeselves
    // indeed oo-bee always uses template's copies
    // (i.e., copy_as_default_*_template with is_a_copy set to 1)
    // soft_free_attrs(theb->default_sym_attrs);
    // soft_free_attrs(theb->default_pub_attrs);
    // soft_free_attrs(theb->default_priv_attrs);
    logout(theb);
    free(theb);
    theb = NULL;
}

void bee_set_default_sym_mechanism(void *b, long m)
{
    CK_MECHANISM_PTR sym;
    bee *theb = (bee*) b;

    sym = (CK_MECHANISM_PTR) malloc(sizeof(CK_MECHANISM));
    fill_mechanism(sym, m);
    free(theb->default_sym_m);
    set_default_sym_mechanism(theb, sym);
}

void bee_set_default_asym_mechanism(void *b, long m)
{
    CK_MECHANISM_PTR asym;
    bee *theb = (bee*) b;

    asym = (CK_MECHANISM_PTR) malloc(sizeof(CK_MECHANISM));
    fill_mechanism(asym, m);
    free(theb->default_asym_m);
    set_default_asym_mechanism(theb, asym);
}

void bee_set_default_sym_template(void *b, void *a)
{
    bee *theb = (bee*) b;
    copy_as_default_sym_template(theb, (attrs*) a, 1, &yes, &no);
}

void bee_set_default_pub_template(void *b, void *a)
{
    bee *theb = (bee*) b;
    copy_as_default_pub_template(theb, (attrs*) a, 1, &yes, &no);
}

void bee_set_default_priv_template(void *b, void *a)
{
    bee *theb = (bee*) b;
    copy_as_default_priv_template(theb, (attrs*) a, 1, &yes, &no);
}

long* bee_get_supported_mechanisms (void *b, long *len)
{
    CK_RV r;
    long *ret;

    if ((r = get_supported_mechanisms(*((bee*) b), (CK_MECHANISM_TYPE_PTR*) &ret, (CK_ULONG_PTR) len)) != CKR_OK)
    {
	last_error = r;
	return NULL;
    }

    return ret;
}

char** bee_get_token_info(void *b)
{
    CK_RV r;
    CK_TOKEN_INFO i;
    char **res;

    if ((r = get_token_info(*((bee*) b), &i)) != CKR_OK)
    {
	last_error = r;
	return NULL;
    }

    res = (char **) malloc(sizeof(char *) * 7);
    res[0] = (char *) malloc(33);
    res[1] = (char *) malloc(33);
    res[2] = (char *) malloc(16 + 1);
    res[3] = (char *) malloc(16 + 1);
    res[4] = (char *) malloc(6); // hwd_version: MM.mm
    res[5] = (char *) malloc(6); // fir_version: MM.mm
    if (!res || !res[0] || !res[1] || !res[2] || !res[3] || !res[4] || !res[5])
    {
	last_error = BEE_ERR_MEM;
	return NULL;
    }

    strncpy(res[0], (const char*) i.label, 32);
    res[0][32] = '\0';

    strncpy(res[1], (const char*) i.manufacturerID, 32);
    res[1][32] = '\0';

    strncpy(res[2], (const char*) i.model, 16);
    res[2][16] = '\0';

    strncpy(res[3], (const char*) i.serialNumber, 16);
    res[3][16] = '\0';

    snprintf(res[4], 6, "%d.%d", i.hardwareVersion.major, i.hardwareVersion.minor);
    snprintf(res[5], 6, "%d.%d", i.firmwareVersion.major, i.firmwareVersion.minor);

    res[6] = NULL;
    return res;
}
