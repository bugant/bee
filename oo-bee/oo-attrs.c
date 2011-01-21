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
#include <oo-bee.h>

void* bee_new_attrs()
{
    attrs *a;

    a = malloc(sizeof(attrs));
    if (!a)
    {
	last_error = BEE_ERR_MEM;
	return NULL;
    }

    init_attrs(a);
    return (void*) a;
}

void* bee_copy_attrs(void *a)
{
    return copy_attrs_with_static_bools(*((attrs*) a), &yes, &no);
}

void* bee_malloc(int len)
{
    void *r = malloc(len);
    if (!r)
    {
	last_error = BEE_ERR_MEM;
	r = NULL_PTR;
    }
    return r;
}

void bee_deep_free_attrs(void *a)
{
    deep_free_attrs((attrs*) a, (CK_VOID_PTR) &yes, (CK_VOID_PTR) &no);
}

void bee_free_attrs(void *a)
{
    free_attrs((attrs*) a);
}

/* attribute accessor methods */

void bee_add_empty_attr(void *a, CK_ATTRIBUTE_TYPE t)
{
    int r = add_attribute((attrs*) a, t, NULL_PTR, 0);
    if (r == -1)
	last_error = BEE_ERR_MEM;
}

CK_VOID_PTR bee_get_attr_value(void *a, CK_ATTRIBUTE_TYPE t, long *len)
{
    CK_ATTRIBUTE_PTR f;

    if ((f = find_attribute(*((attrs*) a), t)) != NULL_PTR)
    {
	*len = (long) f->ulValueLen;
	return f->pValue;
    }

    last_error = BEE_ATTR_NOT_FOUND;
    return NULL_PTR;
}

int bee_get_bool_attr(void *a, CK_ATTRIBUTE_TYPE t)
{
    long len;
    CK_VOID_PTR v = bee_get_attr_value(a, t, &len);
    if (v == NULL_PTR)
	return 0;

    return (*((CK_BBOOL*) v)) == TRUE;
}

const char* bee_get_string_attr(void *a, CK_ATTRIBUTE_TYPE t)
{
    long len;
    char *s, *r;
    s = (char*) (bee_get_attr_value(a, t, &len));
    if (s == NULL)
	return NULL;

    r = (char*) malloc(sizeof(char) * (len + 1));
    if (!r)
    {
	last_error = BEE_ERR_MEM;
	return NULL;
    }

    r = memcpy(r, s, len);
    r[len] = '\0';
    return (const char*) r;
}

void bee_set_attr_value(void *a, CK_ATTRIBUTE_TYPE t, CK_VOID_PTR v, CK_ULONG len)
{
    int r = add_attribute((attrs*) a, t, v, len);
    if (r == -1)
	last_error = BEE_ERR_MEM;
}

void bee_set_bool_attr(void *a, CK_ATTRIBUTE_TYPE t, int v)
{
    CK_BBOOL *val;

    if (v)
	val = &yes;
    else
	val = &no;

    bee_set_attr_value(a, t, val, sizeof(CK_BBOOL));
}

/* Storage objects' attributes */
/* CKA_TOKEN */
void bee_add_token(void *a)
{
    bee_add_empty_attr(a, CKA_TOKEN);
}

int bee_get_token(void *a)
{
    return bee_get_bool_attr(a, CKA_TOKEN);
}

void bee_set_token(void *a, int v)
{
    bee_set_bool_attr(a, CKA_TOKEN, v);
}

/* CKA_PRIVATE */
void bee_add_private(void *a)
{
    bee_add_empty_attr(a, CKA_PRIVATE);
}

int bee_get_private(void *a)
{
    return bee_get_bool_attr(a, CKA_PRIVATE);
}

void bee_set_private(void *a, int v)
{
    bee_set_bool_attr(a, CKA_PRIVATE, v);
}

/* CKA_MODIFIABLE */
void bee_add_modifiable(void *a)
{
    bee_add_empty_attr(a, CKA_MODIFIABLE);
}

int bee_get_modifiable(void *a)
{
    return bee_get_bool_attr(a, CKA_MODIFIABLE);
}

void bee_set_modifiable(void *a, int v)
{
    bee_set_bool_attr(a, CKA_MODIFIABLE, v);
}

/* CKA_LABEL */
void bee_add_label(void *a)
{
    bee_add_empty_attr(a, CKA_LABEL);
}

const char* bee_get_label(void *a)
{
    return bee_get_string_attr(a, CKA_LABEL);
}

void bee_set_label(void *a,  const char *l, long len)
{
    bee_set_attr_value(a, CKA_LABEL,  (CK_VOID_PTR) l, len);
}

/* Key objects' attributes */

/* CKA_CLASS*/
void bee_add_class(void *a)
{
    bee_add_empty_attr(a, CKA_CLASS);
}

long bee_get_class(void *a)
{
    long len;
    CK_VOID_PTR v = bee_get_attr_value(a, CKA_CLASS, &len);
    if (v == NULL_PTR)
	return -1;

    return *( (long*) v);
}

void bee_set_class(void *a, void *v)
{
    bee_set_attr_value(a, CKA_CLASS, (CK_ULONG_PTR) v, sizeof(CK_OBJECT_CLASS));
}

/* CKA_KEY_TYPE */
void bee_add_key_type(void *a)
{
    bee_add_empty_attr(a, CKA_KEY_TYPE);
}

long bee_get_key_type(void *a)
{
    long len;
    CK_VOID_PTR v = bee_get_attr_value(a, CKA_KEY_TYPE, &len);
    if (v == NULL_PTR)
	return -1;

    return *((long*) v);
}

void bee_set_key_type(void *a, void *v)
{
    bee_set_attr_value(a, CKA_KEY_TYPE, (CK_ULONG_PTR) v, sizeof(CK_KEY_TYPE));
}

/* CKA_ID */
void bee_add_id(void *a)
{
    bee_add_empty_attr(a, CKA_ID);
}

const char* bee_get_id(void *a)
{
    return bee_get_string_attr(a, CKA_ID);
}

void bee_set_id(void *a, const char *v, long len)
{
    bee_set_attr_value(a, CKA_ID, (CK_VOID_PTR) v, len);
}

/* CKA_DERIVE */
void bee_add_derive(void *a)
{
    bee_add_empty_attr(a, CKA_DERIVE);
}

int bee_get_derive(void *a)
{
    return bee_get_bool_attr(a, CKA_DERIVE);
}

void bee_set_derive(void *a, int v)
{
    bee_set_bool_attr(a, CKA_DERIVE, v);
}

/* CKA_LOCAL */
void bee_add_local(void *a)
{
    bee_add_empty_attr(a, CKA_LOCAL);
}

int bee_get_local(void *a)
{
    return bee_get_bool_attr(a, CKA_LOCAL);
}

void bee_set_local(void *a, int v)
{
    bee_set_bool_attr(a, CKA_LOCAL, v);
}

/* CKA_ENCRYPT */
void bee_add_encrypt(void *a)
{
    bee_add_empty_attr(a, CKA_ENCRYPT);
}

int bee_get_encrypt(void *a)
{
    return bee_get_bool_attr(a, CKA_ENCRYPT);
}

void bee_set_encrypt(void *a, int v)
{
    bee_set_bool_attr(a, CKA_ENCRYPT, v);
}

/*CKA_DECRYPT */
void bee_add_decrypt(void *a)
{
    bee_add_empty_attr(a, CKA_DECRYPT);
}

int bee_get_decrypt(void *a)
{
    return bee_get_bool_attr(a, CKA_DECRYPT);
}

void bee_set_decrypt(void *a, int v)
{
    bee_set_bool_attr(a, CKA_DECRYPT, v);
}

/* CKA_WRAP */
void bee_add_wrap(void *a)
{
    bee_add_empty_attr(a, CKA_WRAP);
}

int bee_get_wrap(void *a)
{
    return bee_get_bool_attr(a, CKA_WRAP);
}

void bee_set_wrap(void *a, int v)
{
    bee_set_bool_attr(a, CKA_WRAP, v);
}

/* CKA_WRAP_WITH_TRUSTED */
void bee_add_wrap_with_trusted(void *a)
{
    bee_add_empty_attr(a, CKA_WRAP_WITH_TRUSTED);
}

int bee_get_wrap_with_trusted(void *a)
{
    return bee_get_bool_attr(a, CKA_WRAP_WITH_TRUSTED);
}

void bee_set_wrap_with_trusted(void *a, int v)
{
    bee_set_bool_attr(a, CKA_WRAP_WITH_TRUSTED, v);
}

/* CKA_UNWRAP */
void bee_add_unwrap(void *a)
{
    bee_add_empty_attr(a, CKA_UNWRAP);
}

int bee_get_unwrap(void *a)
{
    return bee_get_bool_attr(a, CKA_UNWRAP);
}

void bee_set_unwrap(void *a, int v)
{
    bee_set_bool_attr(a, CKA_UNWRAP, v);
}

/* CKA_SIGN */
void bee_add_sign(void *a)
{
    bee_add_empty_attr(a, CKA_SIGN);
}

int bee_get_sign(void *a)
{
    return bee_get_bool_attr(a, CKA_SIGN);
}

void bee_set_sign(void *a, int v)
{
    bee_set_bool_attr(a, CKA_SIGN, v);
}

/* CKA_SIGN_RECOVER */
void bee_add_sign_recover(void *a)
{
    bee_add_empty_attr(a, CKA_SIGN_RECOVER);
}

int bee_get_sign_recover(void *a)
{
    return bee_get_bool_attr(a, CKA_SIGN_RECOVER);
}

void bee_set_sign_recover(void *a, int v)
{
    bee_set_bool_attr(a, CKA_SIGN_RECOVER, v);
}

/* CKA_VERIFY */
void bee_add_verify(void *a)
{
    bee_add_empty_attr(a, CKA_VERIFY);
}

int bee_get_verify(void *a)
{
    return bee_get_bool_attr(a, CKA_VERIFY);
}

void bee_set_verify(void *a, int v)
{
    bee_set_bool_attr(a, CKA_VERIFY, v);
}

/* CKA_VERIFY_RECOVER */
void bee_add_verify_recover(void *a)
{
    bee_add_empty_attr(a, CKA_VERIFY_RECOVER);
}

int bee_get_verify_recover(void *a)
{
    return bee_get_bool_attr(a, CKA_VERIFY_RECOVER);
}

void bee_set_verify_recover(void *a, int v)
{
    bee_set_bool_attr(a, CKA_VERIFY_RECOVER, v);
}

/* CKA_NEVER_EXTRACTABLE */
void bee_add_never_extractable(void *a)
{
    bee_add_empty_attr(a, CKA_NEVER_EXTRACTABLE);
}

int bee_get_never_extractable(void *a)
{
    return bee_get_bool_attr(a, CKA_NEVER_EXTRACTABLE);
}

void bee_set_never_extractable(void *a, int v)
{
    bee_set_bool_attr(a, CKA_NEVER_EXTRACTABLE, v);
}

/* CKA_EXTRACTABLE */
void bee_add_extractable(void *a)
{
    bee_add_empty_attr(a, CKA_EXTRACTABLE);
}

int bee_get_extractable(void *a)
{
    return bee_get_bool_attr(a, CKA_EXTRACTABLE);
}

void bee_set_extractable(void *a, int v)
{
    bee_set_bool_attr(a, CKA_EXTRACTABLE, v);
}

/* CKA_ALWAYS_SENSITIVE */
void bee_add_always_sensitive(void *a)
{
    bee_add_empty_attr(a, CKA_ALWAYS_SENSITIVE);
}

int bee_get_always_sensitive(void *a)
{
    return bee_get_bool_attr(a, CKA_ALWAYS_SENSITIVE);
}

void bee_set_always_sensitive(void *a, int v)
{
    bee_set_bool_attr(a, CKA_ALWAYS_SENSITIVE, v);
}

/* CKA_SENSITIVE */
void bee_add_sensitive(void *a)
{
    bee_add_empty_attr(a, CKA_SENSITIVE);
}

int bee_get_sensitive(void *a)
{
    return bee_get_bool_attr(a, CKA_SENSITIVE);
}

void bee_set_sensitive(void *a, int v)
{
    bee_set_bool_attr(a, CKA_SENSITIVE, v);
}

/* CKA_TRUSTED */
void bee_add_trusted(void *a)
{
    bee_add_empty_attr(a, CKA_TRUSTED);
}

int bee_get_trusted(void *a)
{
    return bee_get_bool_attr(a, CKA_TRUSTED);
}

void bee_set_trusted(void *a, int v)
{
    bee_set_bool_attr(a, CKA_TRUSTED, v);
}

/* CKA_VALUE */
void bee_add_value(void *a)
{
    bee_add_empty_attr(a, CKA_VALUE);
}

const char* bee_get_value(void *a, long *len)
{
    return (const char*) (bee_get_attr_value(a, CKA_VALUE, len));
}

void bee_set_value(void *a, const char *v, long len)
{
    bee_set_attr_value(a, CKA_VALUE, (CK_VOID_PTR) v, (CK_ULONG) len);
}

/* CKA_VALUE_LEN */
void bee_add_value_len(void *a)
{
    bee_add_empty_attr(a, CKA_VALUE_LEN);
}

long bee_get_value_len(void *a)
{
    long len;
    CK_VOID_PTR v = bee_get_attr_value(a, CKA_VALUE_LEN, &len);
    if (v == NULL_PTR)
	return -1;

    return *((long*) v);
}

void bee_set_value_len(void *a, void *v)
{
    bee_set_attr_value(a, CKA_VALUE_LEN, (CK_ULONG_PTR) v, sizeof(CK_ULONG));
}

/* CKA_MODULUS_BITS */
void bee_add_modulus_bits(void *a)
{
    bee_add_empty_attr(a, CKA_MODULUS_BITS);
}

long bee_get_modulus_bits(void *a)
{
    long len;
    CK_VOID_PTR v = bee_get_attr_value(a, CKA_MODULUS_BITS, &len);
    if (v == NULL_PTR)
	return -1;

    return *((long*) v);
}

void bee_set_modulus_bits(void *a, void *v)
{
    bee_set_attr_value(a, CKA_MODULUS_BITS, (CK_ULONG_PTR) v, sizeof(CK_ULONG));
}

/* CKA_MODULUS */
void bee_add_modulus(void *a)
{
    bee_add_empty_attr(a, CKA_MODULUS);
}

const char* bee_get_modulus(void *a, long *len)
{
    return (const char*) (bee_get_attr_value(a, CKA_MODULUS, len));
}

void bee_set_modulus(void *a, const char *v, long len)
{
    bee_set_attr_value(a, CKA_MODULUS, (CK_VOID_PTR) v, (CK_ULONG) len);
}

/* CKA_PUBLIC_EXPONENET */
void bee_add_public_exponent(void *a)
{
    bee_add_empty_attr(a, CKA_PUBLIC_EXPONENT);
}

const char* bee_get_public_exponent(void *a, long *len)
{
    return (const char*) (bee_get_attr_value(a, CKA_PUBLIC_EXPONENT, len));
}

void bee_set_public_exponent(void *a, const char *v, long len)
{
    bee_set_attr_value(a, CKA_PUBLIC_EXPONENT, (CK_VOID_PTR) v, (CK_ULONG) len);
}

/* CKA_PRIVATE_EXPONENT */
void bee_add_private_exponent(void *a)
{
    bee_add_empty_attr(a, CKA_PRIVATE_EXPONENT);
}

const char* bee_get_private_exponent(void *a, long *len)
{
    return (const char*) (bee_get_attr_value(a, CKA_PRIVATE_EXPONENT, len));
}

void bee_set_private_exponent(void *a, const char *v, long len)
{
    bee_set_attr_value(a, CKA_PRIVATE_EXPONENT, (CK_VOID_PTR) v, (CK_ULONG) len);
}
