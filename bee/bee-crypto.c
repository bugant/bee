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

CK_RV s_encrypt(bee b, CK_BYTE_PTR clear, CK_ULONG len, CK_OBJECT_HANDLE key, CK_BYTE_PTR *cipher, CK_ULONG_PTR out_len)
{
    return encrypt_with_mechanism(b, clear, len, key, b.default_sym_m, cipher, out_len);
}

CK_RV a_encrypt(bee b, CK_BYTE_PTR clear, CK_ULONG len, CK_OBJECT_HANDLE key, CK_BYTE_PTR *cipher, CK_ULONG_PTR out_len)
{
    return encrypt_with_mechanism(b, clear, len, key, b.default_asym_m, cipher, out_len);
}

CK_RV encrypt_with_mechanism(bee b,
	CK_BYTE_PTR clear,
	CK_ULONG len,
	CK_OBJECT_HANDLE key,
	CK_MECHANISM_PTR m,
	CK_BYTE_PTR *cipher,
	CK_ULONG_PTR out_len)
{
    CK_RV r;
    if ((r = atoken_encrypt(b.t, clear, len, m, key, NULL_PTR, out_len)) != CKR_OK)
    {
	*cipher = NULL_PTR;
	return r;
    }

    *cipher = (CK_BYTE_PTR) malloc(sizeof(CK_BYTE) * (*out_len));
    if (!(*cipher))
    {
	CKRLOG("Cannot allocate memory for ciphertext", (CK_RV) CKR_GENERAL_ERROR);
	return (CK_RV) CKR_GENERAL_ERROR;
    }

    return atoken_encrypt_only(b.t, clear, len, *cipher, out_len);
}

CK_RV s_decrypt(bee b, CK_BYTE_PTR cipher, CK_ULONG len, CK_OBJECT_HANDLE key, CK_BYTE_PTR *clear, CK_ULONG_PTR out_len)
{
    return decrypt_with_mechanism(b, cipher, len, key, b.default_sym_m, clear, out_len);
}

CK_RV a_decrypt(bee b, CK_BYTE_PTR cipher, CK_ULONG len, CK_OBJECT_HANDLE key, CK_BYTE_PTR *clear, CK_ULONG_PTR out_len)
{
    return decrypt_with_mechanism(b, cipher, len, key, b.default_asym_m, clear, out_len);
}

CK_RV decrypt_with_mechanism(bee b,
	CK_BYTE_PTR cipher,
	CK_ULONG len,
	CK_OBJECT_HANDLE key,
	CK_MECHANISM_PTR m,
	CK_BYTE_PTR *clear,
	CK_ULONG_PTR out_len)
{
    CK_RV r;
    if ((r = atoken_decrypt(b.t, cipher, len, m, key, NULL_PTR, out_len)) != CKR_OK)
    {
	*clear = NULL_PTR;
	return r;
    }

    *clear = (CK_BYTE_PTR) malloc(sizeof(CK_BYTE) * (*out_len));
    if (!(*clear))
    {
	CKRLOG("Cannot allocate memory for cleartext", (CK_RV) CKR_GENERAL_ERROR);
	return (CK_RV) CKR_GENERAL_ERROR;
    }

    return atoken_decrypt_only(b.t, cipher, len, *clear, out_len);
}

CK_RV s_wrap(bee b, CK_OBJECT_HANDLE wrapping_key, CK_OBJECT_HANDLE to_be_wrapped_key, CK_BYTE_PTR *wrapped, CK_ULONG_PTR len)
{
    return wrap_with_mechanism(b, wrapping_key, b.default_sym_m, to_be_wrapped_key, wrapped, len);
}

CK_RV a_wrap(bee b, CK_OBJECT_HANDLE wrapping_key, CK_OBJECT_HANDLE to_be_wrapped_key, CK_BYTE_PTR *wrapped, CK_ULONG_PTR len)
{
    return wrap_with_mechanism(b, wrapping_key, b.default_asym_m, to_be_wrapped_key, wrapped, len);
}

CK_RV wrap_with_mechanism(bee b,
	CK_OBJECT_HANDLE wrapping_key,
	CK_MECHANISM_PTR m,
	CK_OBJECT_HANDLE to_be_wrapped_key,
	CK_BYTE_PTR *wrapped,
	CK_ULONG_PTR wrapped_len)
{
    CK_RV r;
    if ((r = atoken_wrap(b.t, m, wrapping_key, to_be_wrapped_key, NULL_PTR, wrapped_len)) != CKR_OK)
    {
	*wrapped = NULL_PTR;
	return r;
    }

    *wrapped = (CK_BYTE_PTR) malloc(sizeof(CK_BYTE) * (*wrapped_len));
    if (!(*wrapped))
    {
	CKRLOG("Cannot allocate memory for the wrapped key", (CK_RV) CKR_GENERAL_ERROR);
	return (CK_RV) CKR_GENERAL_ERROR;
    }

    return atoken_wrap(b.t, m, wrapping_key, to_be_wrapped_key, *wrapped, wrapped_len);
}

// BUG: this way we have now way to know anything about the unwrapped key's class and type
// CK_RV s_unwrap(bee b, CK_OBJECT_HANDLE wrapping_key, CK_BYTE_PTR wrapped, CK_ULONG wrapped_len, CK_OBJECT_HANDLE_PTR unwrapped_key)
// {
//     return unwrap_with_mechanism(b, wrapping_key, b.default_sym_m, wrapped, wrapped_len, unwrapped_key);
// }

CK_RV s_unwrap_with_attrs (bee b,
	CK_OBJECT_HANDLE wrapping_key,
	CK_BYTE_PTR wrapped,
	CK_ULONG wrapped_len,
	CK_OBJECT_HANDLE_PTR unwrapped_key,
	attrs a)
{
    return unwrap_with_attrs_and_mechanism(b, wrapping_key, b.default_sym_m, wrapped, wrapped_len, unwrapped_key, a);
}

// BUG: this way we have now way to know anything about the unwrapped key's class and type
// CK_RV a_unwrap(bee b, CK_OBJECT_HANDLE wrapping_key, CK_BYTE_PTR wrapped, CK_ULONG wrapped_len, CK_OBJECT_HANDLE_PTR unwrapped_key)
// {
//     return unwrap_with_mechanism(b, wrapping_key, b.default_asym_m, wrapped, wrapped_len, unwrapped_key);
// }

CK_RV a_unwrap_with_attrs(bee b,
	CK_OBJECT_HANDLE wrapping_key,
	CK_BYTE_PTR wrapped,
	CK_ULONG wrapped_len,
	CK_OBJECT_HANDLE_PTR unwrapped_key,
	attrs a)
{
    return unwrap_with_attrs_and_mechanism(b, wrapping_key, b.default_asym_m, wrapped, wrapped_len, unwrapped_key, a);
}

// BUG: this way we have now way to know anything about the unwrapped key's class and type
// CK_RV unwrap_with_mechanism(bee b,
// 	CK_OBJECT_HANDLE wrapping_key,
// 	CK_MECHANISM_PTR m,
// 	CK_BYTE_PTR wrapped,
// 	CK_ULONG wrapped_len,
// 	CK_OBJECT_HANDLE_PTR unwrapped_key)
// {
//     attrs secret;
//     init_attrs(&a);
//     add_gen_key_attributes(&a, m);
//     // ?? HOW TO DO THIS?? add_gen_key_pair_attributes_1024bits(&a, &a, m);
//     return unwrap_with_attrs_and_mechanism(b, wrapping_key, m, wrapped, wrapped_len, unwrapped_key, a);
// }

CK_RV unwrap_with_attrs_and_mechanism(bee b,
	CK_OBJECT_HANDLE wrapping_key,
	CK_MECHANISM_PTR m,
	CK_BYTE_PTR wrapped,
	CK_ULONG wrapped_len,
	CK_OBJECT_HANDLE_PTR unwrapped_key,
	attrs a)
{
    return atoken_unwrap(b.t, m, wrapping_key, wrapped, wrapped_len, a.as, a.len, unwrapped_key);
}
