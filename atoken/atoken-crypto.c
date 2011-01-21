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

CK_RV atoken_encrypt(atoken t,
	CK_BYTE_PTR payload,
	CK_ULONG len,
	CK_MECHANISM_PTR m,
	CK_OBJECT_HANDLE key,
	CK_BYTE_PTR cipher,
	CK_ULONG_PTR clen)
{
    CK_RV r;

    if ( (r = (*t.fun->C_EncryptInit)(t.session, m, key)) != CKR_OK )
    {
	CKRLOG("C_EncryptInit", r);
	return r;
    }

    if ( (r = (*t.fun->C_Encrypt)(t.session, payload, len, cipher, clen)) != CKR_OK )
	CKRLOG("C_Encrypt", r);

    return r;
}

CK_RV atoken_encrypt_only(atoken t,
	CK_BYTE_PTR payload,
	CK_ULONG len,
	CK_BYTE_PTR cipher,
	CK_ULONG_PTR clen)
{
    CK_RV r;

    if ( (r = (*t.fun->C_Encrypt)(t.session, payload, len, cipher, clen)) != CKR_OK )
	CKRLOG("C_Encrypt", r);

    return r;
}

CK_RV atoken_decrypt(atoken t,
	CK_BYTE_PTR cipher,
	CK_ULONG len,
	CK_MECHANISM_PTR m,
	CK_OBJECT_HANDLE key,
	CK_BYTE_PTR clear,
	CK_ULONG_PTR clen)
{
    CK_RV r;

    if ( (r = (*t.fun->C_DecryptInit)(t.session, m, key)) != CKR_OK )
    {
	CKRLOG("C_DecryptInit", r);
	return r;
    }

    if ( (r = (*t.fun->C_Decrypt)(t.session, cipher, len, clear, clen)) != CKR_OK )
	CKRLOG("C_Decrypt", r);

    return r;
}

CK_RV atoken_decrypt_only(atoken t,
	CK_BYTE_PTR cipher,
	CK_ULONG len,
	CK_BYTE_PTR clear,
	CK_ULONG_PTR clen)
{
    CK_RV r;

    if ( (r = (*t.fun->C_Decrypt)(t.session, cipher, len, clear, clen)) != CKR_OK )
	CKRLOG("C_Decrypt", r);

    return r;
}

CK_RV atoken_wrap(atoken t,
	CK_MECHANISM_PTR m,
	CK_OBJECT_HANDLE wrapping_key,
	CK_OBJECT_HANDLE to_be_wrapped,
	CK_BYTE_PTR wrapped,
	CK_ULONG_PTR wlen)
{
    CK_RV r = (*t.fun->C_WrapKey)(t.session, m, wrapping_key, to_be_wrapped, wrapped, wlen);
    if (r != CKR_OK)
	CKRLOG("C_WrapKey", r);

    return r;
}

CK_RV atoken_unwrap(atoken t,
	CK_MECHANISM_PTR m,
	CK_OBJECT_HANDLE wrapping_key,
	CK_BYTE_PTR wrapped,
	CK_ULONG wlen,
	CK_ATTRIBUTE_PTR attrs,
	CK_ULONG attrs_len,
	CK_OBJECT_HANDLE_PTR key)
{
    CK_RV r = (*t.fun->C_UnwrapKey)(t.session, m, wrapping_key, wrapped, wlen, attrs, attrs_len, key);
    if (r != CKR_OK)
	CKRLOG("C_UnwrapKey", r);

    return r;
}
