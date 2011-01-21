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
#include <oo-bee.h>

char* bee_s_encrypt(void *b, char *clear, long len, long key, long *res_len)
{
    CK_RV r;
    char *res;

    if ((r = s_encrypt(*((bee*) b), (CK_BYTE_PTR) clear, (CK_ULONG) len, (CK_OBJECT_HANDLE) key,
		    (CK_BYTE_PTR*) &res, (CK_ULONG_PTR) res_len)) != CKR_OK)
    {
	last_error = r;
	return NULL;
    }

    return res;
}

char* bee_a_encrypt(void *b, char *clear, long len, long key, long *res_len)
{
    CK_RV r;
    char *res;

    if ((r = a_encrypt(*((bee*) b), (CK_BYTE_PTR) clear, (CK_ULONG) len, (CK_OBJECT_HANDLE) key,
		    (CK_BYTE_PTR*) &res, (CK_ULONG_PTR) res_len)) != CKR_OK)
    {
	last_error = r;
	return NULL;
    }

    return res;
}

char* bee_encrypt_with_mechanism(void *b, char *clear, long len, long key, long m, long *res_len)
{
    CK_RV r;
    char *res;
    CK_MECHANISM me;

    fill_mechanism(&me, (CK_MECHANISM_TYPE) m);
    if ((r = encrypt_with_mechanism(*((bee*) b), (CK_BYTE_PTR) clear, (CK_ULONG) len, (CK_OBJECT_HANDLE) key,
		    &me, (CK_BYTE_PTR*) &res, (CK_ULONG_PTR) res_len)) != CKR_OK)
    {
	last_error = r;
	return NULL;
    }

    return res;
}

char* bee_s_decrypt(void *b, char *cipher, long len, long key, long *res_len)
{
    CK_RV r;
    char *res;

    if ((r = s_decrypt(*((bee*) b), (CK_BYTE_PTR) cipher, (CK_ULONG) len, (CK_OBJECT_HANDLE) key,
		    (CK_BYTE_PTR*) &res, (CK_ULONG_PTR) res_len)) != CKR_OK)
    {
	last_error = r;
	return NULL;
    }

    return res;
}

char* bee_a_decrypt(void *b, char *cipher, long len, long key, long *res_len)
{
    CK_RV r;
    char *res;

    if ((r = a_decrypt(*((bee*) b), (CK_BYTE_PTR) cipher, (CK_ULONG) len, (CK_OBJECT_HANDLE) key,
		    (CK_BYTE_PTR*) &res, (CK_ULONG_PTR) res_len)) != CKR_OK)
    {
	last_error = r;
	return NULL;
    }

    return res;
}

char* bee_decrypt_with_mechanism(void *b, char *cipher, long len, long key, long m, long *res_len)
{
    CK_RV r;
    char *res;
    CK_MECHANISM me;

    fill_mechanism(&me, (CK_MECHANISM_TYPE) m);
    if ((r = decrypt_with_mechanism(*((bee*) b), (CK_BYTE_PTR) cipher, (CK_ULONG) len, (CK_OBJECT_HANDLE) key,
		    &me, (CK_BYTE_PTR*) &res, (CK_ULONG_PTR) res_len)) != CKR_OK)
    {
	last_error = r;
	return NULL;
    }

    return res;
}

char* bee_s_wrap(void *b, long wrapping_key, long to_be_wrapped_key, long *res_len)
{
    CK_RV r;
    char *res;

    if ((r = s_wrap(*((bee*) b), (CK_OBJECT_HANDLE) wrapping_key, (CK_OBJECT_HANDLE) to_be_wrapped_key,
		    (CK_BYTE_PTR*) &res, (CK_ULONG_PTR) res_len)) != CKR_OK)
    {
	last_error = r;
	return NULL;
    }

    return res;
}

char* bee_a_wrap(void *b, long wrapping_key, long to_be_wrapped_key, long *res_len)
{
    CK_RV r;
    char *res;

    if ((r = a_wrap(*((bee*) b), (CK_OBJECT_HANDLE) wrapping_key, (CK_OBJECT_HANDLE) to_be_wrapped_key,
		    (CK_BYTE_PTR*) &res, (CK_ULONG_PTR) res_len)) != CKR_OK)
    {
	last_error = r;
	return NULL;
    }

    return res;
}

char* bee_wrap_with_mechanism(void *b, long wrapping_key, long to_be_wrapped_key, long m, long *res_len)
{
    CK_RV r;
    char *res;
    CK_MECHANISM me;

    fill_mechanism(&me, (CK_MECHANISM_TYPE) m);
    if ((r = wrap_with_mechanism(*((bee*) b), (CK_OBJECT_HANDLE) wrapping_key, &me,
		    (CK_OBJECT_HANDLE) to_be_wrapped_key, (CK_BYTE_PTR*) &res, (CK_ULONG_PTR) res_len)) != CKR_OK)
    {
	last_error = r;
	return NULL;
    }

    return res;
}

// BUG: this way we have now way to know anything about the unwrapped key's class and type
// long bee_s_unwrap(void *b, long wrapping_key, char *wrapped_key, long len)
// {
//     CK_RV r;
//     long key;
// 
//     if ((r = s_unwrap(*((bee*) b), (CK_OBJECT_HANDLE) wrapping_key, (CK_BYTE_PTR) wrapped_key, (CK_ULONG) len,
// 		    (CK_OBJECT_HANDLE_PTR) &key)) != CKR_OK)
//     {
// 	last_error = r;
// 	return -1;
//     }
// 
//     return key;
// }

long bee_s_unwrap_with_attrs(void *b, long wrapping_key, char *wrapped_key, long len, void *a)
{
    CK_RV r;
    long key;

    if ((r = s_unwrap_with_attrs(*((bee*) b), (CK_OBJECT_HANDLE) wrapping_key, (CK_BYTE_PTR) wrapped_key, (CK_ULONG) len,
		    (CK_OBJECT_HANDLE_PTR) &key, *((attrs*) a))) != CKR_OK)
    {
	last_error = r;
	return -1;
    }

    return key;
}

// BUG: this way we have now way to know anything about the unwrapped key's class and type
// long bee_a_unwrap(void *b, long wrapping_key, char *wrapped_key, long len)
// {
//     CK_RV r;
//     long key;
// 
//     if ((r = a_unwrap(*((bee*) b), (CK_OBJECT_HANDLE) wrapping_key, (CK_BYTE_PTR) wrapped_key, (CK_ULONG) len,
// 		    (CK_OBJECT_HANDLE_PTR) &key)) != CKR_OK)
//     {
// 	last_error = r;
// 	return -1;
//     }
// 
//     return key;
// }

long bee_a_unwrap_with_attrs(void *b, long wrapping_key, char *wrapped_key, long len, void *a)
{
    CK_RV r;
    long key;

    if ((r = a_unwrap_with_attrs(*((bee*) b), (CK_OBJECT_HANDLE) wrapping_key, (CK_BYTE_PTR) wrapped_key, (CK_ULONG) len,
		    (CK_OBJECT_HANDLE_PTR) &key, *((attrs*) a))) != CKR_OK)
    {
	last_error = r;
	return -1;
    }

    return key;
}

// BUG: this way we have now way to know anything about the unwrapped key's class and type
// long bee_unwrap_with_mechanism(void *b, long wrapping_key, long m, char *wrapped_key, long len)
// {
//     CK_RV r;
//     long key;
//     CK_MECHANISM me;
// 
//     fill_mechanism(&me, (CK_MECHANISM_TYPE) m);
//     if ((r = unwrap_with_mechanism(*((bee*) b), (CK_OBJECT_HANDLE) wrapping_key, &me, (CK_BYTE_PTR) wrapped_key,
// 		    (CK_ULONG) len, (CK_OBJECT_HANDLE_PTR) &key)) != CKR_OK)
//     {
// 	last_error = r;
// 	return -1;
//     }
// 
//     return key;
// }

long bee_unwrap_with_attrs_and_mechanism(void *b, long wrapping_key, long m, char *wrapped_key, long len, void *a)
{
    CK_RV r;
    long key;
    CK_MECHANISM me;

    fill_mechanism(&me, (CK_MECHANISM_TYPE) m);
    if ((r = unwrap_with_attrs_and_mechanism(*((bee*) b), (CK_OBJECT_HANDLE) wrapping_key, &me,
		    (CK_BYTE_PTR) wrapped_key, (CK_ULONG) len, (CK_OBJECT_HANDLE_PTR) &key, *((attrs*) a))) != CKR_OK)
    {
	last_error = r;
	return -1;
    }

    return key;
}
