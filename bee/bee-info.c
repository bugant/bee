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

CK_RV get_supported_mechanisms(bee b, CK_MECHANISM_TYPE_PTR *m, CK_ULONG_PTR len)
{
    CK_RV r;
    CK_RV error = CKR_GENERAL_ERROR;
    CK_MECHANISM_TYPE_PTR list;
    
    if ((r = atoken_get_mechanisms(b.t, NULL_PTR, len)) != CKR_OK)
	return r;

    list = malloc(sizeof(CK_MECHANISM_TYPE) * (*len));
    if (!list)
    {
	CKRLOG("Cannot allocate memory for supported mechanism list", error);
	return error;
    }

    *m = list;
    return atoken_get_mechanisms(b.t, *m, len);
}

CK_RV get_token_info(bee b, CK_TOKEN_INFO_PTR info)
{
    return atoken_get_info(b.t, info);
}
