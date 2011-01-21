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

CK_RV get_attrs(bee b, CK_OBJECT_HANDLE o, attrs a)
{
    CK_RV r;
    CK_ULONG i;

    /* say good bye to your old values!
     * this could cause memory leaks obviously,
     * who call this function has to be conscious of it
     * and give a proper attrs (with NULL_PTR already set)*/
    for (i = 0; i < a.len; i++)
    {
	a.as[i].pValue = NULL_PTR;
	a.as[i].ulValueLen = 0;
    }

    if ((r = atoken_get_attributes(b.t, o, a.as, a.len)) != CKR_OK)
	return r;

    for (i = 0; i < a.len; i++)
    {
	// ulValueLen is -1 if the specified attribute cannot be
	// revealed or if it is invalid (i.e., not defined for this object)
	if ((CK_LONG) a.as[i].ulValueLen == -1)
	    a.as[i].pValue = NULL_PTR;
	else
	{
	    a.as[i].pValue = (CK_VOID_PTR) malloc(a.as[i].ulValueLen);
	    if (!(a.as[i].pValue))
	    {
		CKRLOG("Cannot allocate memory for attribute(s)", (CK_RV) CKR_GENERAL_ERROR);
		return (CK_RV) CKR_GENERAL_ERROR;
	    }
	}
    }

    return atoken_get_attributes(b.t, o, a.as, a.len);
}

CK_RV set_attrs(bee b, CK_OBJECT_HANDLE o, attrs a)
{
    return atoken_set_attributes(b.t, o, a.as, a.len);
}

CK_RV find_objects_by_name(bee b, const char *name, CK_OBJECT_HANDLE_PTR *found, CK_ULONG_PTR how_many)
{
    attrs search_me;
    init_attrs(&search_me);
    add_attribute(&search_me, CKA_LABEL, (CK_VOID_PTR) name, strlen(name));

    return find_objects(b, search_me, found, how_many);
}

CK_RV find_objects(bee b, attrs search, CK_OBJECT_HANDLE_PTR *found, CK_ULONG_PTR how_many)
{
    return atoken_find_objects(b.t, search.as, search.len, found, how_many);
}

CK_RV create_object(bee b, attrs a, CK_OBJECT_HANDLE_PTR o)
{
    return atoken_create_object(b.t, a.as, a.len, o);
}

CK_RV copy_object(bee b, CK_OBJECT_HANDLE o, attrs a, CK_OBJECT_HANDLE_PTR copy)
{
    return atoken_copy_object(b.t, o, a.as, a.len, copy);
}

CK_RV destroy_object(bee b, CK_OBJECT_HANDLE o)
{
    return atoken_destroy_object(b.t, o);
}

