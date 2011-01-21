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

void bee_get_attrs(void *b, long o, void *a)
{
    CK_RV r;
    if ((r = get_attrs(*((bee*) b), (CK_OBJECT_HANDLE) o, *((attrs*) a))) != CKR_OK)
	last_error = r;
}

void bee_set_attrs(void *b, long o, void *a)
{
    CK_RV r;
    if ((r = set_attrs(*((bee*) b), (CK_OBJECT_HANDLE) o, *((attrs*) a))) != CKR_OK)
	last_error = r;
}

long* bee_find_objects_by_name(void *b, const char *name, long *len)
{
    long *f;
    CK_RV r;

    if ((r = find_objects_by_name(*((bee*) b), name, (CK_OBJECT_HANDLE**) &f, (CK_ULONG_PTR) len)) != CKR_OK)
    {
	last_error = r;
	return NULL;
    }

    return f;
}

long* bee_find_objects(void *b, void *a, long *len)
{
    long *f;
    CK_RV r;

    if ((r = find_objects(*((bee*) b), *((attrs*) a), (CK_OBJECT_HANDLE**) &f, (CK_ULONG_PTR) len)) != CKR_OK)
    {
	last_error = r;
	return NULL;
    }

    return f;
}

long bee_create_object(void *b, void *a)
{
    long o;
    CK_RV r;

    if ((r = create_object(*((bee*) b), *((attrs*) a), (CK_OBJECT_HANDLE_PTR) &o)) != CKR_OK)
    {
	last_error = r;
	return -1;
    }

    return o;
}

long bee_copy_object(void *b, long o, void *a)
{
    long copy;
    CK_RV r;

    if ((r = copy_object(*((bee*) b), (CK_OBJECT_HANDLE) o, *((attrs*) a), (CK_OBJECT_HANDLE_PTR) &copy)) != CKR_OK)
    {
	last_error = r;
	return -1;
    }

    return copy;
}

void bee_destroy_object(void *b, long o)
{
    CK_RV r;

    if ((r = destroy_object(*((bee*) b), (CK_OBJECT_HANDLE) o)) != CKR_OK)
	last_error = r;
}
