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

long bee_generate_key(void *b)
{
    long key;
    CK_RV r;

    if ((r = generate_key(*((bee*) b), (CK_OBJECT_HANDLE_PTR) &key)) != CKR_OK)
    {
	last_error = r;
	return -1;
    }

    return key;
}

long bee_generate_named_key(void *b, const char *name)
{
    long key;
    CK_RV r;

    if ((r = generate_named_key(*((bee*) b), name, (CK_OBJECT_HANDLE_PTR) &key)) != CKR_OK)
    {
	last_error = r;
	return -1;
    }

    return key;
}

long bee_generate_key_with_attrs(void *b, void *a)
{
    long key;
    CK_RV r;

    if ((r = generate_key_with_attrs(*((bee*) b), *((attrs*) a), (CK_OBJECT_HANDLE_PTR) &key)) != CKR_OK)
    {
	last_error = r;
	return -1;
    }

    return key;
}

long bee_generate_key_with_mechanism(void *b, long m)
{
    long key;
    CK_RV r;
    CK_MECHANISM_PTR me;

    me = (CK_MECHANISM_PTR) malloc(sizeof(CK_MECHANISM));
    fill_mechanism(me, m);

    if ((r = generate_key_with_mechanism(*((bee*) b), me, (CK_OBJECT_HANDLE_PTR) &key)) != CKR_OK)
    {
	last_error = r;
	key = -1;
    }

    free(me);
    return key;
}

long bee_generate_key_with_attrs_and_mechanism(void *b, void *a, long m)
{
    long key;
    CK_RV r;
    CK_MECHANISM_PTR me;

    me = (CK_MECHANISM_PTR) malloc(sizeof(CK_MECHANISM));
    fill_mechanism(me, m);

    if ((r = generate_key_with_attrs_and_mechanism(*((bee*) b), *((attrs*) a), me, (CK_OBJECT_HANDLE_PTR) &key)) != CKR_OK)
    {
	last_error = r;
	key = -1;	
    }

    free(me);
    return key;
}

void bee_free_key_pair(long *keys)
{
    if (!keys)
	return;

    free(keys);
}

long* bee_generate_key_pair(void *b, long len)
{
    long *keys;
    CK_RV r;

    keys = (long *) malloc(sizeof(long) * 2);
    if ((r = generate_key_pair(*((bee*) b), len, (CK_OBJECT_HANDLE_PTR) &(keys[0]), (CK_OBJECT_HANDLE_PTR) &(keys[1]))) != CKR_OK)
    {
	last_error = r;
	return NULL;
    }

    return keys;
}

long* bee_generate_named_key_pair(void *b, long len, const char *name)
{
    long *keys;
    CK_RV r;

    keys = (long *) malloc(sizeof(long) * 2);
    if ((r = generate_named_key_pair(*((bee*) b), len, name, (CK_OBJECT_HANDLE_PTR) &(keys[0]), (CK_OBJECT_HANDLE_PTR) &(keys[1]))) != CKR_OK)
    {
	last_error = r;
	return NULL;
    }

    return keys;
}

long* bee_generate_key_pair_with_attrs(void *b, void *pub, void *priv)
{
    long *keys;
    CK_RV r;

    keys = (long *) malloc(sizeof(long) * 2);
    if ((r = generate_key_pair_with_attrs(*((bee*) b), *((attrs*) pub), *((attrs*) priv),
		    (CK_OBJECT_HANDLE_PTR) &(keys[0]), (CK_OBJECT_HANDLE_PTR) &(keys[1]))) != CKR_OK)
    {
	last_error = r;
	return NULL;
    }

    return keys;
}

long* bee_generate_key_pair_with_mechanism(void *b, long len, long m)
{
    long *keys;
    CK_RV r;
    CK_MECHANISM_PTR me;

    me = (CK_MECHANISM_PTR) malloc(sizeof(CK_MECHANISM));
    fill_mechanism(me, m);

    keys = (long *) malloc(sizeof(long) * 2);
    if ((r = generate_key_pair_with_mechanism(*((bee*) b), len, me,
		    (CK_OBJECT_HANDLE_PTR) &(keys[0]), (CK_OBJECT_HANDLE_PTR) &(keys[1]))) != CKR_OK)
    {
	last_error = r;
	keys = NULL;
    }

    free(me);
    return keys;
}

long* bee_generate_key_pair_with_attrs_and_mechanism(void *b, void *pub, void *priv, long m)
{
    long *keys;
    CK_RV r;
    CK_MECHANISM_PTR me;

    me = (CK_MECHANISM_PTR) malloc(sizeof(CK_MECHANISM));
    fill_mechanism(me, m);

    keys = (long *) malloc(sizeof(long) * 2);
    if ((r = generate_key_pair_with_attrs_and_mechanism(*((bee*) b), *((attrs*) pub), *((attrs*) priv), me,
		    (CK_OBJECT_HANDLE_PTR) &(keys[0]), (CK_OBJECT_HANDLE_PTR) &(keys[1]))) != CKR_OK)
    {
	last_error = r;
	keys = NULL;
    }

    free(me);
    return keys;
}
