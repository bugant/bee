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

#ifndef _BEE_H
#define _BEE_H

#include <atoken.h>

typedef struct {
    CK_ATTRIBUTE_PTR as;
    CK_ULONG len;
} attrs;

/* attrs functions -> attrs-utility.c */
void init_attrs(attrs*);
attrs* copy_attrs_with_static_bools(attrs, CK_VOID_PTR, CK_VOID_PTR);
attrs* copy_attrs(attrs);
void deep_free_attrs(attrs*, CK_VOID_PTR, CK_VOID_PTR);
void soft_free_attrs(attrs*);
void free_attrs(attrs*);
int add_bool_attr(attrs*, CK_ATTRIBUTE_TYPE, CK_BBOOL*);
int add_attribute(attrs*, CK_ATTRIBUTE_TYPE, CK_VOID_PTR, CK_ULONG);
CK_ATTRIBUTE_PTR find_attribute(attrs, CK_ATTRIBUTE_TYPE);
void add_gen_key_attributes(attrs*, CK_MECHANISM_PTR);
void add_gen_key_pair_attributes_1024bits(attrs*, attrs*, CK_MECHANISM_PTR);
void add_gen_key_pair_attributes(attrs*, attrs*, CK_ULONG, CK_MECHANISM_PTR);

typedef struct {
    atoken t;
    CK_MECHANISM_PTR default_sym_m;
    CK_MECHANISM_PTR default_asym_m;
    attrs *default_sym_attrs;
    attrs *default_pub_attrs;
    attrs *default_priv_attrs;
} bee;

#define DEFAULT_SYM_M CKM_DES_ECB
#define DEFAULT_ASYM_M CKM_RSA_PKCS

extern CK_BYTE_PTR iv8;
extern CK_BYTE_PTR iv16;
extern CK_MAC_GENERAL_PARAMS_PTR macp;

void malloc_sym_mechanism_parameters();
void init_mechanism_parameter(CK_MECHANISM_PTR);

/* General bee's funs -> bee.c */
CK_RV init(const char*, const unsigned char*, bee*);
CK_RV init_user(const char*, CK_USER_TYPE, const unsigned char*, bee*);
CK_RV init_and_configure(const char*, CK_USER_TYPE, const unsigned char*, CK_MECHANISM_PTR, CK_MECHANISM_PTR, attrs*, attrs*, attrs*, bee*);
CK_RV logout(bee*);

void set_default_sym_mechanism(bee*, CK_MECHANISM_PTR);
void set_default_asym_mechanism(bee*, CK_MECHANISM_PTR);
void copy_as_default_template(bee*, attrs**, attrs*, int, CK_VOID_PTR, CK_VOID_PTR);
void set_default_sym_template(bee*, attrs*);
void copy_as_default_sym_template(bee*, attrs*, int, CK_VOID_PTR, CK_VOID_PTR);
void set_default_pub_template(bee*, attrs*);
void copy_as_default_pub_template(bee*, attrs*, int, CK_VOID_PTR, CK_VOID_PTR);
void set_default_priv_template(bee*, attrs*);
void copy_as_default_priv_template(bee*, attrs*, int, CK_VOID_PTR, CK_VOID_PTR);

/* info -> bee-info.c */
CK_RV get_supported_mechanisms(bee, CK_MECHANISM_TYPE_PTR*, CK_ULONG_PTR);
CK_RV get_token_info(bee, CK_TOKEN_INFO_PTR);

/* Keys -> bee-kyes.c */
CK_RV generate_key(bee, CK_OBJECT_HANDLE_PTR);
CK_RV generate_named_key(bee, const char*, CK_OBJECT_HANDLE_PTR);
CK_RV generate_key_with_attrs(bee, attrs, CK_OBJECT_HANDLE_PTR);
CK_RV generate_key_with_mechanism(bee, CK_MECHANISM_PTR, CK_OBJECT_HANDLE_PTR);
CK_RV generate_key_with_attrs_and_mechanism(bee, attrs, CK_MECHANISM_PTR, CK_OBJECT_HANDLE_PTR);
CK_RV generate_key_pair(bee, CK_ULONG, CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR);
CK_RV generate_named_key_pair(bee, CK_ULONG, const char*, CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR);
CK_RV generate_key_pair_with_attrs(bee, attrs, attrs, CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR);
CK_RV generate_key_pair_with_mechanism(bee, CK_ULONG, CK_MECHANISM_PTR, CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR);
CK_RV generate_key_pair_with_attrs_and_mechanism(bee, attrs, attrs, CK_MECHANISM_PTR, CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR);

/* Objects -> bee-objs.c */
CK_RV get_attrs(bee, CK_OBJECT_HANDLE, attrs);
CK_RV set_attrs(bee, CK_OBJECT_HANDLE, attrs);

CK_RV find_objects_by_name(bee, const char*, CK_OBJECT_HANDLE_PTR*, CK_ULONG_PTR);
CK_RV find_objects(bee, attrs, CK_OBJECT_HANDLE_PTR*, CK_ULONG_PTR);
CK_RV create_object(bee, attrs, CK_OBJECT_HANDLE_PTR);
CK_RV copy_object(bee, CK_OBJECT_HANDLE, attrs, CK_OBJECT_HANDLE_PTR);
CK_RV destroy_object(bee, CK_OBJECT_HANDLE);

/* Crypto + wrap/unwrap -> bee-crypto.c */
CK_RV s_encrypt(bee, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_BYTE_PTR*, CK_ULONG_PTR);
CK_RV a_encrypt(bee, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_BYTE_PTR*, CK_ULONG_PTR);
CK_RV encrypt_with_mechanism(bee, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_MECHANISM_PTR, CK_BYTE_PTR*, CK_ULONG_PTR);

CK_RV s_decrypt(bee, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_BYTE_PTR*, CK_ULONG_PTR);
CK_RV a_decrypt(bee, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_BYTE_PTR*, CK_ULONG_PTR);
CK_RV decrypt_with_mechanism(bee, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_MECHANISM_PTR, CK_BYTE_PTR*, CK_ULONG_PTR);

CK_RV s_wrap(bee, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR*, CK_ULONG_PTR);
CK_RV a_wrap(bee, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR*, CK_ULONG_PTR);
CK_RV wrap_with_mechanism(bee, CK_OBJECT_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_BYTE_PTR*, CK_ULONG_PTR);

CK_RV s_unwrap(bee, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
CK_RV s_unwrap_with_attrs(bee, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR, attrs);
CK_RV a_unwrap(bee, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
CK_RV a_unwrap_with_attrs(bee, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR, attrs);
CK_RV unwrap_with_mechanism(bee, CK_OBJECT_HANDLE, CK_MECHANISM_PTR, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
CK_RV unwrap_with_attrs_and_mechanism(bee, CK_OBJECT_HANDLE, CK_MECHANISM_PTR, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR, attrs);
#endif
