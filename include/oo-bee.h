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

#ifndef _OOBEE_H
#define _OOBEE_H

#include <bee.h>

extern long last_error;
#define BEE_ERR_MEM -1
#define BEE_ATTR_NOT_FOUND -2

extern CK_BBOOL yes;
extern CK_BBOOL no;
extern long last_error;

/* attrs functions -> oo-attrs */
void* bee_new_attrs(); // allocate and init a new attrs
void bee_deep_free_attrs(void*);
void bee_free_attrs(void*);

/* attribute accessor methods */
/* Storage objects' attributes */
void bee_add_token(void*);
int bee_get_token(void*);
void bee_set_token(void*, int);

void bee_add_private(void*);
int bee_get_private(void*);
void bee_set_private(void*, int);

void bee_add_modifiable(void*);
int bee_get_modifiable(void*);
void bee_set_modifiable(void*, int);

void bee_add_label(void*);
const char* bee_get_label(void*);
void bee_set_label(void*, const char*, long);

/* Key objects' attributes */
void bee_add_class(void*);
long bee_get_class(void*);
void bee_set_class(void*, void*);

void bee_add_key_type(void*);
long bee_get_key_type(void*);
void bee_set_key_type(void*, void*);

void bee_add_id(void*);
const char* bee_get_id(void*);
void bee_set_id(void*, const char*, long);

void bee_add_derive(void*);
int bee_get_derive(void*);
void bee_set_derive(void*, int);

void bee_add_local(void*);
int bee_get_local(void*);
void bee_set_local(void*, int);

void bee_add_encrypt(void*);
int bee_get_encrypt(void*);
void bee_set_encrypt(void*, int);

void bee_add_decrypt(void*);
int bee_get_decrypt(void*);
void bee_set_decrypt(void*, int);

void bee_add_wrap(void*);
int bee_get_wrap(void*);
void bee_set_wrap(void*, int);

void bee_add_wrap_with_trusted(void*);
int bee_get_wrap_with_trusted(void*);
void bee_set_wrap_with_trusted(void*, int);

void bee_add_unwrap(void*);
int bee_get_unwrap(void*);
void bee_set_unwrap(void*, int);

void bee_add_sign(void*);
int bee_get_sign(void*);
void bee_set_sign(void*, int);

void bee_add_sign_recover(void*);
int bee_get_sign_recover(void*);
void bee_set_sign_recover(void*, int);

void bee_add_verify(void*);
int bee_get_verify(void*);
void bee_set_verify(void*, int);

void bee_add_verify_recover(void*);
int bee_get_verify_recover(void*);
void bee_set_verify_recover(void*, int);

void bee_add_never_extractable(void*);
int bee_get_never_extractable(void*);
void bee_set_never_extractable(void*, int);

void bee_add_extractable(void*);
int bee_get_extractable(void*);
void bee_set_extractable(void*, int);

void bee_add_always_sensitive(void*);
int bee_get_always_sensitive(void*);
void bee_set_always_sensitive(void*, int);

void bee_add_sensitive(void*);
int bee_get_sensitive(void*);
void bee_set_sensitive(void*, int);

void bee_add_trusted(void*);
int bee_get_trusted(void*);
void bee_set_trusted(void*, int);

void bee_add_value(void*);
const char* bee_get_value(void*, long*);
void bee_set_value(void*, const char*, long);

void bee_add_value_len(void*);
long bee_get_value_len(void*);
void bee_set_value_len(void*, void*);

void bee_add_modulus_bits(void*);
long bee_get_modulus_bits(void*);
void bee_set_modulus_bits(void*, void*);

void bee_add_modulus(void*);
const char* bee_get_modulus(void*, long*);
void bee_set_modulus(void*, const char*, long);

void bee_add_public_exponent(void*);
const char* bee_get_public_exponent(void*, long*);
void bee_set_public_exponent(void*, const char*, long);

void bee_add_private_exponent(void*);
const char* bee_get_private_exponent(void*, long*);
void bee_set_private_exponent(void*, const char*, long);

/* General bee's funs -> oo-bee.c */
void bee_free_mem(void*);
long bee_get_last_error();
void bee_reset_error();
void* bee_new(const char*, const unsigned char*);
void* bee_new_and_configure(const char*, long, const unsigned char*, long, long, void*, void*, void*);
void bee_logout(void*);

void bee_set_default_sym_mechanism(void*, long);
void bee_set_default_asym_mechanism(void*, long);
void bee_set_default_sym_template(void*, void*);
void bee_set_default_pub_template(void*, void*);
void bee_set_default_priv_template(void*, void*);
void fill_mechanism(CK_MECHANISM_PTR, long);

/* info -> bee-info.c */
long* bee_get_supported_mechanisms(void*, long*);
char** bee_get_token_info(void*);

/* Keys -> bee-kyes.c */
long bee_generate_key(void*);
long bee_generate_named_key(void*, const char*);
long bee_generate_key_with_attrs(void*, void*);
long bee_generate_key_with_mechanism(void*, long);
long bee_generate_key_with_attrs_and_mechanism(void*, void*, long);
void bee_free_key_pair(long*);
long* bee_generate_key_pair(void*, long);
long* bee_generate_named_key_pair(void*, long, const char*);
long* bee_generate_key_pair_with_attrs(void*, void*, void*);
long* bee_generate_key_pair_with_mechanism(void*, long, long);
long* bee_generate_key_pair_with_attrs_and_mechanism(void*, void*, void*, long);

/* Objects -> bee-objs.c */
void bee_get_attrs(void*, long, void*);
void bee_set_attrs(void*, long, void*);

long* bee_find_objects_by_name(void*, const char*, long*);
long* bee_find_objects(void*, void*, long*);
long bee_create_object(void*, void*);
long bee_copy_object(void*, long, void*);
void bee_destroy_object(void*, long);

/* Crypto + wrap/unwrap -> bee-crypto.c */
char* bee_s_encrypt(void*, char*, long, long, long*);
char* bee_a_encrypt(void*, char*, long, long, long*);
char* bee_encrypt_with_mechanism(void*, char*, long, long, long, long*);

char* bee_s_decrypt(void*, char*, long, long, long*);
char* bee_a_decrypt(void*, char*, long, long, long*);
char* bee_decrypt_with_mechanism(void*, char*, long, long, long, long*);

char* bee_s_wrap(void*, long, long, long*);
char* bee_a_wrap(void*, long, long, long*);
char* bee_wrap_with_mechanism(void*, long, long, long, long*);

// BUG: this way we have now way to know anything about the unwrapped key's class and type
// long bee_s_unwrap(void*, long, char*, long);
// long bee_a_unwrap(void*, long, char*, long);
// long bee_unwrap_with_mechanism(void*, long, long, char*, long);
long bee_s_unwrap_with_attrs(void*, long, char*, long, void*);
long bee_a_unwrap_with_attrs(void*, long, char*, long, void*);
long bee_unwrap_with_attrs_and_mechanism(void*, long, long, char*, long, void*);
#endif
