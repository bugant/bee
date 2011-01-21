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

#ifndef _ATOKEN_H
#define _ATOKEN_H

#ifdef BEEWIN

#include <windows.h>
#include <conio.h>
#ifndef _WINDOWS
#define _WINDOWS
#endif
#define DLOPEN(lib) LoadLibrary(lib)
#define DLSYM(h, function) GetProcAddress(h, function)
#define DLCLOSE(h) FreeLibrary(h)

// MACROS needed by pkcs#11 header files (Visual Studio)
#pragma pack(push, cryptoki, 1)

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType __declspec(dllexport) name
#define CK_DECLARE_FUNCTION(returnType, name) returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"
#pragma pack(pop, cryptoki)

#else


#include <dlfcn.h>
// MACROS needed by pkcs#11 header files
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"

#define DLOPEN(lib) dlopen(lib, RTLD_NOW)
#define DLSYM(h, function) dlsym(h, function)
#define DLCLOSE(h) dlclose(h)
#endif

#ifdef DEBUG
#define CKRLOG(fct, rv) printf("%s:%d " fct " () exited with error %08lX\n", __FILE__, __LINE__, rv)
#else
#define CKRLOG(fct, rv) if (0)
#endif

typedef struct {
    void *module;
    CK_SLOT_ID slot;
    CK_SESSION_HANDLE session;
    CK_FUNCTION_LIST_PTR fun;
} atoken;

/* atoken features */

/* Generic functions -> atoken.c */
CK_RV atoken_init(atoken*, const char*);
void atoken_quit(atoken*);
CK_RV atoken_login(atoken*, CK_USER_TYPE, CK_CHAR*);
CK_RV atoken_logout(atoken);
CK_RV atoken_get_mechanisms(atoken, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR);
CK_RV atoken_get_info(atoken, CK_TOKEN_INFO_PTR);

/* Crypto -> atoken-crypto.c */
CK_RV atoken_encrypt(atoken, CK_BYTE_PTR, CK_ULONG, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV atoken_encrypt_only(atoken, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV atoken_decrypt(atoken, CK_BYTE_PTR, CK_ULONG, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV atoken_decrypt_only(atoken, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV atoken_wrap(atoken, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV atoken_unwrap(atoken, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);

/* Keys (and objects) -> atoken-keys.c */
CK_RV atoken_new_key(atoken, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
CK_RV atoken_new_key_pair(atoken, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG,
	CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR);
CK_RV atoken_get_attributes(atoken, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
CK_RV atoken_set_attributes(atoken, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
CK_RV atoken_find_objects(atoken, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR*, CK_ULONG_PTR);
CK_RV atoken_create_object(atoken, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
CK_RV atoken_copy_object(atoken, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
CK_RV atoken_destroy_object(atoken, CK_OBJECT_HANDLE);
CK_RV atoken_gen_mechanism(CK_MECHANISM_PTR, CK_MECHANISM_PTR);
#endif
