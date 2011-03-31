/*
 * This is a simple example generating an RSA key pair
 */

#include <stdio.h>
#include <string.h>
#include <bee.h>

int main()
{
    bee b;
    CK_OBJECT_HANDLE pub, priv;
    CK_BBOOL yes = TRUE;
    CK_BBOOL no = FALSE;
    CK_ULONG len = 1024;
    attrs pub_foo, priv_foo;

    /* connect to opencryptoki using PIN 12345, set it as needed */
    if (init("libopencryptoki.so", "12345", &b) != CKR_OK)
    {
	printf("too bad: cannot init my bee!\n");
	return 1;
    }

    init_attrs(&pub_foo);
    add_bool_attr(&pub_foo, CKA_TOKEN, &yes);
    set_default_pub_template(&b, &pub_foo);

    init_attrs(&priv_foo);
    add_bool_attr(&priv_foo, CKA_TOKEN, &yes);
    set_default_priv_template(&b, &priv_foo);

    if (generate_key_pair(b, 1024, &pub, &priv) != CKR_OK)
    {
	printf("too bad: cannot generate a key-pair\n");
	return 1;
    }
    printf("you have a new key-pair\n");

    return;
}
