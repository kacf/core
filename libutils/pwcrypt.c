#include <pwcrypt.h>

int
cf_crypt(char *key, char *salt, char (*encrypted)[1024])
{
    char *value = NULL;
    size_t len;
    int err = 0;
    struct crypt_data cd;

    cd.initialized = 0;
    /* work around the glibc bug */
    cd.current_salt[0] = ~salt[0];

    value = crypt_r((char *) key, (char *) salt, &cd);

    if (value) {
        len = strlen(value);

        strncpy(*encrypted, value, len);
        (*encrypted)[len]='\0';
        return 0;
    }

    printf("crypt_r() failed");

    return 1;
}


#if 0
int main()
{
   char encrypted[1024];

   cf_crypt("vagrant", "$6$aaaaaaaaaa", &encrypted);
   printf("[Encrypted=%s]\n", encrypted);
   return 0;
}
#endif
