#include <pwcrypt.h>

int getrndsalt(PwHashMethod m, char *obuf) {
   int r = (int) (( random() % 8L )+ 8);
   if (m == md5) r = 8;
   char *s = "abcdefghijklmnopqrstuvwxyz" \
             "0123456789./" \
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
   int i;
   strcpy(obuf, "$0$");
   obuf[1] = '0' + m;
   for (i=0; i<r; i++)
   {
       obuf[i+3] = s[random() % 64];
   }
   obuf[r+3]='\0';
   return 0;
}

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

   srand(time(NULL));
   cf_crypt("vagrant", "$6$aaaaaaaaaa", &encrypted);
   printf("[Encrypted=%s]\n", encrypted);


   char obuf[20];
   getrndsalt(5, obuf);
   printf("salt=[%s]\n", obuf);
   return 0;
}
#endif
