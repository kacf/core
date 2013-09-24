#ifndef CFENGINE_PWCRYPT_H
#define CFENGINE_PWCRYPT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define _GNU_SOURCE
#include <crypt.h>

typedef enum {
   md5 = 1,
   sha256 = 5,
   sha512 = 6
} PwHashMethod;

int getrndsalt(PwHashMethod m, char *obuf);
int cf_crypt(char *key, char *salt, char (*encrypted)[1024]);

#endif
