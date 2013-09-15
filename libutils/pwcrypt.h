#ifndef CFENGINE_PWCRYPT_H
#define CFENGINE_PWCRYPT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define _GNU_SOURCE
#include <crypt.h>

int cf_crypt(char *key, char *salt, char (*encrypted)[1024]);

#endif
