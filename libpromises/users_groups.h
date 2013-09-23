#ifndef CFENGINE_USERS_GROUPS_H
#define CFENGINE_USERS_GROUPS_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

int GroupConvert(char *igroup, char *ogroup);
int AreListsOfGroupsEqual(char *groups1, char (*groups2)[1024], int num);
int GroupGetUserMembership(char *user, char (*result)[1024]);

#endif
