#ifndef CFENGINE_USERS_GROUPS_H
#define CFENGINE_USERS_GROUPS_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sequence.h>

int GroupConvert(char *igroup, char *ogroup);
int AreListsOfGroupsEqual(char *groups1, Seq *groups2);
int GroupGetUserMembership(char *user, Seq *result);

#endif
