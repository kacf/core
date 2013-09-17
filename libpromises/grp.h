#ifndef CFENGINE_GRP_H
#define CFENGINE_GRP_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

int groupname2id(char *igroup, char *ogroup);
int do_groups_equal(char *groups1, char (*groups2)[1024], int num);
int get_group_membership(char *user, char (*result)[1024]);

#endif
