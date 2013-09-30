#include <users_groups.h>

/* convert from group name to group id and vice versa */
/* will auto-detect gid/name and act accordingly      */
/* return 0 if found, <>0 otherwise                   */
/* can be used to check whether a group exists        */
int GroupConvert(char *igroup, char *ogroup)
{
    FILE *fp = fopen ("/etc/group", "r");
    if (fp == NULL)
    {
        printf ("cannot open /etc/group file\n");
        return -1;
    }
    char line[1024];
    char gbuf[100];
    if (!isdigit (igroup[0]))
    {
        sprintf (gbuf, "%s:", igroup);
    }
    else
    {
        sprintf (gbuf, ":%s:", igroup);
    }
    while (fgets (line, 1024, fp) != NULL)
    {
        if (!isdigit (igroup[0]))
        {
            if (!strncmp (line, gbuf, strlen (gbuf)))
            {
                sscanf (line, "%[^:]:x:%[^:]:", gbuf, ogroup);
                fclose (fp);
                return 0;
            }
        }
        else
        {
            if (strstr (line, gbuf) != NULL)
            {
                sscanf (line, "%[^:]:x:", ogroup);
                fclose (fp);
                return 0;
            }
        }
    }
    fclose (fp);
    return 1;
}

/*****************************************************/
/* get group membership                              */
/* Achtung : primary group is not part of the result */
/*****************************************************/
/***
Seq *groups1 : only names are accepted here
1 : equal, 0 : differ, <> : error comparing
***/
int AreListsOfGroupsEqual (char *groups1, Seq *groups2)
{
    char *s0 = groups1;
    char *s = NULL;
    int i = 0;
    int found = 0;
    int cnt = 0;

    while ((s = strchr (s0, ',')) != NULL)
    {
        cnt++;
        for (i = 0; i < SeqLength(groups2); i++)
        {
            if (!strncmp ((char *)groups2->data[i], s0, s - s0))
            {
                //printf ("compared %s to %s ? YES\n", (char *)groups2->data[i], s0);
                found = 1;
            }
        }
        if (found == 0)
        {
            return 0;
        }
        s0 = s + 1;
    }
    found = 0;
    for (i = 0; i < SeqLength(groups2); i++)
    {
        if (!strcmp ((char *)groups2->data[i], s0))
        {
            //printf ("compared last %s to %s ? YES\n", (char *)groups2->data[i], s0);
            found = 1;
        }
    }
    if (found == 0)
    {
        return 0;
    }

    //printf ("cnt=%d\n", cnt);
    if (cnt + 1 == SeqLength(groups2))
    {
        return 1;
    }
    else
    {
        //printf ("group list 1 is subset of group list 2\n");
        return 0;
    }
}

/**
 * Frontend to getgrent_r. Reallocates its arguments if needed.
 * @param group_info Returned struct.
 * @param group_buf Returned buffer.
 * @param buf_size Returned size of buffer.
 * @return True if successful, false if not, or if the list has reached the end.
 */
bool GetGroupEntry(struct group **group_info, char **group_buf, size_t *buf_size)
{
    int status;
    struct group *group_info_ptr = *group_info;
    // Group lists can get quite large, so use a dynamic buffer.
    while (true)
    {
        status = getgrent_r(*group_info, *group_buf, *buf_size, &group_info_ptr);
        if (status == ERANGE)
        {
            // Too small buffer.
            *buf_size *= 2;
            // Cap at 50 MB, something has to be wrong if we go over that.
            if (buf_size > 50000000)
            {
                Log(LOG_LEVEL_ERR, "Could not get group information: %s\n", GetErrorStrFromCode(ENOMEM));
                return false;
            }
            *group_buf = xrealloc(group_buf_ret, buf_size);
            continue;
        }
        else if (status == ENOENT)
        {
            return false;
        }
        else
        {
            Log(LOG_LEVEL_ERR, "Could not get group information. (getgrgid_r: '%s')\n", GetErrorStrFromCode(status));
            return false;
        }

        return true;
    }
}

void GroupGetUserMembership (const char *user, Seq *result)
{
    struct group *group_info;

    SeqClear(result);
    setgrent();
    do
    {
        
        for (int i = 0; group_info->gr_mem[i] != NULL; i++)
        {
            if (strcmp(user, group_info->gr_mem[i]) == 0)
            {
                SeqAdd(result, group_info->gr_name);
            }
        }
    }
    endgrent();
}


#if 0
void test_group_membership()
{
    Seq *result = SeqNew(100, free);
    int num = GroupGetUserMembership ("vagrant", result);
    int i;

    for (i = 0; i < num; i++)
    {
        //printf ("res(%d)=%s\n", i, (char *)result->data[i]);
    }
    if(SeqLength(result)==4) {printf("yes\n");} else {printf("no\n");} 
    SeqDestroy(result);
}

void test_group_compare()
{
    Seq *result = SeqNew(100, free);
    GroupGetUserMembership ("vagrant", result);
    int res;
    res = AreListsOfGroupsEqual ("video,cdrom,sudo,audio", result);
    if(res==1) {printf("yes\n");} else {printf("no\n");}
    res = AreListsOfGroupsEqual ("video,sudo,audio", result);
    if(res==0) {printf("yes\n");} else {printf("no\n");}
    res = AreListsOfGroupsEqual ("video,kudo,sudo,audio,walo", result);
    if(res==0) {printf("yes\n");} else {printf("no\n");}
    SeqDestroy(result);
}

int main ()
{

    test_group_convert();
    test_group_membership();
    test_group_compare();
    return 0;

    char *user = "nhari";
    //char *user = "vagrant";
    Seq *result = SeqNew(100, free);
    printf("Hola\n");
    int num = GroupGetUserMembership (user, result);
    printf("Hola\n");
    int i;
    printf ("N = %d\n", num);

    for (i = 0; i < num; i++)
    {
        printf ("res(%d)=%s\n", i, (char *)result->data[i]);
    }

    int res;
    SeqClear(result);
    res = AreListsOfGroupsEqual ("g1,g2,sudo,vagrant", result);
    printf ("found=%d\n", res);
    //res = AreListsOfGroupsEqual ("audio,sudo,vagrant,v1", result);
    SeqClear(result);
    res = AreListsOfGroupsEqual ("audio,sudo", result);
    printf ("found=%d\n", res);

    char gbuf[100];
    res = GroupConvert ("nogroup", gbuf);
    printf ("converted nogroup to %s\n", gbuf);
    res = GroupConvert ("1003", gbuf);
    printf ("converted 1003 to %s\n", gbuf);


    return 0;
}
#endif

