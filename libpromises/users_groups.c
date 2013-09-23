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

/************************/
/* get group membership */
/************************/
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
                printf ("compared %s to %s ? YES\n", (char *)groups2->data[i], s0);
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
            printf ("compared last %s to %s ? YES\n", (char *)groups2->data[i], s0);
            found = 1;
        }
    }
    if (found == 0)
    {
        return 0;
    }

    printf ("cnt=%d\n", cnt);
    if (cnt + 1 == SeqLength(groups2))
    {
        return 1;
    }
    else
    {
        printf ("group list 1 is subset of group list 2\n");
        return 0;
    }
}

int GroupGetUserMembership (char *user, Seq *result)
{
    int num = 0;
    FILE *fp = fopen ("/etc/group", "r");
    if (fp == NULL)
    {
        printf ("cannot open /etc/group file\n");
        return -1;
    }
    char line[1024];
    while (fgets (line, 1024, fp) != NULL)
    {
        if (strstr (line, user) != NULL)
        {
            size_t len = -1;
            len = strcspn (line, "\r\n");
            if (len > 0)
            {
                line[len] = '\0';
            }
            printf ("matched %s\n", 1 + strrchr (line, ':'));
            char *s0 = 1 + strrchr (line, ':');
            char *s = NULL;
            char obuf[1024];
            while ((s = strchr (s0, ',')) != NULL)
            {
                printf ("\tS0=%s[%u]\n", s0, s - s0);
                if (!strncmp (s0, user, s - s0))
                {
                    //strncpy(obuf, s0, s - s0);
                    //obuf[s - s0] = '\0';
                    sscanf (line, "%[^:]:", obuf);
                    SeqAppend(result, strdup(obuf));
                    num++;
                    printf ("\t\tcool1\n");
                }
                s0 = s + 1;
            }
            printf ("\tS0=%s[%u]\n", s0, strlen (s0));
            if (!strcmp (s0, user))
            {
                //strcpy(obuf, s0);
                sscanf (line, "%[^:]:", obuf);
                SeqAppend(result, strdup(obuf));
                num++;
                printf ("\t\tcool2\n");
            }
        }
    }
    fclose (fp);
    return num;
}

#if 0
int main ()
{
    char *user = "nhari";
    //char *user = "vagrant";
    Seq *result = SeqNew(100, free);

    int num = GroupGetUserMembership (user, result);

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

