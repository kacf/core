#include <stdio.h>
#include <string.h>

#include <pwcrypt.h>
#include <grp.h>

//#define STANDALONE 1

#define CFUSR_CHECKBIT(v,p) ((v) & (1UL << (p)))
#define CFUSR_SETBIT(v,p)   ((v)   |= ((1UL) << (p)))
#define CFUSR_CLEARBIT(v,p) ((v) &= ((1UL) << (p)))

#if STANDALONE
typedef enum {
    false,
    true
} bool;

typedef enum
{
    USER_STATE_PRESENT,
    USER_STATE_ABSENT,
    USER_STATE_LOCKED,
    USER_STATE_NONE
} UserState;

typedef struct {
    UserState state;
    char *uid;
    char *user;
    char *password;
    char *comment;
    bool create_home;
    char *group;
    char *groups2;
    char *home;
    char *shell;
    bool remove;
} User;
#endif

typedef enum {
    i_uid,
    i_user,
    i_password,
    i_comment,
    i_group,
    i_groups,
    i_home,
    i_shell
} which;

#define CFUSR_CMDADD "/usr/sbin/useradd"
#define CFUSR_CMDDEL "/usr/sbin/userdel"
#define CFUSR_CMDMOD "/usr/sbin/usermod"
#define CFUSR_PWFILE "/etc/shadow"

#define CFUSR_KEPT      0
#define CFUSR_REPAIRED  1
#define CFUSR_NOTKEPT   2

bool VerifyIfUserExists(char *user)
{
    char entries[7][1024] = {0};
    char line[2048];
    char *s = NULL;
    FILE *fp;
    fp = fopen("/etc/passwd", "r");
    if (fp == NULL)
    {
        printf("cannot open file /etc/passwd\n");
        return false;
    }
    while (fgets(line, 2048, fp) != NULL)
    {
        if (strncmp(line, user, strlen(user))==0
            && line[strlen(user)] == ':')
        {
           fclose(fp);
           return true; 
        }
    }
    fclose(fp);
    return false;
}

bool ReadSimpleFile(char *fname, const char *user,
                    char (*entries)[1024])
{
    char line[2048];
    char *s = NULL;
    FILE *fp;
    fp = fopen(fname, "r");
    if (fp == NULL)
    {
        printf("cannot open file %s\n", fname);
        goto clean;
    }
    while (fgets(line, 2048, fp) != NULL)
    {
        char *s2 = NULL;
        int j;
        if (strncmp(line, user, strlen(user))==0
            && line[strlen(user)] == ':')
        {
printf("LINE=%s for user %s\n", line, user);
            s = line;
            j = 0;
            while ((s2 = strchr(s, ':')) != NULL)
            {
               strncpy(entries[j], s, s2 -s);
               entries[j][s2-s] = '\0';
               //printf("S=[%s]\n", entries[j]);
               s = s2 + 1;
               j++;
            }
        }
        if (s != NULL)
        {
            s2 = strchr(s, '\n');
            if (s2!=NULL) {
               s[s2-s]='\0';
               strcpy(entries[j], s);
               //printf("S=[%s]\n", s);
            }
        }
    }
    fclose(fp);
    return true;
clean:
    return false;
}

bool ReadComplicatedFile(char *fname, const char *user,
                    char (*entries)[1024], int key_idx )
{
    char line[2048];
    char *s = NULL;
    FILE *fp;
    fp = fopen(fname, "r");
    if (fp == NULL)
    {
        printf("cannot open file %s\n", fname);
        goto clean;
    }
    while (fgets(line, 2048, fp) != NULL)
    {
        char *s2 = NULL;
        int j;
        s = line;
        //////////////
        char tmp[1024] = "";
        j = key_idx + 1;
        //printf("L\n");
        while ((s2 = strchr(s, ':')) != NULL && j!=0)
        {
           strncpy(tmp, s, s2 -s);
           tmp[s2-s] = '\0';
           //printf("S%d=[%s]\n", j, tmp);
           s = s2 + 1;
           j--;
        }
        //if(s)   printf("S(j=%d)=[%s]\n", j, tmp);
        //////////////
        if(j==0 && (strcmp(tmp, user) == 0))
        {
            //printf("Found[%s]\n", line);
            s = line;
            j = 0;
            while ((s2 = strchr(s, ':')) != NULL)
            {
               strncpy(entries[j], s, s2 -s);
               entries[j][s2-s] = '\0';
               //printf("S%d=[%s]\n", j, entries[j]);
               s = s2 + 1;
               j++;
            }
            if (s != NULL)
            {
                s2 = strchr(s, '\n');
                if (s2!=NULL) {
                   s[s2-s]='\0';
                   strcpy(entries[j], s);
                   //printf("S=[%s]\n", s);
                }
            }

        }
    }
    fclose(fp);
    return true;
clean:
    return false;
}

bool FetchUserBasicInfo(const char *user, char (*entries)[1024] )
{
    return ReadSimpleFile("/etc/passwd", user, entries);
}

bool FetchUserPasswdInfo(const char *user, char (*entries)[1024] )
{
    //1. md5 5. sha256 6. sha512
    return ReadSimpleFile("/etc/shadow", user, entries);
}

bool FetchUserGroupInfo(const char *group, char (*entries)[1024] )
{
    return ReadComplicatedFile("/etc/group", group, entries, 2 /*3rd*/);
}

#if 0
int main()
{
    char *user = "vboxadd";
    char entries[7][1024] = {0};

    FetchUserBasicInfo(user, entries);
    printf("%s\n%s\n", entries[0], entries[6]);

    return 0;
}
#endif

int VerifyIfUserNeedsModifs(char *puser, User u, char (*binfo)[1024], 
                             char (*pinfo)[1024], char (*ginfo)[1024],
                             unsigned long int *changemap)
{
    bool res;
    res = FetchUserBasicInfo (puser, binfo);
    res = FetchUserPasswdInfo(puser, pinfo);
    printf("binfo[3rd]='%s'\n", binfo[3]);
    printf("pinfo[1st]='%s'\n", pinfo[1]);
    res = FetchUserGroupInfo (binfo[3]/*4th*/, ginfo);
    printf("ginfo[1st]='%s'\n", ginfo[0]);

    if (res == true)
    {
       //name;pass;id;grp;comment;home;shell
       if(u.comment != NULL && strcmp(u.comment, binfo[4]))
       {
           CFUSR_SETBIT(*changemap, i_comment);
           printf("bit %d changed\n", i_comment);
       }
       if(u.uid != NULL && (atoi(u.uid) != atoi(binfo[2])) )
       {
           CFUSR_SETBIT(*changemap, i_uid);
           printf("bit %d changed\n", i_uid);
       }
       if(u.home != NULL && strcmp(u.home, binfo[5]))
       {
           CFUSR_SETBIT(*changemap, i_home);
           printf("bit %d changed\n", i_home);
       }
       if(u.shell != NULL && strcmp(u.shell, binfo[6]))
       {
           CFUSR_SETBIT(*changemap, i_shell);
           printf("bit %d changed\n", i_shell);
       }
       if(u.password != NULL && strcmp(u.password, ""))
       {
           if(u.password[0] != '$') {
               char encrypted[1024];
               //TODO: fetch "salt" from pinfo[2nd field]
               char salt[20];
               getrndsalt((PwHashMethod)(pinfo[1][1] - '0'),salt);
               cf_crypt(u.password, salt, &encrypted);
               if(strcmp(encrypted, pinfo[1]))
               {
                   CFUSR_SETBIT(*changemap, i_password);
                   printf("bit %d changed\n", i_password);
               }
           } else {
               if(strcmp(u.password, pinfo[1]))
               {
                   CFUSR_SETBIT(*changemap, i_password);
                   printf("bit %d changed\n", i_password);
               }
           }
       }
       //TODO #2: parse groups and compare with /etc/groups
       char gbuf[100];
       int res;
       res = GroupConvert(binfo[6], gbuf);

       if(u.group != NULL && 
          (strcmp(u.group, binfo[6]) && strcmp(u.group, gbuf) ))
       {
           CFUSR_SETBIT(*changemap, i_group);
           printf("bit %d changed\n", i_group);
       }
       char glist[100][1024] = {0};
       int num = GroupGetUserMembership(puser, glist);
       printf("The big %s versus %d[%s,%s] other groups\n", u.groups2, num, glist[0], glist[1]);

       /*TODO: fix differs fct*/
       if(u.groups2 != NULL && AreListsOfGroupsEqual(u.groups2, glist, num) == 0)
       {
           CFUSR_SETBIT(*changemap, i_groups);
           printf("bit %d changed\n", i_groups);
       }
       ////////////////////////////////////////////
    }
    if(*changemap == 0L)
      return 0;
    else
      return 1;
}

int DoCreateUser(char *puser, User u)
{
    char cmd[4096];
    if (puser == NULL || !strcmp(puser, ""))
    {
        return -1;
    }
    strcpy(cmd, CFUSR_CMDADD);

    if (u.uid != NULL && strcmp(u.uid, ""))
    {
        sprintf(cmd, "%s -u %d", cmd, atoi(u.uid));
    }

    if (u.password != NULL && strcmp(u.password, ""))
    {
        ////////////////////////////////////////////
        //TODO: generate random salt              //
        //TODO: might have an algorithm input     //
        ////////////////////////////////////////////
        if(u.password[0] != '$') {
            char encrypted[1024];
            char salt[20];
            getrndsalt(sha512, salt);
            cf_crypt(u.password, salt, &encrypted);
            sprintf(cmd, "%s -p '%s'", cmd, encrypted);
        } else {
            sprintf(cmd, "%s -p '%s'", cmd, u.password);
        }
    }

    if (u.comment != NULL && strcmp(u.comment, ""))
    {
        sprintf(cmd, "%s -c \"%s\"", cmd, u.comment);
    }

    if (u.create_home == true)
    {
        sprintf(cmd, "%s -m", cmd);
    }
    if (u.group != NULL && strcmp(u.group, ""))
    {
        //TODO: check that group exists
        sprintf(cmd, "%s -g \"%s\"", cmd, u.group);
    }
    if (u.groups2 != NULL && strcmp(u.groups2, ""))
    {
        //TODO: check that groups exists
        sprintf(cmd, "%s -G \"%s\"", cmd, u.groups2);
    }
    if (u.home != NULL && strcmp(u.home, ""))
    {
        sprintf(cmd, "%s -d \"%s\"", cmd, u.home);
    }
    if (u.shell != NULL && strcmp(u.shell, ""))
    {
        sprintf(cmd, "%s -s \"%s\"", cmd, u.shell);
    }
    bool remove;
    if (strcmp(puser, ""))
    {
        sprintf(cmd, "%s %s", cmd, puser);
    }

    printf("cmd=[%s]\n", cmd);
    return 0;
}

int DoRemoveUser(char *puser, User u)
{
    char cmd[4096];

    strcpy(cmd, CFUSR_CMDDEL);

    if (u.remove == true)
    {
        //TODO: needs force to delete home for sure
        sprintf(cmd, "%s -r", cmd);
    }
    if (strcmp(puser, ""))
    {
        sprintf(cmd, "%s %s", cmd, puser);
    }

    return 0;
}

int DoModifyUser(char *puser, User u, unsigned long changemap)
{
    char cmd[4096];

    strcpy(cmd, CFUSR_CMDMOD);

    if(CFUSR_CHECKBIT(changemap, i_uid) != 0)
    {
        //3rd
        sprintf(cmd, "%s -u %d", cmd, atoi(u.uid));
    }

    if(CFUSR_CHECKBIT(changemap, i_password) != 0)
    {
        if(u.password[0] != '$') {
            //Generate with a different salt
            char encrypted[1024];
            char salt[20];
            getrndsalt(sha512, salt);
            cf_crypt(u.password, salt, &encrypted);
            sprintf(cmd, "%s -p '%s'", cmd, encrypted);
        } else {
            sprintf(cmd, "%s -p '%s'", cmd, u.password);
        }
    }

    if(CFUSR_CHECKBIT(changemap, i_comment) != 0)
    if (strcmp(u.comment, ""))
    {
        //5th
        sprintf(cmd, "%s -c \"%s\"", cmd, u.comment);
    }

    if(CFUSR_CHECKBIT(changemap, i_group) != 0)
    {
        //4th
        sprintf(cmd, "%s -g \"%s\"", cmd, u.group);
    }

    if(CFUSR_CHECKBIT(changemap, i_groups) != 0)
    {
        //TODO: check that groups (id forms and name forms) differ (4th in /etc/group)
        sprintf(cmd, "%s -G \"%s\"", cmd, u.groups2);
    }

    if(CFUSR_CHECKBIT(changemap, i_home) != 0)
    {
        sprintf(cmd, "%s -d \"%s\"", cmd, u.home);
//sant lagues modifirest
//utjevningmandat
    }

    if(CFUSR_CHECKBIT(changemap, i_shell) != 0)
    {
        //7th
        sprintf(cmd, "%s -s \"%s\"", cmd, u.shell);
    }

#if 0
    if(CFUSR_CHECKBIT(changemap, i_user) != 0)
    {
        //1st (should be given)
        sprintf(cmd, "%s %s", cmd, u.user);
    }
#endif

    sprintf(cmd, "%s %s", cmd, puser);

    printf("cmd=[%s]\n", cmd);
    return 0;
}

void VerifyOneUsersPromise(char *puser, User u, int *result)
{
    int res;

    char binfo[7][1024] = {0};
    char pinfo[7][1024] = {0};
    char ginfo[7][1024] = {0};

    if (u.state == USER_STATE_PRESENT)
    {
        if (VerifyIfUserExists(puser) == true)
        {
            unsigned long int cmap = 0;
            if (VerifyIfUserNeedsModifs(puser, u, binfo, pinfo, ginfo, &cmap) == 1)
            {
                printf("should act on cmap=%u\n", cmap);
                res = DoModifyUser(puser, u, cmap);
                if (!res)
                {
                    result = CFUSR_REPAIRED;
                }
                else
                {
                    result = CFUSR_NOTKEPT;
                }
            }
            else
            {
                result = CFUSR_KEPT;
            }
        }
        else
        {
            res = DoCreateUser(puser, u);
            if (!res)
            {
                result = CFUSR_REPAIRED;
            }
            else
            {
                result = CFUSR_NOTKEPT;
            }
        }
    }
    else if (u.state == USER_STATE_ABSENT)
    {
        if (VerifyIfUserExists(puser) == true)
        {
            res = DoRemoveUser(puser, u);
            if (!res)
            {
                result = CFUSR_REPAIRED;
            }
            else
            {
                result = CFUSR_NOTKEPT;
            }
        }
        else
        {
            result = CFUSR_KEPT;
        }
    }
}

#if STANDALONE
int test01()
{
    User u0 = {0};
    u0.state = USER_STATE_PRESENT;
    u0.password = strdup("v344t");
    u0.group = strdup("xorg13");
    u0.groups2 = strdup("xorg11,xorg10");

    User u1 = {0};
    u1.state = USER_STATE_PRESENT;
    u1.group = strdup("xorg12");
    u1.groups2 = strdup("xorg11,xorg13");

    User u2 = {0};
    u2.state = USER_STATE_PRESENT;
    u2.password = strdup("$6$gDNrZkGDnUFMV9g$Ud94uWbcMXVfusUR9VMB07eUu53BuMgkboT9nwugpelcEY9PH57Oh.4Zl0bGnjeR.YYB9lQTAuUFBBdfJIhim/");

    User u3 = {0};
    u3.state = USER_STATE_PRESENT;
    u3.password = strdup("v344t");

    int result;
    //VerifyOneUsersPromise("xusr13", u0, &result);
    //VerifyOneUsersPromise("xusr13", u1, &result);
    VerifyOneUsersPromise("xusr13", u3, &result);

}

int main()
{
    test01();
    exit(0);
    User u = {0};
    u.state = USER_STATE_PRESENT;
    u.uid = NULL;
    u.create_home = true;
    //u.user = strdup("nhari");
    //u.user = strdup("vagrant");
    u.password = strdup("v344t");
    u.comment = strdup("Pierre Nhari");
    u.group = strdup("myg");
    u.groups2 = strdup("myg1,myg2,myg3");
    u.home = strdup("/home/nhyet");
    u.shell = strdup("/bin/sh");
    u.remove = false;

    int result;
    VerifyOneUsersPromise("vagrant", u, &result);
    //DoCreateUser(u);
    return 0;
}
#endif
