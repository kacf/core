#include <cf3.defs.h>
#include <bufferlist.h>

#include <stdio.h>
#include <string.h>

#include <security/pam_appl.h>

#include <pwcrypt.h>
#include <sys/types.h>
#include <grp.h>

// TODO REMOVE
#define HAVE_SHADOW_H
#define HAVE_GETSPNAM

#ifdef HAVE_SHADOW_H
# include <shadow.h>
#endif

//#define STANDALONE 1

#define CFUSR_CHECKBIT(v,p) ((v) & (1UL << (p)))
#define CFUSR_SETBIT(v,p)   ((v)   |= ((1UL) << (p)))
#define CFUSR_CLEARBIT(v,p) ((v) &= ((1UL) << (p)))

typedef enum
{
    i_uid,
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

static int PasswordSupplier(int num_msg, const struct pam_message **msg,
           struct pam_response **resp, void *appdata_ptr)
{
    // All allocations here will be freed by the pam framework.
    *resp = xmalloc(num_msg * sizeof(struct pam_response));
    for (int i = 0; i < num_msg; i++)
    {
        if ((*msg)[i].msg_style == PAM_PROMPT_ECHO_OFF)
        {
            (*resp)[i].resp = xstrdup((const char *)appdata_ptr);
        }
        else
        {
            (*resp)[i].resp = xstrdup("");
        }
        (*resp)[i].resp_retcode = 0;
    }

    return PAM_SUCCESS;
}

static bool IsPasswordCorrect(const char *puser, const char* password, PasswordFormat format, const struct passwd *passwd_info)
{
    /*
     * Check if password is already correct. If format is 'hash' we just do a simple
     * comparison with the supplied hash value, otherwise we try a pam login using
     * the real password.
     */

    if (format == PASSWORD_FORMAT_HASH)
    {
#ifdef HAVE_GETSPNAM
        // If the hash is very short, it's probably a stub. Try getting the shadow password instead.
        if (strlen(passwd_info->pw_passwd) <= 4)
        {
            struct spwd *spwd_info;
            errno = 0;
            spwd_info = getspnam(puser);
            if (!spwd_info)
            {
                if (errno)
                {
                    Log(LOG_LEVEL_ERR, "Could not get information from user shadow database. (getspnam: '%s')", GetErrorStr());
                    return false;
                }
                else
                {
                    Log(LOG_LEVEL_ERR, "Could not find user when checking password.");
                    return false;
                }
            }
            else if (spwd_info)
            {
                return (strcmp(password, spwd_info->sp_pwdp) == 0);
            }
        }
#endif // HAVE_GETSPNAM
        return (strcmp(password, passwd_info->pw_passwd) == 0);
    }
    else if (format != PASSWORD_FORMAT_PLAINTEXT)
    {
        ProgrammingError("Unknown PasswordFormat value");
    }

    int status;
    pam_handle_t *handle;
    struct pam_conv conv;
    conv.conv = PasswordSupplier;
    conv.appdata_ptr = (void*)password;

    status = pam_start("login", puser, &conv, &handle);
    if (status != PAM_SUCCESS)
    {
        Log(LOG_LEVEL_ERR, "Could not initialize pam session. (pam_start: '%s')", pam_strerror(NULL, status));
        return false;
    }
    status = pam_authenticate(handle, PAM_SILENT);
    pam_end(handle, status);
    if (status == PAM_SUCCESS)
    {
        return true;
    }
    else if (status != PAM_AUTH_ERR)
    {
        Log(LOG_LEVEL_ERR, "Could not check password for user '%s' against stored password. (pam_authenticate: '%s')",
            puser, pam_strerror(handle, status));
        return false;
    }

    return false;
}

static int ChangePassword(const char *puser, const char *password, PasswordFormat format)
{
    int status;
    const char *cmd_str;
    if (format == PASSWORD_FORMAT_PLAINTEXT)
    {
        cmd_str = "chpasswd";
    }
    else if (format == PASSWORD_FORMAT_HASH)
    {
        cmd_str = "chpasswd -e";
    }
    else
    {
        ProgrammingError("Unknown PasswordFormat value");
    }
    FILE *cmd = cf_popen_sh(cmd_str, "w");
    if (!cmd)
    {
        Log(LOG_LEVEL_ERR, "Could not launch password changing command '%s': %s.", cmd_str, GetErrorStr());
        return PROMISE_RESULT_FAIL;
    }

    // String lengths plus a ':' and a '\n', but not including '\0'.
    size_t total_len = strlen(puser) + strlen(password) + 2;
    char change_string[total_len + 1];
    snprintf(change_string, total_len + 1, "%s:%s\n", puser, password);
    clearerr(cmd);
    if (fwrite(change_string, total_len, 1, cmd) != 1)
    {
        const char *error_str;
        if (ferror(cmd))
        {
            error_str = GetErrorStr();
        }
        else
        {
            error_str = "Unknown error";
        }
        Log(LOG_LEVEL_ERR, "Could not write password to password changing command '%s': %s.", cmd_str, error_str);
        cf_pclose(cmd);
        return PROMISE_RESULT_FAIL;
    }
    status = cf_pclose(cmd);
    if (status)
    {
        Log(LOG_LEVEL_ERR, "'%s' returned non-zero status: %i\n", cmd_str, status);
        return PROMISE_RESULT_FAIL;
    }

    return PROMISE_RESULT_CHANGE;
}

#if 0
int main ()
{
    char *user = "vboxadd";
    char entries[7][1024] = { 0 };

    FetchUserBasicInfo (user, entries);
    printf ("%s\n%s\n", entries[0], entries[6]);

    return 0;
}
#endif

bool AreListsOfGroupsEqual (const BufferList *groups1, const BufferList *groups2)
{
    if (BufferListCount(groups1) != BufferListCount(groups2))
    {
        return false;
    }

    // Dumb comparison. O(n^2), but number of groups is never that large anyway.
    bool found = true;
    BufferListIterator *i1;
    printf("In %s at %i with counts %i and %i\n", __FUNCTION__, __LINE__, BufferListCount(groups1), BufferListCount(groups2));
    for (i1 = BufferListIteratorGet(groups1); i1; i1 = (BufferListIteratorNext(i1) == 0) ? i1 : 0)
    {
        found = false;
        BufferListIterator *i2;
        printf("In %s at %i\n", __FUNCTION__, __LINE__);
        for (i2 = BufferListIteratorGet(groups2); i2; i2 = (BufferListIteratorNext(i2) == 0) ? i2 : 0)
        {
            printf("In %s at %i, comapring \"%s\" and \"%s\"\n", __FUNCTION__, __LINE__, BufferData(BufferListIteratorData(i1)), BufferData(BufferListIteratorData(i2)));
            if (strcmp(BufferData(BufferListIteratorData(i1)), BufferData(BufferListIteratorData(i2))) == 0)
            {
                found = true;
                break;
            }
        }
        BufferListIteratorDestroy(&i2);
        if (!found)
        {
            break;
        }
    }
    BufferListIteratorDestroy(&i1);
    return found;
}

bool GroupGetUserMembership (const char *user, BufferList *result)
{
    bool ret = true;
    struct group *group_info;

    setgrent();
    while (true)
    {
        errno = 0;
        group_info = getgrent();
        if (!group_info)
        {
            if (errno)
            {
                Log(LOG_LEVEL_ERR, "Error while getting group list. (getgrent: '%s')", GetErrorStr());
                ret = false;
            }
            break;
        }
        printf("In %s at %i, adding group name %s\n", __FUNCTION__, __LINE__, group_info->gr_name);
        for (int i = 0; group_info->gr_mem[i] != NULL; i++)
        {
            if (strcmp(user, group_info->gr_mem[i]) == 0)
            {
                printf("In %s at %i, adding group name %s\n", __FUNCTION__, __LINE__, group_info->gr_name);
                BufferListAppend(result, BufferNewFrom(group_info->gr_name, strlen(group_info->gr_name) + 1));
                break;
            }
        }
    }
    endgrent();

    return ret;
}

static void TransformGidsToGroups(BufferList *list)
{
    BufferListIterator *i;
    for (i = BufferListIteratorGet(list); i; i = (BufferListIteratorNext(i) == 0) ? i : 0)
    {
        const char *data = BufferData(BufferListIteratorData(i));
        if (strlen(data) != strspn(data, "0123456789"))
        {
            // Cannot possibly be a gid.
            continue;
        }
        // In groups vs gids, groups take precedence. So check if it exists.
        errno = 0;
        struct group *group_info = getgrnam(data);
        if (!group_info)
        {
            switch (errno)
            {
            case 0:
            case ENOENT:
            case EBADF:
            case ESRCH:
            case EWOULDBLOCK:
            case EPERM:
                // POSIX is apparently ambiguous here. All values mean "not found".
                errno = 0;
                group_info = getgrgid(atoi(data));
                if (!group_info)
                {
                    switch (errno)
                    {
                    case 0:
                    case ENOENT:
                    case EBADF:
                    case ESRCH:
                    case EWOULDBLOCK:
                    case EPERM:
                        // POSIX is apparently ambiguous here. All values mean "not found".
                        //
                        // Neither group nor gid is found. This will lead to an error later, but we don't
                        // handle that here.
                        break;
                    default:
                        Log(LOG_LEVEL_ERR, "Error while checking group name '%s'. (getgrgid: '%s')", data, GetErrorStr());
                        return;
                    }
                }
                else
                {
                    // Replace gid with group name.
                    BufferSet(BufferListIteratorData(i), group_info->gr_name, strlen(group_info->gr_name) + 1);
                }
                break;
            default:
                Log(LOG_LEVEL_ERR, "Error while checking group name '%s'. (getgrnam: '%s')", data, GetErrorStr());
                return;
            }
        }
    }
    BufferListIteratorDestroy(&i);
}

int VerifyIfUserNeedsModifs (char *puser, User u, const struct passwd *passwd_info,
                             uint32_t *changemap)
{
    //name;pass;id;grp;comment;home;shell
    if (u.description != NULL && strcmp (u.description, passwd_info->pw_gecos))
    {
        CFUSR_SETBIT (*changemap, i_comment);
    }
    if (u.uid != NULL && (atoi (u.uid) != passwd_info->pw_uid))
    {
        CFUSR_SETBIT (*changemap, i_uid);
    }
    if (u.home_dir != NULL && strcmp (u.home_dir, passwd_info->pw_dir))
    {
        CFUSR_SETBIT (*changemap, i_home);
    }
    if (u.shell != NULL && strcmp (u.shell, passwd_info->pw_shell))
    {
        CFUSR_SETBIT (*changemap, i_shell);
    }
    if (u.password != NULL && strcmp (u.password, ""))
    {
        if (!IsPasswordCorrect(puser, u.password, u.password_format, passwd_info))
        {
            CFUSR_SETBIT (*changemap, i_password);
        }
    }

    if (u.group_primary != NULL)
    {
        bool group_is_gid = (strlen(u.group_primary) == strspn(u.group_primary, "0123456789"));
        int gid;

        if (group_is_gid)
        {
            gid = atoi(u.group_primary);
        }
        else
        {
            struct group *group_info;
            errno = 0;
            group_info = getgrnam(u.group_primary);
            if (!group_info && errno != 0 && errno != ENOENT)
            {
                Log(LOG_LEVEL_ERR, "Could not obtain information about group '%s'. (getgrnam: '%s')", u.group_primary, GetErrorStr());
                gid = -1;
            }
            else if (!group_info)
            {
                Log(LOG_LEVEL_ERR, "No such group '%s'.", u.group_primary);
                gid = -1;
            }
            else
            {
                gid = group_info->gr_gid;
            }
        }

        if (gid != passwd_info->pw_gid)
        {
            CFUSR_SETBIT (*changemap, i_group);
        }
    }
    if (u.groups_secondary != NULL)
    {
        BufferList *wanted_groups = BufferListNew();
        for (Rlist *ptr = u.groups_secondary; ptr; ptr = ptr->next)
        {
            BufferListAppend(wanted_groups, BufferNewFrom(RvalScalarValue(ptr->val), strlen(RvalScalarValue(ptr->val)) + 1));
        }
        TransformGidsToGroups(wanted_groups);
        BufferList *current_groups = BufferListNew();
        if (!GroupGetUserMembership (puser, current_groups))
        {
            CFUSR_SETBIT (*changemap, i_groups);
        }
        else if (!AreListsOfGroupsEqual (current_groups, wanted_groups))
        {
            CFUSR_SETBIT (*changemap, i_groups);
        }
        BufferListDestroy(&current_groups);
        BufferListDestroy(&wanted_groups);
    }

    ////////////////////////////////////////////
    if (*changemap == 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

int DoCreateUser (char *puser, User u, enum cfopaction action)
{
    char cmd[CF_BUFSIZE];
    if (puser == NULL || !strcmp (puser, ""))
    {
        return -1;
    }
    strcpy (cmd, CFUSR_CMDADD);

    if (u.uid != NULL && strcmp (u.uid, ""))
    {
        StringAppend(cmd, " -u \"", sizeof(cmd));
        StringAppend(cmd, u.uid, sizeof(cmd));
        StringAppend(cmd, "\"", sizeof(cmd));
    }

    if (u.description != NULL && strcmp (u.description, ""))
    {
        StringAppend(cmd, " -c \"", sizeof(cmd));
        StringAppend(cmd, u.description, sizeof(cmd));
        StringAppend(cmd, "\"", sizeof(cmd));
    }

    if (u.create_home == true)
    {
        StringAppend(cmd, " -m", sizeof(cmd));
    }
    if (u.group_primary != NULL && strcmp (u.group_primary, ""))
    {
        // TODO: Should check that group exists
        StringAppend(cmd, " -g \"", sizeof(cmd));
        StringAppend(cmd, u.group_primary, sizeof(cmd));
        StringAppend(cmd, "\"", sizeof(cmd));
    }
    if (u.groups_secondary != NULL)
    {
        // TODO: Should check that groups exist
        StringAppend(cmd, " -G \"", sizeof(cmd));
        char sep[2] = { '\0', '\0' };
        for (Rlist *i = u.groups_secondary; i; i = i->next)
        {
            StringAppend(cmd, sep, sizeof(cmd));
            StringAppend(cmd, RvalScalarValue(i->val), sizeof(cmd));
            sep[0] = ',';
        }
        StringAppend(cmd, "\"", sizeof(cmd));
    }
    if (u.home_dir != NULL && strcmp (u.home_dir, ""))
    {
        StringAppend(cmd, " -d \"", sizeof(cmd));
        StringAppend(cmd, u.home_dir, sizeof(cmd));
        StringAppend(cmd, "\"", sizeof(cmd));
    }
    if (u.shell != NULL && strcmp (u.shell, ""))
    {
        StringAppend(cmd, " -s \"", sizeof(cmd));
        StringAppend(cmd, u.shell, sizeof(cmd));
        StringAppend(cmd, "\"", sizeof(cmd));
    }
    StringAppend(cmd, " ", sizeof(cmd));
    StringAppend(cmd, puser, sizeof(cmd));
    printf("In %s at %i, cmd = \"%s\"\n", __FUNCTION__, __LINE__, cmd);

    if (action == cfa_warn || DONTDO)
    {
        Log(LOG_LEVEL_NOTICE, "Need to create user '%s'.", puser);
    }
    else
    {
        if (strlen(cmd) >= sizeof(cmd) - 1)
        {
            // Instead of checking every string call above, assume that a maxed out
            // string length overflowed the string.
            Log(LOG_LEVEL_ERR, "Command line too long while creating user '%s'", puser);
            return 1;
        }

        int status;
        status = system(cmd);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        {
            Log(LOG_LEVEL_ERR, "Command returned error while creating user '%s'. (Command line: '%s')", puser, cmd);
            return 1;
        }

        if (u.password != NULL && strcmp (u.password, ""))
        {
            ChangePassword(puser, u.password, u.password_format);
        }
    }

    return 0;
}

int DoRemoveUser (char *puser, enum cfopaction action)
{
    char cmd[CF_BUFSIZE];

    strcpy (cmd, CFUSR_CMDDEL);

    StringAppend(cmd, " ", sizeof(cmd));
    StringAppend(cmd, puser, sizeof(cmd));

    if (action == cfa_warn || DONTDO)
    {
        Log(LOG_LEVEL_NOTICE, "Need to remove user '%s'.", puser);
    }
    else
    {
        if (strlen(cmd) >= sizeof(cmd) - 1)
        {
            // Instead of checking every string call above, assume that a maxed out
            // string length overflowed the string.
            Log(LOG_LEVEL_ERR, "Command line too long while removing user '%s'", puser);
            return 1;
        }

        int status;
        status = system(cmd);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        {
            Log(LOG_LEVEL_ERR, "Command returned error while removing user '%s'. (Command line: '%s')", puser, cmd);
            return 1;
        }
    }
    return 0;
}

int DoModifyUser (char *puser, User u, uint32_t changemap, enum cfopaction action)
{
    char cmd[CF_BUFSIZE];

    strcpy (cmd, CFUSR_CMDMOD);

    printf("In %s at %i\n", __FUNCTION__, __LINE__);
    if (CFUSR_CHECKBIT (changemap, i_uid) != 0)
    {
        StringAppend(cmd, " -u \"", sizeof(cmd));
        StringAppend(cmd, u.uid, sizeof(cmd));
        StringAppend(cmd, "\"", sizeof(cmd));
    }
    printf("In %s at %i\n", __FUNCTION__, __LINE__);

    if (CFUSR_CHECKBIT (changemap, i_password) != 0)
    {
        if (action == cfa_warn || DONTDO)
        {
            Log(LOG_LEVEL_NOTICE, "Need to change password for user '%s'.", puser);
        }
        else
        {
            ChangePassword(puser, u.password, u.password_format);
        }
    }
    printf("In %s at %i\n", __FUNCTION__, __LINE__);

    if (CFUSR_CHECKBIT (changemap, i_comment) != 0)
    {
        if (strcmp (u.description, ""))
        {
            StringAppend(cmd, " -c \"", sizeof(cmd));
            StringAppend(cmd, u.description, sizeof(cmd));
            StringAppend(cmd, "\"", sizeof(cmd));
        }
    }

    printf("In %s at %i\n", __FUNCTION__, __LINE__);
    if (CFUSR_CHECKBIT (changemap, i_group) != 0)
    {
        StringAppend(cmd, " -g \"", sizeof(cmd));
        StringAppend(cmd, u.group_primary, sizeof(cmd));
        StringAppend(cmd, "\"", sizeof(cmd));
    }

    printf("In %s at %i\n", __FUNCTION__, __LINE__);
    if (CFUSR_CHECKBIT (changemap, i_groups) != 0)
    {
        StringAppend(cmd, " -G \"", sizeof(cmd));
        char sep[2] = { '\0', '\0' };
        for (Rlist *i = u.groups_secondary; i; i = i->next)
        {
            StringAppend(cmd, sep, sizeof(cmd));
            StringAppend(cmd, RvalScalarValue(i->val), sizeof(cmd));
            sep[0] = ',';
        }
        StringAppend(cmd, "\"", sizeof(cmd));
    }

    printf("In %s at %i\n", __FUNCTION__, __LINE__);
    if (CFUSR_CHECKBIT (changemap, i_home) != 0)
    {
    printf("In %s at %i\n", __FUNCTION__, __LINE__);
        StringAppend(cmd, " -d \"", sizeof(cmd));
        StringAppend(cmd, u.home_dir, sizeof(cmd));
        StringAppend(cmd, "\"", sizeof(cmd));
    }

    printf("In %s at %i\n", __FUNCTION__, __LINE__);
    if (CFUSR_CHECKBIT (changemap, i_shell) != 0)
    {
    printf("In %s at %i\n", __FUNCTION__, __LINE__);
        StringAppend(cmd, " -s \"", sizeof(cmd));
        StringAppend(cmd, u.shell, sizeof(cmd));
        StringAppend(cmd, "\"", sizeof(cmd));
    }

    printf("In %s at %i\n", __FUNCTION__, __LINE__);
    StringAppend(cmd, " ", sizeof(cmd));
    StringAppend(cmd, puser, sizeof(cmd));
    printf("In %s at %i with cmd = \"%s\"\n", __FUNCTION__, __LINE__, cmd);

    if (action == cfa_warn || DONTDO)
    {
        Log(LOG_LEVEL_NOTICE, "Need to update user attributes (command '%s').", cmd);
    }
    else
    {
        if (strlen(cmd) >= sizeof(cmd) - 1)
        {
            // Instead of checking every string call above, assume that a maxed out
            // string length overflowed the string.
            Log(LOG_LEVEL_ERR, "Command line too long while modifying user '%s'", puser);
            return 1;
        }

        int status;
        status = system(cmd);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        {
            Log(LOG_LEVEL_ERR, "Command returned error while modifying user '%s'. (Command line: '%s')", puser, cmd);
            return 1;
        }
    }
    return 0;
}

void VerifyOneUsersPromise (char *puser, User u, PromiseResult *result, enum cfopaction action)
{
    int res;

    struct passwd *passwd_info;
    errno = 0;
    passwd_info = getpwnam(puser);
    if (errno)
    {
        Log(LOG_LEVEL_ERR, "Could not get information from user database. (getpwnam: '%s')", GetErrorStr());
        return;
    }

    if (u.policy == USER_STATE_PRESENT)
    {
        if (passwd_info)
        {
            uint32_t cmap = 0;
            if (VerifyIfUserNeedsModifs (puser, u, passwd_info, &cmap)
                == 1)
            {
                res = DoModifyUser (puser, u, cmap, action);
                if (!res)
                {
                    *result = PROMISE_RESULT_CHANGE;
                }
                else
                {
                    *result = PROMISE_RESULT_FAIL;
                }
            }
            else
            {
                *result = PROMISE_RESULT_NOOP;
            }
        }
        else
        {
            res = DoCreateUser (puser, u, action);
            if (!res)
            {
                *result = PROMISE_RESULT_CHANGE;
            }
            else
            {
                *result = PROMISE_RESULT_FAIL;
            }
        }
    }
    else if (u.policy == USER_STATE_ABSENT)
    {
        if (passwd_info)
        {
            res = DoRemoveUser (puser, action);
            if (!res)
            {
                *result = PROMISE_RESULT_CHANGE;
            }
            else
            {
                *result = PROMISE_RESULT_FAIL;
            }
        }
        else
        {
            *result = PROMISE_RESULT_NOOP;
        }
    }
}

#if STANDALONE
int test01 ()
{
    User u0 = { 0 };
    u0.policy = USER_STATE_PRESENT;
    u0.password = strdup ("v344t");
    u0.group_primary = strdup ("xorg13");
    u0.groups2_secondary = strdup ("xorg11,xorg10");

    User u1 = { 0 };
    u1.policy = USER_STATE_PRESENT;
    u1.group_primary = strdup ("xorg12");
    u1.groups2_secondary = strdup ("xorg11,xorg13");

    User u2 = { 0 };
    u2.policy = USER_STATE_PRESENT;
    u2.password =
        strdup
        ("$6$gDNrZkGDnUFMV9g$Ud94uWbcMXVfusUR9VMB07eUu53BuMgkboT9nwugpelcEY9PH57Oh.4Zl0bGnjeR.YYB9lQTAuUFBBdfJIhim/");

    User u3 = { 0 };
    u3.policy = USER_STATE_PRESENT;
    u3.password = strdup ("v344t");

    int result;
    //VerifyOneUsersPromise("xusr13", u0, &result);
    //VerifyOneUsersPromise("xusr13", u1, &result);
    VerifyOneUsersPromise ("xusr13", u3, &result, cfa_fix);

}

int main ()
{
    test01 ();
    exit (0);
    User u = { 0 };
    u.policy = USER_STATE_PRESENT;
    u.uid = NULL;
    u.create_home = true;
    //u.user = strdup("nhari");
    //u.user = strdup("vagrant");
    u.password = strdup ("v344t");
    u.description = strdup ("Pierre Nhari");
    u.group_primary = strdup ("myg");
    u.groups2_secondary = strdup ("myg1,myg2,myg3");
    u.home_dir = strdup ("/home/nhyet");
    u.shell = strdup ("/bin/sh");
    u.remove = false;

    int result;
    VerifyOneUsersPromise ("vagrant", u, &result, cfa_fix);
    //DoCreateUser(u);
    return 0;
}
#endif
