/*
   Copyright (C) CFEngine AS

   This file is part of CFEngine 3 - written and maintained by CFEngine AS.

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA

  To the extent this program is licensed as part of the Enterprise
  versions of CFEngine, the applicable Commerical Open Source License
  (COSL) may apply to this file if you as a licensee so wish it. See
  included file COSL.txt.
*/

#include <verify_users.h>

#include <promises.h>
#include <dir.h>
#include <files_names.h>
#include <files_interfaces.h>
#include <vars.h>
#include <conversion.h>
#include <expand.h>
#include <scope.h>
#include <vercmp.h>
#include <matching.h>
#include <attributes.h>
#include <string_lib.h>
#include <pipes.h>
#include <locks.h>
#include <exec_tools.h>
#include <policy.h>
#include <misc_lib.h>
#include <rlist.h>
#include <ornaments.h>
#include <env_context.h>
#include <retcode.h>
#include <cf-agent-enterprise-stubs.h>
#include <cf-windows-functions.h>

/** Entry points from VerifyUsersPromise **/

static int UserSanityCheck(EvalContext *ctx, Attributes a, Promise *pp);

/*===========================================================================*/
/*===========================================================================*/
/*===========================================================================*/
#include "vuser.c"
/*===========================================================================*/
/*===========================================================================*/
/*===========================================================================*/

/*****************************************************************************/

void VerifyUsersPromise(EvalContext *ctx, Promise *pp)
{
    Attributes a = { {0} };
    CfLock thislock;
    char lockname[CF_BUFSIZE];

    a = GetUserAttributes(ctx, pp);

    if (!UserSanityCheck(ctx, a, pp))
    {
        return;
    }

    PromiseBanner(pp);

// Now verify the package itself

    snprintf(lockname, CF_BUFSIZE - 1, "user-%s-%d", pp->promiser, a.users.policy);

    thislock = AcquireLock(ctx, lockname, VUQNAME, CFSTARTTIME, a.transaction, pp, false);

    if (thislock.lock == NULL)
    {
        return;
    }

    /*Do things*/
    //cfPS(ctx, LOG_LEVEL_ERR, PROMISE_RESULT_FAIL, pp, a, "KO");
#if 0
    printf("pp->promiser=[%s]\n", pp->promiser);
    printf("a ->policy   =[%d]\n", a.users.policy);
    printf("a ->uid     =[%s]\n", a.users.uid);
    printf("a ->group_primary =[%s]\n", a.users.group_primary);
#endif

    int result;
    VerifyOneUsersPromise(pp->promiser, a.users, &result);

    switch (result) {
         case CFUSR_KEPT:
             cfPS(ctx, LOG_LEVEL_INFO, PROMISE_RESULT_NOOP, pp, a, "NOOP");
             break;
         case CFUSR_NOTKEPT:
             //cfPS(ctx, LOG_LEVEL_ERR, PROMISE_RESULT_INTERRUPTED, pp, a, "KO");
             cfPS(ctx, LOG_LEVEL_ERR, PROMISE_RESULT_FAIL, pp, a, "KO");
             break;
         case CFUSR_REPAIRED:
             cfPS(ctx, LOG_LEVEL_INFO, PROMISE_RESULT_CHANGE, pp, a, "OK");
             break;
         default:
             printf("Problem: result is unknwon\n");
    }
 

    YieldCurrentLock(thislock);
}

/** Pre-check of promise contents **/

static int UserSanityCheck(EvalContext *ctx, Attributes a, Promise *pp)
{
    return true;
}

