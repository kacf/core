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

    snprintf(lockname, CF_BUFSIZE - 1, "user-%s-%d", pp->promiser, a.users.state);

    thislock = AcquireLock(ctx, lockname, VUQNAME, CFSTARTTIME, a.transaction, pp, false);

    if (thislock.lock == NULL)
    {
        return;
    }

    /*Do things*/
    //cfPS(ctx, LOG_LEVEL_ERR, PROMISE_RESULT_FAIL, pp, a, "KO");
    cfPS(ctx, LOG_LEVEL_INFO, PROMISE_RESULT_NOOP, pp, a, "NOOP");
    //cfPS(ctx, LOG_LEVEL_ERR, PROMISE_RESULT_CHANGE, pp, a, "KO");

    YieldCurrentLock(thislock);
}

/** Pre-check of promise contents **/

static int UserSanityCheck(EvalContext *ctx, Attributes a, Promise *pp)
{
    return true;
}

