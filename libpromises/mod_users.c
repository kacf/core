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

#include <mod_users.h>

#include <syntax.h>

static const ConstraintSyntax users_constraints[] =
{
    ConstraintSyntaxNewOption("policy", "present,absent,locked", "The promised state of a given user", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewString("user", "", "User name", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewString("uid", "", "User id", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewString("user_password", "", "User password", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewString("description", "", "User comment", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewBool("create_home", "If true, create home directory for new users", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewString("group", "", "User primary group", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewStringList("groups_secondary", ".*", "User additional groups", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewString("groups2_secondary", "", "Duplicated (just in order to test standalone code)", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewString("home_dir", "", "User home directory", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewString("shell", "", "User shell", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewBool("remove", "If true, remove ???", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewNull()
};

const PromiseTypeSyntax CF_USERS_PROMISE_TYPES[] =
{
    PromiseTypeSyntaxNew("agent", "users", users_constraints, NULL, SYNTAX_STATUS_NORMAL),
    PromiseTypeSyntaxNewNull()
};
