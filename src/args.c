/* 
   Copyright (C) 2008 - Mark Burgess

   This file is part of Cfengine 3 - written and maintained by Mark Burgess.
 
   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 3, or (at your option) any
   later version. 
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
 
  You should have received a copy of the GNU General Public License
  
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA

*/

/*****************************************************************************/
/*                                                                           */
/* File: args.c                                                              */
/*                                                                           */
/*****************************************************************************/

#include "cf3.defs.h"
#include "cf3.extern.h"

/******************************************************************/
/* Argument propagation                                           */
/******************************************************************/

/*

When formal parameters are passed, they should be literal strings, i.e.
values (check for this). But when the values are received the
receiving body should state only variable names without literal quotes.
That way we can feed in the received parameter name directly in as an lvalue

e.g.
       access => myaccess("$(person)"),

       body files myaccess(user)

leads to Hash Association (lval,rval) => (user,"$(person)")

*/

/******************************************************************/

int MapBodyArgs(char *scopeid,struct Rlist *give,struct Rlist *take)
      
{ struct Rlist *rpg,*rpt;
  struct FnCall *fp;
  enum cfdatatype dtg = cf_notype,dtt = cf_notype;
  char *lval;
  void *rval;
  int len1,len2;
  
Debug("MapBodyArgs(begin)\n");

len1 = RlistLen(give);
len2 = RlistLen(take);

if (len1 != len2)
   {
   snprintf(OUTPUT,CF_BUFSIZE,"Body template [+args] = %d, [-args] = %d",len1,len2);
   CfLog(cferror,OUTPUT,"");
   return false;
   }

for (rpg = give, rpt = take; rpg != NULL && rpt != NULL; rpg=rpg->next,rpt=rpt->next)
   {
   dtg = StringDataType(scopeid,(char *)rpg->item);
   dtt = StringDataType(scopeid,(char *)rpt->item);
   
   if (dtg != dtt)
      {
      snprintf(OUTPUT,CF_BUFSIZE,"Type mismatch between logical/formal parameters %s/%s\n",(char *)rpg->item,(char *)rpt->item);
      CfLog(cferror,OUTPUT,"");
      snprintf(OUTPUT,CF_BUFSIZE,"%s is %s whereas %s is %s\n",(char *)rpg->item,CF_DATATYPES[dtg],(char *)rpt->item,CF_DATATYPES[dtt]);
      CfLog(cferror,OUTPUT,"");
      }

   switch (rpg->type)
      {
      case CF_SCALAR:

          lval = (char *)rpt->item;
          rval = rpg->item;

          Debug("MapBodyArgs(SCALAR,%s,%s)\n",lval,rval);
          AddVariableHash(scopeid,lval,rval,CF_SCALAR,dtg,NULL,0);
          break;

      case CF_LIST:
          lval = (char *)rpt->item;
          rval = rpg->item;

          Debug("MapBodyArgs(LIST,%s,\n",lval);
          ShowRlist(stdout,rval);
          Debug(")\n");
          AddVariableHash(scopeid,lval,rval,CF_LIST,dtg,NULL,0);
          
          break;
          
      case CF_FNCALL:
          fp = (struct FnCall *)rpt->item;
          dtg = FunctionReturnType(fp->name);

          // Should not happen in this context?
          break;
          
      default:
          /* Nothing else should happen */
          FatalError("Software error: something not a scalar/function in argument literal");
      }
   
   }

Debug("MapBodyArgs(end)\n");
return true;
}

/******************************************************************/

struct Rlist *NewExpArgs(struct FnCall *fp, struct Promise *pp)

{ int i, len, ref = 0;
  struct Rval rval;
  struct Rlist *rp,*newargs = NULL;
  struct FnCall *subfp;

/* Check if numargs correct and expand recursion */
  
len = RlistLen(fp->args); 

for (i = 0; CF_FNCALL_TYPES[i].name != NULL; i++)
   {
   if (strcmp(fp->name,CF_FNCALL_TYPES[i].name) == 0)
      {
      ref = CF_FNCALL_TYPES[i].numargs;
      }
   }

if (ref != len)
   {
   snprintf(OUTPUT,CF_BUFSIZE,"Arguments to function %s(.) do not tally. Expect %d not %d",fp->name,ref,len);
   CfLog(cferror,OUTPUT,"");
   snprintf(OUTPUT,CF_BUFSIZE,"Function reference in %s @ promise near line %d",pp->audit->filename,pp->lineno);
   CfLog(cferror,OUTPUT,"");
   }

for (rp = fp->args; rp != NULL; rp = rp->next)
   {   
   switch (rp->type)
      {
      case CF_FNCALL:          
          subfp = (struct FnCall *)rp->item;
          rval = EvaluateFunctionCall(subfp,pp);
          break;
      default:
          rval.item = rp->item;
          rval.rtype = rp->type;
          break;
      }

   AppendRlist(&newargs,rval.item,rval.rtype);
   }

return newargs;
}

/******************************************************************/

void DeleteExpArgs(struct Rlist *args)

{
DeleteRvalItem(args,CF_LIST);
}

/******************************************************************/

void ArgTemplate(struct FnCall *fp,char **argtemplate, enum cfdatatype *argtypes,struct Rlist *realargs)

{ int argnum,i;
  struct Rlist *rp = fp->args;
  char id[CF_BUFSIZE];

snprintf(id,CF_MAXVARSIZE,"built-in FnCall %s-arg",fp->name);
  
for (argnum = 0; argtemplate[argnum] != NULL; argnum++)
    {
    if (rp->type != CF_FNCALL)
       {
       /* Nested functions will not match to lval so don't bother checking */
       CheckConstraintTypeMatch(id,rp->item,rp->type,argtypes[argnum],argtemplate[argnum],1);
       }
    rp = rp->next;
    }

if (argnum != RlistLen(fp->args))
   {
   printf("Arg mismatch handling function %s\n",fp->name);
   FatalError("Software error - should not happen");
   }

if (argnum != RlistLen(realargs))
   {
   snprintf(OUTPUT,CF_BUFSIZE,"Argument template mismatch handling function %s(",fp->name);
   ReportError(OUTPUT);
   ShowRlist(stderr,realargs);
   fprintf(stderr,")\n",fp->name);

   for (i = 0, rp = realargs; i < argnum; i++)
      {
      printf("  arg[%d] range %s\t",i,argtemplate[i]);
      if (rp != NULL)
         {
         ShowRval(stdout,rp->item,rp->type);
         rp=rp->next;
         }
      else
         {
         printf(" ? ");
         }
      printf("\n");
      }
   
   FatalError("Bad arguments");
   }

Debug("End ArgTemplate\n");
}
