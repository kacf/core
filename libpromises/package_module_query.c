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
  versions of CFEngine, the applicable Commercial Open Source License
  (COSL) may apply to this file if you as a licensee so wish it. See
  included file COSL.txt.
*/

#include <cf3.defs.h>
#include <csv_parser.h>
#include <files_names.h>
#include <package_module_query.h>
#include <regex.h>

static void NullUpdater(ARG_UNUSED EvalContext *ctx, ARG_UNUSED bool force_update)
{
    // Noop
}

void (*MaybeUpdatePackagesCache)(EvalContext *ctx, bool force_update) =
    &NullUpdater;

JsonElement *GetNewPackagesMatching(EvalContext *ctx,
                                    const char *regex_package,
                                    const char *regex_version,
                                    const char *regex_arch,
                                    const char *regex_method,
                                    bool upgrades)
{
    MaybeUpdatePackagesCache(ctx, false);
    dbid id = upgrades ? dbid_packages_updates : dbid_packages_installed;
    CF_DB *dbp;
    if (!OpenDB(&dbp, id))
    {
        Log(LOG_LEVEL_ERR, "Could not open package '%s' database.",
            upgrades ? "upgrades", "installed");
        return NULL;
    }

    JsonElement *json = NULL;

    CF_DBC *cursor;
    if (!NewDBCursor(dbp, &cursor))
    {
        Log(LOG_LEVEL_ERR, "Could not open database cursor in "
            "package '%s' database.",
            upgrades ? "upgrades", "installed");
        goto ret;
    }

    char *key, *value;
    int ksize, vsize;
    while (NextDB(dbcp, &key, &ksize, &value, &vsize))
    {
        if (
    }

ret:
    CloseDB(dbp);
    return json;
}


JsonElement *GetOldPackagesMatching(const char *regex_package,
                                    const char *regex_version,
                                    const char *regex_arch,
                                    const char *regex_method,
                                    bool upgrades)
{
    pcre *matcher;
    {
        char regex[CF_BUFSIZE];

        // Here we will truncate the regex if the parameters add up to over CF_BUFSIZE
        snprintf(regex, sizeof(regex), "^%s,%s,%s,%s$",
                 regex_package, regex_version, regex_arch, regex_method);
        matcher = CompileRegex(regex);
        if (matcher == NULL)
        {
            return NULL;
        }
    }

    char filename[CF_MAXVARSIZE];
    if (upgrades)
    {
        GetSoftwarePatchesFilename(filename);
    }
    else
    {
        GetSoftwareCacheFilename(filename);
    }

    Log(LOG_LEVEL_DEBUG, "Reading package inventory from '%s'", filename);

    FILE *const fin = fopen(filename, "r");
    if (fin == NULL)
    {
        Log(LOG_LEVEL_VERBOSE,
            "Cannot open the %s packages inventory '%s' - "
            "This is not necessarily an error. "
            "Either the inventory policy has not been included, "
            "or it has not had time to have an effect yet. "
            "A future call may still succeed. (fopen: %s)",
            upgrades ? "available" : "installed",
            filename,
            GetErrorStr());

        pcre_free(matcher);
        return NULL;
    }

    JsonElement *json = JsonArrayCreate(50);
    int linenumber = 0;
    char *line;

    while (NULL != (line = GetCsvLineNext(fin)))
    {
        if (strlen(line) > CF_BUFSIZE - 80)
        {
            Log(LOG_LEVEL_ERR,
                "Line %d from package inventory '%s' is too long (%zd) to be sensible",
                linenumber, filename, strlen(line));
            free(line);
            break; /* or continue ? */
        }

        if (StringMatchFullWithPrecompiledRegex(matcher, line))
        {
            Seq *list = SeqParseCsvString(line);
            if (SeqLength(list) != 4)
            {
                Log(LOG_LEVEL_ERR,
                    "Line %d from package inventory '%s' did not yield 4 elements: %s",
                    linenumber, filename, line);
                ++linenumber;
                SeqDestroy(list);
                free(line);
                continue;
            }

            JsonElement *line_obj = JsonObjectCreate(4);
            JsonObjectAppendString(line_obj, "name",    SeqAt(list, 0));
            JsonObjectAppendString(line_obj, "version", SeqAt(list, 1));
            JsonObjectAppendString(line_obj, "arch",    SeqAt(list, 2));
            JsonObjectAppendString(line_obj, "method",  SeqAt(list, 3));
            SeqDestroy(list);

            JsonArrayAppendObject(json, line_obj);
        }

        ++linenumber;
        free(line);
    }
    const char *errstr = GetErrorStr(); /* Only relevant if fail */

    bool fail = !feof(fin);
    fclose(fin);
    pcre_free(matcher);

    if (fail)
    {
        Log(LOG_LEVEL_ERR,
            "Unable to read (%s) package inventory from '%s'.",
            errstr, filename);
        JsonDestroy(json);
        return NULL;
    }

    return json;
}
