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

#include "platform.h"

#include "files_copy.h"

#include "files_names.h"
#include "files_interfaces.h"
#include "instrumentation.h"
#include "policy.h"
#include "files_lib.h"
#include "string_lib.h"

/*
 * Copy data jumping over areas filled by '\0', so files automatically become sparse if possible.
 */
static bool CopyData(const char *source, int sd, const char *destination, int dd, char *buf, size_t buf_size)
{
    off_t n_read_total = 0;

    while (true)
    {
        ssize_t n_read = read(sd, buf, buf_size);

        if (n_read == -1)
        {
            if (errno == EINTR)
            {
                continue;
            }

            Log(LOG_LEVEL_ERR, "Unable to read source file while copying '%s' to '%s'. (read: %s)", source, destination, GetErrorStr());
            return false;
        }

        if (n_read == 0)
        {
            /*
             * As the tail of file may contain of bytes '\0' (and hence
             * lseek(2)ed on destination instead of being written), do a
             * ftruncate(2) here to ensure the whole file is written to the
             * disc.
             */
            if (ftruncate(dd, n_read_total) < 0)
            {
                Log(LOG_LEVEL_ERR, "Copy failed (no space?) while copying '%s' to '%s'. (ftruncate: %s)", source, destination, GetErrorStr());
                return false;
            }

            return true;
        }

        n_read_total += n_read;

        /* Copy/seek */

        void *cur = buf;
        void *end = buf + n_read;

        while (cur < end)
        {
            void *skip_span = MemSpan(cur, 0, end - cur);
            if (skip_span > cur)
            {
                if (lseek(dd, skip_span - cur, SEEK_CUR) < 0)
                {
                    Log(LOG_LEVEL_ERR, "Failed while copying '%s' to '%s' (no space?). (lseek: %s)", source, destination, GetErrorStr());
                    return false;
                }

                cur = skip_span;
            }


            void *copy_span = MemSpanInverse(cur, 0, end - cur);
            if (copy_span > cur)
            {
                if (FullWrite(dd, cur, copy_span - cur) < 0)
                {
                    Log(LOG_LEVEL_ERR, "Failed while copying '%s' to '%s' (no space?). (write: %s)", source, destination, GetErrorStr());
                    return false;
                }

                cur = copy_span;
            }
        }
    }
}

bool CopyRegularFileDisk(const char *source, const char *destination)
{
    int sd;
    int dd = 0;
    char *buf = 0;
    bool result = false;

    if ((sd = open(source, O_RDONLY | O_BINARY)) == -1)
    {
        Log(LOG_LEVEL_INFO, "Can't copy '%s'. (open: %s)", source, GetErrorStr());
        goto end;
    }
    /*
     * We need to stat the file in order to get the right source permissions.
     */
    struct stat statbuf;

    if (stat(source, &statbuf) == -1)
    {
        Log(LOG_LEVEL_INFO, "Can't copy '%s'. (stat: %s)", source, GetErrorStr());
        goto end;
    }

#ifdef WITH_SELINUX
    security_context_t old_con = 0;
    security_context_t new_con = 0;
    bool fscon_set = false;
    if (getfscreatecon(&old_con) != 0)
    {
        if (errno != ENOTSUP)
        {
            Log(LOG_LEVEL_ERR, "Could not get file creation security context. (getfscreatecon: %s)", GetErrorStr());
            goto end;
        }
    }
    else
    {
        if (getfilecon(source, &new_con) != 0)
        {
            if (errno != ENOTSUP && errno != ENODATA)
            {
                Log(LOG_LEVEL_ERR, "Could not get security context. (getfilecon: %s)", GetErrorStr());
                goto end;
            }
        }
        if (new_con)
        {
            if (setfscreatecon(new_con) != 0)
            {
                if (errno != ENOTSUP)
                {
                    Log(LOG_LEVEL_ERR, "Could not set file creation security context. (setfscreatecon: %s)", GetErrorStr());
                    goto end;
                }
            }
            fscon_set = true;
        }
    }
#endif

    unlink(destination);                /* To avoid link attacks */

    if ((dd = open(destination, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL | O_BINARY, statbuf.st_mode)) == -1)
    {
        Log(LOG_LEVEL_INFO, "Unable to open destination file while copying '%s' to '%s'. (open: %s)", source, destination, GetErrorStr());
        goto end;
    }

    int buf_size = ST_BLKSIZE(dstat);
    buf = xmalloc(buf_size);

    result = CopyData(source, sd, destination, dd, buf, buf_size);
    if (!result)
    {
        unlink(destination);
        goto end;
    }

    result = CopyACLs(source, destination);

end:
#ifdef WITH_SELINUX
    if (fscon_set)
    {
        if (setfscreatecon(old_con) != 0)
        {
            Log(LOG_LEVEL_ERR, "Failed to set file creation security context back to default. (setfscreatecon: %s)", GetErrorStr());
            // Nothing we can do about it.
        }
    }
    if (new_con)
    {
        freecon(new_con);
    }
    if (old_con)
    {
        freecon(old_con);
    }
#endif

    if (buf)
    {
        free(buf);
    }
    if (dd)
    {
        close(dd);
    }
    if (!result)
    {
        unlink(destination);
    }
    close(sd);
    return result;
}
