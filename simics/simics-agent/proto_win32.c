/* This Software is part of Wind River Simics. The rights to copy, distribute,
   modify, or otherwise make use of this Software may be licensed only
   pursuant to the terms of an applicable Wind River license agreement.

   Copyright 2012-2016 Intel Corporation */

#ifdef _WIN32
#include "agent.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>

const char *sys_cap = "C99,WINDOWS,POSIX,SHELL";

static BOOL
isLeapYear(WORD year)
{
        if ((year % 400) == 0)
                return TRUE;
        if ((year % 100) == 0)
                return FALSE;
        if ((year % 4) == 0)
                return TRUE;
        return FALSE;
}

static int
dayOfYear(WORD year, WORD month, WORD day)
{
        static const int accum_days[] = {
                0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365
        };
        int yday = accum_days[month] + day;
        if ((month > 2) && isLeapYear(year))
                yday++;
        return yday;
}

int
get_time_response(struct matic_buffer *buf, struct agent *my)
{
        SYSTEMTIME st;
        struct tm tm;

        GetSystemTime(&st);
        tm.tm_sec = st.wSecond;
        tm.tm_min = st.wMinute;
        tm.tm_hour = st.wHour;
        tm.tm_mday = st.wDay;
        tm.tm_mon = st.wMonth - 1;
        tm.tm_year = st.wYear;
        tm.tm_wday = st.wDayOfWeek;
        tm.tm_yday = dayOfYear(st.wYear, st.wMonth, st.wDay);
        tm.tm_isdst = -1;
        DBG_PRINT(": date %d-%02d-%02d time %02d:%02d",
                  tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min);

        buf->head.size = strftime(buf->data, MAX_PAYLOAD_SIZE,
                                  "%a, %d %b %Y %H:%M:%S %z", &tm);
        if (!buf->head.size)
                return common_error_response(buf, EMSGSIZE, "strftime()");

        buf->head.code |= 2; /* get-time-response */
        buf->head.num = 0;
        buf->head.size++;
        return 0;
}


int
set_time_response(struct matic_buffer *buf, struct agent *my)
{
        time_t sec = *buf->u64;
        SYSTEMTIME st;
        struct tm *tm;

        tm = gmtime(&sec);
        st.wYear = tm->tm_year + 1900;
        st.wMonth = tm->tm_mon + 1;
        st.wDayOfWeek = tm->tm_wday;
        st.wDay = tm->tm_mday;
        st.wHour = tm->tm_hour;
        st.wMinute = tm->tm_min;
        st.wSecond = tm->tm_sec;
        st.wMilliseconds = buf->head.num;
        DBG_PRINT(": date %04d-%02d-%02d time %02d:%02d",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
        if (!SetSystemTime(&st))
                return common_error_response(buf, EINVAL, "SetSystemTime()");

        buf->head.size = 0;
        buf->head.num = 0;
        buf->head.code |= 1; /* set-time-ok */
        return 0;
}

#endif /* _WIN32 */
