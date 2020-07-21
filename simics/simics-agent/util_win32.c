/* This Software is part of Wind River Simics. The rights to copy, distribute,
   modify, or otherwise make use of this Software may be licensed only
   pursuant to the terms of an applicable Wind River license agreement.

   Copyright 2012-2016 Intel Corporation */

#ifdef _WIN32
#include "agent.h"
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <dirent.h>
#include <io.h>

size_t
dynstr_listdir(char **files, const char *path)
{
        size_t at = 0;
        DBG_PRINT("(%p, '%s'): *files=%p", files, path, *files);
        WIN32_FIND_DATA fd;
        HANDLE h = FindFirstFile(path, &fd);
        if (h == INVALID_HANDLE_VALUE)
                return 0;

        do {
                /* Try with long file name, then the short 8.3 alternative */
                if (fd.cFileName)
                        at = dynstr_printf(files, at, "%s", fd.cFileName);
                else if (fd.cAlternateFileName)
                        at = dynstr_printf(files, at, "%s",
                                           fd.cAlternateFileName);
                else
                        continue;  /* fail-safe, continue to the next entry */
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                        at = dynstr_printf(files, at, "\\");
                at++;
        } while (FindNextFile(h, &fd));
        FindClose(h);

        return at;
}

inline void
sleep_millisec(uint32_t ms)
{
        Sleep(ms);
}

int
uname(struct utsname *sys)
{
        static const char *winfive[2][3] = {
                {
                        "Windows 2000",
                        "Windows XP",
                        "Windows XP x64",
                },
                {
                        "Windows 2000",
                        "Windows XP",
                        "Windows Server 2003",
                }
        };
        static const char *winsix[2][4] = {
                {
                        "Windows Vista",
                        "Windows 7",
                        "Windows 8",
                        "Windows 8.1",
                },
                {
                        "Windows Server 2008",
                        "Windows Server 2008 R2",
                        "Windows Server 2012",
                        "Windows Server 2012 R2",
                }
        };

        SYSTEM_INFO nfo;
        OSVERSIONINFOEX osvi;
        static char hostname[81];
        static char release[16];
        static char version[144];
        DWORD size = 40;

        GetComputerName(hostname, &size);
        sys->nodename = hostname;

        ZeroMemory(&osvi, sizeof(osvi));
        osvi.dwOSVersionInfoSize = sizeof(osvi);

        GetVersionEx((LPOSVERSIONINFO)&osvi);
        sprintf(release, "%lu.%lu.%lu",
                osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
        sys->release = release;
        sys->sysname = "Microsoft Windows";
        BOOL server = osvi.wProductType != VER_NT_WORKSTATION;
        if (osvi.dwMajorVersion == 5) {
                if (osvi.dwMinorVersion < 3)
                        sys->sysname = (char *)
                                winfive[server][osvi.dwMinorVersion];
        } else if (osvi.dwMajorVersion == 6) {
                if (osvi.dwMinorVersion < 4)
                        sys->sysname = (char *)
                                winsix[server][osvi.dwMinorVersion];
        }
        sprintf(version, "%s (%d.%d)", osvi.szCSDVersion,
                osvi.wServicePackMajor, osvi.wServicePackMinor);
        sys->version = version;

        GetSystemInfo(&nfo);
        switch (nfo.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
                sys->machine = "x86_64";
                break;
        case PROCESSOR_ARCHITECTURE_IA64:
                sys->machine = "ia64";
                break;
        case PROCESSOR_ARCHITECTURE_INTEL:
                sys->machine = "x86";
                break;
        default:
                sys->machine = "unknown";
                break;
        }
        return 0;
}

inline int
wrap_execve(const char *filename, char *const *argv)
{
        return _execve(filename,
                       (const char *const *)argv,
                       (const char *const *)environ);
}

#endif /* _WIN32 */
