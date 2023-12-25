#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

inline void errquit(const char* msg)
{
    perror(msg);
    exit(1);
}

inline void quitIfError(int res, const char* msg)
{
    if (res < 0)
    {
        errquit(msg);
    }
}