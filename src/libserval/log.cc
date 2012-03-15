/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
// Copyright (c) 2010 The Trustees of Princeton University (Trustees)

// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and/or hardware specification (the “Work”) to deal
// in the Work without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Work, and to permit persons to whom the Work is
// furnished to do so, subject to the following conditions: The above
// copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Work.

// THE WORK IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE WORK OR THE USE OR OTHER
// DEALINGS IN THE WORK.

#include "log.hh"
#include <serval/platform.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/file.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>

#define DEFAULT_LOG_FNAME "sf.log"
char *Logger::_dirname = NULL;
char *Logger::_log_fname = NULL;

#define DIRNAME_STR "log"
#if defined(OS_ANDROID)
const char *Logger::PREFIX = "/data/local/tmp"; // todo: autoconf
#else
const char *Logger::PREFIX = "/tmp"; // todo: autoconf
#endif

FILE *Logger::_logfd = 0;
bool Logger::_initialized = false;
Logger::Level Logger::_debug_level = (Level)(_LOG_MAX - 1);

#define LOG_TO_DEBUGFS 1

Logger::~Logger()
{
}

void Logger::set_debug_level(unsigned int level)
{
    _debug_level = level > (_LOG_MAX - 1) ? (Level)(_LOG_MAX - 1) : (Level)level;
}

int
Logger::initialize(const char *name)
{
    if (!_initialized) {

        if (_log_fname)
            delete [] _log_fname;

        _log_fname = new char[strlen(name) + 1];

        if (!_log_fname)
            return -1;

        strcpy(_log_fname, name);

        if (_dirname)
            delete [] _dirname;

        _dirname = new char[strlen(PREFIX) + strlen(DIRNAME_STR) + 2];

        if (!_dirname)
            return -1;
        
        sprintf(_dirname, "%s/%s", PREFIX, DIRNAME_STR);

        setup_logfd();

        _initialized = true;
    }
    return 0;
}

void Logger::static_uninitialize()
{
    _initialized = false;

    if (_dirname)
        delete [] _dirname;

    if (_log_fname)
        delete [] _log_fname;
}

int
Logger::xlog(Level level, const char *func, const char *format, ...)
{
    if (!_initialized || _debug_level == LOG_OFF || (level > _debug_level)) {
        return 0;
    }

    if (_logfd == NULL)
        return -1;

    pid_t id = getpid();

    va_list ap;
    va_start (ap, format);
    fprintf(_logfd, "[%s]%s: [%d] [%3s] ", get_time(), func, id, get_level_str(level));
    vfprintf(_logfd, format, ap);
    fprintf(_logfd, "\n");
    //fflush(_logfd);
    va_end(ap);

    return 0;
}

const char *Logger::log_fname()
{
    return _log_fname;
}

const char *Logger::dirname()
{
    return _dirname;
}

const char *
Logger::get_time()
{
    static char buf[512];
    time_t now = time(0);
    struct tm p;
    localtime_r(&now, &p);
    strftime(buf, 512, "%b %e %T", &p);
    return buf;
}

const char *Logger::level_str[] = {
    "OFF", // should not be allowed level, only for suppressing
    "FTL",
    "ERR",
    "WRN",
    "INF",
    "DBG",
    "_MAX"
};

const char *
Logger::get_level_str(Level level)
{
    return level_str[level];
}

void
Logger::setup_logfd()
{
#define BUFLEN 256
    char buf[BUFLEN];
    setup_log_dir();

    if (_logfd) {
        fclose(_logfd);
        _logfd = NULL;
    }

    memset(buf, 0, BUFLEN);

    snprintf(buf, BUFLEN - 1, "%s/%s", dirname(), log_fname());
    
    _logfd = fopen(buf, "w");
    
    if (!_logfd) {
        fprintf(stderr, "Could not open log fd at %s, directing to /dev/null\n", buf);
        _logfd = fopen("/dev/null", "w");
    } 
}

int
Logger::setup_log_dir()
{
    struct stat dirstat;
    if (stat(dirname(), &dirstat) != 0) {
        if (errno == ENOENT) {
            mkdir(dirname(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
            if (stat(dirname(), &dirstat) != 0) {
                fprintf(stderr, "Warning: could not create dir %s\n",
                        dirname());
                return -1;
            }
        } else {
            fprintf(stderr, "Warning: could not stat dir %s\n", dirname());
            return -1;
        }
    }

    return 0;
}
