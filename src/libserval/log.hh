/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef LOG_HH
#define LOG_HH

#include <sys/file.h>
#include <stdio.h>

class Logger {
  public:
    typedef enum { 
	    LOG_OFF = 0, 
	    LOG_FATAL, 
	    LOG_ERROR, 
	    LOG_WARN, 
	    LOG_INFO, 
	    LOG_DEBUG, 
	    _LOG_MAX } Level;
    static int xlog(Level l, const char *func, const char *format, ...);
    static int initialize(const char *name);
    static void static_uninitialize();
    static bool initialized() { return _initialized; }
    static const char *log_fname();
    static const char *dirname();
    static void set_debug_level(unsigned int level);
  private:
    static const char *level_str[];
    ~Logger();
    static int setup_log_dir();
    static void setup_logfd();
    static const char *get_time();
    static const char *get_level_str(Level level);
    static const char *PREFIX;
    static char *_dirname;
    static char *_log_fname;
    static FILE *_logfd;
    static bool _initialized;
    static Level _debug_level;
};


#ifdef ENABLE_DEBUG
#define debug(format, ...) Logger::xlog(Logger::LOG_DEBUG, __func__, format, ## __VA_ARGS__)
#define info(format, ...) Logger::xlog(Logger::LOG_INFO, __func__, format, ## __VA_ARGS__)
#define lerr(format, ...) Logger::xlog(Logger::LOG_ERROR, __func__, format, ## __VA_ARGS__)
#else
#define debug(X, ...)
#define info(X, ...)
#define lerr(format, ...) Logger::xlog(Logger::LOG_ERROR, __func__, format, ## __VA_ARGS__)
#endif

#endif
