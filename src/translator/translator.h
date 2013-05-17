#ifndef __TRANSLATOR_H__
#define __TRANSLATOR_H__

struct sockaddr_sv;

enum signal_types {
        SIGNAL_EXIT = 1,
	SIGNAL_NEW_CLIENT,
        SIGNAL_EPOLL_REARM,
};

extern struct signal main_signal;

enum translator_mode {
        DUAL_MODE = 0,
        INET_ONLY_MODE,
        SERVAL_ONLY_MODE,
};

enum debug_level {
    DBG_LVL_NONE,
    DBG_LVL_MIN,
    DBG_LVL_MED,
    DBG_LVL_MAX,
};

extern enum debug_level debuglevel;

#define LOG_MIN(format, ...) ({				\
	    if (debuglevel >= DBG_LVL_MIN) {		\
		LOG_DBG(format, ## __VA_ARGS__);	\
	    }						\
	})
#define LOG_MED(format, ...) ({				\
	    if (debuglevel >= DBG_LVL_MED) {		\
		LOG_DBG(format, ## __VA_ARGS__);	\
	    }						\
	})
#define LOG_MAX(format, ...) ({				\
	    if (debuglevel >= DBG_LVL_MAX) {		\
		LOG_DBG(format, ## __VA_ARGS__);	\
	    }						\
	})

int run_translator(unsigned short port,
                   struct sockaddr_sv *sv,
                   int cross_translate, 
                   unsigned int mode);

#endif /* __TRANSLATOR_H__ */
