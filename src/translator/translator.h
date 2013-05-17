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

int run_translator(unsigned short port,
                   struct sockaddr_sv *sv,
                   int cross_translate, 
                   unsigned int mode);

#endif /* __TRANSLATOR_H__ */
