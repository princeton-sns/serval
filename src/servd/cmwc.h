#ifndef CONTROLLER_INTERFACE_HH__
#define CONTROLLER_INTERFACE_HH__

#define MAX_NUM 4294967295.0f

extern unsigned long Q[4096],c;

//unsigned long scmwc4096(unsigned long seed, unsigned long q[]);
unsigned long scmwc4096(unsigned long* seed, unsigned long q[], int i);
unsigned long ucmwc4096(unsigned long seed, unsigned long q[], int i);
unsigned long cmwc4096(void);

#endif
