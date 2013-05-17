#if defined(__KERNEL__)
#include <linux/list.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
#define hlist_for_each_entry_compat(tpos, pos, head, member)	\
  pos = NULL; /* silence compiler */				\
  hlist_for_each_entry(tpos, head, member) 
#else
#define hlist_for_each_entry_compat(tpos, pos, head, member)	\
  hlist_for_each_entry(tpos, pos, head, member) 
#endif
#else
#include <common/list.h>
#define hlist_for_each_entry_compat(tpos, pos, head, member)	\
  hlist_for_each_entry(tpos, pos, head, member)
#endif


