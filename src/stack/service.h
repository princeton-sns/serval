/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SERVICE_H_
#define _SERVICE_H_

struct service_entry;
struct service_id;

struct net_device *service_entry_get_dev(struct service_entry *se, 
                                         const char *ifname);
void service_entry_remove_dev(struct service_entry *se, 
			      const char *ifname);
int service_entry_add_dev(struct service_entry *se, 
                          struct net_device *dev, 
                          gfp_t alloc);

int service_add(struct service_id *srvid, unsigned int prefix_size,
		struct net_device *dev, gfp_t alloc);
void service_del(struct service_id *srvid, unsigned int prefix_size);
int service_del_dev(const char *devname);

void service_entry_hold(struct service_entry *se);
void service_entry_put(struct service_entry *se);

int services_print(char *buf, int buflen);

#endif /* _SERVICE_H_ */
