/*
 * NET4:Sysctl interface to net af_serval subsystem.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 */
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <net/net_namespace.h>
#include <af_serval.h>

extern struct netns_serval net_serval;
static int encap_port_max = 65535;
static int encap_port_min = 1;

extern int udp_encap_init_port(unsigned short);
extern void udp_encap_fini(void);

static int proc_udp_encap_port(struct ctl_table *table, int write,
			       void *buffer, size_t *lenp, loff_t *ppos)
{
	int err;
	unsigned short old_port = net_serval.sysctl_udp_encap_port;

	err = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (err == 0) {
		udp_encap_fini();
		err = udp_encap_init_port(net_serval.sysctl_udp_encap_port);
		
		if (err) {
			net_serval.sysctl_udp_encap_port = old_port;
			udp_encap_init_port(old_port);
			/* If we fail to reinitialize UDP
			 * encapsulation here, there isn't much we can
			 * do */
		}
	} 

	return err;
}
	

static ctl_table serval_table[] = {
	{
		.procname= "sal_forward",
		.data= &net_serval.sysctl_sal_forward,
		.maxlen= sizeof(int),
		.mode= 0644,
		.proc_handler= proc_dointvec
	},
	{
		.procname= "udp_encap",
		.data= &net_serval.sysctl_udp_encap,
		.maxlen= sizeof(int),
		.mode= 0644,
		.proc_handler= proc_dointvec
	},
	{
		.procname= "udp_encap_port",
		.data= &net_serval.sysctl_udp_encap_port,
		.maxlen= sizeof(int),
		.mode= 0644,
		.proc_handler= proc_udp_encap_port,
		.extra1 = &encap_port_min,
		.extra2 = &encap_port_max,
	},
	{ }
};

static struct ctl_path serval_path[] = {
	{ .procname = "net", },
	{ .procname = "serval", },
	{ },
};

int __net_init serval_sysctl_register(struct net *net)
{
	struct ctl_table *table;

	table = kmemdup(serval_table, sizeof(serval_table), GFP_KERNEL);
	if (table == NULL)
		goto err_alloc;

	table[0].data = &net_serval.sysctl_sal_forward;
	net_serval.ctl = register_net_sysctl_table(net, serval_path, table);
	if (net_serval.ctl == NULL)
		goto err_reg;

	return 0;

err_reg:
	kfree(table);
err_alloc:
	return -ENOMEM;
}

void serval_sysctl_unregister(struct net *net)
{
	struct ctl_table *table;

	table = net_serval.ctl->ctl_table_arg;
	unregister_sysctl_table(net_serval.ctl);
	kfree(table);
}
