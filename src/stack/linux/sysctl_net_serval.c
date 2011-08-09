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
