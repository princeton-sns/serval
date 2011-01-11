/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <linux/version.h>
#include <linux/net.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <service.h>
#include <neighbor.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23))
#define proc_net init_net.proc_net
#endif

#define SCAFFOLD_PROC_DIR "scaffold"
#define SCAFFOLD_PROC_FILE_SERVICE_TBL "service_table"
#define SCAFFOLD_PROC_FILE_NEIGHBOR_TBL "neighbor_table"

static struct proc_dir_entry *scaffold_dir = NULL;

static int scaffold_proc_service_table_read(char *page, char **start, 
                                            off_t off, int count, 
                                            int *eof, void *data)
{
	int len;
        len = 0;

        len = services_print(page, count);

        if (len <= off + count) 
                *eof = 1;
        
        *start = page + off;
        len -= off;
        
        if (len > count) 
                len = count;

        if (len < 0) 
                len = 0;

        return len;
}

static int scaffold_proc_neighbor_table_read(char *page, char **start, 
                                            off_t off, int count, 
                                            int *eof, void *data)
{
	int len;
        len = 0;

        len = neighbors_print(page, count);

        if (len <= off + count) 
                *eof = 1;
        
        *start = page + off;
        len -= off;
        
        if (len > count) 
                len = count;

        if (len < 0) 
                len = 0;

        return len;
}

int __init proc_init(void)
{
        struct proc_dir_entry *proc;
        int ret = -ENOMEM;

        scaffold_dir = proc_mkdir(SCAFFOLD_PROC_DIR, proc_net);

	if (!scaffold_dir) {
                return -ENOMEM;
	}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30))
	scaffold_dir->owner = THIS_MODULE;
#endif
      
        proc = create_proc_read_entry(SCAFFOLD_PROC_FILE_SERVICE_TBL, 0, 
                                      scaffold_dir, 
                                      scaffold_proc_service_table_read, 
                                      NULL);

        if (!proc)
                goto fail_service_tbl;

        proc = create_proc_read_entry(SCAFFOLD_PROC_FILE_NEIGHBOR_TBL, 0, 
                                      scaffold_dir, 
                                      scaffold_proc_neighbor_table_read, 
                                      NULL);

        if (!proc)
                goto fail_neighbor_tbl;

        ret = 0;
out:        
        return ret;
fail_neighbor_tbl:
        remove_proc_entry(SCAFFOLD_PROC_FILE_SERVICE_TBL, scaffold_dir);
fail_service_tbl:
        remove_proc_entry(SCAFFOLD_PROC_DIR, proc_net);
        goto out;
}

void proc_fini(void)
{
        if (!scaffold_dir)
                return;

        remove_proc_entry(SCAFFOLD_PROC_FILE_SERVICE_TBL, scaffold_dir);
        remove_proc_entry(SCAFFOLD_PROC_FILE_NEIGHBOR_TBL, scaffold_dir);
	remove_proc_entry(SCAFFOLD_PROC_DIR, proc_net);
}
