/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <linux/version.h>
#include <linux/net.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <service.h>
#include <serval_sock.h>
#include "log.h"

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23))
#define proc_net init_net.proc_net
#endif

#define SERVAL_PROC_DIR "serval"
#define SERVAL_PROC_DBG "dbg"
#define SERVAL_PROC_FILE_SERVICE_TBL "service_table"
#define SERVAL_PROC_FILE_FLOW_TBL "flow_table"

static struct proc_dir_entry *serval_dir = NULL;

static int serval_proc_service_table_read(char *page, char **start, 
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

static int serval_proc_flow_table_read(char *page, char **start, 
                                       off_t off, int count, 
                                       int *eof, void *data)
{
	int len;
        len = 0;

        len = flows_print(page, count);

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

/*
  Debug output through /proc/serval/dbg based on linux kernel
  /proc/kmsg

*/
extern wait_queue_head_t log_wait;

static int dbg_open(struct inode *inode, struct file *file)
{
	return do_log(LOG_ACTION_OPEN, NULL, 0, LOG_FROM_FILE);
}

static int dbg_release(struct inode *inode, struct file *file)
{
	(void) do_log(LOG_ACTION_CLOSE, NULL, 0, LOG_FROM_FILE);
	return 0;
}

static ssize_t dbg_read(struct file *file, char __user *buf,
			 size_t count, loff_t *ppos)
{
	if ((file->f_flags & O_NONBLOCK) &&
	    !do_log(LOG_ACTION_SIZE_UNREAD, NULL, 0, LOG_FROM_FILE))
		return -EAGAIN;
	return do_log(LOG_ACTION_READ, buf, count, LOG_FROM_FILE);
}

static unsigned int dbg_poll(struct file *file, poll_table *wait)
{
	poll_wait(file, &log_wait, wait);
	if (do_log(LOG_ACTION_SIZE_UNREAD, NULL, 0, LOG_FROM_FILE))
		return POLLIN | POLLRDNORM;
	return 0;
}

static const struct file_operations proc_dbg_operations = {
	.read		= dbg_read,
	.poll		= dbg_poll,
	.open		= dbg_open,
	.release	= dbg_release,
	.llseek		= generic_file_llseek,
};

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25))
static inline 
struct proc_dir_entry *proc_create(const char *name, mode_t mode, 
                                   struct proc_dir_entry *parent,
                                   const struct file_operations *proc_fops)
{
        struct proc_dir_entry *proc;

        proc = create_proc_entry(name, mode, parent);

        if (proc) {
                proc->proc_fops = proc_fops;
        }

        return proc;
}
#endif

int __init proc_init(void)
{
        struct proc_dir_entry *proc;
        int ret = -ENOMEM;

        serval_dir = proc_mkdir(SERVAL_PROC_DIR, proc_net);

	if (!serval_dir) {
                return -ENOMEM;
	}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30))
	serval_dir->owner = THIS_MODULE;
#endif
      
	proc = proc_create(SERVAL_PROC_DBG, S_IRUGO, serval_dir, 
                           &proc_dbg_operations);

        if (!proc)
                goto fail_dbg;

        proc = create_proc_read_entry(SERVAL_PROC_FILE_SERVICE_TBL, 0, 
                                      serval_dir, 
                                      serval_proc_service_table_read, 
                                      NULL);

        if (!proc)
                goto fail_service_tbl;

        proc = create_proc_read_entry(SERVAL_PROC_FILE_FLOW_TBL, 0, 
                                      serval_dir, 
                                      serval_proc_flow_table_read, 
                                      NULL);

        if (!proc)
                goto fail_flow_tbl;
        
        ret = 0;
out:        
        return ret;

fail_flow_tbl:
        remove_proc_entry(SERVAL_PROC_FILE_SERVICE_TBL, serval_dir);
fail_service_tbl:
        remove_proc_entry(SERVAL_PROC_DBG, serval_dir);
fail_dbg:
        remove_proc_entry(SERVAL_PROC_DIR, proc_net);
        goto out;
}

void proc_fini(void)
{
        if (!serval_dir)
                return;

        remove_proc_entry(SERVAL_PROC_FILE_SERVICE_TBL, serval_dir);
        remove_proc_entry(SERVAL_PROC_FILE_FLOW_TBL, serval_dir);
        remove_proc_entry(SERVAL_PROC_DBG, serval_dir);
	remove_proc_entry(SERVAL_PROC_DIR, proc_net);
}
