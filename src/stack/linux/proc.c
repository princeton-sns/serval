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

static int proc_generic_read(char **static_buf, int *static_buflen,
                             char *page, char **start, 
                             off_t off, int count, 
                             int *eof, void *data,
                             int (*print_func)(char *buf, int buflen),
                             void (*lock_func)(void),
                             void (*unlock_func)(void))
{
        if (!*static_buf) {
                int len;

                if (off > 0) {
                        /* Since no static_buf was allocated in the
                           previous call, and off > 0, we know that
                           everything printed fitted in the first
                           page. Therefore, just return 0 and indicate
                           that we are done. */
                        *start = NULL;
                        *eof = 1;
                        return 0;
                }
                
                lock_func();

                /* Find the size needed for printing */
                len = print_func(page, -1);
                
                /* Check if everything will fit in a single page */
                if (len < count) {
                        len = print_func(page, count);
                        *eof = 1;
                        /* Set the start pointer so that off will be
                           non-zero in the next call. */
                        *start = page;
                        unlock_func();
                        return len;
                }
                /* Ok, it didn't fit. Allocate a buffer large enough
                   to hold everything we print */
                *static_buflen = len + 1;
                *static_buf = kmalloc(*static_buflen, GFP_ATOMIC);
                
                if (!*static_buf) {
                        *eof = 1;
                        *static_buflen = 0;
                        unlock_func();
                        return 0;
                }
                len = print_func(*static_buf, *static_buflen);
                unlock_func();
        }
        /* If we get here, we have allocated memory and printed the
           information into it. Now output the info into each page
           through recursive calls to this function. */


        /* Check if we are done, i.e., static_buflen has reached
           zero */
        if (*static_buflen == 0) {
                if (*static_buf)
                        kfree(*static_buf);
                *static_buf = NULL;
                *start = NULL;
                *eof = 1;
                return 0;
        }

        /* Check if this is the last page to output stuff into. */
        if (count >= *static_buflen) {
                /* We should not write a complete page. */
                count = *static_buflen;
                *static_buflen = 0;
                *eof = 1;
        } else {
                /* Not the last page, just decrement the buflen */
                *static_buflen -= count;
        }

        /* Copy the information from our memory area into the page */
        strncpy(page, *static_buf + off, count);

        /* Make sure the offset (off) is updated in the next call by
           pointing start to our page. */
        *start = page;

        return count;
}

static int proc_service_table_read(char *page, char **start, 
                                   off_t off, int count, 
                                   int *eof, void *data)
{
        static char *buf = NULL;
        static int buflen = 0;

        return proc_generic_read(&buf, &buflen, page, start, off, 
                                 count, eof, data,
                                 __service_table_print,
                                 service_table_read_lock,
                                 service_table_read_unlock);
}

static int proc_flow_table_read(char *page, char **start, 
                                off_t off, int count, 
                                int *eof, void *data)
{
        static char *buf = NULL;
        static int buflen = 0;

        return proc_generic_read(&buf, &buflen, page, start, off, 
                                 count, eof, data,
                                 __flow_table_print,
                                 flow_table_read_lock,
                                 flow_table_read_unlock);
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
                                      proc_service_table_read, 
                                      NULL);

        if (!proc)
                goto fail_service_tbl;

        proc = create_proc_read_entry(SERVAL_PROC_FILE_FLOW_TBL, 0, 
                                      serval_dir, 
                                      proc_flow_table_read, 
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
