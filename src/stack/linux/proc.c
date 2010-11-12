#include <linux/version.h>
#include <linux/net.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23))
#define proc_net init_net.proc_net
#endif

#define SCAFFOLD_PROC_DIR "scaffold"
#define SCAFFOLD_PROC_FILE_UDP "udp"
#define SCAFFOLD_PROC_FILE_TCP "tcp"
#define SCAFFOLD_PROC_FILE_CTRL_TBL "control_table"
#define SCAFFOLD_PROC_FILE_SOCK_TBL "socket_table"
#define SCAFFOLD_PROC_FILE_TRANSMIT "transmit"

static struct proc_dir_entry *scaffold_dir = NULL;

static int scaffold_proc_udp_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	int len;
        
        len = 0;
//        len = sfnet_read_stat(STAT_UDP, page, count);
        
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

#define PROC_READ_BUFSIZE 10000

static int scaffold_proc_tcp_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
        static char buffer[PROC_READ_BUFSIZE];
	static int len = 0;
        int ret = 0;

        if (off == 0) {
//                len = sfnet_read_stat(STAT_TCP, buffer, PROC_READ_BUFSIZE);
        } 

        *start = page;

        if (len > count) {
                memcpy(page, buffer + off, count);
                ret = count;
                len -= count;
        } else if (len > 0) {
                memcpy(page, buffer + off, len);
                ret = len;
                len = 0;
                *eof = 1;
        } else {
                *eof = 1;
        }

        return ret;
}

static int scaffold_proc_sock_table_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	int len;
        len = 0;
        // len = sfnet_read_stat(STAT_SOCK_TBL, page, count);
        
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

static int scaffold_proc_control_table_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	int len;
        len = 0;
        //= sfnet_read_stat(STAT_CTRL_TBL, page, count);
        
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

static int scaffold_proc_transmit_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	int len;

        len = 0;
        //= sfnet_read_stat(STAT_TRANSMIT, page, count);
        
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

int __init scaffold_proc_init(void)
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

        proc = create_proc_read_entry(SCAFFOLD_PROC_FILE_UDP, 0, 
                                      scaffold_dir, scaffold_proc_udp_read, NULL);

        if (!proc)
                goto out_udp_fail;

        proc = create_proc_read_entry(SCAFFOLD_PROC_FILE_TCP, 0, 
                                      scaffold_dir, scaffold_proc_tcp_read, NULL);

        if (!proc)
                goto out_tcp_fail;
        
        proc = create_proc_read_entry(SCAFFOLD_PROC_FILE_CTRL_TBL, 0, 
                                      scaffold_dir, scaffold_proc_control_table_read, NULL);

        if (!proc)
                goto out_ctrl_tbl_fail;

        proc = create_proc_read_entry(SCAFFOLD_PROC_FILE_SOCK_TBL, 0, 
                                      scaffold_dir, scaffold_proc_sock_table_read, NULL);

        if (!proc)
                goto out_sock_tbl_fail;

        proc = create_proc_read_entry(SCAFFOLD_PROC_FILE_TRANSMIT, 0, 
                                      scaffold_dir, scaffold_proc_transmit_read, NULL);

        if (!proc)
                goto out_transmit_fail;

        ret = 0;
out:        
        return ret;
out_transmit_fail:
        remove_proc_entry(SCAFFOLD_PROC_FILE_SOCK_TBL, scaffold_dir);
out_sock_tbl_fail:
        remove_proc_entry(SCAFFOLD_PROC_FILE_CTRL_TBL, scaffold_dir);
out_ctrl_tbl_fail:
        remove_proc_entry(SCAFFOLD_PROC_FILE_TCP, scaffold_dir);
out_tcp_fail:
        remove_proc_entry(SCAFFOLD_PROC_FILE_UDP, scaffold_dir);
out_udp_fail:
        remove_proc_entry(SCAFFOLD_PROC_DIR, proc_net);
        goto out;
}

void scaffold_proc_fini(void)
{
        if (!scaffold_dir)
                return;

        remove_proc_entry(SCAFFOLD_PROC_FILE_TRANSMIT, scaffold_dir);
        remove_proc_entry(SCAFFOLD_PROC_FILE_SOCK_TBL, scaffold_dir);
        remove_proc_entry(SCAFFOLD_PROC_FILE_CTRL_TBL, scaffold_dir);
        remove_proc_entry(SCAFFOLD_PROC_FILE_UDP, scaffold_dir);
        remove_proc_entry(SCAFFOLD_PROC_FILE_TCP, scaffold_dir);
	remove_proc_entry(SCAFFOLD_PROC_DIR, proc_net);
}
