#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/cdev.h>

#define DEVICE_NAME "backdoor"
#define BUFFER_SIZE 88
#define USER_BUFFER_SIZE 64
#define IOCTL_CMD 100

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("FOOBAR");
MODULE_DESCRIPTION("FOOBAR");
MODULE_VERSION("0.1");

static int major;
struct cdev *kernel_cdev;
static char *kernel_buffer;

void backdoor(void) {
    printk(KERN_INFO "Backdoor accessed!\n");
	while(1) {};
}

void custom_strncpy(char *dest, const char *src, size_t n) {
    while (n--) {
        *dest++ = *src++;
    }
}

static long backdoor_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    
	char user_buffer[USER_BUFFER_SIZE];

    if (cmd == IOCTL_CMD) {
        if (copy_from_user(kernel_buffer, (char *)arg, BUFFER_SIZE) != 0) {
            return -EFAULT;
        }
        custom_strncpy(user_buffer, kernel_buffer, BUFFER_SIZE); // Vulnerable function
		printk(KERN_INFO "Hello, %s!\n", user_buffer);
    }
    return 0;
}

static struct file_operations fops = {
    .unlocked_ioctl = backdoor_ioctl,
};

static int __init backdoor_init(void)
{
	int ret;
	dev_t dev_no, dev;

	kernel_cdev = cdev_alloc();
	kernel_cdev->ops = &fops;
	kernel_cdev->owner = THIS_MODULE;

    ret = alloc_chrdev_region(&dev_no, 0, 1, "backdoor");
    if (ret < 0) {
        printk(KERN_ALERT "Failed to register a major number\n");
        return ret;
    }

	major = MAJOR(dev_no);
	dev = MKDEV(major, 0);
	printk("The major number for your device is %d\n", major);
	ret = cdev_add(kernel_cdev, dev, 1);
	if (ret < 0) {
		pr_info(KERN_INFO "unable to allocate cdev");
		return ret;
	}

    kernel_buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL);
	if (!kernel_buffer) {
		cdev_del(kernel_cdev);
        unregister_chrdev_region(major, 1);
        printk(KERN_ALERT "Failed to allocate kernel buffer\n");
        return -ENOMEM;
    }

	return 0;
}

static void __exit backdoor_exit(void) {
    kfree(kernel_buffer);
	cdev_del(kernel_cdev);
    unregister_chrdev_region(major, 1);
    printk(KERN_INFO "Unregistered correctly\n");
}

module_init(backdoor_init);
module_exit(backdoor_exit);
