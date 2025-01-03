/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesd-circular-buffer.h"
#include "aesdchar.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Canis Lupus"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;
char *buff_reg[10];
size_t buff_ptr;

int aesd_open(struct inode *inode, struct file *filp)
{
	struct aesd_dev *my_data = container_of(inode->i_cdev, struct aesd_dev, cdev);

	PDEBUG("open");
	filp->private_data = my_data;
	return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    size_t entry_offset_byte_rtn;
    size_t char_offset = *f_pos;
    struct aesd_dev *my_data = filp->private_data;

    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    mutex_lock_interruptible(&my_data->lock);
    struct aesd_buffer_entry *entry = aesd_circular_buffer_find_entry_offset_for_fpos(
	    &my_data->buffer, char_offset, &entry_offset_byte_rtn);

    if (entry != NULL) {
	    retval = ((entry->size - entry_offset_byte_rtn) < count)
			     ? (entry->size - entry_offset_byte_rtn)
			     : count;
	    copy_to_user(buf, entry->buffptr, retval);
	    *f_pos += retval;
    }
    mutex_unlock(&my_data->lock);

    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    struct aesd_dev *my_data = filp->private_data;
    struct aesd_buffer_entry entry;
    char *tmp_buf;

    PDEBUG("write %zu bytes with offset %lld", count, *f_pos);

    mutex_lock_interruptible(&my_data->lock);
    tmp_buf = kmalloc(count + my_data->write_buf_size, GFP_KERNEL);

    if (tmp_buf == NULL) {
	    mutex_unlock(&my_data->lock);
	    goto exit;
    }

    memcpy(tmp_buf, my_data->write_buf, my_data->write_buf_size);
    copy_from_user(tmp_buf + my_data->write_buf_size, buf, count);

    if (my_data->write_buf != NULL) {
	    kfree(my_data->write_buf);
    }

    my_data->write_buf = tmp_buf;
    my_data->write_buf_size = count + my_data->write_buf_size;

    if (my_data->write_buf[my_data->write_buf_size - 1] == '\n') {
	    if (my_data->buffer.full) {
		    entry = *aesd_circular_buffer_remove_oldest(&my_data->buffer);
		    if (entry.buffptr != NULL) {
			    kfree(entry.buffptr);
		    }
	    }

	    entry.buffptr = my_data->write_buf;
	    entry.size = my_data->write_buf_size;
	    aesd_circular_buffer_add_entry(&my_data->buffer, &entry); // memleak after 10 writes
	    my_data->write_buf_size = 0;
	    my_data->write_buf = NULL;
    }
    retval = count;
    mutex_unlock(&my_data->lock);

    /**
     * TODO: handle write
     */
exit:
    return retval;
}
struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}

int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    aesd_circular_buffer_init(&aesd_device.buffer);
    aesd_device.write_buf = NULL;
    aesd_device.write_buf_size = 0;
    mutex_init(&aesd_device.lock);

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);
    struct aesd_buffer_entry *entry;

    cdev_del(&aesd_device.cdev);

    mutex_destroy(&aesd_device.lock);

    if (aesd_device.write_buf != NULL) {
	kfree(aesd_device.write_buf);
    }

    while ((entry = aesd_circular_buffer_remove_oldest(&aesd_device.buffer)) != NULL) {
	kfree(entry->buffptr);
    }

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
