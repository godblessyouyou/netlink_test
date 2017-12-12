#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <linux/bio.h>

#define NETLINK_TEST 21
#define MAX_SPACE_NAME_LEN 20
#define MAX_MSG_LEN 36864
#define MAX_PAYLOAD 81920
#define IO_LEN 4096

struct sock *nl_sk = NULL;
EXPORT_SYMBOL_GPL(nl_sk);

typedef struct sanlock_read_message {
    unsigned int blknum;
    unsigned int offset;
    unsigned int len;
    unsigned char operation;
    char space_name[MAX_SPACE_NAME_LEN];
    char buff[0];
}nl_msg;

static void handle_complete(struct bio *bio, int err)
{
    if (err) {
        printk(KERN_ERR "Handle lock read or write error %d\n", err);
    }
    complete(bio->bi_private);
    bio_put(bio);
}

/* bdev, open the device
 * blknum, block number to read or write
 * offset, which pos to read or write
 * length, the data length to read or write
 * do_write, 1, write, 0, read
 */
static int lock_area_block_io(struct block_device *bdev, uint64_t blknum, unsigned int offset, 
			      unsigned int length, struct page *raw_data, int do_write)
{
    int ret = 0;
    struct bio *bio;
    struct completion event;

    init_completion(&event);
    bio = bio_alloc(GFP_KERNEL, 1);
    bio->bi_bdev = bdev;
    bio->bi_sector = (blknum << (12 - 9)) + offset / 512; // 4K = 2**12, and sector = 2**9
    bio->bi_private = &event;
    bio->bi_end_io = handle_complete;

    bio_add_page(bio, raw_data, length, 0);
    do_write ? submit_bio(WRITE|REQ_SYNC, bio) : submit_bio(READ|REQ_SYNC, bio);
    wait_for_completion(&event);

    ret = test_bit(BIO_UPTODATE, &bio->bi_flags);
    return ret;
}

static ssize_t data_process(struct block_device *bdev, uint64_t blknum, unsigned int offset,
			    unsigned int length, char *read_data, int flags) 
{
    ssize_t pos = 0;
    struct page *tmp_data = NULL;
    /* read may get 512 bytes or 36Kb;
     * so we should confirm the length, and offset, to call lock_area_block_io.
     */
    int times = length / IO_LEN; // each bio is 4Kb
    if (times == 0) {
        lock_area_block_io(bdev, blknum, offset, length, tmp_data, 0);
        memcpy(read_data, page_address(tmp_data), length); // length is 512 bytes
	pos = length;
    }
    else if(times == 9) {
        int i;
        for(i = 0; i < times; i++) {
            blknum += i;
            lock_area_block_io(bdev, blknum, offset, IO_LEN, tmp_data, 0);
            strcat(read_data, page_address(tmp_data));
            tmp_data = NULL;
        }
	pos = length;
    }

    return pos;
} 

void respond_msg(u32 pid, nl_msg *msg) {
    struct sk_buff *skb = alloc_skb(NLMSG_SPACE(msg->len), GFP_ATOMIC);
    struct nlmsghdr *nlh = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(msg->len), 0);
    NETLINK_CB(skb).creds.pid = 0;
    int rc = 0;

    // check the operation, read or write.
    if (!msg->operation) {
        //char *read_data = kmalloc(msg.len, GFP_ATOMIC);
        //struct block_device *bdev = blkdev_get_by_path(msg.space_name, FMODE_WRITE|FMODE_READ, NULL);
        //data_process(bdev, msg.blknum, msg.offset, msg.len, read_data, 0);
        char *read_data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        strcpy(NLMSG_DATA(nlh), read_data);
    
        // start to send
        rc = netlink_unicast(nl_sk, skb, pid, MSG_DONTWAIT);
        if (rc < 0) {
            printk(KERN_ERR "net_link: can not unicast skb (%d)\n", rc);
        }
        printk("net_link: send is ok.\n");
        //kfree(bdev);
        return;
    }
    //struct block_device *bdev = blkdev_get_by_path(msg.space_name, FMODE_WRITE|FMODE_READ, NULL);
    //data_process(bdev, msg.blknum, msg.offset, msg.len, read_data, 1);
    // start to send

    char *write_recv = msg->buff;
    strcpy(NLMSG_DATA(nlh), write_recv);
    rc = netlink_unicast(nl_sk, skb, pid, MSG_DONTWAIT);
    if (rc < 0) {
        printk(KERN_ERR "net_link: can not unicast skb (%d)\n", rc);
    }
    printk("net_link: send is ok.\n");
    //kfree(bdev);
    return;
}

void nl_data_ready(struct sk_buff *__skb)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    u32 pid;
    nl_msg *msg;
    printk("net_link: data is ready to read.\n");

    skb = skb_get(__skb);
    printk("skb length is %d.\n", skb->len);
    // header is 16 bytes, nl_msg is 32 bytes
    if (skb->len >= NLMSG_SPACE(sizeof(nl_msg))) {
        // the size may be 512 or 36 * 1024
        msg = kmalloc(sizeof(nl_msg) + MAX_MSG_LEN, GFP_KERNEL);
        nlh = nlmsg_hdr(skb);
        memcpy(msg, NLMSG_DATA(nlh), MAX_MSG_LEN + sizeof(nl_msg));
        pid = nlh->nlmsg_pid; /*pid of sending process */
        printk("net_link: pid is %d\n", pid);
        kfree_skb(skb);
        respond_msg(pid, msg);
    }
    return;
}

static int test_netlink(void) {
    struct netlink_kernel_cfg cfg = {
        .input = nl_data_ready,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST, &cfg);
    if (!nl_sk) {
        printk(KERN_ERR "net_link: Cannot create netlink socket.\n");
        return -EIO;
    }
    printk("net_link: create socket ok.\n");
    return 0;
}

static int netlink_init(void)
{
    test_netlink();
    return 0;
}

static void netlink_exit(void)
{
    if (nl_sk){
        netlink_kernel_release(nl_sk);
    }
    printk("net_link: remove ok.\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("inspur");

module_init(netlink_init);
module_exit(netlink_exit);
