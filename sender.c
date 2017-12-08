#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <fcntl.h>

#define PORT 21
#define MAX_SPACE_NAME_LEN 20
#define MAX_MSG_LEN 36864 /* 36Kb */
#define MAX_PAYLOAD 81920 /* maximum payload size*/

typedef struct sanlock_read_message {
    unsigned int blknum;
    unsigned int offset;
    unsigned int len;
    char space_name[MAX_SPACE_NAME_LEN];
    char buff[0];
}nl_msg;


static int create_socket(struct sockaddr_nl *dest_addr)
{
    int sock_fd;
    struct sockaddr_nl src_addr;
    sock_fd = socket(PF_NETLINK, SOCK_RAW, PORT);
    // src_addr define
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); /* self pid */
    src_addr.nl_groups = 0; /* not in mcast groups */
    bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));

    // dest_addr define
    memset(dest_addr, 0, sizeof(dest_addr));
    dest_addr->nl_family = AF_NETLINK;
    dest_addr->nl_pid = 0; /* For Linux Kernel */
    dest_addr->nl_groups = 0; /* unicast */

    return sock_fd;
}

static void handle_message(int sock_fd, struct sockaddr_nl dest_addr, nl_msg *msg_data)
{
    struct msghdr msg;
    struct iovec iov;
    struct nlmsghdr *nlh=(struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    
    /* Fill the netlink message header */
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD); // the message len may be 512 or 36 * 1024
    nlh->nlmsg_pid = getpid(); /* self pid */
    nlh->nlmsg_flags = 0;
    memcpy(NLMSG_DATA(nlh), msg_data, sizeof(nl_msg));

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;

    // fill the message
    memset(&msg, 0, sizeof(msg));    
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    sendmsg(sock_fd, &msg, 0);
    
    // receive message
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    recvmsg(sock_fd, &msg, 0);
    printf("received message is: %s\n", NLMSG_DATA(nlh));
}


/* read net link message length is
 *
 *
 */
static int read_lockspace(unsigned long int blknum, unsigned int offset, 
                            unsigned int len, char *uuid, void *buff)
{
    int fd;
    struct sockaddr_nl dest_addr;
    int sock_fd;
    nl_msg msg;
    msg.blknum = blknum;
    msg.len = len;
    msg.offset = offset;
    strcpy(msg.space_name, uuid);

    // start to send the msg and receive msg
    sock_fd = create_socket(&dest_addr);
    handle_message(sock_fd, dest_addr, &msg);
    close(sock_fd);
}

/*
    write_lockspace or read_lockspace.
    according to the length, fill the message.
    send the message and wait the respond.
    return result.
*/
int main(int argc, char* argv[])
{
    int ret = read_lockspace(0, 1, 20, "/dev/sdb", "hello_world..");
    return ret;
}
