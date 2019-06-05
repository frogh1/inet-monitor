#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/inet_diag.h>
#include <netinet/tcp.h>

static const char* tcp_states_map[]={
    [TCP_ESTABLISHED] = "ESTABLISHED",
    [TCP_SYN_SENT] = "SYN-SENT",
    [TCP_SYN_RECV] = "SYN-RECV",
    [TCP_FIN_WAIT1] = "FIN-WAIT-1",
    [TCP_FIN_WAIT2] = "FIN-WAIT-2",
    [TCP_TIME_WAIT] = "TIME-WAIT",
    [TCP_CLOSE] = "CLOSE",
    [TCP_CLOSE_WAIT] = "CLOSE-WAIT",
    [TCP_LAST_ACK] = "LAST-ACK",
    [TCP_LISTEN] = "LISTEN",
    [TCP_CLOSING] = "CLOSING"
};

#define MAGIC_SEQ 123456
//Copied from libmnl source
#define SOCKET_BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)

int socket_open()
{
    int nl_sock;
    struct sockaddr_nl local;
  
    if((nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_INET_DIAG)) == -1){
        printf("nl socket error\n");
        return -1;
    }

    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_pid = getpid();//it is not must
    local.nl_groups = 0;

    if (bind(nl_sock, (struct sockaddr *)&local, sizeof(struct sockaddr_nl)) < 0) {
        printf("bind socket error %s\n", strerror(errno));
        return -1;
    }

    return nl_sock;
}

int send_diag_msg(int sockfd){
    struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
    //In order to be universal，use inet_diag_req,not inet_diag_req_v2
    struct {
        struct nlmsghdr nlh;
        struct inet_diag_req r;
    } req = {
        .nlh.nlmsg_len = sizeof(req),
        .nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST,
        .nlh.nlmsg_seq = MAGIC_SEQ,
        .nlh.nlmsg_type = TCPDIAG_GETSOCK,
        .r.idiag_family = AF_INET,
        .r.idiag_states = ((1 << TCP_SYN_SENT) | (1 << TCP_LISTEN) | (1 << TCP_ESTABLISHED)),//filter
    };

    struct iovec iov = {.iov_base = &req, .iov_len = sizeof(req)};
    struct msghdr msg = {
        .msg_name = (void *)&nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
        };

    //send msg
    if (sendmsg(sockfd, &msg, 0) < 0 )
    {
        printf("sendmsg error %s\n",strerror(errno));
        return -1;
    }
    return 0;
}

void parse_diag_msg(struct inet_diag_msg *msg)
{
    char local[128]  = {0};//INET6_ADDRSTRLEN
    char remote[128] = {0};
    if(msg->idiag_family == AF_INET){
        inet_ntop(AF_INET, (struct in_addr*) &(msg->id.idiag_src),
            local, 128);
        inet_ntop(AF_INET, (struct in_addr*) &(msg->id.idiag_dst),
            remote, 128);
    } else if(msg ->idiag_family == AF_INET6){
        inet_ntop(AF_INET6, (struct in_addr6*) &(msg ->id.idiag_src),
                local, 128);
        inet_ntop(AF_INET6, (struct in_addr6*) &(msg ->id.idiag_dst),
                remote, 128);
    } else {
        printf( "Unknown family\n");
        return;
    }

    printf("type:%s state:%s srcip:%s sport:%d dstip:%s dport:%d uid:%d inode:%u iface:%u\n",(msg->idiag_family == AF_INET)?"ipv4":"ipv6",\
        tcp_states_map[msg->idiag_state],local,ntohs(msg->id.idiag_sport),remote,ntohs(msg->id.idiag_dport),msg->idiag_uid,msg->idiag_inode,\
        msg->id.idiag_if);

}


int recv_msg(int sock)
{
    struct sockaddr_nl nladdr;
    struct iovec iov;
    int status = 0;
    int msglen = 0;
    char recv_buf[SOCKET_BUFFER_SIZE];

    struct msghdr msg = {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    //recv msg from kernel
    iov.iov_base = recv_buf;
    iov.iov_len = sizeof(recv_buf);

    status = recvmsg(sock, &msg, 0);
    if (status < 0) {
        if (errno == EINTR || errno == EAGAIN)
            {
                printf("netlink receive error %s (%d)\n",strerror(errno), errno);
                return -1;
            }
        }

    if (status == 0) {
        printf("EOF on netlink\n");
        return 0;
    }

    struct nlmsghdr *h = (struct nlmsghdr*)recv_buf;
    msglen = status;
    while (NLMSG_OK(h, msglen)) {
        if (h->nlmsg_type == NLMSG_DONE) {
            printf("NLMSG_DONE\n");
            break;
        }

        if (h->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
            if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
                printf("ERROR truncated \n");
            }
            else {
                errno = -err->error;
                if(errno == ENOENT ||errno == EOPNOTSUPP)
                {
                    printf("RTNETLINK answers:%s\n", strerror(errno));
                }
            }
            return -1;
        }

        struct inet_diag_msg *inetmsg = (struct inet_diag_msg *)NLMSG_DATA(h);
        parse_diag_msg(inetmsg);

        h = NLMSG_NEXT(h, msglen);
    }
    
    return 0;

}

int main(int argc, char const *argv[])
{
    int nl_sock = 0;

    //create socket
    if ((nl_sock = socket_open()) < 0)
    {
        printf("open socket error\n");
        return EXIT_FAILURE;
    }
    
    //send request
    if(send_diag_msg(nl_sock) < 0){
        printf("send_diag_msg error\n ");
        close(nl_sock);
        return EXIT_FAILURE;
    }
    
    //receive msg
    recv_msg(nl_sock);

    close(nl_sock);
    return 0;
}
