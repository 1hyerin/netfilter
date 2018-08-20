/* 2018-08-20 */
/* BoB 7th Consulting 1hyerin */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <errno.h>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

/* IP header */
  struct ip_header {
    u_int8_t ip_vhl; /* version and header length */
    u_int8_t ip_tos;  /* type of service */
    u_int16_t ip_len; /* total length */
    u_int16_t ip_id; /* identification */
    u_int16_t ip_off; /* fragment offset field */
    #define IP_RF 0x8000 /* reserved fragment flag */
    #define IP_DF 0x4000 /* dont fragment flag */
    #define IP_MF 0x2000 /* more fragments flag */
    #define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
    u_int8_t ip_ttl; /* time to live */
    u_int8_t ip_p; /* protocol */
    u_int16_t ip_sum; /* checksum */
    struct in_addr ip_source;   /* source ip address */
    struct in_addr ip_destination; /* dest ip address */
  };
  #define IP_HL(ip)   (((ip)->ip_vhl) & 0x0f) //ip_vhl = ip_version(4bit) + ip_header_length(4bit) 
  #define IP_V(ip)    (((ip)->ip_vhl) >> 4)


  /* TCP header */
  typedef u_int tcp_seq;

  struct tcp_header{
    u_int16_t th_sport; /* source port */
    u_int16_t th_dport; /* destination port */
    u_int32_t th_seq; /* sequence number */
    u_int32_t th_ack; /* acknowledgement number */
    u_int8_t th_off_x2; /* data offset & (unused) */
    #define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)  //th_off(8bit) = data_offset(4bit) + reserved(3bit) 
    u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    u_int16_t th_win; /* window */
    u_int16_t th_sum; /* checksum */
    u_int16_t th_urp; /* urgent pointer */
};
/* -------------------------------------------------------------------------- */

int checking = 0;
char* blockingSite;


void usage() {
  printf("sample: netfilter_block www.sex.com\n");
}

void dump(uncheckinged char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0) {
            printf("\n");
        }
        printf("%02x ", buf[i]);
    }
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb) {
    //refernece: https://github.com/irontec/netfilter-nfqueue-samples/blob/master/sample-helloworld.c
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark, ifi; 
    int ret;
    uncheckinged char *data;


    struct ip_header* netfilter_ip;
    struct tcp_header* netfilter_tcp;

    char* host;
    char* str[6] = {"GET","POST", "HEAD", "PUT", "DELETE", "OPTIONS"};

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }
    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
    {   
        dump(data, ret);
        int ipSize, tcpSize;

        netfilter_ip = (struct ip_header*)(data);
        ipSize = IP_HL(netfilter_ip)*4; //ip header length

        if(netfilter_ip->ip_p == 6){
            netfilter_tcp = (struct tcp_header*)(data + ipSize);
            tcpSize = ((((netfilter_tcp)->th_offx2 & 0xf0) >> 4) * 4;//tcp header size

            for(int i=0;i<6;i++) {
                int chkFirst = strncmp((data + ipSize + tcpSize), str[i], strlen(str[i]));
                if(chkFirst == 0) {
                    for(int j = 0;j<strlen(data + ipSize + tcpSize + strlen(str[i]));j++){
                        int chkNext = strncmp(data + ipSize + tcpSize + strlen(str[i]) + j, "Host: ", strlen("Host: "));

                        if(chkNext == 0){
                            printf("Checking the host\n");
                            int chkFinal = strncmp(data + ipSize + tcpSize + strlen(str[i]) + j + strlen("Host: "), url, strlen(url));

                            if(chkFinal == 0){
                                host = (char*)malloc(sizeof(url));
                                strncpy(host, data + ipSize + tcpSize + j + strlen(str[i])+strlen("Host: "), strlen(url));
                                printf("Target: %s\n", host);
                                checking = 1; 
                            }
                        }
                    }
                }
            }
        }
    }
    fputc('\n', stdout);
    return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    printf("entering callback\n");
    if(checking == 0)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    else{
        checking = 0;
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
}

int main(int argc, char **argv)
{
    if (argc != 2) {
    usage();
    return -1;
    }

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));


    blockingSite = (char*)malloc(sizeof(strlen(argv[1])));
    strcpy(blockingSite, argv[1]);

    system("iptables -L");
    system("iptables -F");
    system("iptables -A INPUT -j NFQUEUE --queue-num 0");
    system("iptables -A OUTPUT -j NFQUEUE --queue-num 0");



     /*------------------------------------------------------------------------*/
    //Reference: https://lists.debian.org/debian-user/2012/04/msg01639.html
    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
    /*------------------------------------------------------------------------*/
}
