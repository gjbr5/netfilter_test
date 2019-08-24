#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <linux/netfilter.h> /* for NF_ACCEPT */
#include <linux/types.h>

#include "callback.h"

static std::set<std::string> blacklist;

static int cb(struct nfq_q_handle *qh,
              struct nfgenmsg * /*nfmsg*/,
              struct nfq_data *nfa,
              void * /*data*/)
{
    u_int32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }
    return nfq_set_verdict(qh, id, filter(nfa, blacklist), 0, nullptr);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: %s <host1> <host2> <host3>...\n", argv[0]);
        return 0;
    }
    //    iptables
    system("sudo iptables -A INPUT -j NFQUEUE");
    system("sudo iptables -A OUTPUT -j NFQUEUE");

    for (int i = 1; i < argc; i++)
        blacklist.insert(argv[i]);

    char buf[4096] __attribute__((aligned));

    printf("opening library handle\n");

    struct nfq_handle *h = nfq_open();
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

    struct nfq_q_handle *qh = nfq_create_queue(h, 0, &cb, nullptr);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    int fd = nfq_fd(h);

    for (;;) {
        int rv = static_cast<int>(recv(fd, buf, sizeof(buf), 0));
        if (rv >= 0) {
            //printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
        }
        /* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
        else if (errno == ENOBUFS) {
            printf("losing packets!\n");
        } else {
            perror("recv failed");
            break;
        }
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
}
