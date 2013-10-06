
/**
 * This little example shows how using nfq (netfiler queue)
 * reinject packet, and set RST instead of FIN.
 *
 * (need for some crawling tests)
 *
 * Based on nfq/utils/nfqnl_test.c
 * (Created only to reporduce some issues, it is far from perfect.)
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <limits.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#define bool int
#include <libnetfilter_queue/pktbuff.h>
#undef bool
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>

#include <linux/tcp.h> // tcphdr
#include <string.h>


struct cb_arg
{
	uint64_t num_of_rst_pkt;
	uint64_t win_rst;
};

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *arg)
{
	char buf[PATH_MAX] __attribute__ ((aligned));
	struct cb_arg *cb_arg = (struct cb_arg *)arg;

	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;

	unsigned char *data;
	int packet_len;

	struct pkt_buff *pkt;
	struct tcphdr *tcp;
	struct iphdr *ip;

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
	}
	packet_len = nfq_get_payload(nfa, &data);
	pkt = pktb_alloc(AF_INET /* TODO */, data, packet_len, 0);
	ip = nfq_ip_get_hdr(pkt);
	nfq_ip_set_transport_header(pkt, ip);
	tcp = nfq_tcp_get_hdr(pkt);
	if (tcp) {
		/**
		 * TODO: swapping it
		 */
		if (tcp->fin && !tcp->psh) {
			++cb_arg->num_of_rst_pkt;

			if ((cb_arg->num_of_rst_pkt % 2) == 1) {
				cb_arg->win_rst = 1;
				tcp->window = 0;
			}
			
			// tcpdump call this "th_offx2"
			tcp->doff = 5;
			tcp->fin = 0;
			tcp->rst = 1;
			nfq_ip_set_checksum(ip);
			nfq_tcp_compute_checksum_ipv4(tcp, ip);

			memcpy(data, pktb_data(pkt), packet_len);
		}

		nfq_tcp_snprintf(buf, PATH_MAX, tcp);
		printf("%s\n", buf);
	} else {
		printf("%s\n", "NOT TCP");
	}

	pktb_free(pkt);
	return nfq_set_verdict(qh, id, NF_ACCEPT, packet_len, data);
}

int main(int argc, char **argv)
{
	struct cb_arg cb_arg;
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

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
	qh = nfq_create_queue(h,  0, &cb, &cb_arg);
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
		 * on your application, this error may be ignored. Please, see
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
}

