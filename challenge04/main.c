

/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   Copyright(c) 2017 Hiroki SHIROKURA All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_hexdump.h>
#include <rte_log.h>
#include <rte_mbuf.h>



enum eth_type {
	eth_ipv4 = 0x0800,
	eth_arp  = 0x0806,
	eth_ipv6 = 0x86dd,
};

struct eth_hdr {
	uint8_t  dst[6];
	uint8_t  src[6];
	uint16_t type;
} __attribute__((__packed__));

enum ip_proto {
	ipproto_icmp = 1,
	ipproto_tcp  = 6,
	ipproto_udp  = 17,
};

struct ip4_hdr {
	uint8_t  version_ihl;
	uint8_t  tos;
	uint16_t totlen;
	uint16_t id;
	uint16_t flag_off;
	uint8_t  ttl;
	uint8_t  proto;
	uint16_t checksum;
	uint8_t  src[4];
	uint8_t  dst[4];
} __attribute__((__packed__));

struct udp_hdr {
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t len;
  uint16_t cksum;
} __attribute__((__packed__));


static struct rte_mbuf* get_pkt(void)
{
	static const unsigned char dns_pkt[] = {
		0x74, 0x03, 0xbd, 0x3d, 0x78, 0x96, 0x00, 0xa0,
		0xde, 0xc6, 0x52, 0x07, 0x08, 0x00, 0x45, 0x00,
		0x00, 0x48, 0x09, 0x47, 0x00, 0x00, 0xff, 0x11,
		0x59, 0x16, 0xac, 0x14, 0x00, 0x01, 0xac, 0x14,
		0x01, 0x1e, 0x00, 0x35, 0xd2, 0xf4, 0x00, 0x34,
		0x73, 0x43, 0xb0, 0x00, 0x81, 0x80, 0x00, 0x01,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x64,
		0x70, 0x64, 0x6b, 0x05, 0x6e, 0x69, 0x6e, 0x6a,
		0x61, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c,
		0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x08, 0x39,
		0x00, 0x04, 0xa3, 0x2c, 0xa5, 0x31
	};

	const size_t NUM_MBUFS = 8191;
	const size_t MBUF_CACHE_SIZE = 250;
	struct rte_mempool *mempool;
	mempool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mempool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	struct rte_mbuf* m = rte_pktmbuf_alloc(mempool);
	uint8_t* p = rte_pktmbuf_mtod(m, uint8_t*);
	size_t   l = sizeof(dns_pkt);
	m->pkt_len  = l;
	m->data_len = l;
	memcpy(p, dns_pkt, l);
	return m;
}

static void analyze_packet(struct rte_mbuf* m)
{
	rte_hexdump(stdout, "Packet-Hexdump",
			rte_pktmbuf_mtod(m, uint8_t*), m->pkt_len);
}

int main(int argc, char **argv)
{
	int ret = rte_eal_init(argc, argv);
	if (ret < 0) rte_panic("Cannot init EAL\n");

	struct rte_mbuf* m = get_pkt();
	analyze_packet(m);
	return 0;
}


