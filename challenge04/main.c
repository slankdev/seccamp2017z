

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

struct tcp_hdr {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t sent_seq;
	uint32_t recv_ack;
	uint8_t  data_off;
	uint8_t  tcp_flags;
	uint16_t rx_win;
	uint16_t cksum;
	uint16_t tcp_urp;
} __attribute__((__packed__));

static const unsigned char pkt_raw[] = {
	0x00, 0xe0, 0x4d, 0x10, 0x15, 0x0c, 0x00, 0x23,
	0xdf, 0xff, 0xa8, 0xa7, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x34, 0x8c, 0x98, 0x40, 0x00, 0x40, 0x06,
	0x00, 0x00, 0xc0, 0xa8, 0x00, 0x84, 0xc0, 0xe5,
	0xed, 0x60, 0xe2, 0xea, 0x01, 0xbb, 0x70, 0x27,
	0x09, 0x7d, 0x05, 0x77, 0x78, 0x12, 0x80, 0x10,
	0x0f, 0x7d, 0x6f, 0x99, 0x00, 0x00, 0x01, 0x01,
	0x08, 0x0a, 0x3e, 0xc9, 0x69, 0xdf, 0x6d, 0xe7,
	0x40, 0x35
};

static void analyze_http(const uint8_t* pkt, size_t len)
{
	rte_hexdump(stdout, "Packet-Hexdump", pkt, len);
}

int main(int argc, char **argv)
{
	rte_log_set_global_level(RTE_LOG_EMERG);
	int ret = rte_eal_init(argc, argv);
	if (ret < 0) rte_panic("Cannot init EAL\n");

	analyze_http(pkt_raw, sizeof(pkt_raw));
	return 0;
}


