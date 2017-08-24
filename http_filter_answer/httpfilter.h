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

#ifndef _HTTPFILTER_H_
#define _HTTPFILTER_H_

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
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_ethdev.h>

#include "protocol.h"

#define FIN (0x01 << 0)
#define SYN (0x01 << 1)
#define RST (0x01 << 2)
#define PSH (0x01 << 3)
#define ACK (0x01 << 4)
#define URG (0x01 << 5)

inline static bool is_domain(uint8_t * ptr){
  //printf("\n=====HTTP=====\n");
  const char httpget[] = "GET / HTTP/1.1\r\nHost: dpdk.ninja\r\n";
  return memcmp(ptr, httpget, sizeof(httpget)-1) == 0;
}

inline static void send_rst_ack(struct rte_mbuf* m,
    uint8_t srcip[4], uint8_t dstip[4],
    uint16_t srcport, uint16_t dstport,
    uint32_t seq, uint32_t ack){

  struct ether_hdr *eth;
  struct ip4_hdr *ip;
  struct tcp_hdr *tcp;
  size_t pkt_size;

  // ==========CRAFTING PACKET==========
  // -----ethernet-----
  eth = rte_pktmbuf_mtod(m, struct ether_hdr *);  // points to start of the data in the mbuf, return type
  rte_eth_macaddr_get(0, &eth->s_addr); // port, macAddr of Eth device
  memset(&eth->d_addr, 0xFF, ETHER_ADDR_LEN); // FF:FF:FF:FF:FF
  eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4); // CPU's endian -> big endian

  // -----ip-----
  ip = (struct ip4_hdr *)(eth+1);
  ip->version_ihl = 0x45;
  ip->tos = 0x00;
  ip->totlen = rte_cpu_to_be_16(sizeof(struct ip4_hdr) + sizeof(struct tcp_hdr));
  ip->id = rte_cpu_to_be_16(0xbeef);
  ip->flag_off = rte_cpu_to_be_16((0x02 << 13) & 0x00); // 0x02 and 0x00 -> 010 0000000000000(13 bits)
  ip->ttl = 0x40;
  ip->proto = 0x06;
  ip->checksum = 0;
  for(int i = 0; i < 4; i++){
    ip->src[i] = srcip[i];
    ip->dst[i] = dstip[i];
  }
  ip->checksum = (rte_ipv4_cksum((struct ipv4_hdr *)ip));

  // -----tcp-----
  tcp = (struct tcp_hdr *)((uint8_t *)ip + (ip->version_ihl & 0x0f)* 4);
  tcp->src_port = rte_cpu_to_be_16(srcport);
  tcp->dst_port = rte_cpu_to_be_16(dstport);
  tcp->sent_seq = rte_cpu_to_be_32(seq);

  tcp->recv_ack = rte_cpu_to_be_32(ack);
  size_t hl = (ip->version_ihl&0x0f) << 2;
  tcp->recv_ack = rte_cpu_to_be_32(ack + (ip->totlen - hl));

  tcp->data_off = (sizeof(struct tcp_hdr) / 4) << 4;
  tcp->tcp_flags = RST | ACK;
  tcp->rx_win = rte_cpu_to_be_16(4000);
  tcp->cksum = 0;
  tcp->tcp_urp = rte_cpu_to_be_16(0);
  tcp->cksum =  (rte_ipv4_udptcp_cksum((struct ipv4_hdr*)ip, tcp));

  pkt_size = sizeof(struct ether_hdr) + sizeof(struct ip4_hdr) + sizeof(struct tcp_hdr);
  m->data_len = pkt_size;
  m->pkt_len = pkt_size;
  // ==========CRAFTING PACKET==========

  rte_eth_tx_burst(m->port, 0, &m, 1);
  //rte_hexdump(stdout, "hoge", rte_pktmbuf_mtod(m, struct ether_hdr *), m->pkt_len);
}

#endif
