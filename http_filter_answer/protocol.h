#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include <rte_byteorder.h>

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

struct dns_hdr {
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
} __attribute__((__packed__));

struct resrec {
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t len;
} __attribute__((__packed__));

static inline bool
is_printable_char(char c){
  return ((c >= 'a' && c <= 'z') ||
          (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9'));
}

static inline int
domain_reader(uint8_t *dns_pointer){
  uint8_t * c;
  uint8_t len;
  char domain[100];

  c = dns_pointer;
  while(*c != 0){
    c++;
  }
  len = c - dns_pointer + 1; // for memory
  memcpy(domain, dns_pointer+1, len-1);  //length of domain name (dpdk.ninja)
  for(int i = 0; i < len - 2; i++){  // pre&post counts '4'dpdk5ninja'0'
    if(!is_printable_char(domain[i]))
      domain[i] = '.';
  }
  printf("Domain %s\n", domain);

  return len;
}

/*
static inline size_t
analyze_rr(uint8_t * ptr){
  const uint8_t * const ptr_head = ptr; // const hoge * const makes changing VALUE impossible as well as its ADDRESS
  if(*ptr == 0xc0){
    ptr++;
    //printf("Offset 0x%x\n", *ptr);
    ptr++;
  } else{
    ptr += domain_reader(ptr);
  }
  struct resrec *rr = (struct resrec *)(ptr);
  printf("Type %x\n", rte_be_to_cpu_16(rr->type));
  printf("Class %x\n", rte_be_to_cpu_16(rr->class));
  printf("Time to Live %d\n", rte_be_to_cpu_32(rr->ttl));
  printf("Length %x\n", rte_be_to_cpu_16(rr->len));
  ptr += sizeof(struct resrec);
  return ptr - ptr_head;
}
*/

static inline size_t
analyze_eth(uint8_t * ptr, struct eth_hdr ** eth){
  const uint8_t * const ptr_head = ptr;
  *eth = (struct eth_hdr *)(ptr);
  (void)(*eth);

  /*
  //if (length < sizeof(struct eth_hdr)) return ; // error
  printf("\n=====DATA LINK=====\n");
  printf("dst %02x:%02x:%02x:%02x:%02x:%02x\n", eth->dst[0], eth->dst[1], eth->dst[2], eth->dst[3], eth->dst[4], eth->dst[5]);
  printf("src %02x:%02x:%02x:%02x:%02x:%02x\n", eth->src[0], eth->src[1], eth->src[2], eth->src[3], eth->src[4], eth->src[5]);
  */
  //printf("type\n%x", rte_be_to_cpu_16(eth->type));
  /*
  switch(rte_be_to_cpu_16((*eth)->type)){
    case eth_ipv4:
      printf("Type IPv4\n");
      break;
    case eth_arp:
      printf("Type ARP\n");
      break;
    case eth_ipv6:
      printf("Type IPv6\n");
      break;
    default:
      //printf("Type error\n");
      break;
  }
  */
  ptr += sizeof(struct eth_hdr);
  return ptr - ptr_head;
}

static inline size_t
analyze_ip(uint8_t * ptr, struct ip4_hdr ** ip){
  const uint8_t * const ptr_head = ptr;
  *ip = (struct ip4_hdr *)(ptr);

  /*
  printf("\n=====NETWORK=====\n");
  printf("Version %02x\n", (ip->version_ihl & 0xf0) >> 4);
  printf("Header Length %d\n", (ip->version_ihl & 0x0f) * 4);
  printf("Type of Service %d\n", ip->tos);
  printf("Total Length%d\n", rte_be_to_cpu_16(ip->totlen));
  printf("Identification %d\n", rte_be_to_cpu_16(ip->id));
  printf("Type of Service %d\n", rte_be_to_cpu_16(ip->flag_off));
  printf("Time to Live %d\n", ip->ttl);
  //printf("Protocol %d\n", ip->proto);
  switch(ip->proto){
    case ipproto_icmp:
      printf("Protocol ICMP\n");
      break;
    case ipproto_tcp:
      printf("Protocol TCP\n");
      break;
    case ipproto_udp:
      printf("Protocol UDP\n");
      break;
    default:
      printf("Protocol error\n");
      break;
  }
  printf("Checksum %d\n", rte_be_to_cpu_16(ip->checksum));
  */
  printf("Source IP %3d.%3d.%3d.%3d / Destination IP %3d.%3d.%3d.%3d\n",
      (*ip)->src[0], (*ip)->src[1], (*ip)->src[2], (*ip)->src[3], (*ip)->dst[0], (*ip)->dst[1], (*ip)->dst[2], (*ip)->dst[3]);
  //printf("Destination IP %3d.%3d.%3d.%3d\n", (*ip)->src[0], (*ip)->src[1], (*ip)->src[2], (*ip)->src[3]);

  ptr += sizeof(struct ip4_hdr);
  return ptr - ptr_head;
}

static inline size_t
analyze_udp(uint8_t * ptr, struct udp_hdr ** udp){
  const uint8_t * const ptr_head = ptr;
  *udp = (struct udp_hdr *)(ptr);

  //printf("\n=====TRANSPORT=====\n");
  printf("Source Port %x / Destination Port %x\n",
      rte_be_to_cpu_16((*udp)->src_port), rte_be_to_cpu_16((*udp)->dst_port));
  //printf("Destination Port %d\n", rte_be_to_cpu_16((*udp)->dst_port));
  /*
  printf("Length %d\n", rte_be_to_cpu_16(udp->len));
  printf("Checksum %d\n", rte_be_to_cpu_16(udp->cksum));
  */

  ptr += sizeof(struct udp_hdr);
  return ptr - ptr_head;
}

/*
static inline size_t
analyze_dns(uint8_t * ptr, struct dns_hdr * dns){
  const uint8_t * const ptr_head = ptr;
  *dns = (struct dns_hdr *)(ptr);
  uint16_t qdc = rte_be_to_cpu_16(dns->qdcount);
  uint16_t anc = rte_be_to_cpu_16(dns->ancount);
  uint16_t nsc = rte_be_to_cpu_16(dns->nscount);
  uint16_t arc = rte_be_to_cpu_16(dns->arcount);

  printf("\n=====APPLICATION=====\n");
  printf("ID %d\n", rte_be_to_cpu_16(dns->id));
  printf("Flags %d\n", rte_be_to_cpu_16(dns->flags));
  printf("QD Count %d\n", qdc);
  printf("AN Count %d\n", anc);
  printf("NS Count %d\n", nsc);
  printf("AR Count %d\n", arc);

  struct query {
    uint16_t type;
    uint16_t class;
  } __attribute__((__packed__));

  //printf("\n---question---\n");
  for(int i = 0; i < qdc; i++){
    ptr += domain_reader(ptr);
    struct query *qry = (struct query *)(ptr);
    //printf("Type %x\n", rte_be_to_cpu_16(qry->type));
    //printf("Class %x\n", rte_be_to_cpu_16(qry->class));
    ptr += sizeof(struct query);
  }

  //printf("\n---answer---\n");
  for(int i = 0; i < anc; i++){
    ptr += analyze_rr(ptr);
    //printf("Address %3d.%3d.%3d.%3d\n", *(ptr), *(ptr+1), *(ptr+2), *(ptr+3));
    ptr+=4;
  }

  //printf("\n---authority---\n");
  for(int i = 0; i < nsc; i++){
    analyze_rr(ptr);
  }

  //printf("\n---additional rec---\n");
  for(int i = 0; i < arc; i++){
    analyze_rr(ptr);
  }

  ptr += sizeof(struct dns_hdr);
  return ptr - ptr_head;
}
*/

static inline size_t
analyze_tcp(uint8_t * ptr, struct tcp_hdr ** tcp){
  *tcp = (struct tcp_hdr *)(ptr);

  /*
  printf("\n=====TRANSPORT=====\n");
  */
  printf("Source Port %02x / Destination Port %02x\n",
      rte_be_to_cpu_16((*tcp)->src_port), rte_be_to_cpu_16((*tcp)->dst_port));
  //printf("Destination Port %02x\n", rte_be_to_cpu_16((*tcp)->dst_port));
  /*
  printf("Sequence Number %02x\n", rte_be_to_cpu_32(tcp->sent_seq));
  printf("Ack Number %02x\n", rte_be_to_cpu_32(tcp->recv_ack));
  */
  size_t len = ((*tcp)->data_off & 0xf0) >> 4;
  /*
  printf("Data Off %lx\n", len);
  printf("Flags %02x\n", tcp->tcp_flags);
  printf("Window %02x\n", rte_be_to_cpu_16(tcp->rx_win));
  printf("Checksum %02x\n", rte_be_to_cpu_16(tcp->cksum));
  printf("Urgent %02x\n", rte_be_to_cpu_16(tcp->tcp_urp));
  */

  return len * 4;
}

#endif
