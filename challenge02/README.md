
# 事前課題2 c言語によるパケット解析入門

本課題で使用するサンプルコード. 以下のプログラムを編集して
いくつかの課題をこなしてもらいます！遊びだと思って楽しくできたら幸いです。

ヒントとしてキーワードを用意したのでそれを参考にGoogleで検索したり,
チューターや講師に頼ってください.

```c:main.c
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

static const unsigned char pkt131[66] = {
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

int main()
{
	return 0;
}
```


## 課題 パケットのヘッダを解析してみよう

上記のプルグラムの``pkt131``という変数にパケットのデータのポインタがあります。
``pkt131``と``eth_hdr``構造体と``ip4_hdr``構造体をつかってEthernetヘッダと
IPヘッダの各要素を正しく表示するプログラムを書いてみてください.

キーワード[ethernetヘッダ, ipヘッダ, c言語 構造体 ポインタ, htons, ntohs]


## 課題 htons,htonl,ntohs,ntohl関数は何者?

課題1ではntohs関数やhtons関数を使う機会が出たかもしれません。
ではこれらの関数は一体何を表しているでしょうか。
以下のキーワードを用いて軽く説明してみてください

キーワード[endian, network-byte-order, host-byte-order]






