#ifndef __FILLPACKET__H_
#define __FILLPACKET__H_

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

typedef char u8;
typedef unsigned short u16;

#define PACKET_SIZE    92
#define IP_OPTION_SIZE 8
#define ICMP_PACKET_SIZE   PACKET_SIZE - (int)sizeof(struct ip) - IP_OPTION_SIZE
#define ICMP_DATA_SIZE     ICMP_PACKET_SIZE - (int)sizeof(struct icmphdr)
#define DEFAULT_SEND_COUNT 4
#define DEFAULT_TIMEOUT 1500

typedef struct
{
	struct ip ip_hdr;
	struct icmphdr icmp_hdr;
	u8 data[10];
} myicmp ;

void 
fill_iphdr (struct ip *ip_hdr, const char* dst_ip);

void
fill_icmphdr (struct icmphdr *icmp_hdr, u8 *data,int pid, int seq);

u16
fill_cksum (u16 *b, int len);

#endif

