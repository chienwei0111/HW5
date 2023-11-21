#include "fill_packet.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "debug.h"

void 
fill_iphdr ( struct ip *ip_hdr , const char* dst_ip)
{
	ip_hdr->ip_hl = sizeof(struct ip) / 4 ;
	ip_hdr->ip_v = IPVERSION;
	ip_hdr->ip_len = htons(PACKET_SIZE);
	ip_hdr->ip_tos = 0;
	ip_hdr->ip_id = htons(0);
	ip_hdr->ip_off = htons(IP_DF);
	ip_hdr->ip_ttl = 1;
	ip_hdr->ip_p = IPPROTO_ICMP;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = fill_cksum((u16 *)ip_hdr,sizeof(struct ip)/2);
	ip_hdr->ip_src.s_addr = inet_addr("10.0.2.15");
	ip_hdr->ip_dst.s_addr = inet_addr(dst_ip);
	//printf("IP header");
	//print_buffer((const unsigned char *) ip_hdr, sizeof(struct ip));
}

void
fill_icmphdr (struct icmphdr *icmp_hdr, u8 *data,int pid, int seq)
{
	
    	// Copy data into ICMP payload
    	char *myID="M123140018";
	strncpy(data, myID, strlen(myID)+1);

	icmp_hdr->type = ICMP_ECHO;
        icmp_hdr->code = 0;
        icmp_hdr->un.echo.id = htons(pid);
        icmp_hdr->un.echo.sequence = htons(seq);
        icmp_hdr->checksum = 0;
	//printf("ICMP header");
        
	// Calculate checksum including data
    	icmp_hdr->checksum = fill_cksum((u16 *)icmp_hdr, sizeof(struct icmphdr) / 2 +
                                             sizeof("M123140018") / 2);
	//print_buffer((const unsigned char *) icmp_hdr, sizeof(struct icmphdr));
}

u16
fill_cksum(u16 *buf, int len)
{
	unsigned long sum = 0;
	while (len-- > 0) {
        	sum += *buf++;
    	}
    	sum = (sum >> 16) + (sum & 0xffff);
    	sum += (sum >> 16);
    	return (unsigned short)(~sum);
}


