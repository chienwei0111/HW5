#include "pcap.h"
#include <sys/types.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <string.h>


extern pid_t pid;
extern u16 icmp_req;

static const char* dev = "enp0s3";
static char* net;
static char* mask;

static char filter_string[FILTER_STRING_SIZE] = " icmp and icmp[icmptype]=0";

static pcap_t *p;
static struct pcap_pkthdr *hdr=NULL;

/*
 * This function is almost completed.
 * But you still need to edit the filter string.
 */
void pcap_init_me( const char* dst_ip ,int timeout )
{	
	int ret;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	
	struct in_addr addr;
	
	struct bpf_program fcode;
	
	ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
	if(ret == -1){
		fprintf(stderr,"%s\n",errbuf);
		exit(1);
	}
	
	addr.s_addr = netp;
	net = inet_ntoa(addr);	
	if(net == NULL){
		perror("inet_ntoa");
		exit(1);
	}
	
	addr.s_addr = maskp;
	mask = inet_ntoa(addr);
	if(mask == NULL){
		perror("inet_ntoa");
		exit(1);
	}
	
	p = pcap_open_live(dev, 8000, 1, timeout, errbuf);
	if(!p){
		fprintf(stderr,"%s\n",errbuf);
		exit(1);
	}
	
	/*
	 *    you should complete your filter string before pcap_compile
	 */
//	pcap_setnonblock(p, 1, errbuf);	
	
	if(pcap_compile(p, &fcode, filter_string, 0, maskp) == -1){
		pcap_perror(p,"pcap_compile");
		exit(1);
	}
	
	if(pcap_setfilter(p, &fcode) == -1){
		pcap_perror(p,"pcap_setfilter");
		exit(1);
	}
}


int pcap_get_reply( void )
{
	int ptr;
	const u_char *content = NULL;
	ptr = pcap_next_ex(p, &hdr,&content);
	/*
	 * google "pcap_next" to get more information
	 * and check the packet that ptr pointed to.
	 */
		
	if(ptr == 1)
	{
		struct ip *ipHeader = (struct ip*)(content+14);
		if(ipHeader->ip_p == IPPROTO_ICMP)
		{
			const struct icmp* icmpHeader = (struct icmp*)(content +14+ipHeader->ip_hl*4);
			if(icmpHeader->icmp_type == 0)
			{
				printf("\n\tReply from %s success!",inet_ntoa(ipHeader->ip_src));
			/*	struct timeval timestamp = content->ts;
				long long rtt = (timestamp.tv_sec *1000 + timestamp.tv_usec /1000);
				printf("\n\tRTT: %lld ms\n",rtt);
			*/
			}
		}	

	}else
		printf("%d Timeout or FAIL!\n",ptr);

	pcap_close(p);
	return 0;
}
