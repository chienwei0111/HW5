#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "debug.h"
#include "fill_packet.h"
#include "pcap.h"


pid_t pid;
void print_usage()
{
	printf("[Subnet IP Scanner]\n");
	printf("./ipscanner -i <network-interface-name> -t <timeout>\n");
}
int main(int argc, char* argv[])
{
	int sockfd,sockfd_recv;
	int on = 1,timeout = DEFAULT_TIMEOUT;
	struct ifreq ifr;
	char *interface = "eth0";
	struct in_addr network, broadcast;
	pid = getpid();
	if((argc < 5) || !strcmp(argv[1],"-h")) 
	{
		print_usage();
		exit(1);
	}
	if(!strcmp(argv[1],"-i"))
	{	
		interface = argv[2];
	}
	else 
	{
		print_usage();
		exit(1);
	}
	if(!strcmp(argv[3],"-t")) 
	{
		timeout = atoi(argv[4]);
	}
	else 
	{
		print_usage();
		exit(1);
	}
	struct sockaddr_in dst;
	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
    	//dst.sin_addr.s_addr = inet_addr(target_ip);	

	strncpy(ifr.ifr_name, interface, IFNAMSIZ);
	if(((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_RAW)) < 0)||((sockfd_recv = socket(AF_INET, SOCK_RAW , IPPROTO_RAW)) < 0))
        {
                perror("socket");
                exit(1);
        }
	// Get the IP address
    	if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
        	perror("ioctl");
        	close(sockfd);
        	return 1;
    	}

    	struct sockaddr_in *ipAddr = (struct sockaddr_in *)&ifr.ifr_addr;
    	char ip_interface[INET_ADDRSTRLEN];
	strncpy(ip_interface, inet_ntoa(ipAddr->sin_addr), INET_ADDRSTRLEN - 1);
	ip_interface[INET_ADDRSTRLEN - 1] = '\0';
	// Get the subnet mask
    	if (ioctl(sockfd, SIOCGIFNETMASK, &ifr) == -1) {
        	perror("ioctl");
        	close(sockfd);
        	exit(1);
    	}
    	struct sockaddr_in *subnetMask_addr = (struct sockaddr_in *)&ifr.ifr_netmask;
	char *subnetMask = inet_ntoa(subnetMask_addr->sin_addr);
       	//strncpy(subnetMask, inet_ntoa(subnetMask_addr->sin_addr), INET_ADDRSTRLEN - 1);
	//subnetMask[INET_ADDRSTRLEN - 1] = '\0';
	printf("Interface: %s / IP: %s / Submask: %s\n", interface, ip_interface, subnetMask);
	

	if(setsockopt( sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		perror("setsockopt");
		exit(1);
	}
	
	/*struct timeval timeout_t;
    	timeout_t.tv_sec = timeout/1000;
    	timeout_t.tv_usec = 0;

    	if (setsockopt(sockfd_recv, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_t, sizeof(timeout_t)) < 0) 
	{
        	perror("Error setting socket timeout");
        	close(sockfd_recv);
    		exit(1);
	}*/
	
	inet_pton(AF_INET, ip_interface, &network);
	inet_pton(AF_INET, subnetMask, &broadcast);

	network.s_addr = network.s_addr & broadcast.s_addr;
    	broadcast.s_addr = network.s_addr | ~broadcast.s_addr;	
	int seq = 0;
	for (uint32_t i = ntohl(network.s_addr) + 1; i < ntohl(broadcast.s_addr); i++) 
	{
        	dst.sin_addr.s_addr = i;
		struct in_addr host;
        	host.s_addr = htonl(i);
		

		pcap_init_me( inet_ntoa(host), timeout);
		

		myicmp *packet = (myicmp*)malloc(PACKET_SIZE);
                memset(packet, 0, PACKET_SIZE);
                fill_icmphdr(&packet->icmp_hdr,packet->data, pid, ++seq);
                fill_iphdr(&packet->ip_hdr,inet_ntoa(host));
                
		if(sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&dst, sizeof(dst))<0)
                {
                        perror("sendto");
                        exit(1);
                }else printf("\nPING %s: / Timeout: %d / data_size: %d / seq: %d",inet_ntoa(host), timeout, 10,seq);
        	
		//print_buffer((const unsigned char*)packet,PACKET_SIZE);
	        pcap_get_reply();
		/*char buffer[1024];
		int numbytes_recv = recv(sockfd, buffer, sizeof(buffer), 0);
                printf("%d",numbytes_recv);
		if(numbytes_recv < 0)
                {
                        perror("receive error!");
                	close(sockfd_recv);
			close(sockfd);
			exit(1);
                }
*/
		free(packet);
    	}
	return 0;
}

