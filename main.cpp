#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6 

void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

//스스로 제작한 구조체
struct ip_addr {
	u_int8_t s_ip[4];
};

//libnet_header 참고 이더넷 구조체
struct libnet_ethernet_hdr
{
	u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
	u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
	u_int16_t ether_type;                 /* protocol */    
};

//libnet_header 참고 ipv4 구조체
struct libnet_ipv4_hdr
{
	u_int8_t ip_hl_v;		//header length and version - modified

/*
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,      // header length
           ip_v:4;         // version
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       // version
           ip_hl:4;        // header length
#endif
*/

	u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
	u_int16_t ip_len;         /* total length */
	u_int16_t ip_id;          /* identification */
	u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
	u_int8_t ip_ttl;          /* time to live */
	u_int8_t ip_p;            /* protocol */
	u_int16_t ip_sum;         /* checksum */
	struct ip_addr ip_src, ip_dst; /* source and dest address */
};


//libnet_header 참고 tcp 구조체
struct libnet_tcp_hdr
{
	u_int16_t th_sport;       /* source port */
	u_int16_t th_dport;       /* destination port */

	u_int32_t th_seq;          /* sequence number */
	u_int32_t th_ack;          /* acknowledgement number */

	u_int8_t th_x2_off;        // data offset and (unused) - modified

/*
#if (LIBNET_LIL_ENDIAN)
	u_int8_t th_x2:4,         // (unused) 
		   th_off:4;        // data offset 
#endif
#if (LIBNET_BIG_ENDIAN)
	u_int8_t th_off:4,        // data offset 
		   th_x2:4;         // (unused) 
#endif
*/

	u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
	u_int16_t th_win;         /* window */
	u_int16_t th_sum;         /* checksum */
	u_int16_t th_urp;         /* urgent pointer */
};



int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	//pcap_live (window)
	//dev = en0
	//   
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}


	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		//packet info coding - assignment
		//packet -> blabla
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
	
		//assignment start.

		//ethernet_struct
		struct libnet_ethernet_hdr* eth = (struct libnet_ethernet_hdr *)packet;
		printf("\nInfo\n");		
		
		printf("\nsrc mac: %02X:%02X:%02X:%02X:%02X:%02X\n",
			eth->ether_shost[0],
			eth->ether_shost[1],
			eth->ether_shost[2],
			eth->ether_shost[3],
			eth->ether_shost[4],
			eth->ether_shost[5]
			);
		printf("dst mac: %02X:%02X:%02X:%02X:%02X:%02X\n",
			eth->ether_dhost[0], 
			eth->ether_dhost[1], 
			eth->ether_dhost[2],
			eth->ether_dhost[3],
			eth->ether_dhost[4],
			eth->ether_dhost[5]
			);

		eth->ether_type = ntohs(eth->ether_type);
//		printf("이더넷 타입: 0x%04X\n\n",eth->ether_type); /* 디버깅 용 */

		//ip
		if(eth->ether_type == 0x0800){
			printf("\nIt's IP\n");
			struct libnet_ipv4_hdr* ip4 = (struct libnet_ipv4_hdr *)(packet + 14);
//			printf("ip version : 4\n"); /* 디버깅 용 */

			uint8_t ip_hd_len = (ip4->ip_hl_v & 0xf) * 4;

//			printf("ip header length : %d\n", ip_hd_len);  /* 디버깅 용 */

			printf("src ip : %d.%d.%d.%d\n",
				ip4->ip_src.s_ip[0],
				ip4->ip_src.s_ip[1], 
				ip4->ip_src.s_ip[2], 
				ip4->ip_src.s_ip[3]
				);
			printf("dst ip : %d.%d.%d.%d\n", 
				ip4->ip_dst.s_ip[0], 
				ip4->ip_dst.s_ip[1], 
				ip4->ip_dst.s_ip[2], 
				ip4->ip_dst.s_ip[3]
				);      
//			printf("ip 타입: %d\n\n", ip4->ip_p);  /* 디버깅 용 */

			//tcp
			if(ip4->ip_p == 6) {
				printf("\nIt's TCP\n");
				struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr *)(packet + 14 + ip_hd_len);

				tcp->th_sport = ntohs(tcp->th_sport);
				tcp->th_dport = ntohs(tcp->th_dport);

				printf("tcp source port : %d \n", tcp->th_sport);
				printf("tcp destination port : %d \n", tcp->th_dport);

//				printf("tcp->th_x2_off : %x\n", tcp->th_x2_off);   /* 디버깅 용 */
				uint16_t tcp_hd_len = ((tcp->th_x2_off & 0xf0)>>4) * 4;
				ip4->ip_len = ntohs(ip4->ip_len);

				uint16_t tcp_len = ip4->ip_len - ip_hd_len;
//				printf("tcp length : %d\n", tcp_len);		
						
                uint16_t tcp_payload_len = tcp_len - tcp_hd_len ;


//				printf("tcp header length : %d\n", tcp_hd_len); /* 디버깅 용 */
//				printf("tcp payload length : %d\n", tcp_payload_len); /* 디버깅 용 */

                uint8_t *tcp_payload = (uint8_t *)packet + 14 + ip_hd_len + tcp_hd_len;
                printf("tcp payload(DATA): ");
				// payload
				if(tcp_payload_len < 16) {
					for(int i = 0; i < tcp_payload_len; i++) {
						printf("%02x", tcp_payload[i]);
					}
				}
				else {
					for(int i = 0; i < 16; i++) {
						printf("%02x", tcp_payload[i]);
					}
				}
				printf("\nend\n\n");
			}
		}
	//else not ip version 4 ignore.
	}
	pcap_close(handle);
	return 0;
}
