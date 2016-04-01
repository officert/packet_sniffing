#ifndef STRUCTS_H
#define STRUCTS_H

#include <arpa/inet.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* 4 bytes IP address */
struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
};

/* Ethernet header */
struct ethernet_header {
	u_char destination_host[ETHER_ADDR_LEN]; /* Destination host address */
	u_char source_host[ETHER_ADDR_LEN]; /* Source host address */
	u_short type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct ip_header {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct ip_address src_address; // source address
	struct ip_address dest_address; // dest address
};

		// #define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
		// #define IP_V(ip)		(((ip)->ip_vhl) >> 4)
		//
		// /* TCP header */
		// typedef u_int tcp_seq;
		//
		// struct sniff_tcp {
		// 	u_short th_sport;	/* source port */
		// 	u_short th_dport;	/* destination port */
		// 	tcp_seq th_seq;		/* sequence number */
		// 	tcp_seq th_ack;		/* acknowledgement number */
		// 	u_char th_offx2;	/* data offset, rsvd */
		// #define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		// 	u_char th_flags;
		// #define TH_FIN 0x01
		// #define TH_SYN 0x02
		// #define TH_RST 0x04
		// #define TH_PUSH 0x08
		// #define TH_ACK 0x10
		// #define TH_URG 0x20
		// #define TH_ECE 0x40
		// #define TH_CWR 0x80
		// #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		// 	u_short th_win;		/* window */
		// 	u_short th_sum;		/* checksum */
		// 	u_short th_urp;		/* urgent pointer */
		//};

#endif
