/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)

#include <iostream>
#include <pcap.h>
#include <stdio.h>

#include "sniffer.h"
#include "structs.h"

using namespace std;

//function prototypes
char* get_device_name(const char *device);
void log(const char *message);
pcap_t* create_session(const char *device);
void on_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

// void print_payload(const u_char *payload, int len);
// void print_hex_ascii_line(const u_char *payload, int len, int offset);

void Sniffer::sniff(const char *device, const int num_packets)
{
	pcap_t* session_handle;
	struct pcap_pkthdr header; // The header that pcap gives us

	try {
		session_handle = create_session(device);
	} catch (const char* exception) {
		cout << exception << endl;
		return;
	}

	if (session_handle == NULL) {
		cout << "Error creating pcap session" << endl;

		return;
	}

	printf("Number of packets to capture: %d\n", num_packets);

	if (session_handle == NULL)
	{
		throw "Error, session cannot be null";
	}

	pcap_loop(session_handle, num_packets, on_packet, NULL);

	pcap_close(session_handle);

	return;
}

char* get_device_name(const char *device)
{
	char *device_name;

	char error_buffer[PCAP_ERRBUF_SIZE];

	if (device == NULL)
	{
		device_name = pcap_lookupdev(error_buffer);

		if (device_name == NULL)
		{
			cout << error_buffer << endl;
		}

		return device_name;
	} else {
		device_name = strdup(device);

		return device_name;
	}
}

pcap_t* create_session(const char *device)
{
	pcap_t* session;
	char error_buffer[PCAP_ERRBUF_SIZE];

	struct bpf_program fp; // The compiled filter expression
	char filter_exp[] = "ip"; // The filter expression
	bpf_u_int32 mask; // The netmask of our sniffing device
	bpf_u_int32 net; // The IP of our sniffing device

	char *device_name = get_device_name(device);

	if (device_name == NULL)
	{
		throw "Error, could not get device name";
	}

	// get network number and mask associated with capture device
	if (pcap_lookupnet(device, &net, &mask, error_buffer) == -1)
	{
		printf("Couldn't get netmask for device %s: %s\n", device, error_buffer);

		net = 0;

		mask = 0;
	}

	printf("Device: %s\n", device_name);
	printf("Filter expression: %s\n", filter_exp);
	printf("Net: %u\n", net);
	printf("Mask: %u\n", mask);

	session = pcap_open_live(device_name, SNAP_LEN, 1, 1000, error_buffer);

	if (session == NULL)
	{
		printf("Error Buffer: %s\n", error_buffer);

		throw "Error opening session to device";
	}

	// if (pcap_datalink(session) != DLT_EN10MB) {
	//   fprintf(stderr, "%s is not an Ethernet\n", device);
	//      throw "Device is not an Ethernet device";
	// }
	//
	// //create and compile a filter for only packets on port 23
	// if (pcap_compile(session, &fp, filter_exp, 0, net) == -1)
	// {
	//      fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(session));
	//
	//      throw "Couldn't parse filter";
	// }
	//
	// //set the filter to actually apply it to our current session
	// if (pcap_setfilter(session, &fp) == -1)
	// {
	//      fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(session));
	//
	//      throw "Couldn't install filter";
	// }

	return session;
}

void on_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static int count = 1; //packet counter

	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_ethernet *ethernet; /* The Ethernet header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const u_char *payload; /* Packet payload */
	int size_payload;

	u_int size_ip;
	u_int size_tcp;

	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);

	//determine protocol
	switch(ip->ip_p) {
	case IPPROTO_TCP:
		printf("   Protocol: TCP\n");
		break;
	case IPPROTO_UDP:
		printf("   Protocol: UDP\n");
		return;
	case IPPROTO_ICMP:
		printf("   Protocol: ICMP\n");
		return;
	case IPPROTO_IP:
		printf("   Protocol: IP\n");
		return;
	default:
		printf("   Protocol: unknown\n");
		return;
	}

	printf("\nPacket number %d:\n", count);

	count++;

	//print source and destination IP addresses
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));

	/*
	 *  OK, this packet is TCP.
	 */

	/* define/compute tcp header offset */
	// size_tcp = TH_OFF(tcp)*4;
	// if (size_tcp < 20) {
	// 	printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
	// 	return;
	// }
	//
	// printf("   Src port: %d\n", ntohs(tcp->th_sport));
	// printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	//
	// /* define/compute tcp payload (segment) offset */
	// payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	//
	// /* compute tcp payload (segment) size */
	// size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	//
	// /*
	//  * Print payload data; it might be binary, so don't just
	//  * treat it as a string.
	//  */
	// if (size_payload > 0) {
	// 	printf("   Payload (%d bytes):\n", size_payload);
	// 	print_payload(payload, size_payload);
	// }

	return;
}

// --------------------------------------------- //

// void print_payload(const u_char *payload, int len)
// {
//      int len_rem = len;
//      int line_width = 16;        /* number of bytes per line */
//      int line_len;
//      int offset = 0;                     /* zero-based offset counter */
//      const u_char *ch = payload;
//
//      if (len <= 0)
//              return;
//
//      /* data fits on one line */
//      if (len <= line_width) {
//              print_hex_ascii_line(ch, len, offset);
//              return;
//      }
//
//      /* data spans multiple lines */
//      for (;; ) {
//              /* compute current line length */
//              line_len = line_width % len_rem;
//              /* print line */
//              print_hex_ascii_line(ch, line_len, offset);
//              /* compute total remaining */
//              len_rem = len_rem - line_len;
//              /* shift pointer to remaining bytes to print */
//              ch = ch + line_len;
//              /* add offset */
//              offset = offset + line_width;
//              /* check if we have line width chars or less */
//              if (len_rem <= line_width) {
//                      /* print last line and get out */
//                      print_hex_ascii_line(ch, len_rem, offset);
//                      break;
//              }
//      }
//
//      return;
// }
//
// void print_hex_ascii_line(const u_char *payload, int len, int offset)
// {
//
//      int i;
//      int gap;
//      const u_char *ch;
//
//      /* offset */
//      printf("%05d   ", offset);
//
//      /* hex */
//      ch = payload;
//      for(i = 0; i < len; i++) {
//              printf("%02x ", *ch);
//              ch++;
//              /* print extra space after 8th byte for visual aid */
//              if (i == 7)
//                      printf(" ");
//      }
//      /* print space to handle line less than 8 bytes */
//      if (len < 8)
//              printf(" ");
//
//      /* fill hex gap with spaces if not full line */
//      if (len < 16) {
//              gap = 16 - len;
//              for (i = 0; i < gap; i++) {
//                      printf("   ");
//              }
//      }
//      printf("   ");
//
//      /* ascii (if printable) */
//      ch = payload;
//      for(i = 0; i < len; i++) {
//              if (isprint(*ch))
//                      printf("%c", *ch);
//              else
//                      printf(".");
//              ch++;
//      }
//
//      printf("\n");
//
//      return;
// }
