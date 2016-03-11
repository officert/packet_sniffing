/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

#include <iostream>
#include <pcap.h>
#include <stdio.h>

#include "sniffer.h"

using namespace std;

//function prototypes
char* get_device_name(const char *device);
void log(const char *message);
pcap_t* create_session(const char *device);
void fancy_printf(char* fmt, ...);
void on_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void Sniffer::sniff(const char *device, const int num_packets)
{
  pcap_t* session_handle;
  struct pcap_pkthdr header;	// The header that pcap gives us

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

	printf((char *)"Number of packets: %d\n", num_packets);

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
	int buffer_size = SNAP_LEN;
	int promisc = 1;
	int to_ms = 1000;
	char error_buffer[PCAP_ERRBUF_SIZE];

  struct bpf_program fp; // The compiled filter expression
  char filter_exp[] = "port 23";  // The filter expression
  bpf_u_int32 mask; // The netmask of our sniffing device
  bpf_u_int32 net;  // The IP of our sniffing device

  char *device_name = get_device_name(device);

  // get network number and mask associated with capture device
	if (pcap_lookupnet(device, &net, &mask, error_buffer) == -1)
  {
		printf("Couldn't get netmask for device %s: %s\n", device, error_buffer);

		net = 0;

		mask = 0;
	}

  printf((char *)"Device: %s\n", device_name);
	printf((char *)"Filter expression: %s\n", filter_exp);
	printf((char *)"Net: %s\n", net);
	printf((char *)"Mask: %s\n", mask);

  if (device_name == NULL)
  {
    throw "Error, could not get device name";
  }

	session = pcap_open_live(device_name, buffer_size, promisc, to_ms, error_buffer);

	if (session == NULL)
	{
		printf("Error Buffer: %s\n", error_buffer);

		throw "Error opening session to device";
	}

	//create and compile a filter for only packets on port 23
	if (pcap_compile(session, &fp, filter_exp, 0, net) == -1)
  {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(session));

		throw "Couldn't parse filter %s: %s\n", pcap_geterr(session);
	}

	//set the filter to actually apply it to our current session
	if (pcap_setfilter(session, &fp) == -1)
  {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(session));

		throw "Couldn't install filter %s: %s\n", pcap_geterr(session);
	}

	return session;
}

void on_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  static int count = 1; //packet counter
  char errbuf[PCAP_ERRBUF_SIZE]; //error buffer

  printf("\nPacket number %d:\n", count);

  count++;

  return;
}

void fancy_printf(char* fmt, ...)
{
  char start[] = "\n/----------------------------------------\n\n";
  char end[] = "\n----------------------------------------/\n";
  int result_length = strlen(start) + strlen(fmt) + strlen(end);
  char result[result_length];

  strcpy(result, start);
  strcat(result, fmt);
  strcat(result, end);

  fmt = result;

  va_list args;

  va_start(args,fmt);

  vprintf(fmt,args);

  va_end(args);
}
