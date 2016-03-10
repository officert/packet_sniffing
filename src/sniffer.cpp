#include <iostream>
#include <pcap.h>
#include <stdio.h>

#include "sniffer.h"

using namespace std;

//function prototypes
void get_device_name(const char *device, bpf_u_int32 mask, bpf_u_int32 net, char *error_buffer);
void log(const char *message);
pcap_t* create_session(const char *device);
void sniff_session(pcap_t *session);
void fancy_printf(char* fmt, ...);

void Sniffer::sniff(const char *device)
{
  pcap_t* session_handle;

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

	printf("\nSniffing on device: %s\n", device);

	try {
		sniff_session(session_handle);
	} catch (const char* exception) {
		cout << "Error, " << exception << endl;
	}

  return;
}

void get_device_name(const char *device, bpf_u_int32 mask, bpf_u_int32 net, char *error_buffer)
{
  if (device == NULL) {
    if (pcap_lookupnet(device, &net, &mask, error_buffer) == -1)
    {
      fprintf(stderr, "Can't get netmask for device %s\n", device);
    }
  }
}

pcap_t* create_session(const char *device)
{
	int buffer_size = BUFSIZ;
	int promisc = 1;
	int to_ms = 1000;
	char *error_buffer;

  struct bpf_program fp;		/* The compiled filter expression */
  char filter_exp[] = "port 23";	/* The filter expression */
  bpf_u_int32 mask;		/* The netmask of our sniffing device */
  bpf_u_int32 net;		/* The IP of our sniffing device */

  get_device_name(device, mask, net, error_buffer);

  fancy_printf("Device Name %s\n", device);
  fancy_printf("Net %s\n", net);
  fancy_printf("Mask %s\n", mask);

  if(device == NULL)
  {
    throw "Error, could not get device name";
  }

  printf("\nUsing device: %s\n", device);

	pcap_t* session = pcap_open_live(device, buffer_size, promisc, to_ms, error_buffer);

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

void sniff_session(pcap_t *session)
{
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

	if (session == NULL)
	{
		throw "Error, session cannot be null";
	}

	// grab a packet
	packet = pcap_next(session, &header);

	fancy_printf("Jacked a packet with length of [%d]\n", header.len);

	pcap_close(session);
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
