#include <iostream>
#include <stdio.h>
#include <pcap.h>

using namespace std;

//function prototypes
pcap_t& create_session(const char *device);

int main(int argc, char *argv[])
{
	char *device = argv[1];

	if (device == NULL)
	{
	 cout << "Error, must pass a device name" << endl;

	 return(1);
	}

	pcap_t& session_handle = create_session(device);

	printf("Device: %s\n", device);

	return(0);
}

pcap_t& create_session(const char *device) {
	int buffer_size = BUFSIZ;
	int promisc = 1;
	int to_ms = 1000;
	char *error_buffer;

	struct bpf_program fp;		/* The compiled filter expression */
	char filter_exp[] = "port 23";	/* The filter expression */
	bpf_u_int32 mask;		/* The netmask of our sniffing device */
	bpf_u_int32 net;		/* The IP of our sniffing device */

	pcap_t* session = pcap_open_live(device, buffer_size, promisc, to_ms, error_buffer);

	if(session == NULL)
	{
		printf("Error Buffer: %s\n", error_buffer);

		throw "Error opening session to device";
	}

	if (pcap_compile(session, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(session));

		throw "Couldn't parse filter %s: %s\n", pcap_geterr(session);
	}

	if (pcap_setfilter(session, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(session));

		throw "Couldn't install filter %s: %s\n", pcap_geterr(session);
	}

	return *session;
}
