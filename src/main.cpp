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

	pcap_t* session = pcap_open_live(device, buffer_size, promisc, to_ms, error_buffer);

	if(session == NULL)
	{
		printf("Error Buffer: %s\n", error_buffer);

		throw "Error opening session to device";
	}

	return *session;
}
