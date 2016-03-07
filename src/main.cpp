#include <iostream>
#include <stdio.h>
#include <pcap.h>

//function prototypes
pcap_t* create_session(const char *device);

int main(int argc, char *argv[])
{
	 char *device = argv[1];
	 pcap_t* session_handle;

	 if (device == NULL)
	 {
     std::cout << "Error, must pass a device name" << std::endl;

		 return(1);
   }

	 session_handle = create_session(device);

	 printf("Device: %s\n", device);

	 return(0);
}

pcap_t* create_session(const char *device) {
	int buffer_size = BUFSIZ;
	int promisc = 1;
	int to_ms = 1000;
	char *error_buffer;

	pcap_t* session = pcap_open_live(device, buffer_size, promisc, to_ms, error_buffer);

	return session;
}
