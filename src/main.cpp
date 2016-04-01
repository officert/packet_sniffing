#include <iostream>

#include "sniffer.h"

int main(int argc, char *argv[])
{
	char *device = argv[1];

	Sniffer sniffer;

	sniffer.sniff(device, 100);

	return(0);
}
