SRC_DIR = src
BUILD_DIR = build
PROGRAM_NAME = main
GCC = g++
FLAGS = -o $(BUILD_DIR)/$(PROGRAM_NAME) -lpcap -L/usr/include/pcap

build: clean
	mkdir $(BUILD_DIR); \
	$(GCC) $(SRC_DIR)/*.cpp ${FLAGS}

clean:
	rm -rf $(BUILD_DIR)

run:
	$(BUILD_DIR)/$(PROGRAM_NAME) ${d}

.PHONY: build
