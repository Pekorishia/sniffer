#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <arpa/inet.h>			//ntohs	
#include <stdint.h>				//uint8_t, uint16_t and uint32_t
#include <sys/socket.h>			//socket functions

typedef struct 
{
	uint8_t type;				//block type
	uint8_t studentID[8];		//student ID
	uint8_t length[2];			//name length
}Block;

typedef struct
{
	uint16_t srcPort;			//source port
	uint16_t destPort;			//destination port
	uint16_t length;			//length of the payload
	uint16_t checksum;			
}UDPHeader;

typedef struct 
{
	uint8_t versionAndHLenght;	//version and header length
	uint8_t tos;				//type of service
	uint16_t totalLenght;		//total IP packet length
	uint16_t id;				//identification
	uint16_t fragOffset;		//frament offset
	uint8_t ttl;				//time to live
	uint8_t protocol;			//payload protocol
	uint16_t hChecksum;			//header checksum
	uint8_t srcIP[4];			//source IP
	uint8_t destIP[4];			//destination IP
}IPHeader;

typedef struct 
{
	uint8_t destMac[6];			//destination MAC address
	uint8_t srcMac[6];			//source MAC address
	uint16_t type;				//payload protocol type
}EthHeader;


/*
 * prints the important information that the message contains
 */
void printMessage(EthHeader *ethH, IPHeader *ipH, UDPHeader *udpH, Block *block)
{
	printf("________________________________\n");
	
	printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ethH->srcMac[0],ethH->srcMac[1],ethH->srcMac[2],ethH->srcMac[3],ethH->srcMac[4],ethH->srcMac[5]);
	printf("dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ethH->destMac[0],ethH->destMac[1],ethH->destMac[2],ethH->destMac[3],ethH->destMac[4],ethH->destMac[5]);
	printf("src IP: %u.%u.%u.%u\n", ipH->srcIP[0],ipH->srcIP[1],ipH->srcIP[2],ipH->srcIP[3]);
	printf("dest IP: %u.%u.%u.%u\n", ipH->destIP[0],ipH->destIP[1],ipH->destIP[2],ipH->destIP[3]);
	printf("protocol: %u\n", ipH->protocol);
	printf("src Port: %u\n", ntohs(udpH->srcPort));
	printf("dest Port: %u\n", ntohs(udpH->destPort));
	
	printf("--------------------------------\n");

	if (block->type == 2)
	{
		printf("Message type: %u\n", block->type);
		printf("studentID: %c%c%c%c%c%c%c%c\n", block->studentID[0],block->studentID[1],block->studentID[2],block->studentID[3],block->studentID[4],block->studentID[5],block->studentID[6],block->studentID[7]);
	}else if (block->type == 1)
	{
		printf("message type: %u\n", block->type);
		printf("studentID: %c%c%c%c%c%c%c%c\n", block->studentID[0],block->studentID[1],block->studentID[2],block->studentID[3],block->studentID[4],block->studentID[5],block->studentID[6],block->studentID[7]);
		
		//the length receives is formated based on each 
		//digity (ex: 79, length[0] = 7 and length[1] = 9)
		int size = block->length[0]*10 + block->length[1];
		printf("length: %u\n", size);

		//getting each byte after the length using the pointer
		for (char c = 0; c < size; ++c)
		{
			printf("%c", *(block->length + 2 + c));
		}
		printf("\n");
	}
	printf("________________________________\n");
}


/*
 *receives the buffer and its size and breaks it
 *into the structures, checking if the headers matches
 *with the ones the activity asks for
 */
void sniffer(unsigned char *buffer, int dataSize)
{
	EthHeader *ethH = (EthHeader *) buffer;

	//if the protocol type inside of the frame is IP
	if(ntohs(ethH->type) == 0x0800)
	{
		//takes the next not filled address from ethH and puts it inside the IP header
		IPHeader *ipH = (IPHeader *)(ethH + 1);

		//if the protocol inside the packet is UDP
		if(ipH->protocol == 0x11) //17 in decimal
		{
			UDPHeader *udpH = (UDPHeader *) (ipH + 1);

			//if the destination port inside the datagram is 1234
			if(ntohs(udpH->destPort) == 1234)
			{
				Block *block = (Block *) (udpH + 1);

				//prints the information of the message received
				printMessage(ethH, ipH, udpH, block);
			}
		}
	}
}

int main()
{
	//structure that stores the sending address
	struct sockaddr sockAddr;

	//creating a buffer that will receive the socket data
	unsigned char *buffer = (unsigned char *) malloc (65534); //max uint value to hold all possible data

	/*
	 *creates a raw socket that will sniff through all messages
	 *PF_PACKET to receive raw packet
	 *SOCK_RAW provides the packet including link level header
	 *0x0003 receives all types of protocols
	*/
	int rawSocket = socket(PF_PACKET, SOCK_RAW, htons(0x0003)); 

	if (rawSocket < 0)
	{
		printf("Socket Error!\n");
		return 1;
	}

	while(1)
	{
		int sockAddrSize = sizeof(sockAddr);

		//receives the data from the socket and stores it into the buffer
		int dataSize = recvfrom(rawSocket, buffer, 65534, 0, &sockAddr, &sockAddrSize);

		if(dataSize < 0)
		{
			printf("Packet Receive Error!\n");
			return 1;
		}
		sniffer(buffer, dataSize);
	}	
	return 0;
}