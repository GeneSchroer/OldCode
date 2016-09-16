#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#define UDP_PORT 53 /* access port for the DNS name server */

/* Name: Gene Schroer                      	*/
/* Project: Name Sever Lookup; Final Project	*/
/* Class: CSC 217: C Programming Language	*/
/* Professor Thomas Re 			    	*/
/* Description: This program attempts to emulate*/
/* the most basic DNS query search, as seen with*/
/* NSLookup and similar programs.		*/
/* It formats a packet of information and sends */
/* it via datagram to a DNS server before 	*/
/* receiving a response, and attempts to 	*/
/* read the information. It currently sends a 	*/
/* query correctly, but it not guaranteed to 	*/
/* read the response correctly.			*/


/* our 'packet' contains the following information (not necessarily all structs):
Header
Question
Answer
Authority
Additional
*/



/* Holds header information */
typedef struct Header{
unsigned short ID;

unsigned short RD	:1;
unsigned short TC	:1;
unsigned short AA	:1;
unsigned short OPCODE	:4;
unsigned short QR	:1;
unsigned short RCODE	:4;
unsigned short Z	:3;
unsigned short RA	:1;

unsigned short QDCOUNT;
unsigned short ANCOUNT;
unsigned short NSCOUNT;
unsigned short ARCOUNT;
}HEADER;

/* Hold query info, inserted after qname. */
typedef struct Query{
short QTYPE;
short QCLASS;
} QUERY;



/* Contains the data used in a Resource Record EXCEPT the Name and RData, which are variable. The packet uses 3 RRs: Answer, Authority, and Additional. */
typedef struct ResourceRecord{
short TYPE;
short CLASS;
unsigned int TTL;
unsigned short RDLENGTH;
}RR;



/* Set up a query to send to a DNS server. A query consists of 5 parts:
	Header - a list of options/requests to the name server.
	Query
	Answer
	Authoritive
	Additional
*/

int main(int argc, char** argv){
	if(argc==1) 
		printf("MyLookup options: \n MyLookup <host name>\n");
	else{	/*setting up the packet*/

		/* 1) Create the packet and socket */

		HEADER MyHeader; QUERY MyQuery; RR Padding; 
		memset(&MyHeader, 0, sizeof(MyHeader) );
		memset(&Padding, 0, sizeof(Padding) );
		MyQuery.QTYPE= 1; /* 1 = Host address(A)*/
		MyQuery.QCLASS= 1; /* 1 = The Internet (IN)*/

		int total=0; /* current "length" of the packet */	
		int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
		struct sockaddr_in saddr;
		if(sock_fd < 0){
			perror("Socket: ");
			exit(EXIT_FAILURE); }
		/* clear and set up the address structs*/
		memset(&saddr, 0, sizeof (saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_addr.s_addr = htonl(INADDR_ANY);	
		saddr.sin_port = htons(UDP_PORT);
		if(argc == 3)
			inet_pton(AF_INET, argv[2], &(saddr.sin_addr));
		else 
			inet_pton(AF_INET, "127.0.1.1", &(saddr.sin_addr));

		bind(sock_fd, (struct sockaddr*) &saddr, sizeof(saddr));
		if(connect(sock_fd, (struct sockaddr *) &saddr, sizeof(saddr)) == -1 ){
			perror("Connection failed: ");
			exit(EXIT_FAILURE); }
		int i=0,j=1;
		
		char* packet;
		if( (packet = malloc(512)) == NULL){
			printf("Can't create packet!\n");
			exit(EXIT_FAILURE); }

		memset(packet, 0, 512);
		MyHeader.QDCOUNT= htons(1);
		MyHeader.RD = 0;

		memcpy(packet, &MyHeader, sizeof(MyHeader));
		total = sizeof(MyHeader); 
		/* label[0] is length, label[65] is to have */
		/*  enough space for null terminator */			
		char label[64];
		memset(&label, 0, sizeof(label));
		/* This only handles standard input for now */
		for(i=0;( i<strlen(argv[1])&&(i<255) );++i){ 
			/* Have we reach a new label? */	
			if(argv[1][i]=='.'){
			/* attach label to end of packet */
			memcpy(&packet[total], &label, 
			j); 
			total += j;
			/* reset for next label */
			memset(&label, 0, sizeof(label));
			j=1; }	
			else{
			label[j] = argv[1][i];
			++label[0];
		++j; }	}

	memcpy(&packet[total], &label, j);
	total += j; 
	packet[total]='\0';
	++total;
	/* swap bytes to network order */
	MyQuery.QTYPE = htons(MyQuery.QTYPE);
	MyQuery.QCLASS = htons(MyQuery.QCLASS);
	memcpy(&packet[total], &MyQuery, sizeof(MyQuery));
	total += sizeof(MyQuery);	

	printf("Message sent: \n");
	for(i=0;i<total;++i)
		printf("%d", packet[i]);
	printf("\n\n");

	/*for(i=0;i<total;++i)
		printf("%c", packet[i]); 
	printf("\n");*/

	socklen_t length;
	sendto(sock_fd, packet, total+1, 0, (struct sockaddr*) &saddr, sizeof(struct sockaddr_in));
	struct sockaddr_in receive;
	socklen_t reclen=sizeof(receive);

	printf("\n\nWaiting for message: \n");

	char* packet_r = malloc(524); /* max size of UDP message, and the most we will get back*/

	recvfrom(sock_fd, packet_r, 525, 0, 0, 0);
	total = 0; /* total reused to traverse over packet_r */

	/* Response is cast to various structs to process the information */
	HEADER* HeadR = (HEADER *) packet_r;

	printf("Header Section. \n\n");
	printf("\nQR Flag: %d\n", HeadR->QR);	
	printf("\nOpcode: %d\n", HeadR->OPCODE);
	printf("\nAA Flag: %d\n", HeadR->AA);
	printf("\nTC Flag: %d\n", HeadR->TC);
	printf("\nRD Flag: %d\n", HeadR->OPCODE);
	printf("\nRA Flag: %d\n", HeadR->RA);
	printf("\nZ: %d\n", HeadR->Z);	
	printf("\nResponse Code: %d\n", HeadR->RCODE);	

	total+=sizeof(HEADER); /* start of Query */

	/* This loop will traverse through the QNAME field until it finds a null terminator */

	printf("Address: \n");

	i, j = 0;
	while(packet_r[total]!='\0'){
		j = packet_r[total++]; /* j = length of label, total increases by 1 */
		for(i=0;i<j;++i)
			printf("%c", packet_r[total++]);
		if(packet_r[total]!='\0')
			printf("."); }

	printf("\n");
	++total;
	total += sizeof(QUERY); /* total = start of Answer packet*/
	printf("ANSWER: \n\n");

	/* NOTE: *NOT* guaranteed to format correctly */
	if(packet_r[total]==(char)192){ /* RNAME is a pointer */
		int point = packet_r[++total];
		printf("Pointer to offset: %d\n", point);
		printf("Address: \n");
		while( packet[point]!='\0'){
			j = packet[point];
			for(i=0;i<j;++i){
				++point;
				printf("%c", packet[point]); }
		if(packet[point+1]!='\0')
			printf(".");
		++point; }
	}
	else
		while(packet_r[total]!='\0'){ 
			j=packet_r[total++]; /* j = length of label */
			for(i=0;i<j;++i)
				printf("%c", packet_r[total++]);
			if(packet_r[total+1]!='\0')	
				printf(".");
			}		
		++total; /* points to the Answer RR in packet_r*/
		printf("%d\n", total);
		RR *Answer = (RR*)(packet_r+total); 
		printf("TYPE: %u\n\n", ntohs(Answer->TYPE));
		j = ntohs(Answer-> RDLENGTH);
		total +=sizeof(RR); /* jump to Answer/RDATA */
		
		/* I ran out of time trying to get this part to format the RDATA of Answer, so I have commented it out. */
		/*while( packet_r[total]!='\0'){
			for(i=0;i<j;++i){
				printf("%u", packet_r[total]); }
				if(packet_r[total+1]!='\0')		
					printf(".");		
			++total; }
	
		printf("\n");
		*/

		for(i=0;i<512;++i)
			printf("%d ", packet_r[i]); 

		/* free memory */
		free(packet);
		free(packet_r);
		close(sock_fd);	
	}
	exit(EXIT_SUCCESS); 
}
