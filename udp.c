#include "udp.h"

int udp_send (int sockfd, struct sockaddr_in *from, struct sockaddr_in *to){
	struct sockaddr_in sock, server;
	int sockfd;
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("Can't create socket");
		exit(-1);
	}

	const char *content = "SIP/2.0 \\0";

	memset(&sock, 0, sizeof sock);
	sock.sin_family = AF_INET; 
	sock.sin_addr.s_addr=inet_addr(argv[1]);
	sock.sin_port = htons(atoi(argv[2]));  

	
	server.sin_family = AF_INET; 
	server.sin_addr.s_addr=htonl(INADDR_ANY);
	server.sin_port = htons(6060);  

	if ((bind(sockfd, (struct sockaddr *) &server, sizeof(server))) == -1) {
		close(sockfd);
		perror("Can't bind");
	}

	printf("Bind ok\n");
	sendto(sockfd, content, strlen(content), 0, (struct sockaddr *)&sock, sizeof(sock));
	close(sockfd);
	
	return 0;
}

