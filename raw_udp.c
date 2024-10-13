/*  
	Viet Nguyen @ viatelecom.com
*/

// Send an IPv4 UDP packet via raw socket.
// Stack fills out layer 2 (data link) information (MAC addresses) for us.
// Includes some UDP data.

#ifdef __cplusplus
extern "C" {
#endif
#include "raw_udp.h"

int raw_udp_send (const char *src_ip, int srcport, const char *dst_ip, int dstport)
{
  int datalen, sd, *ip_flags;
  const int on = 1;
  struct ip iphdr;
  struct udphdr udphdr;
  unsigned char *packet;
  const char *data = "SIP/2.0 \\0";
  struct sockaddr_in sin;
  void *tmp;

// Allocate memory for various arrays.

  // Maximum UDP payload size = 65535 - IPv4 header (20 bytes) - UDP header (8 bytes)
  tmp = (unsigned char *) malloc (IP_MAXPACKET * sizeof (unsigned char));
  if (tmp != NULL) {
    packet = (unsigned char *)tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'packet'.\n");
    return (EXIT_FAILURE);
  }
  memset (packet, 0, IP_MAXPACKET * sizeof (unsigned char));

  tmp = (int *) malloc (4 * sizeof (int));
  if (tmp != NULL) {
    ip_flags = (int*)tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'ip_flags'.\n");
    return (EXIT_FAILURE);
  }
  memset (ip_flags, 0, 4 * sizeof (int));

// UDP data
  datalen = strlen(data);

// IPv4 header
// IPv4 header length (4 bits): Number of 32-bit words in header = 5
  //iphdr.ip_hl = IP4_HDRLEN / sizeof (unsigned long int);
  iphdr.ip_hl = 5;

// Internet Protocol version (4 bits): IPv4
  iphdr.ip_v = 4;

// Type of service (8 bits)
  iphdr.ip_tos = 0;

// Total length of datagram (16 bits): IP header + UDP header + datalen
  iphdr.ip_len = htons (IP4_HDRLEN + UDP_HDRLEN + datalen);

// ID sequence number (16 bits): unused, since single datagram
  iphdr.ip_id = htons (0);

// Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

  // Zero (1 bit)
  ip_flags[0] = 0;

  // Do not fragment flag (1 bit)
  ip_flags[1] = 0;

  // More fragments following flag (1 bit)
  ip_flags[2] = 0;

  // Fragmentation offset (13 bits)
  ip_flags[3] = 0;

  iphdr.ip_off = htons ((ip_flags[0] << 15)
                      + (ip_flags[1] << 14)
                      + (ip_flags[2] << 13)
                      +  ip_flags[3]);

// Time-to-Live (8 bits): default to maximum value
  iphdr.ip_ttl = 255;

// Transport layer protocol (8 bits): 17 for UDP
  iphdr.ip_p = IPPROTO_UDP;

// Source IPv4 address (32 bits)
  inet_pton (AF_INET, src_ip, &(iphdr.ip_src));

// Destination IPv4 address (32 bits)
  inet_pton (AF_INET, dst_ip, &iphdr.ip_dst);

// IPv4 header checksum (16 bits): set to 0 when calculating checksum
  iphdr.ip_sum = 0;
  iphdr.ip_sum = checksum ((unsigned short int *) &iphdr, IP4_HDRLEN);

// UDP header

// Source port number (16 bits): pick a number
  udphdr.source = htons (srcport);

// Destination port number (16 bits): pick a number
  udphdr.dest = htons (dstport);

// Length of UDP datagram (16 bits): UDP header + UDP data
  udphdr.len = htons (UDP_HDRLEN + datalen);

// UDP checksum (16 bits)
  udphdr.check = udp4_checksum (iphdr, udphdr, (unsigned char*)data, datalen);

// Prepare packet.

// First part is an IPv4 header.
  memcpy (packet, &iphdr, IP4_HDRLEN);

// Next part of packet is upper layer protocol header.
  memcpy ((packet + IP4_HDRLEN), &udphdr, UDP_HDRLEN);

// Finally, add the UDP data.
  memcpy (packet + IP4_HDRLEN + UDP_HDRLEN, data, datalen);

// The kernel is going to prepare layer 2 information (ethernet frame header) for us.
// For that, we need to specify a destination for the kernel in order for it
// to decide where to send the raw datagram. We fill in a struct in_addr with
// the desired destination IP address, and pass this structure to the sendto() function.
  memset (&sin, 0, sizeof (struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = iphdr.ip_dst.s_addr;

// Submit request for a raw socket descriptor.
  if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror ("socket() failed ");
    return (EXIT_FAILURE);
  }

// Set flag so socket expects us to provide IPv4 header.
  if (setsockopt (sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
    perror ("setsockopt() failed to set IP_HDRINCL ");
    return (EXIT_FAILURE);
  }

// Send packet.
  if (sendto (sd, packet, IP4_HDRLEN + UDP_HDRLEN + datalen, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0)  {
    perror ("sendto() failed ");
    return (EXIT_FAILURE);
  }

// Close socket descriptor.
  close (sd);

// Free allocated memory.
  free (packet);
  free (ip_flags);

  return (EXIT_SUCCESS);
}

// Checksum function
unsigned short int
checksum (unsigned short int *addr, int len)
{
  int nleft = len;
  int sum = 0;
  unsigned short int *w = addr;
  unsigned short int answer = 0;

  while (nleft > 1) {
    sum += *w++;
    nleft -= sizeof (unsigned short int);
  }

  if (nleft == 1) {
    *(unsigned char *) (&answer) = *(unsigned char *) w;
    sum += answer;
  }

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}

// Build IPv4 UDP pseudo-header and call checksum function.
unsigned short int
udp4_checksum (struct ip iphdr, struct udphdr udphdr, unsigned char *payload, int payloadlen)
{
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
  ptr += sizeof (iphdr.ip_src.s_addr);
  chksumlen += sizeof (iphdr.ip_src.s_addr);

  // Copy destination IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
  ptr += sizeof (iphdr.ip_dst.s_addr);
  chksumlen += sizeof (iphdr.ip_dst.s_addr);

  // Copy zero field to buf (8 bits)
  *ptr = 0; ptr++;
  chksumlen += 1;

  // Copy transport layer protocol to buf (8 bits)
  memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
  ptr += sizeof (iphdr.ip_p);
  chksumlen += sizeof (iphdr.ip_p);

  // Copy UDP length to buf (16 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy UDP source port to buf (16 bits)
  memcpy (ptr, &udphdr.source, sizeof (udphdr.source));
  ptr += sizeof (udphdr.source);
  chksumlen += sizeof (udphdr.source);

  // Copy UDP destination port to buf (16 bits)
  memcpy (ptr, &udphdr.dest, sizeof (udphdr.dest));
  ptr += sizeof (udphdr.dest);
  chksumlen += sizeof (udphdr.dest);

  // Copy UDP length again to buf (16 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy UDP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy payload to buf
  memcpy (ptr, payload, payloadlen);
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return checksum ((unsigned short int *) buf, chksumlen);
}
#ifdef __cplusplus
}
#endif
