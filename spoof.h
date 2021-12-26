#ifndef SPOOF_H
#define SPOOF_H

#include <netinet/ip.h>
#include <netinet/udp.h>

#define MAX_PAYLOAD_SIZE 1000
#define MTU 1500

/**
 * @brief craft a packet, i.e fills the ip and udp headers
 * @param ip_header the ip header of the packet
 * @param udp_header the udp header of the packet
 * @param src_addr the spoofing address (and port), chosen by the user
 * @param dst_addr the target address (and port), passed through the arguments of the function 'main'
 */

void fill_hdr(struct ip *ip_header,
               struct udphdr *udp_header,
               struct sockaddr_in *src_addr,
               struct sockaddr_in *dst_addr,
               int datalen
               );


/**
 * @brief ask the user which ip address and port they want to use for spoofing.
 * @param spoof_addr a struct sockaddr_in, i.e contains an ip address AND a port number
 */

void choose_ip_addr(struct sockaddr_in *spoof_addr);


/**
 * @brief this function starts a loop that waits for a message written by the user, and sends it to the target
 * @param dest the target address
 * @param spoof the spoofing address 
 */

void spoof(struct sockaddr_in *dest, struct sockaddr_in *spoof);

#endif // SPOOF_H