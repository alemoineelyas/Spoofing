#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

#include "spoof.h"

#define TRUE 1

int main(int argc, char **argv) {

    if (getuid() != 0) {
        fprintf(stderr, "Please run with sudo\n");
        return EXIT_FAILURE;
    }

    if (argc != 3) {
        fprintf(stderr, "Usage: ./spoof <dest_ip> <dest_port>\n");
        return EXIT_FAILURE;
    }
    // save the arguments into the appropriate structure

    struct sockaddr_in dest_addr, spoof_addr;

    dest_addr.sin_addr.s_addr = inet_addr(argv[1]);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(atoi(argv[2]));

    // make the user choose its own ip address

    choose_ip_addr(&spoof_addr);

    // start spoofing

    spoof(&dest_addr, &spoof_addr);

}

void fill_hdr(struct ip *ip_header, struct udphdr *udp_header, struct sockaddr_in *src_addr, struct sockaddr_in *dst_addr, int datalen) {

    // IP header

    ip_header->ip_hl    = sizeof(struct ip) / 4; // ip_hl is the size of the header in 32bit words (==> /4)
    ip_header->ip_v     = 4; //IPV4
    ip_header->ip_tos   = 0; // type of service, see RFC 791
    ip_header->ip_len   = htons(sizeof(struct ip) + sizeof(struct udphdr) + datalen);
    ip_header->ip_id    = 0;
    ip_header->ip_off   = 0; // fragment offset, RFC 791
    ip_header->ip_ttl   = IPDEFTTL; // time to live, default 60
    ip_header->ip_p     = IPPROTO_UDP;
    ip_header->ip_sum   = 0; // set by kernel

    // Source & destination addresses

    memcpy(&(ip_header->ip_src), &(src_addr->sin_addr), sizeof(struct in_addr));
    memcpy(&(ip_header->ip_dst), &(dst_addr->sin_addr), sizeof(struct in_addr));

    // UDP header

    udp_header->uh_sport    = src_addr->sin_port; // already in network byte order
    udp_header->uh_dport    = dst_addr->sin_port;
    udp_header->uh_ulen     = htons(sizeof(struct udphdr) + datalen);
    udp_header->uh_sum      = 0; // set by the kernel
}

void choose_ip_addr(struct sockaddr_in *spoof_addr) {
    printf("Please choose your future ip address: ");
    char ip[15];
    int bool = 0;

    // try to check that the address given by the user has the right format

    do {
        if (bool) printf("\nip invalid format, please try again: ");
        memset(ip, 0, 15);
        fgets(ip, 15, stdin);
    } while(bool = (spoof_addr->sin_addr.s_addr = inet_addr(ip)) == (in_addr_t) -1);

    // no need to check for unsigned short since it cannot get out of range because of its type

    u_short port;
    printf("\nNow choose a port number: ");
    fscanf(stdin, "%hu", &port);
    spoof_addr->sin_port = port;
}

void spoof(struct sockaddr_in *dest, struct sockaddr_in *spoof) {
    
    // create the headers that are going to be crafted

    struct ip ip_header;
    struct udphdr udp_header;

    // Get the message from the user

    char payload[MAX_PAYLOAD_SIZE];
    int datalen; // = strlen(payload)

    u_char datagram[MTU];

    int sockfd = socket(AF_INET,        // use IPV4
                        SOCK_RAW,       // allows us to craft our own protocol header
                        IPPROTO_RAW);   // we supply all the headers from the IP layer to the highest we are using


    while (TRUE) {
        memset(payload, 0, MAX_PAYLOAD_SIZE);
        printf("Send a message:\n");
        fgets(payload, MAX_PAYLOAD_SIZE, stdin);

        // create the datagram and fill it with all this stuff

        datalen = strlen(payload);

        fill_hdr(&ip_header, &udp_header, spoof, dest, datalen);

        memset(datagram, 0, MTU);
        memcpy(datagram, &ip_header, sizeof(ip_header));
        memcpy(datagram + sizeof(struct ip), &udp_header, sizeof(struct udphdr));
        memcpy(datagram + sizeof(struct ip) + sizeof(struct udphdr), payload, datalen);

        int datagramlen = sizeof(struct ip) + sizeof(struct udphdr) + datalen;

        // create the socket

        if (sendto(sockfd, datagram, datagramlen, 0, (struct sockaddr *)dest, sizeof(struct sockaddr)) == -1) {
            fprintf(stderr, "Cannot send the data: %d\n", errno);
            return;
        }
    }
}