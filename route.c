#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <inttypes.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

/*
** ARP, IP and ICMP header sturcts were developed based off of information 
** provided by networksourcery.com. full link below
** http://www.networksorcery.com/enp/default.htm
** 
** CheckSum method was developed in the book and help from another student
**
*/

struct ARP_header{
    unsigned short hard;
    unsigned short proto;
    unsigned char hard_addr_len;
    unsigned char proto_addr_len;
    unsigned short opcode;
    unsigned char s_hard_addr[6];
    unsigned char s_proto_addr[4];
    unsigned char d_hard_addr[6];
    unsigned char d_proto_addr[4];
};

struct routing_table {
    char addr[10];
    char prefix[3];
    char ll_hop[9];
    char interface_name[8];
};

struct interface{
    char * name;
    int socket;
    unsigned char mac_addr[6];
    struct sockaddr* ip_addr;
};

//Declearations of functions
u_short Checksum(u_short *buf, int count);
int Send_ARP_Reply(char *data, unsigned char my_mac_address[6], int current_socket);
int Send_ARP_Request(char * host_ip, unsigned char my_mac_address[6],char * dest_ip, int socket);
int Forward_IP_Packet(char * buf, int current_socket,unsigned char my_mac_address[6], int packet_size);
int Send_ICMP_Error(unsigned char my_mac_address[6], int current_socket,int type_of_error,struct in_addr my_ip);

int main(){

    struct interface interfaces[4];
    int packet_socket;
    unsigned char my_mac_addr[6];
    int counter = 0;
    int counter2 = 0;
    const char * r_num_c;
    struct routing_table rt[5];
    FILE *fp;
    char file_name[13];
    char part[10];
    char part1[10];
    char part2[10];
    struct in_addr* list_of_ips[6];
    int number_of_ips = 0;
    int packet_size;
   // unordered_multimap<string,string> ip_map;


    //create the ifaddrs linked list
    struct ifaddrs *ifaddr, *tmp;
    if(getifaddrs(&ifaddr)==-1){
        perror("getifaddrs");
        return 1;
    }

    //create the file descriptors
    fd_set sockets;
    FD_ZERO(&sockets);

//================================================================
//loop through the linked list of interfaces
//================================================================
  //have the list, loop over the list
    for(tmp = ifaddr; tmp!=NULL; tmp=tmp->ifa_next){

        //check if packet address
        if(tmp->ifa_addr->sa_family==AF_PACKET){

            //create a packet socket on interface r?-eth1
            if(!strncmp(&(tmp->ifa_name[3]),"eth",3)){

                r_num_c = (const char *) &(tmp->ifa_name[1]);

                printf("Creating Socket on interface %s\n",tmp->ifa_name);

                //create a packet socket
                packet_socket = socket(AF_PACKET, //AF_PACKET makes it a packet socket
                                    SOCK_RAW,   //SOCK_RAW makes it so we get the entire packet
                                    htons(ETH_P_ALL)); //ETH_P_ALL indicates we want all (upper layer) protocols
                
                if(packet_socket<0){
                    perror("socket");
                    return 2;
                }

                 //Bind the socket to the address, so we only get packets recieved on this specific interface. 
                if(bind(packet_socket,tmp->ifa_addr,sizeof(struct sockaddr_ll))==-1){
                    perror("bind");
                }
                
                //Add the socket on this interface to our fd list
                FD_SET(packet_socket,&sockets);     

                //set the values of interfaces                          
                interfaces[counter].name =tmp->ifa_name;
                interfaces[counter].socket = packet_socket;
                struct sockaddr_ll *my_address_info = (struct sockaddr_ll *)tmp->ifa_addr;
                memcpy(interfaces[counter].mac_addr, my_address_info->sll_addr,6);

                counter++;
            }
        }

        //check the IP part of the interface
        if(tmp->ifa_addr->sa_family == AF_INET){

            //if it is on ethernet
            if(!strncmp(&(tmp->ifa_name[3]),"eth",3)){
                
                //add the IP address to our interfaces list
                interfaces[counter2].ip_addr = tmp->ifa_addr;

                //create a list of IPs
                struct sockaddr_in *temp_sockaddr_in;
                temp_sockaddr_in = (struct sockaddr_in * ) interfaces[counter2].ip_addr;  
                list_of_ips[number_of_ips] = &(temp_sockaddr_in->sin_addr);
                number_of_ips++;
                counter2++;
            }
        }
    }

//================================================================
//reading in the routing table
//================================================================
    
    int rnum = atoi(r_num_c);
    
    if(rnum == 1){
        strcpy(file_name,"r1-table.txt");
    }else if(rnum == 2){
        strcpy(file_name,"r2-table.txt");
    }else{
        printf("Error creating routing table\n");
        exit(-1);
    }

    fp = fopen(file_name, "r");
    if (fp == NULL) {
        printf("Error creating routing table\n");
        exit(-1);
    }

    int rt_rows=0;
    do{
        int file_check = fscanf(fp,"%s%s%s",part,part1,part2);
        strcpy(rt[rt_rows].addr, strtok(part, "/"));
        strcpy(rt[rt_rows].prefix,&part[9]);
        strcpy(rt[rt_rows].ll_hop, part1);
        strcpy(rt[rt_rows].interface_name, part2);
        rt_rows++;
    }while(fgetc(fp) != EOF);

    if(rt_rows < 1 ){
        printf("Error creating routing table\n");
        exit(1);
    }
    printf("Routing Table Established\n");
    int i =0;

//================================================================
//listen for incomeing data
//================================================================
  //loop and recieve packets. 
    printf("Ready to recieve now\n");
    while(1){
        char buf[1500];
        struct sockaddr_ll recvaddr;
        unsigned int recvaddrlen=sizeof(struct sockaddr_ll);
        
        fd_set tmp_set = sockets; 
        select(FD_SETSIZE, &tmp_set, NULL, NULL, NULL);
        int current_socket = 0;  
        
        for(current_socket; current_socket< FD_SETSIZE; current_socket++){
            if(FD_ISSET(current_socket, &tmp_set)){

                //receive our data
                packet_size = recvfrom(current_socket, buf, 1500,0,(struct sockaddr*)&recvaddr, &recvaddrlen);

                //only care about incoming packets
                if(recvaddr.sll_pkttype==PACKET_OUTGOING){
                    continue;
                }

                //start processing all others
                printf("\nGot a %d byte packet", packet_size);

                //incoming ethernet header
                struct ether_header *eth = (struct ether_header *) buf;
                
                //Ethernet type
                unsigned short type = ntohs(eth->ether_type);

                struct interface temp_interface;
                // loop through sockets and find our mac addr
                for (i = 0; i < counter; i++) {
                    if (interfaces[i].socket == current_socket) {
                        //find the sockets MAC addr and place it into my_mac_addr
                        temp_interface = interfaces[i];
                        break;
                    }   
                }
                //set our mac address for late access
                memcpy(my_mac_addr, temp_interface.mac_addr,6);

//================================================================
//if the incoming data is an arp
//================================================================
                //if the ethernet type is an arp
                if(type == ETHERTYPE_ARP){
                    int ret_val = 0;

                    //the incoming arp header
                    struct ARP_header *arp = (struct ARP_header *) (buf + sizeof(struct ether_header));

                    if(htons(arp->opcode) == 1){
                        printf("\n..... ARP request ..... \n\n");

                        ret_val = Send_ARP_Reply(buf, my_mac_addr, current_socket);
                        if(! ret_val){
                            
                            printf("ARP reply sent.\n\n");
                        }else{
                            printf("Error send ARP");
                            continue;
                        }
                    }

//================================================================
//if the incoming data is IP
//================================================================
                }else if(type == ETHERTYPE_IP){
                    printf("\n..... IP ..... \n\n");

                    //the response packet
                    char response[1500];
                    memcpy(response,buf,1500);

                    //the outgoing ethernet header
                    struct ether_header *eth_to_send = (struct ether_header *) response;

                    //This is the construction of the IP header
                    //we must do this here to make sure that the header following this is of type
                    //ICMP. This information is stored in the protocol part of the struct
                    struct iphdr *ip = (struct iphdr *) (buf + sizeof(struct ether_header));
                    int itr;

                    if (Checksum((u_short*)ip, 10) != 0) {
                        printf("Wrong checksum, dropping packet\n");
                        continue;
                    }
                    printf("Checksum verified. TTL:%d \n",ip->ttl);

                    
                    

                    //This loop will check to see if the destination IP is one of our IP address.
                    int my_ip_check = 0;
                    struct in_addr current_ip_socket;
                    for (itr = 0; itr < counter; itr++) {
                        //check to see if the IP is in our list of addresses
                        if (list_of_ips[itr]->s_addr == ip->daddr) {
                            my_ip_check = 1;
                            current_ip_socket = *list_of_ips[itr];
                            printf("%s belongs to us\n", inet_ntoa(current_ip_socket));
                            break;
                        }
                    }

                    //TTL decrement the ttl
                    ip->ttl = ip->ttl - 1;
                    
                    if(ip->ttl < 1){
                        printf("ttl is 0, dropping packet\n");
                        Send_ICMP_Error(my_mac_addr,current_socket,1,current_ip_socket); //TTL exceded
                    }

                    printf("ttl updated to %d\n",ip->ttl);
                     
                    if(my_ip_check == 0){
                        //this is the destination of the IP packet
                        char * dest_ip = inet_ntoa(*(struct in_addr*)&ip->daddr);

                        //save the routing table row to access later
                        struct routing_table current_rt;

                        //this loop will check to see if the destination is in our router table
                        int rt_match = 0;
                        for(itr=0; itr<rt_rows;itr++){
                            //Change this if the routing table changes
                            //calculates how many bits we have to check
                            int prefix_length = (atoi(rt[itr].prefix) / 8) * 2;
                            //check if the IP is in the routing table
                            if ((memcmp(dest_ip, rt[itr].addr, prefix_length)) == 0) {
                                current_rt = rt[itr];
                                rt_match = 1;
                                break;
                            }
                        }

                        int ret_val=1;
                        
                        if(rt_match == 1){

                            //find my IP address
                            for(itr =0; itr<counter;itr++){
                                //if the interface name matches a name in the routing table
                                if((memcmp(interfaces[itr].name, current_rt.interface_name,7))  == 0){
                                    
                                    //store the destination IP in a secure area
                                    char * dest_ip2 = (char *) malloc(sizeof(dest_ip));
                                    strcpy(dest_ip2,dest_ip);

                                    //create the host address
                                    struct sockaddr_in *temp_sockaddr_in;
                                    temp_sockaddr_in = (struct sockaddr_in *) interfaces[itr].ip_addr; 
                                    char * host_ip = inet_ntoa(temp_sockaddr_in->sin_addr);
                                    
                                    if(memcmp(current_rt.ll_hop, "-", 1) != 0){
                                        printf("Passing packet to next router.\n");
                                        dest_ip2 = current_rt.ll_hop;
                                    }


                                    //try and send the arp request
                                    ret_val = Send_ARP_Request(host_ip, my_mac_addr, dest_ip2,interfaces[itr].socket );
                                    if(!ret_val){
                                        printf("ARP request sent\nIP packet added to queue\n");

                                        int ARP_request_response = Forward_IP_Packet(buf,interfaces[itr].socket,my_mac_addr,packet_size );
                                        
                                        if( ARP_request_response == 1){
                                            printf("ARP Reply not received.");
                                            Send_ICMP_Error(my_mac_addr,current_socket,2,current_ip_socket);//host unreachable
                                            break;
                                        }else if (ARP_request_response == 0){
                                            printf("IP packet forwarded to %s\n",dest_ip2);
                                            break;
                                        }


                                    }else if(ret_val == 1){
                                        printf("Error sending ARP request");
                                    }
                                    break;
                                }
                            }
                            

                        }else if(rt_match == 0){
                            printf("IP dest not in network, dropping packet.\n");
                            Send_ICMP_Error(my_mac_addr,current_socket,3,current_ip_socket); //network unreachable
                            continue;
                        }
                    }
//================================================================
//if the incoming data is ICMP and sent to this router
//================================================================
                    //1 = ICMP protocl
                    else if(ip->protocol == IPPROTO_ICMP && my_ip_check > 0){

                       // if(ip->daddr ==  )
                        printf("\n..... ICMP request ..... \n\n");

                        //This is the construction of the ethernet header.
                        memcpy(eth_to_send->ether_dhost,eth->ether_shost,6);
                        memcpy(eth_to_send->ether_shost,eth->ether_dhost,6);
                        eth_to_send->ether_type = ntohs(ETHERTYPE_IP);

                        //This is the construction of the IP header to send
                        struct iphdr *ip_to_send = (struct iphdr *) (response + sizeof(struct ether_header));

                        ip_to_send->saddr = ip->daddr;
                        ip_to_send->daddr = ip->saddr;

                        //This is the construction of the ICMP header
                        struct  icmphdr *icmp = (struct icmphdr *) (buf+ sizeof(struct ether_header) + sizeof(struct iphdr));
                        struct icmphdr *icmp_to_send = (struct icmphdr *) (response+ sizeof(struct ether_header) + sizeof(struct iphdr));

                        if(icmp->type == ICMP_ECHO){

                            //type 0 because it is an echo reply
                            icmp_to_send->type = htons(0);

                            //Check this to make sure that it is correct
                            //network sorcery says: further quantifies the ICMP message
                            //so zero should be fine for PART ONE
                            icmp_to_send->code = htons(0);

                            //TEMP FOR PART ONE
                            //this will change once we implement a correct check sum function
                            
                            //icmp_to_send->checksum = icmp->checksum;

                            //send the response
                            int send_error = send(current_socket,response,98,0);

                            //error sending the response
                            if(send_error < 0){
                                printf("error sending response\n");
                                continue;
                            }
                            printf("ICMP reply sent.\n\n");
                        }else if(icmp->type == ICMP_ECHOREPLY){
                            //dosomething
                        }
                    }
                }
            }   
        }
    }

    //free the interface list when we don't need it anymore
    freeifaddrs(ifaddr);
    //exit
    return 0;
}

/*================================================================
* Send an arp request
* about
* Parameters
* return
=================================================================*/
int Send_ARP_Request(char * host_ip ,unsigned char my_mac_address[6], char * dest_ip, int current_socket){

    printf("Sending ARP request to: %s from: %s\n",dest_ip,host_ip);
    //the response packet
    char request[1500];

    //create destination ip
    struct in_addr dest, host;
    inet_aton(dest_ip, &dest);
    inet_aton(host_ip, &host);

    //the outgoing ethernet header
    struct ether_header *eth_to_send = (struct ether_header *) request;

    //This is the construction of the ethernet header.

    //broadcast mac address
    eth_to_send->ether_dhost[0] = 0xFFU;
    eth_to_send->ether_dhost[1] = 0xFFU;
    eth_to_send->ether_dhost[2] = 0xFFU;
    eth_to_send->ether_dhost[3] = 0xFFU;
    eth_to_send->ether_dhost[4] = 0xFFU;
    eth_to_send->ether_dhost[5] = 0xFFU;

    //ethernet source host MAC address
    memcpy(eth_to_send->ether_shost,my_mac_address,6);
    eth_to_send->ether_type = ntohs(ETHERTYPE_ARP);

    //the outgoing arp header
    struct ARP_header *arp_to_send = (struct ARP_header *) (request + sizeof(struct ether_header));

    //This is the construction of the arp header
    //1 = ethernet
    arp_to_send->hard = htons(1);
    //IP macro
    arp_to_send->proto = htons(ETH_P_IP);
    //mac address length = 6
    arp_to_send->hard_addr_len = 6;
    //IP addr length = 4
    arp_to_send->proto_addr_len = 4;
    //1 = request
    arp_to_send->opcode = htons(1);

    //sender MAC address
    memcpy(arp_to_send->s_hard_addr, my_mac_address,6); 

    //sender ip address
    arp_to_send->s_proto_addr[0] = (unsigned char)(host.s_addr) & 0xFFU;
    arp_to_send->s_proto_addr[1] = (unsigned char)(host.s_addr >> 8) & 0xFFU;
    arp_to_send->s_proto_addr[2] = (unsigned char)(host.s_addr >> 16) & 0xFFU;
    arp_to_send->s_proto_addr[3] = (unsigned char)(host.s_addr >> 24) & 0xFFU;

    //Broadcast address
    arp_to_send->d_hard_addr[0] = 0xFFU;
    arp_to_send->d_hard_addr[1] = 0xFFU;
    arp_to_send->d_hard_addr[2] = 0xFFU;
    arp_to_send->d_hard_addr[3] = 0xFFU;
    arp_to_send->d_hard_addr[4] = 0xFFU;
    arp_to_send->d_hard_addr[5] = 0xFFU;

    //Destination IP address
    arp_to_send->d_proto_addr[0] = (unsigned char)(dest.s_addr) & 0xFFU;
    arp_to_send->d_proto_addr[1] = (unsigned char)(dest.s_addr >> 8) & 0xFFU;
    arp_to_send->d_proto_addr[2] = (unsigned char)(dest.s_addr >> 16) & 0xFFU;
    arp_to_send->d_proto_addr[3] = (unsigned char)(dest.s_addr >> 24) & 0xFFU;

    //send the request
    int send_error = send(current_socket,request,42,0);

    //error sending the request
    if(send_error < 0){
        printf("error sending request");
        return(1);
    }

    return 0;
}

/*================================================================
* Send an arp reply
* about
* Parameters
* return
=================================================================*/
int Send_ARP_Reply(char *data, unsigned char my_mac_address[6], int current_socket ){

    struct ether_header *eth = (struct ether_header *) data;

    //the response packet
    char response[1500];

    //the incoming arp header
    struct ARP_header *arp = (struct ARP_header *) (data + sizeof(struct ether_header));

    //the outgoing ethernet header
    struct ether_header *eth_to_send = (struct ether_header *) response;

    //This is the construction of the ethernet header.
    memcpy(eth_to_send->ether_dhost,eth->ether_shost,6);

    //need a new way to find the mac address of us
    memcpy(eth_to_send->ether_shost,my_mac_address,6);
    eth_to_send->ether_type = ntohs(ETHERTYPE_ARP);

    //the outgoing arp header
    struct ARP_header *arp_to_send = (struct ARP_header *) (response + sizeof(struct ether_header));

    //This is constructing the arp header
    arp_to_send->hard = htons(1); //1 = ethernet
    arp_to_send->proto = htons(ETH_P_IP);  //IP macro
    arp_to_send->hard_addr_len = 6;  //mac address length = 6
    arp_to_send->proto_addr_len = 4; //IP addr length = 4
    arp_to_send->opcode = htons(2); //2 = reply
    memcpy(arp_to_send->s_hard_addr, my_mac_address,6); //sender MAC address
    memcpy(arp_to_send->s_proto_addr, arp->d_proto_addr,4); //sender ip address
    memcpy(arp_to_send->d_hard_addr, arp->s_hard_addr,6); //Destination MAC address
    memcpy(arp_to_send->d_proto_addr, arp->s_proto_addr,4); //Destination IP address

    //send the response
    int send_error = send(current_socket,response,42,0);

    //error sending the response
    if(send_error < 0){
        printf("error sending response");
        return(1);
    }
    return(0);
}

/*================================================================
* Forward_IP_Packet
* about
* Parameters
* return
=================================================================*/
int Forward_IP_Packet(char*buf, int current_socket, unsigned char my_mac_address[6],int packet_size){

    char temp_buf[1500]; 
    int n = recv(current_socket, temp_buf, 1500, 0);

    struct ether_header *temp_eth = (struct ether_header *) temp_buf;
    if(ntohs(temp_eth->ether_type) == ETHERTYPE_ARP){
        struct ARP_header *arp = (struct ARP_header *) (temp_buf + sizeof(struct ether_header));

        printf("ARP Reply MAC addr: %02X:%02X:%02X:%02X:%02X:%02X\n",
                arp->s_hard_addr[0],
                arp->s_hard_addr[1],
                arp->s_hard_addr[2],
                arp->s_hard_addr[3],
                arp->s_hard_addr[4],
                arp->s_hard_addr[5]);
        
        //change IP header and ethernet header in buf
        struct ether_header *eth = (struct ether_header *) buf;
        memcpy(eth->ether_dhost,temp_eth->ether_shost,6);
        memcpy(eth->ether_dhost,temp_eth->ether_shost,6);

        //update the checksum
        struct iphdr *ip = (struct iphdr *) (buf + sizeof(struct ether_header));
        ip->check = 0x0000U;
        ip->check = Checksum((u_short*)ip,10);
        printf("updated checksum:%u\n",ip->check);

        if(send(current_socket,buf,packet_size,0)<0){
            printf("Error forwarding packet");
            return(1);
        }
    }
   return 0; 
}

/*================================================================
* Checksum
* about FROM BOOK
* Parameters
* return
=================================================================*/
u_short Checksum(u_short *buf, int count) {
    register u_long sum = 0;

    while (count--) {
        sum += *buf++;
        if (sum & 0xFFFF0000) {
            sum &= 0xFFFF;
            sum++;
        }
    }
    return ~(sum & 0xFFFF);
}

/*================================================================
* Send_ICMP_Error
* about nws
* Parameters
* return
=================================================================*/

//1 = ttl exception
//2 = host unreachable
//3 = network unreachable
int Send_ICMP_Error(unsigned char my_mac_address[6], int current_socket,int type_of_error,struct in_addr my_ip){
    char error[42];

    //construct the ethernet header
    struct ether_header* eth = (struct ether_header*) error;

    memcpy(eth->ether_dhost, eth->ether_shost, 6);
    memcpy(eth->ether_shost, my_mac_address, 6);
    eth->ether_type = ntohs(0x0800);

    //construct the ip header
    struct iphdr* ip = (struct iphdr*) (error + sizeof(struct ether_header));
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = 42;
    ip->id = ip->id + 1;
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = 1;
    ip->check = 0;
    ip->saddr = my_ip.s_addr;
    ip->daddr = ip->saddr;

    //construct the icmp header
    struct icmphdr* icmp = (struct icmphdr*)(error + sizeof(struct ether_header)+ sizeof(struct iphdr));

    if(type_of_error == 1){
        icmp->type = ICMP_TIMXCEED;
        icmp->code = ICMP_TIMXCEED_INTRANS;
    }else if(type_of_error == 2){
        icmp->type = ICMP_UNREACH;
        icmp->code = ICMP_UNREACH_HOST;
    }else if(type_of_error == 3){
        icmp->type = ICMP_DEST_UNREACH;
        icmp->code = ICMP_NET_UNREACH;
    }

    //update the checksum
    ip->check = Checksum((u_short*)ip, 10);
    icmp->checksum = Checksum((u_short*)icmp, 10);

    send(current_socket, error, 42, 0);

    return 0;
}