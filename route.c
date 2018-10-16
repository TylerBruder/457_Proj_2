#include <sys/socket.h> 
#include <netpacket/packet.h> 
#include <net/ethernet.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <inttypes.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <unistd.h>

//declaration of the checksum 
//will change after part 1 
u_short toCksum(char *data, int length);

/*
** ARP, IP and ICMP header sturcts were developed based off of information 
** provided by networksourcery.com. full link below
** http://www.networksorcery.com/enp/default.htm
*/

struct ARP_header{
  unsigned short hard;
  unsigned short proto;
  uint8_t hard_addr_len;
  uint8_t proto_addr_len;
  unsigned short opcode;
  uint8_t s_hard_addr[6];
  uint8_t s_proto_addr[4];
  uint8_t d_hard_addr[6];
  uint8_t d_proto_addr[4];
};

struct IP_header{
  uint8_t ihl:4, v:4;  //each are 4 bits
  uint8_t diff_services;  //8 bits 
  unsigned short total_length; //16 bits
  unsigned short ID; //16 bits
  uint8_t flags; //3 bits
  uint8_t fragment_offset; //13 bits
  uint8_t time_to_live; //8 bits
  uint8_t proto; //8 bits
  unsigned char checksum; //16bits 
  uint8_t s_ip[4]; //32 bits
  uint8_t d_ip[4]; //32 bits
};

struct ICMP_header{
  uint8_t type;
  uint8_t code;
  uint8_t checksum;
};


int main(){

  int packet_socket;
  unsigned char my_addr[6];
  
  //create the ifaddrs linked listeth
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
      printf("Interface: %s\n",tmp->ifa_name);

      //create a packet socket on interface r?-eth1
      if(!strncmp(&(tmp->ifa_name[3]),"eth1",4)){

      	printf("Creating Socket on interface %s\n",tmp->ifa_name);

        struct sockaddr_ll *my_mac = (struct sockaddr_ll *)tmp->ifa_addr;
        memcpy(my_addr, my_mac->sll_addr,6); //tmp->ifa_addr->sll_addr

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
        FD_SET(packet_socket,&sockets);
      }
    }
  }

//================================================================
//listen for incomeing data
//================================================================
  //loop and recieve packets. 
  printf("Ready to recieve now\n");
  while(1){
    char buf[1500];
    struct sockaddr_ll recvaddr;
    int recvaddrlen=sizeof(struct sockaddr_ll);
    
    //receive our data
    int n = recvfrom(packet_socket, buf, 1500,0,(struct sockaddr*)&recvaddr, &recvaddrlen);
    

    fd_set tmp_set = sockets; 
    select(FD_SETSIZE, &tmp_set, NULL, NULL, NULL);
    int current_socket = 0;  
    
    for(current_socket; current_socket< FD_SETSIZE; current_socket++){
      if(FD_ISSET(current_socket, &tmp_set)){
        //only care about incoming packets
        if(recvaddr.sll_pkttype==PACKET_OUTGOING)
          continue;

        //start processing all others
        printf("Got a %d byte packet\n", n);

        //incoming ethernet header
        struct ether_header *eth = (struct ether_header *) buf;
        
        //Ethernet type
        unsigned short type = ntohs(eth->ether_type);
        // printf("type: %d",type);

//================================================================
//if the incoming data is an arp
//================================================================
        //if the ethernet type is an arp
        if(type == ETHERTYPE_ARP){
          printf("ITS A tARP\n");

          //the response packet
          char response[1500];

          //the incoming arp header
          struct ARP_header *arp = (struct ARP_header *) (buf + sizeof(struct ether_header));

          //the outgoing ethernet header
          struct ether_header *eth_to_send = (struct ether_header *) response;

          //This is the construction of the ethernet header.
          memcpy(eth_to_send->ether_dhost,eth->ether_shost,6);
          memcpy(eth_to_send->ether_shost,my_addr,6);
          eth_to_send->ether_type = ntohs(ETHERTYPE_ARP);

          //the outgoing arp header
          struct ARP_header *arp_to_send = (struct ARP_header *) (response + sizeof(struct ether_header));

          // printf("shardaddr: %hu\n",arp->s_hard_addr);
          // printf("sprotoaddr: %hu\n",arp->s_proto_addr);
          // printf("dhardaddr: %hu\n",arp->d_hard_addr);
          // printf("dprotoaddr: %hu\n\n",arp->d_proto_addr);


          //This is constructing the arp header
          arp_to_send->hard = htons(1); //1 = ethernet
          arp_to_send->proto = htons(ETH_P_IP);  //IP macro
          arp_to_send->hard_addr_len = 6;  //mac address length = 6
          arp_to_send->proto_addr_len = 4; //IP addr length = 4
          arp_to_send->opcode = htons(2); //2 = reply
          memcpy(arp_to_send->s_hard_addr, my_addr,6); //sender MAC address
          memcpy(arp_to_send->s_proto_addr, arp->d_proto_addr,4); //sender ip address
          memcpy(arp_to_send->d_hard_addr, arp->s_hard_addr,6); //Destination MAC address
          memcpy(arp_to_send->d_proto_addr, arp->s_proto_addr,4); //Destination IP address

          // printf("shardaddr: %hu\n",arp_to_send->s_hard_addr);
          // printf("sprotoaddr: %hu\n",arp_to_send->s_proto_addr);
          // printf("dhardaddr: %hu\n",arp_to_send->d_hard_addr);
          // printf("dprotoaddr: %hu\n\n",arp_to_send->d_proto_addr);

          //send the response
          int send_error = send(current_socket,response,42,0);

          //error sending the response
          if(send_error < 0){
            printf("error sending response");
            continue;
          }
          printf("ARP reply sent.\n\n");
//================================================================
//if the incoming data is an ICMP
//================================================================
        }else if(type == ETHERTYPE_IP){
          printf("IP packet\n");

          //the response packet
          char response[1500];
          memcpy(response,buf,1500);
          
          //the outgoing ethernet header
          struct ether_header *eth_to_send = (struct ether_header *) response;

          //This is the construction of the IP header
          //we must do this here to make sure that the header following this is of type 
          //ICMP. This information is stored in the protocol part of the struct
          // struct iphdr *ip = (struct iphdr *) (buf + sizeof(struct ether_header));
          struct iphdr *ip = (struct iphdr *) (buf + sizeof(struct ether_header));
          
          //1 = ICMP protocl 
         // if(ntohs((ip->proto)) == 1){
            printf("ICMP packet\n");

            //This is the construction of the ethernet header.
            memcpy(eth_to_send->ether_dhost,eth->ether_shost,6);
            memcpy(eth_to_send->ether_shost,eth->ether_dhost,6);
            eth_to_send->ether_type = ntohs(ETHERTYPE_IP);

            //This is the construction of the IP header to send
//            struct iphdr *ip_to_send = (struct iphdr *) (response + sizeof(struct ether_header));
            struct iphdr *ip_to_send = (struct iphdr *) (response + sizeof(struct ether_header));

            //12 = sizeof(ihl + v + diff_services + total_length + ID + flags + fragment_offset + time_to_live + proto + checksum) 
            //this is alwasy true 
            //given from network sourcery
            memcpy(ip_to_send,ip,12);
            ip_to_send->saddr = ip->daddr;  
            ip_to_send->daddr = ip->saddr;
                          
            //This is the construction of the ICMP header
            struct ICMP_header *icmp = (struct ICMP_header *) (buf+ sizeof(struct ether_header) + sizeof(struct iphdr));
            struct ICMP_header *icmp_to_send = (struct ICMP_header *) (response+ sizeof(struct ether_header) + sizeof(struct iphdr));
           // char data[100] = (buf+ sizeof(struct ether_header) + sizeof(struct iphdr)) + sizeof(icmp);
            //memcpy(icmp_to_send,icmp,sizeof(icmp));

            //type 0 because it is an echo reply 
            icmp_to_send->type = htons(0);

            //Check this to make sure that it is correct
            //network sorcery says: further quantifies the ICMP message 
            //so zero should be fine for PART ONE 
            icmp_to_send->code = htons(0);

            //TEMP FOR PART ONE 
            //this will change once we implement a correct check sum function 
            icmp_to_send->checksum = icmp->checksum;
            
            //send the response
            int send_error = send(current_socket,response,98,0);

            //error sending the response
            if(send_error < 0){
              printf("error sending response\n");
              continue;
            }
            printf("ICMP reply sent.\n\n");
          //}
      }
    }
  }
}
  //free the interface list when we don't need it anymore
  freeifaddrs(ifaddr);
  //exit
  return 0;
}


//CHECKSUM METHOD goes here
//talked to classmates about this method in last project 
u_short toCksum(char *data, int length) {
    u_short checkSum= 0;
    unsigned int cl = length;
      while (cl != 0){
		checkSum -= *data++;
		cl--;
      }
      return checkSum;
}

//from the book
//
//u_short cksum(u_short *buf, int count) { 
//	register u_long sum = 0;
//	while (count--){
//		sum += *buf++; 
//		if (sum & 0xFFFF0000)
//		{
//		/* carry occurred, so wrap around */ 
//		sum &= 0xFFFF; sum++;
//		}
//	} 
//	return ˜~(sum & 0xFFFF);
//}
