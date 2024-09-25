#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h> 
#include <net/ethernet.h> 
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <ctype.h>
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <netinet/if_ether.h> 

const char* ivar = NULL;
int tot_header_size = 0;
int tcp_flows = 0;
int udp_flows = 0;
short unsigned int filt_port = 0;
int hflag = 0;
int iflag = 0;
int rflag = 0;
int fflag = 0;
FILE *logfile;
int total = 0;
int tcp_total_bytes = 0;
int udp_total_bytes = 0;
int packet_payloadd;
long int payloadd_addr;
int tcp = 0;
int udp =0;
int packet_contr = 0;
char* ip_src = NULL;
char* ip_dst = NULL;
short unsigned int packet_src = 0;
short unsigned int packet_dst = 0;
unsigned int ip_version = 0;
const char* packet_prot = NULL;

int retransmissionn=0;
struct floww
{
	char *src_ip;
    char *dest_ip;

    uint16_t src_port;
    uint16_t dest_port;

    const char* protocol;

    int currseq_num;
    int nextexp_seq_num;

    struct floww *next;
};

struct floww *flows = NULL;


int retransmission_(struct floww *head_flow, struct tcphdr *tcph, int payload_size)
{
    struct floww *curr_flow = head_flow;

    while(curr_flow != NULL)
    {
    	if ((strcmp(curr_flow->src_ip, ip_src) == 0) && (strcmp(curr_flow->dest_ip, ip_dst) == 0) && (curr_flow->src_port == packet_src) && (curr_flow->dest_port == packet_dst) && (strcmp(curr_flow->protocol, packet_prot)))
        {
       
            //"Keep alives" are different thing than retransmission
            if ((payload_size <= 1) && ((tcph->th_flags & TH_SYN) || (tcph->th_flags & TH_FIN) || (tcph->th_flags & TH_RST)) && ((ntohl(tcph->th_seq) - curr_flow->nextexp_seq_num) == -1))
            	return 0; 

            //That's a retransmission though in terms of TCP
            if (((payload_size > 0) || (tcph->th_flags & TH_SYN) || (tcph->th_flags & TH_FIN)) && ((curr_flow->nextexp_seq_num) > ntohl(tcph->th_seq)) )
            {
            	//mark the actor packet.
            	retransmissionn = 1;
                return 1; 
            }
        }
        curr_flow = curr_flow->next;
    }
    return 0;
}


struct floww *list_flow(struct floww *head, struct floww *node)
{
	if(!head)
		return node;

	struct floww *curr = head;
	while(curr->next != NULL)
	{
		curr = curr->next;
	}
	curr->next = node;

	return head;
}

int flow_exists(struct floww *head, struct floww *node)
{
	struct floww *curr_flow = head;

	//parse the list..
	while(curr_flow)
	{
		if ((strcmp(curr_flow->src_ip, node->src_ip) == 0) && (strcmp(curr_flow->dest_ip, node->dest_ip) == 0) && (curr_flow->src_port == node->src_port) && (curr_flow->dest_port == node->dest_port) && (strcmp(curr_flow->protocol ,node->protocol)==0))
        	return 1;
        //move on
        curr_flow = curr_flow->next;

	}

	//if reached there flow is unique..
	return 0;
}


struct floww *udp_flow_constructor( struct udphdr *udph)
{	
	struct floww *f = (struct floww *)malloc(sizeof(struct floww));
	
	f->src_ip = ip_src;
	f->dest_ip = ip_dst;
	f->dest_port = packet_dst;
	f->src_port = packet_src;
	f->protocol = packet_prot;
	f->next = NULL;

	f->currseq_num = 0;
	f->nextexp_seq_num = 0;

	return f;
}


struct floww *tcp_flow_constructor( struct tcphdr *tcph, int payload_size)
{	
	struct floww *f = (struct floww *)malloc(sizeof(struct floww));
	
	f->src_ip = ip_src;
	f->dest_ip = ip_dst;
	f->dest_port = packet_dst;
	f->src_port = packet_src;
	f->protocol = packet_prot;
	f->next = NULL;

	f->currseq_num = ntohl(tcph->th_seq);
	f->nextexp_seq_num = ntohl(tcph->th_seq) + payload_size;

	return f;
}

void packet_printrr(){
	if(rflag==1){
		printf("Packet's protocol: %s\n", packet_prot);
		printf("Packet's ip version: %d\n", ip_version);
		printf("Packet's ip source: %s\n", ip_src);
		printf("Packet's ip destination: %s\n", ip_dst);
		printf("Packet's source port: %d\n", packet_src);
		printf("Packet's destination port: %d\n", packet_dst);
		printf("Packet's Packet's header length: %d\n", tot_header_size);
		printf("Packet's payload: %d\n", packet_payloadd);
		printf("Packet's payload address: %ld\n", payloadd_addr);
		printf("Retransmission: %d\n\n\n\n", retransmissionn);
	}

	if(iflag==1){
		logfile = fopen("log", "a");
		fprintf(logfile, "Packet's protocol: %s\n", packet_prot);
		fprintf(logfile, "Packet's ip version: %d\n", ip_version);
		fprintf(logfile, "Packet's ip source: %s\n", ip_src);
		fprintf(logfile, "Packet's ip destination: %s\n", ip_dst);
		fprintf(logfile, "Packet's source port: %d\n", packet_src);
		fprintf(logfile, "Packet's destination port: %d\n", packet_dst);
		fprintf(logfile, "Packet's Packet's header length: %d\n", tot_header_size);
		fprintf(logfile, "Packet's payload: %d\n", packet_payloadd);
		fprintf(logfile, "Packet's payload address: %ld\n", payloadd_addr);
		fprintf(logfile, "Retransmission: %d\n\n\n\n", retransmissionn);
		fclose(logfile);
	}
}

void packet_infoG(const u_char *packet, int size){
	if(packet_contr==1){// its a tcp packet
		packet_prot = "tcp";
		unsigned short iphdrlen;
		struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
		iphdrlen = iph->ihl*4;
		
		ip_src = (char*)malloc(sizeof(INET_ADDRSTRLEN));
		ip_dst = (char*)malloc(sizeof(INET_ADDRSTRLEN));
		inet_ntop(AF_INET, &(iph->saddr), ip_src, INET_ADDRSTRLEN) ;
		inet_ntop(AF_INET, &(iph->daddr), ip_dst, INET_ADDRSTRLEN);
		
		struct tcphdr *tcph = (struct tcphdr*)(packet + sizeof(struct ethhdr) + iphdrlen);
		tot_header_size = sizeof(struct ethhdr) + iphdrlen + sizeof(struct tcphdr);
		packet_src = ntohs(tcph->source);
		packet_dst = ntohs(tcph->dest);

		if(fflag==1){
			if(packet_src!=filt_port&&packet_dst!=filt_port){
				return;
			}
		}

		packet_payloadd = size - tot_header_size;
		payloadd_addr = (long int)(&packet) + tot_header_size;

		if(!retransmission_(flows, tcph, packet_payloadd)){
			struct floww *fl = tcp_flow_constructor( tcph, packet_payloadd);
			if(!flow_exists(flows,fl))
			{
				tcp_flows++;
				flows = list_flow(flows, fl);
			}
		}

	}

	if(packet_contr==2){// its a udp packet
		packet_prot = "udp";
		unsigned short iphdrlen;
		struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
		iphdrlen = iph->ihl*4;
		ip_version = (unsigned int)iph->version;

		ip_src = (char*)malloc(sizeof(INET_ADDRSTRLEN));
		ip_dst = (char*)malloc(sizeof(INET_ADDRSTRLEN));
		inet_ntop(AF_INET, &(iph->saddr), ip_src, INET_ADDRSTRLEN) ;
		inet_ntop(AF_INET, &(iph->daddr), ip_dst, INET_ADDRSTRLEN);

		struct udphdr *udph = (struct udphdr*)(packet + iphdrlen  + sizeof(struct ethhdr));
		tot_header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof(struct udphdr);
		packet_src = ntohs(udph->source);
		packet_dst = ntohs(udph->dest);

		if(fflag==1){
			if(packet_src!=filt_port&&packet_dst!=filt_port){
				return;
			}
		}

		packet_payloadd = size - tot_header_size;
		payloadd_addr = (long int)(&packet) + tot_header_size;

		struct floww *fl = udp_flow_constructor(udph);

			//check if there..
			if(!flow_exists(flows,fl))
			{
				udp_flows++;
				flows = list_flow(flows, fl);
			}
	}
	if(packet_contr==1 || packet_contr==2)
		packet_printrr();
}

void packet_analysis(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	packet_contr = 0;
	int size = header->len;

	struct ether_header *eth = (struct ether_header*)(packet);

	if(ntohs(eth->ether_type)==ETHERTYPE_IPV6){
		ip_version = 6;
	}

	if(ntohs(eth->ether_type)==ETHERTYPE_IP){
		ip_version = 4;
	}

	struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
	switch(iph->protocol){
	case 6:
		tcp_total_bytes += size;
		++tcp;
		packet_contr = 1;
		packet_infoG(packet, size);
		break;
	case 17:
		udp_total_bytes += size;
		++udp;
		packet_contr = 2;
		packet_infoG(packet, size);
		break;
	case '?':
		return;
	}
}

int main(int argc, char *argv[])
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;	

	const char* rvar = NULL;
	int c;

	while ((c = getopt (argc, argv, "i:r:f h")) != -1){
		switch(c){
			case 'i':		// the user provides the filename of plaintext
			ivar = optarg;
			iflag = 1;
			break;

			case 'r':		// the user provides the filename where ciphertext will be stored
			rvar = optarg;
			rflag = 1;
			break;

			case 'f':		// the user provides the filename from which the keys will be retrieved
			fflag = 1;
			break;

			case 'h':
			hflag = 1;
			printf("\nThis help message\n");
			break;

			case '?':
				if(isprint(optopt))
					fprintf(stderr, "Uknown option '-%c'.\n", optopt);
				else
					fprintf(stderr,"Uknown option character'\\x%x'.\n", optopt );
				return 1;
				default: abort();
		}
		
	}

	if(iflag==1){
		remove("log");
		
		printf("How many packets would you like to scan for ");
		scanf("%d", &total);

		if(fflag==1){
			printf("which port would you like to filter: ");
			scanf("%hd", &filt_port);
		}

		handle = pcap_open_live(ivar, 65536, 1, -1, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			return(2);
		}
		pcap_loop(handle, total, packet_analysis, NULL);
		pcap_close(handle);

		int total_flows = udp_flows + tcp_flows;
		printf("Statistics\n");
		printf("Total packets recieved : %d\n", total);
		printf("Total tcp packets recieved : %d\n", tcp);
		printf("Total udp packets recieved : %d\n", udp);
		printf("Total tcp bytes recieved : %d\n", tcp_total_bytes);
		printf("Total udp bytes recieved : %d\n", udp_total_bytes);
		printf("Total flows recieved : %d\n", total_flows);
		printf("Total tcp flows recieved : %d\n", tcp_flows);
		printf("Total udp flows recieved : %d\n", udp_flows);

		printf("\nLive capture complete.\n");
		return 0;
	}

	if(rflag==1){

		printf("How many packets would you like to scan for ");
		scanf("%d", &total);

		if(fflag==1){
			printf("which port would you like to filter: ");
			scanf("%hd", &filt_port);
		}

		handle = pcap_open_offline(rvar, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			return(2);
		}
		pcap_loop(handle, total, packet_analysis, NULL);
		pcap_close(handle);

		int total_flows = udp_flows + tcp_flows;
		printf("Statistics\n");
		printf("Total packets recieved : %d\n", total);
		printf("Total tcp packets recieved : %d\n", tcp);
		printf("Total udp packets recieved : %d\n", udp);
		printf("Total tcp bytes recieved : %d\n", tcp_total_bytes);
		printf("Total udp bytes recieved : %d\n", udp_total_bytes);
		printf("Total flows recieved : %d\n", total_flows);
		printf("Total tcp flows recieved : %d\n", tcp_flows);
		printf("Total udp flows recieved : %d\n", udp_flows);

		printf("\nCapture complete.\n");
		return 0;
	}	
}