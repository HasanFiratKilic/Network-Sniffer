#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <netinet/ip.h> 
#include <netinet/tcp.h>

void print_usage(const char *program_name);
void sniff(char *dev,char *filter_exp);
int check_device(char *dev,char *errbuf);

int count = 0;
char pyld[200] ="Payload: ";  
#define ETHERNET_HEADER_SIZE 14
//performs the action indicated on the sniffed package.
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
	
 	struct ip *ip_header = (struct ip *)(packet + ETHERNET_HEADER_SIZE); // Ethernet header is 14 bytes
        struct tcphdr *tcp_header = NULL;
        const char *payload = NULL;
        int ip_header_size = 0;
        int tcp_header_size = 0;
        int payload_size = 0;

        if (ip_header->ip_p == IPPROTO_TCP) {
        	
        	ip_header_size = ip_header->ip_hl * 4; // IP header length in bytes
        	tcp_header = (struct tcphdr *)(packet + ETHERNET_HEADER_SIZE + ip_header_size);
        	tcp_header_size = tcp_header->th_off * 4; // TCP header length in bytes
        	payload = (const char *)(packet + ETHERNET_HEADER_SIZE + ip_header_size + tcp_header_size);
        	payload_size = ntohs(ip_header->ip_len) - (ip_header_size + tcp_header_size);
		strcat(pyld,("%.*s\n", payload_size, payload));
        	if (count > 6) {
            		
            		printf("Captured packet:\n");
            		printf("Src IP: %s\n", inet_ntoa(ip_header->ip_src));
            		printf("Dst IP: %s\n", inet_ntoa(ip_header->ip_dst));
           		printf("Payload (%d bytes):\n", payload_size);
            		
            		
            		printf("%s\n",pyld);
            		count = 0;
        	}
        	count++;
        }
    
	
            
        
}


int main(int argc, char *argv[]){
	
	int opt;
	char *dev;
	char *filter_exp;
	while((opt = getopt(argc,argv,"hd:b:")) !=-1 ){
		
		switch(opt){
			case 'h':
				print_usage(argv[0]);
				break;
			case 'd':
				dev = optarg;
				
				break;
			case 'b':
				filter_exp = optarg;
				
				break;
			default:
                		printf("error");
                		return 1;
				
		}
	}
	sniff(dev,filter_exp);
		
}

//prints the arguments related to the use
void print_usage(const char *program_name) {
    printf("Usage: %s [-h help] [-d Device name] [-b BPF expression]\n", program_name);
    printf("Options:\n");
    printf("  -h              This shows the help message.\n");
    printf("  -d              Specifies the device name to use.\n");
    printf("  -b              Specifies BPF query\n");
}

//Performs packet sniffing
void sniff(char *dev,char *filter_exp){
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;		
	bpf_u_int32 net;  
    	bpf_u_int32 mask;  
    	pcap_t *handle;
    	
	if(check_device(dev,errbuf)==1){
		 if(pcap_lookupnet(dev,&net,&mask,errbuf)==-1){
		 	fprintf(stderr, "Error finding device: %s\n", errbuf);
		 }
		 
		 handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
		 if(handle ==NULL){
		 	fprintf(stderr,"Couldn't open device %s: %s\n", dev, errbuf);
		 }
		 
		 if(pcap_compile(handle,&fp,filter_exp,0,net)==-1){
		 	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		 }
		 
		 if(pcap_setfilter(handle,&fp) == -1){
		 	fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		 }
		 
		 pcap_loop(handle,-1,packet_handler,NULL);		
	}
	
}
//checks whether the entered interface is present or not   
int check_device(char *dev,char *errbuf){
	pcap_if_t *d;
	pcap_if_t *alldevs; 
	
	
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        	fprintf(stderr, "Error finding devices: %s\n", errbuf);
        	
    	}
    	
    	for (d = alldevs; d != NULL; d = d->next) {
    		
    		if((strcmp(dev,d->name))==0){
    			printf("%s = %s",dev,d->name);
    			return 1;
    		}
    	}
    	return 0;
    		
    
}   
    
 
    
    
    
    
    
  
