#include<stdio.h>
#include<pcap.h>

int main(int argc, char const *argv[]) {
    pcap_t *handle;         /* Session Handler */
    struct bpf_program fp;   /* stroring compiled filter */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error Buf */
    char dev[] = "eth1";            /* Device to Sniff */
    char filter[] = "port 5060";      /* Capture Filter, Let's capture some SIP :) */
    bpf_u_int32 mask;		/* The netmask of our sniffing device */
    bpf_u_int32 net;		/* The IP of our sniffing device */

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if(handle == NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
    }

    if(pcap_compile(handle, &fp, filter, 0, net) == -1){
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
        return(2);
    }

    if(pcap_setfilter(handle, &fp) == -1){
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
        return(2);
    }

    return 0;
}
