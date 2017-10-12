#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<pcap.h>

int main(int argc, char const *argv[]) {
    char * dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    dev = malloc(sizeof(char)* strlen(argv[1]));
    strcpy(dev, argv[1]);

    printf("Provided Interface : %s \n", dev);

    handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);


    if(handle == NULL){
        fprintf(stderr, "Unable to Open the Device %s\n", errbuf );
        return 0;
    }

    return 0;
}
