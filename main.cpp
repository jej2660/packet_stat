#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/in.h>
#include "ip.h"
#include <map>
#include <unordered_map>
#include "info.h"
#include <vector>
#include <iostream>
#include <algorithm>

using namespace std;
vector<PacketInfo> table;

void usage() {
    printf("syntax: pcap-test pcapng\n");
    printf("sample: pcap-test test.pcapng\n");
}
void parsing(const u_char *packet, pcap_pkthdr *header);
void statistics();

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(dev, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            //printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        parsing(packet,header);
    }
    statistics();
    pcap_close(handle);
}

void parsing(const u_char *packet, pcap_pkthdr *header){
    struct PacketInfo tmp;
    libnet_ipv4_hdr *ipv4 = (libnet_ipv4_hdr *)(packet + 14);
    u_char pro = ipv4->ip_p;

    //protocol classfication
    if(pro == IPPROTO_TCP){
        libnet_tcp_hdr *tcphdr = (libnet_tcp_hdr *)(packet + 14 + ipv4->ip_hl * 4);
        tmp.sourceip = Ip(ntohl(ipv4->ip_src.s_addr));
        tmp.destip = Ip(ntohl(ipv4->ip_dst.s_addr));
        tmp.sourceport = ntohs(tcphdr->th_sport);
        tmp.destport = ntohs(tcphdr->th_dport);
        tmp.bytelen = header->caplen;
        tmp.flag = 0;
        tmp.protocol = IPPROTO_TCP;
        table.push_back(tmp);
    }
    else if(pro == IPPROTO_UDP){
        libnet_udp_hdr *udphdr = (libnet_udp_hdr *)(packet + 14 + ipv4->ip_hl * 4);
        tmp.sourceip = Ip(ntohl(ipv4->ip_src.s_addr));
        tmp.destip = Ip(ntohl(ipv4->ip_dst.s_addr));
        tmp.sourceport = ntohs(udphdr->uh_sport);
        tmp.destport = ntohs(udphdr->uh_dport);
        tmp.bytelen = header->caplen;
        tmp.flag = 0;
        tmp.protocol = IPPROTO_UDP;
        table.push_back(tmp);
    }
}


void statistics(){
    vector<PacketInfo>::iterator it;
    vector<PacketInfo>::iterator st;
    unordered_map<Check, vector<PacketInfo>, MyHashFuntion> stat;
    unordered_map<Check, vector<PacketInfo>, MyHashFuntion>::iterator mit;
    for(it = table.begin();it != table.end();it++){
        Check tmp(it->sourceip, it->sourceport, it->destip, it->destport);
        Check tmp2(it->destip, it->destport, it->sourceip, it->sourceport);
        vector<PacketInfo> tmpvec;

        if(!(stat.count(tmp) == 1 || stat.count(tmp2) == 1)){
            for(st = (it++);st != table.end();st++){
                if( (it->sourceip.ip_ == st->destip.ip_) && (it->sourceport == st->destport) &&
                        (it->destip.ip_ == st->sourceip.ip_) && (it->destport == st->sourceport) )//ban dae
                {
                    st->flag = 1;
                    tmpvec.push_back(*st);
                }
                else if( (it->sourceip.ip_ == st->sourceip.ip_) && (it->sourceport == st->sourceport) &&
                         (it->destip.ip_ == st->destip.ip_) && (it->destport == st->destport))//dong ill
                {
                    tmpvec.push_back(*st);
                }
            }
            stat[tmp] = tmpvec;
        }
    }
    vector<DisplayInfo> result;
    for(mit = stat.begin();mit != stat.end();mit++){
        PacketInfo ptmp = *(mit->second.begin());
        DisplayInfo dtmp(ptmp.sourceip, ptmp.destip,ptmp.sourceport,ptmp.destport,0,0,0,0);
        for(it = mit->second.begin(); it != mit->second.end();it++){
            if(it->flag == 1){
                dtmp.dbyte += it->bytelen;
                dtmp.dcount++;
            }
            else{
                dtmp.sbyte += it->bytelen;
                dtmp.scount += it->bytelen;
            }
        }
        result.push_back(dtmp);
    }
    for(vector<DisplayInfo>::iterator it = result.begin();it != result.end();it++){
        cout << "IP A: " << string(it->sip) << endl << "IP B: " << string(it->dip) << endl << "port A: " << it->sp << endl << "port B: " << it->dp
              << endl << "All count: " << it->dcount + it->scount << endl << "All packet byte: " << it->dbyte + it->sbyte << endl << "count A-->B: " << it->scount << endl
             << "count B-->A: " << it->dcount << endl << "Byte A-->B: " << it->sbyte << endl << "Byte B-->A: " << it->dbyte << endl << endl << endl;

    }
}
