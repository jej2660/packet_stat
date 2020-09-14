#ifndef INFO_H
#define INFO_H

#endif // INFO_H
#include "ip.h"
using namespace std;
struct PacketInfo{
public:
    u_int16_t sourceport;
    u_int16_t destport;
    Ip sourceip;
    Ip destip;
    int bytelen;
    int protocol;
    int flag;
};

struct Check{
public:
    Ip ip;
    u_int16_t port;
    Ip dip;
    u_int16_t dport;
    Check(Ip ip, u_int16_t port, Ip dip, u_int16_t dport){
        this->ip = ip;
        this->port = port;
        this->dip = dip;
        this->dport = dport;
    }
    Check();
    bool operator== (const Check &r) const{
        return ( (this->ip == r.ip && this->port == r.port && this->dip == r.dip && this->dport == r.dport));
    }
    /*
    bool operator< (const Check &r) const {
        return ( this->ip.ip_ < r.ip.ip_);
    }*/
};

class MyHashFuntion{
public:
    size_t operator() (const Check &c) const {
      return (hash<uint32_t>() (c.ip.ip_) ^ hash<uint32_t>() (c.dip.ip_) ^ hash<u_int16_t>() (c.port) ^ hash<u_int16_t>() (c.dport));
    }
};

struct DisplayInfo{
public:
    Ip sip;
    Ip dip;
    u_int16_t sp;
    u_int16_t dp;
    int scount;
    int dcount;
    int sbyte;
    int dbyte;

    DisplayInfo();
    DisplayInfo(Ip sip, Ip dip, u_int16_t sp, u_int16_t dp, int scount, int dcount, int sbyte, int dbyte){
        this->sip = sip;
        this->dip = dip;
        this->sp = sp;
        this->dp = dp;
        this->scount = scount;
        this->dcount = dcount;
        this->sbyte = sbyte;
        this->dbyte = dbyte;
    }
};
