#ifndef INFO_H
#define INFO_H

#endif // INFO_H
#include "ip.h"

struct PacketInfo{
public:
    u_int16_t sourceport;
    u_int16_t destport;
    Ip sourceip;
    Ip destip;
    int bytelen;
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
        return ( (this->ip == r.ip && this->port == r.port && this->dip == r.dip && this->dport == r.dport)
                 || (this->ip == r.dip && this->port == r.dport && this->dip == r.ip && this->dport == r.port));
    }
    bool operator< (const Check &r) const {
        return ( this->ip.ip_ < r.ip.ip_);
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
