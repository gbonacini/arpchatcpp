// -----------------------------------------------------------------
// arplib - a library to send arbitrary ARP packets
// Copyright (C) 2023  Gabriele Bonacini
//
// This program is distributed under dual license:
// - Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0) License 
// for non commercial use, the license has the following terms:
// * Attribution — You must give appropriate credit, provide a link to the license, 
// and indicate if changes were made. You may do so in any reasonable manner, 
// but not in any way that suggests the licensor endorses you or your use.
// * NonCommercial — You must not use the material for commercial purposes.
// A copy of the license it's available to the following address:
// http://creativecommons.org/licenses/by-nc/4.0/
// - For commercial use a specific license is available contacting the author.
// -----------------------------------------------------------------

#pragma once

#include <cstddef>

#include <sys/capability.h>
#include <sys/un.h>
#include <sys/select.h>

#include <netinet/ip.h>
#include <net/if.h>
#include <linux/if_packet.h>  // struct sockaddr_ll 

#include <time.h>

#include <exception>
#include <string>
#include <array>
#include <vector> 
#include <queue>
#include <map>
#include <tuple>
#include <functional>

#include <thread>
#include <mutex>

#include <anyexcept.hpp>
#include <debug.hpp>

namespace arplib{

    constexpr size_t  MAC_ARRAY_LEN {6 };
    constexpr size_t  IP_ARRAY_LEN  {4 };
    constexpr size_t  MSG_LEN       {10};
    constexpr uint8_t MAX_ATTEMPTS  {3 };

    enum PACKET_MAPPING : size_t { IPHDR_DEST_MAC=0, IPHDR_SRC_MAC=6, FRAME_TYPE=12, HARD_TYPE=14, PROT_TYPE=16, 
                                   HARD_SIZE=18, PROT_SIZE=19, OP_SIZE=20, SENDER_MAC=22, SENDER_IP=28, 
                                   DEST_MAC=32, DEST_IP=38 };

    using MacAddr=std::array<uint8_t, MAC_ARRAY_LEN>; 
    using IpAddr=std::array<uint8_t, IP_ARRAY_LEN>;
    
    union FilterValue{
         uint8_t  bt;
         uint16_t doublebt;
         MacAddr  btarrMAC;
         IpAddr   btarrIp;

         FilterValue(uint8_t val)                   noexcept;
         FilterValue(uint16_t val)                  noexcept;
         FilterValue(MacAddr&& val)                 noexcept;
         FilterValue(IpAddr&& val)                  noexcept;
    };

    using FilterMap=std::map<std::string, FilterValue>;

    enum MSG_DATA_IDXS : size_t { PART_ID_IDX=0, EXPIRING_TIME_IDX=1, ATTEMPTS_IDX=2, MSG_DATA_IDX=3 };

    struct ArpPkt {
         uint8_t  hdrTargetMAC[MAC_ARRAY_LEN],
                  hdrSenderMAC[MAC_ARRAY_LEN];
         uint16_t frameType,
                  hardType,
                  protType;
         uint8_t  hardSize { 0x6 },
                  protSize { 0x4 };
         uint16_t opcode;
         uint8_t  senderMAC[MAC_ARRAY_LEN],
                  senderIp[IP_ARRAY_LEN],
                  targetMAC[MAC_ARRAY_LEN],
                  targetIp[IP_ARRAY_LEN];
    };

    using ArpBuffer=std::array<uint8_t, IP_MAXPACKET>;

    class Arpsocket{

        private:

           using FilterActions=std::map<std::string, std::function<bool(ArpPkt&, FilterValue&)>>;
           using Ifreq=struct ifreq;
           using SockaddrIn=struct sockaddr_in;
           using SockaddrLl=struct sockaddr_ll;
           using SockaddrUn=struct sockaddr_un;
           using Sockaddr=struct sockaddr;
           using MsgId=size_t;
           using PartId=size_t;
           using ExpiringTime=time_t;
           using Attempts=uint8_t;
           using MsgData=std::map<PartId, std::array<uint8_t, MSG_LEN> >;
           using MsgQueue=std::map<MsgId, std::tuple<PartId, ExpiringTime, Attempts, MsgData> >;

           std::string                UDDevice       {"/tmp/.arpchat.uddsocket.server"},
                                      interface      {""};
           int                        sfd            { -1 },
                                      udsfd          { -1 },
                                      nfds           { -1 };
           ArpPkt                     arppkt         {};
           Ifreq                      ifreq          {};
           SockaddrIn*                sockaddrin     { nullptr };
           SockaddrLl                 sockaddrll     {};
           SockaddrUn                 udsclient      {};
           ArpBuffer                  etherFrame,
                                      incoming;
           std::deque<ArpPkt>         incomingQueue;
           FilterActions              filterActions;
           fd_set                     fdset;
           struct  timeval            tvMin          {3,0},
                                      tvMax          {10,0};
           std::thread                *reader        {nullptr};
           std::mutex                 queueMtx;
           FilterMap                  filters;
           MsgQueue                   received,
                                      sent;
           bool                       running        {true};
           debugmode::DEBUG_MODE      debugLevel;

           void resolve(void)                                      anyexcept;
           void printSrcMAC(void)                        const     noexcept;
           void printDstMAC(void)                        const     noexcept;
           void printSrcIp(void)                         const     noexcept;

        public:

           Arpsocket(std::string iface, 
                     FilterMap&& filt)                             noexcept;
           ~Arpsocket(void)                                        noexcept;

           void init(void)                                         anyexcept;

           void     setSrcHdrMAC(const MacAddr& shMAC)             noexcept;
           void     setDestHdrMAC(const MacAddr& dhMAC)            noexcept;
           void     setAllDestMAC(const MacAddr& dhMAC)            noexcept;
           void     setFrameType(uint16_t fr)                      noexcept;
           void     setHardType(uint16_t  ht)                      noexcept;
           void     setProtType(uint16_t  pt)                      noexcept;
           void     setHardSize(uint8_t   hs)                      noexcept;
           void     setProtSize(uint8_t   ps)                      noexcept;
           void     setOpcode(uint16_t    op)                      noexcept;
           void     setDestMAC(const MacAddr& dMAC)                noexcept;
           void     setDestIp(const std::string& dIp)              noexcept;
           void     setSrcMAC(const MacAddr& sMAC)                 noexcept;
           void     setSrcIp(const std::string& sIp)               noexcept;

           void     getSrcHdrMAC(MacAddr& dest)              const noexcept;
           void     getDestHdrMAC(MacAddr& dest)             const noexcept;
           uint16_t getFrameType(void)                       const noexcept;
           uint16_t getHardType(void)                        const noexcept;
           uint16_t getProtType(void)                        const noexcept;
           uint16_t getHardSize(void)                        const noexcept;
           uint16_t getProtSize(void)                        const noexcept;
           uint16_t getOpcode(void)                          const noexcept;
           void     getDestMAC(MacAddr& dest)                const noexcept;
           void     getDestIp(std::string& dest)             const noexcept;
           void     getSrcMAC(MacAddr& dest)                 const noexcept;
           void     getSrcIp(std::string& sIp)               const noexcept;

           void     printConfig(void)                        const noexcept;
           void     open(void)                                     anyexcept;
           int      send(void)                                     anyexcept;
           int      receive(void)                                  anyexcept;
           void     receiveAll(void)                               noexcept;
           void     startReceiverThread(void)                      anyexcept;
           void     getLocalIp(void)                               anyexcept;
           void     getLocalMAC(void)                              anyexcept;
           void     shutdown(void)                                 noexcept;
           ArpPkt   popPacket(void)                                anyexcept;
           size_t   availeblePackets(void)                         noexcept;
    };

    class ArpSocketException final : public std::exception {
        public:
           ArpSocketException(std::string& errString)              noexcept;
           ArpSocketException(std::string&& errString)             noexcept;
           const char* what(void)                        const     noexcept override;
        private:
           std::string errorMessage;
    };

    class Capability{
            public:
                             Capability(void)                                 noexcept;
                             ~Capability(void)                                noexcept;
                   void      init(bool noRoot)                                anyexcept;
                   void      printStatus(void)                         const  noexcept;
                   void      getCredential(void)                              anyexcept;
                   void      reducePriv(const std::string& capText)           anyexcept;

            private:
                   uid_t     uid,
                             euid;
                   gid_t     gid,
                             egid;
                   cap_t     cap,
                             newcaps;
    };

    class CapabilityException final{
            public:
               CapabilityException(std::string&  errString);
               CapabilityException(std::string&& errString);
               std::string what(void)                                  const  noexcept;
            private:
               std::string errorMessage;
    };
    
} // End namespace arplib

