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

#include <arplib.hpp>
#include <debug.hpp>
#include <StringUtils.hpp>

#include <errno.h>  
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/prctl.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if_arp.h>

#include <linux/if_ether.h>   // ETH_P_ARP = 0x0806 
#include <linux/if.h>

#include <sstream>
#include <random>
#include <cstring>
#include <algorithm>
#include <cstdio>
#include <utility>

#include <cstring>

namespace arplib{

    using std::copy,
          std::array,
          std::stringstream,
          std::string,
          std::to_string,
          std::setfill,
          std::setw,
          std::hex,
          std::dec,
          std::vector,
          std::mt19937,
          std::uniform_int_distribution,
          std::random_device,
          std::tuple_size,
          std::thread,
          std::memcpy,
          std::terminate,
          debugmode::DEBUG_MODE,
          debugmode::Debug,
          stringutils::mergeStrings;

    FilterValue::FilterValue(uint8_t val)   noexcept
         : bt{val}
    {}

    FilterValue::FilterValue(uint16_t val) noexcept
         : doublebt{val}
    {}

    FilterValue::FilterValue(MacAddr&& val) noexcept
         : btarrMAC{val}
    {}

    FilterValue::FilterValue(IpAddr&& val) noexcept
         : btarrIp{val}
    {}

    Arpsocket::Arpsocket(string iface,  FilterMap&& filt) noexcept
        : interface{iface}, 
          filterActions{ 
               { "frameType",  [](ArpPkt& pck, FilterValue& ft)-> bool { return ft.doublebt == pck.frameType ? false : true;} },
               { "hardType",   [](ArpPkt& pck, FilterValue& ft)-> bool { return ft.doublebt == pck.hardType ? false : true;} },
               { "protType",   [](ArpPkt& pck, FilterValue& ft)-> bool { return ft.doublebt == pck.protType ? false : true;} },
               { "hardSize",   [](ArpPkt& pck, FilterValue& ft)-> bool { return ft.bt == pck.hardSize  ? false : true;} },
               { "protSize",   [](ArpPkt& pck, FilterValue& ft)-> bool { return ft.bt == pck.protSize ? false : true;} },
               { "opcode",     [](ArpPkt& pck, FilterValue& ft)-> bool { return ft.doublebt == pck.opcode  ? false : true;} },
               { "senderMAC",  [](ArpPkt& pck, FilterValue& ft)-> bool { for(size_t el=0; el< sizeof(pck.senderMAC); el++) if(ft.btarrMAC.at(el) != pck.senderMAC[el]) return true; return false;} },
               { "senderIp",   [](ArpPkt& pck, FilterValue& ft)-> bool { for(size_t el=0; el< sizeof(pck.senderIp); el++) if(ft.btarrIp.at(el) != pck.senderIp[el]) return true; return false;} },
               { "targetMAC",  [](ArpPkt& pck, FilterValue& ft)-> bool { for(size_t el=0; el< sizeof(pck.targetMAC); el++) if(ft.btarrMAC.at(el) != pck.targetMAC[el]) return true; return false;} },
               { "targetIp",   [](ArpPkt& pck, FilterValue& ft)-> bool { for(size_t el=0; el< sizeof(pck.senderIp); el++) if(ft.btarrIp.at(el) != pck.senderIp[el]) return true; return false;} } 
          },
          filters{filt},
          debugLevel{Debug::getDebugLevel()}
    {
        // Default Frame Type (Request or Reply)
        arppkt.frameType = htons(0x0806);

        // Hard Type (0x1 -> Ethernet )
        arppkt.hardType = htons(1);

        // Protocol Type (IP Addresses ):
        arppkt.protType = htons(0x800);
        
        // OpCode (ARP request):
        arppkt.opcode = htons(0x1);

        inet_pton(AF_INET, "127.0.0.1", arppkt.targetIp);

        sockaddrll.sll_family = AF_PACKET;
        sockaddrll.sll_halen = htons(6);

        udsclient.sun_family = AF_UNIX;
    }

    void Arpsocket::init(void) anyexcept{
        copy(UDDevice.c_str(), UDDevice.c_str() + UDDevice.size(), udsclient.sun_path);

        resolve();

        if((sockaddrll.sll_ifindex = if_nametoindex (interface.c_str())) == 0) {
            string errmsg = mergeStrings({"Error: if_nametoindex() bad index : ", strerror(errno)});
            Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
            throw ArpSocketException(errmsg);
        }
    }

    Arpsocket::~Arpsocket(void) noexcept{
        shutdown();
        try{
            reader->join(); 
            delete reader;
        }catch(...){
            Debug::printLog("Errro: Arpsocket dtor.", DEBUG_MODE::ERR_DEBUG);
        }
        if(sfd != -1) close(sfd);
        if(udsfd != -1) close(udsfd);
    }

    void Arpsocket::printSrcMAC(void) const noexcept{
        stringstream msg;

        msg << "Src MAC: " ;
        for(const uint8_t& digit : arppkt.senderMAC)
                msg << " " << setfill('0') << setw(2) << hex << static_cast<int>(digit);

        msg << "\n" ;

        Debug::printLog(msg.str(), DEBUG_MODE::ERR_DEBUG);
    }

    void Arpsocket::printDstMAC(void) const noexcept{
        stringstream  msg;

        msg << "Dst MAC: " ;
        for(const uint8_t& digit : arppkt.targetMAC)
                msg << " " << setfill('0') << setw(2) << hex << static_cast<int>(digit);

        msg << "\n" ;

        Debug::printLog(msg.str(), DEBUG_MODE::ERR_DEBUG);
    }

    void Arpsocket::printSrcIp(void) const  noexcept{
        stringstream msg;

        msg << "Local IP: " ;
        for(const uint8_t& digit : arppkt.senderIp)
                msg << " " << dec << static_cast<int>(digit);

        msg << "\n" ;
        Debug::printLog(msg.str(), DEBUG_MODE::ERR_DEBUG);
    }

    void Arpsocket::printConfig(void) const noexcept{
         printSrcMAC();
         printDstMAC();
         printSrcIp();

         stringstream msg;
         msg << "ArpPkt size: " << sizeof(ArpPkt) << "\n" ;
         Debug::printLog(msg.str(), DEBUG_MODE::ERR_DEBUG);
    }

    void Arpsocket::setAllDestMAC(const MacAddr& dhMAC) noexcept{
         setDestHdrMAC(dhMAC);
         setDestMAC(dhMAC);
    }

    void Arpsocket::setDestHdrMAC(const MacAddr& dhMAC) noexcept{
        static_assert( sizeof(arppkt.hdrTargetMAC) == MAC_ARRAY_LEN);
        copy(dhMAC.begin(), dhMAC.begin() + sizeof(arppkt.hdrTargetMAC), arppkt.hdrTargetMAC);
    }

    void Arpsocket::setSrcHdrMAC(const MacAddr& shMAC) noexcept{
        static_assert( sizeof(arppkt.hdrTargetMAC) == MAC_ARRAY_LEN);
        copy(shMAC.begin(), shMAC.begin() + sizeof(arppkt.hdrSenderMAC), arppkt.hdrSenderMAC);
    }

    void Arpsocket::setFrameType(uint16_t fr)  noexcept{
        arppkt.frameType = htons(fr);
    }

    void Arpsocket::setHardType(uint16_t  ht)  noexcept{
        arppkt.hardType = htons(ht);
    }

    void Arpsocket::setProtType(uint16_t  pt)  noexcept{
        arppkt.protType =  htons(pt);
    }

    void Arpsocket::setHardSize(uint8_t   hs)  noexcept{
        arppkt.hardSize = hs;
    }

    void Arpsocket::setProtSize(uint8_t   ps)  noexcept{
        arppkt.protSize = ps;
    }

    void Arpsocket::setOpcode(uint16_t    op)  noexcept{
        arppkt.opcode = htons(op);
    }

    void Arpsocket::setDestMAC(const MacAddr& dMAC) noexcept{
        static_assert( sizeof(arppkt.targetMAC) == MAC_ARRAY_LEN);
        copy(dMAC.begin(), dMAC.begin() + sizeof(arppkt.targetMAC), arppkt.targetMAC);
    }

    void Arpsocket::setDestIp(const string& dIp)  noexcept{
         inet_pton(AF_INET, dIp.c_str(), arppkt.targetIp);
    }

    void Arpsocket::setSrcMAC(const MacAddr& sMAC) noexcept{
        static_assert( sizeof(arppkt.senderMAC) == MAC_ARRAY_LEN);
        copy(sMAC.begin(), sMAC.begin() + sizeof(arppkt.senderMAC), arppkt.senderMAC);
    }

    void Arpsocket::setSrcIp(const string& sIp) noexcept{
         inet_pton(AF_INET, sIp.c_str(), arppkt.senderIp);
    }

    void Arpsocket::getSrcHdrMAC(MacAddr& dest)  const noexcept{
        copy(incoming.begin() + PACKET_MAPPING::IPHDR_SRC_MAC, incoming.begin() + PACKET_MAPPING::IPHDR_SRC_MAC + MAC_ARRAY_LEN, dest.data());
    }
    
    void Arpsocket::getDestHdrMAC(MacAddr& dest) const noexcept{
        copy(incoming.begin() + PACKET_MAPPING::IPHDR_DEST_MAC, incoming.begin() + PACKET_MAPPING::IPHDR_DEST_MAC + MAC_ARRAY_LEN, dest.data());
    }

    uint16_t Arpsocket::getFrameType(void) const noexcept{
        return *(reinterpret_cast<const uint16_t*>(incoming.data() + PACKET_MAPPING::FRAME_TYPE));
    }

    uint16_t Arpsocket::getHardType(void) const noexcept{
        return *(reinterpret_cast<const uint16_t*>(incoming.data() + PACKET_MAPPING::HARD_TYPE));
    }

    uint16_t Arpsocket::getProtType(void) const noexcept{
        return *(reinterpret_cast<const uint16_t*>(incoming.data() + PACKET_MAPPING::PROT_TYPE));
    }

    uint16_t Arpsocket::getHardSize(void) const noexcept{
        return *(reinterpret_cast<const uint16_t*>(incoming.data() + PACKET_MAPPING::HARD_SIZE));
    }

    uint16_t Arpsocket::getProtSize(void) const noexcept{
        return *(reinterpret_cast<const uint16_t*>(incoming.data() + PACKET_MAPPING::PROT_SIZE));
    }

    uint16_t Arpsocket::getOpcode(void) const noexcept{
        return *(reinterpret_cast<const uint16_t*>(incoming.data() + PACKET_MAPPING::OP_SIZE));
    }

    void Arpsocket::getDestMAC(MacAddr& dest)  const noexcept{
        copy(incoming.begin() + PACKET_MAPPING::DEST_MAC, incoming.begin() + PACKET_MAPPING::DEST_MAC + MAC_ARRAY_LEN, dest.data());
    }

    void Arpsocket::getDestIp(string& dest) const noexcept{ 
        dest.resize(IP_ARRAY_LEN);
        copy(incoming.begin() + PACKET_MAPPING::DEST_IP, incoming.begin() + PACKET_MAPPING::DEST_IP + IP_ARRAY_LEN, dest.data());
    }

    void Arpsocket::getSrcMAC(MacAddr& dest) const noexcept{
        copy(incoming.begin() + PACKET_MAPPING::SENDER_MAC, incoming.begin() + PACKET_MAPPING::SENDER_MAC + MAC_ARRAY_LEN, dest.data());
    }

    void Arpsocket::getSrcIp(string& dest) const noexcept{
        dest.resize(IP_ARRAY_LEN);
        copy(incoming.begin() + PACKET_MAPPING::SENDER_IP, incoming.begin() + PACKET_MAPPING::SENDER_IP + IP_ARRAY_LEN, dest.data());
    }

    void Arpsocket::open(void) anyexcept{
         if((sfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
            string errmsg = mergeStrings({"Error: socket() : ", strerror(errno)});
            Debug::printLog(errmsg, debugLevel);
            throw ArpSocketException(errmsg);
         }
    }

    int Arpsocket::send(void) anyexcept{
        static_assert( sizeof(arppkt) <= tuple_size<decltype(etherFrame)>{} );
        memcpy(etherFrame.data(), &arppkt, sizeof(arppkt));

        int bytesSent = sendto(sfd, etherFrame.data(), sizeof(ArpPkt), 0, reinterpret_cast<Sockaddr*>(&sockaddrll), sizeof (sockaddrll));
        if (bytesSent  <= 0){
             string errmsg = mergeStrings({"Error: sendto() : ", strerror(errno)});
             Debug::printLog(errmsg, debugLevel);
             throw ArpSocketException(errmsg);
        }
 
        if(debugLevel >= DEBUG_MODE::VERBOSE_DEBUG) Debug::trace("Sent:", etherFrame.data(), sizeof(ArpPkt), 0, 14);
 
        return bytesSent;
    }

    void Arpsocket::receiveAll(void) noexcept{

        try{ 
            string errmsg {""};

            udsfd = socket(AF_UNIX, SOCK_STREAM, 0);
            if(udsfd == -1){
                errmsg = mergeStrings({"Error: can't create UDS : ", strerror(errno)});
                Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
                throw ArpSocketException(errmsg);
            }

            int udsret { -1 },
                retry  {  5 };
            while( retry != 0){
                 udsret = connect(udsfd, reinterpret_cast<const Sockaddr*>(&udsclient), sizeof(SockaddrUn));
                 if(udsret != -1) break;
                 retry--;
                 usleep(1000);
            }
            if(udsret == -1){
                errmsg = mergeStrings({"Error: can't connect UDS : ", strerror(errno)});
                Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
                throw ArpSocketException(errmsg);
            }

            while(running){
                    FD_ZERO(&fdset);
                    FD_SET(sfd, &fdset);
    
                    if(sfd > nfds)
                        nfds = sfd + 1;
    
                    ssize_t ret {::select(nfds, &fdset, nullptr, nullptr, &tvMin)};
                    switch(ret){
                        case -1:
                            errmsg = "readLineTimeout: Select Error.";
                            Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
                            throw ArpSocketException(errmsg);
                        case  0:
                            Debug::printLog("Select Timeout.", DEBUG_MODE::VERBOSE_DEBUG);
                            break;
                        default:
                            try{
                                ret = receive();
                            } catch (ArpSocketException& err){
                                    errmsg = mergeStrings({"Error: receiveAll() from receive() : ", err.what()});
                                    Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
                                    throw ArpSocketException(errmsg);
                            }
                            switch(ret){
                                case -2:
                                    Debug::printLog("All packed filtered with provided rule(s).", DEBUG_MODE::VERBOSE_DEBUG);
                                    break;
                                case -1:
                                    errmsg = mergeStrings({"Error: recvfrom() : ", strerror(errno)});
                                    Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
                                    throw ArpSocketException(errmsg);
                                case 0:
                                    errmsg = "readTimeout: Connection Closed by peer.";
                                    Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
                                    throw ArpSocketException(errmsg);
                                default:
                                        Debug::printLog("Packet Received.", DEBUG_MODE::VERBOSE_DEBUG);
                                        queueMtx.lock();
                                        string buf { to_string(incomingQueue.size()) };
                                        udsret = write(udsfd, buf.c_str(), buf.size());
                                        queueMtx.unlock();
                                        if(udsret == -1){
                                             errmsg = mergeStrings({"Error: can't write on UDS : ", strerror(errno)});
                                             Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
                                             throw ArpSocketException(errmsg);
                                        }
                            }
                    }
                    usleep(250);
            }
        } catch(ArpSocketException& err){
            Debug::printLog(mergeStrings({"Error in receiveAll() thread : ", err.what()}), DEBUG_MODE::ERR_DEBUG);
        } catch(...){
            Debug::printLog("Unhandled Exception in receiveAll().", DEBUG_MODE::ERR_DEBUG);
        }

        running = false;
    }

    void Arpsocket::startReceiverThread(void)  anyexcept{
          try{
              reader = new thread([&](){ receiveAll(); } );
          }catch (...){
                string msg {"Error: startReceiverThread() - creation "};
                Debug::printLog(msg, DEBUG_MODE::ERR_DEBUG);
                throw ArpSocketException(msg);
          }
    }

    int Arpsocket::receive(void)  anyexcept{
        SockaddrIn cliaddr;
        socklen_t clilen { sizeof(cliaddr) };

        static_assert( sizeof(ArpPkt) <= tuple_size<decltype(incoming)>{} );
        incoming = {};
        int bytesRecv = recvfrom(sfd, incoming.data(), incoming.size(), 0, reinterpret_cast<Sockaddr*>(&cliaddr), &clilen);
        if(bytesRecv == -1 ) return bytesRecv;

        ArpPkt lastPacketRecv;
        memcpy(&lastPacketRecv, incoming.data(), sizeof(ArpPkt)) ;

        for(auto& [key, filter]: filters)
             if( filterActions[key](lastPacketRecv, filter) )
                  return -2;

        queueMtx.lock();
        incomingQueue.push_back(lastPacketRecv);
        queueMtx.unlock();

        if(debugLevel >= DEBUG_MODE::VERBOSE_DEBUG) Debug::trace("Received:", incoming.data(), sizeof(ArpPkt), 0, 14);

        return bytesRecv;
    }

    ArpPkt Arpsocket::popPacket(void) anyexcept{
         queueMtx.lock();

         if(incomingQueue.empty()){
            queueMtx.unlock();
            string errmsg { "Error: attempt to pop from empty queue" };
            Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
            throw ArpSocketException(errmsg);
         }

         ArpPkt ret { incomingQueue.front() };
         incomingQueue.pop_front();
         queueMtx.unlock();
         return ret;
    }

    size_t Arpsocket::availeblePackets(void) noexcept{ 
        queueMtx.lock();
        size_t len { incomingQueue.size() };
        queueMtx.unlock();
        return len;
    }

    void Arpsocket::getLocalIp(void) anyexcept {
         int tempFd { socket(AF_INET, SOCK_DGRAM, 0) };
         if(tempFd == -1){
            string errmsg { mergeStrings({"getLocalIp: Error opening socket: ", strerror(errno)}) };
            Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
            throw ArpSocketException(errmsg);
         }
     
         ifreq.ifr_addr.sa_family = AF_INET;
         strncpy(ifreq.ifr_name, interface.c_str(), IFNAMSIZ-1); 
     
         if(ioctl(tempFd, SIOCGIFADDR, &ifreq) == -1){
            string errmsg { mergeStrings({"getLocalIp: Error setting socket: ", strerror(errno)}) };
            Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
            throw ArpSocketException(errmsg);
         }

         sockaddrin=reinterpret_cast<SockaddrIn *>(&ifreq.ifr_addr);
     
         close(tempFd);
    }

    void Arpsocket::getLocalMAC(void) anyexcept {
        int tempFd { socket(AF_INET, SOCK_DGRAM, 0) };
        if(tempFd == -1){
            string errmsg { mergeStrings({"getLocalMAC: Error opening socket: ", strerror(errno)})};
            Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
            throw ArpSocketException(errmsg);
        }

        snprintf (ifreq.ifr_name, sizeof (ifreq.ifr_name), "%s", interface.c_str());
        if(ioctl (tempFd , SIOCGIFHWADDR, &ifreq) < 0){
            string errmsg { mergeStrings({"Error: ioctl() can't read source MAC address : ", strerror(errno)}) };
            Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
            throw ArpSocketException(errmsg);
        }

        close(tempFd);
    }

    void Arpsocket::resolve(void)  anyexcept {
        getLocalIp();
        static_assert( sizeof(reinterpret_cast<uint8_t*>(&sockaddrin->sin_addr)) >= sizeof(arppkt.senderIp));
        copy(reinterpret_cast<uint8_t*>(&sockaddrin->sin_addr), reinterpret_cast<uint8_t*>(&sockaddrin->sin_addr) + sizeof(arppkt.senderIp) , arppkt.senderIp);

        getLocalMAC();
        static_assert( sizeof(ifreq.ifr_hwaddr.sa_data) >= sizeof(arppkt.senderMAC));
        copy(ifreq.ifr_hwaddr.sa_data, ifreq.ifr_hwaddr.sa_data + sizeof(arppkt.senderMAC), arppkt.senderMAC);

        static_assert( sizeof(arppkt.hdrSenderMAC) == sizeof(arppkt.hdrSenderMAC));
        copy(arppkt.senderMAC, arppkt.senderMAC + sizeof(arppkt.hdrSenderMAC), arppkt.hdrSenderMAC);

        static_assert( sizeof(sockaddrll.sll_addr) >= sizeof(arppkt.senderMAC));
        copy(arppkt.senderMAC, arppkt.senderMAC + sizeof(arppkt.senderMAC), sockaddrll.sll_addr);
    }

    ArpSocketException::ArpSocketException(string& errString) noexcept
        : errorMessage{errString}
    {}

    ArpSocketException::ArpSocketException(string&& errString) noexcept
        : errorMessage{errString}
    {}
 
    const char*  ArpSocketException::what() const noexcept{
       return errorMessage.c_str();
    }
    
    void Arpsocket::shutdown(void)  noexcept{
         running = false;
    }

    Capability::Capability(void)  noexcept
        : uid{getuid()},       euid{geteuid()},
          gid{getgid()},       egid{getegid()},
          cap{cap_get_proc()}, newcaps{cap}
    {}

    void  Capability::init(bool noRoot)  anyexcept{
        if(noRoot) 
             if(uid == 0 || gid == 0 ){
                string errmsg { "Root user or group are not permitted: use a standard user instead." };
                Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
                throw ArpSocketException(errmsg);
             }
    }

    Capability::~Capability(void) noexcept{
          cap_free(cap);
          cap_free(nullptr);
    }

    void Capability::printStatus(void) const noexcept{
           Debug::printLog(mergeStrings({ "UID: ", to_string(uid).c_str(), " EUID: ", to_string(euid).c_str(),
                                          "\nGID: ", to_string(gid).c_str(), " GID:  ", to_string(egid).c_str(),
                                          "\nRunning with capabilities: ",  cap_to_text(cap, nullptr), "\n"
                                       }), 
                                       DEBUG_MODE::VERBOSE_DEBUG);
    }

    void Capability::getCredential(void) anyexcept{
           uid  = getuid();
           euid = geteuid(); 
           gid  = getgid();
           egid = getegid();
           cap  = cap_get_proc();
           if(cap == nullptr){
               string errmsg { mergeStrings({ "Capability error reading credential: ", strerror(errno)}) };
               Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
               throw ArpSocketException(errmsg);
           }
    }

    void Capability::reducePriv(const string& capText) noexcept(false){
           if(prctl(PR_SET_KEEPCAPS, 1) ==  -1){
               string errmsg { mergeStrings({ "Capability setting : prctl error: ", strerror(errno)}) };
               Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
               throw ArpSocketException(errmsg);
           }

           newcaps  = cap_from_text(capText.c_str());

           if(setresgid(gid, gid, gid)  ==  -1){
               string errmsg { mergeStrings({ "Capability setting : setresgid error: ", strerror(errno)}) };
               Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
               throw ArpSocketException(errmsg);
           }
           if(setresuid(uid, uid, uid)  ==  -1){
               string errmsg { mergeStrings({ "Capability setting : setresuid error: ", strerror(errno)}) };
               Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
               throw ArpSocketException(errmsg);
           }
           if(cap_set_proc(newcaps)     ==  -1){
               string errmsg { mergeStrings({ "Capability setting : cap_set_proc error: ", strerror(errno)}) };
               Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
               throw ArpSocketException(errmsg);
           }
    }

    CapabilityException::CapabilityException(string& errString)
        :  errorMessage{errString}
    {}
   
    CapabilityException::CapabilityException(string&& errString)
        :  errorMessage{errString}
    {}
    
    string CapabilityException::what() const noexcept{
           return errorMessage;
    }

} // End namespace arplib

