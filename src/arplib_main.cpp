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

#include <unistd.h>
#include <stdlib.h>
#include <termios.h>

#include <string>
#include <iostream>

#include <parseCmdLine.hpp>
#include <arplib.hpp>
#include <chat.hpp>
#include <debug.hpp>
#include <configFile.hpp>

using namespace std;
using namespace arplib;
using namespace debugmode;

using parcmdline::ParseCmdLine;
using chatterminal::Chat;
using chatterminal::ArpChatException;
using configFile::ConfigFileException;
using configFile::ConfigFile;

#ifdef __clang__
  void printInfo(char* cmd) __attribute__((noreturn));
#else
  [[ noreturn ]]
  void printInfo(char* cmd);
#endif

int main(int argc, char** argv){
    const char       flags[]      { "hd:i:f:"};
    DEBUG_MODE       debugMode    { DEBUG_MODE::ERR_DEBUG };
    string           iface        { "" },
                     configFile   { "./arpchat.lua"};
    int              ret          { 0 };
    array<uint8_t,6> hdMAC,
                     hsMAC,
                     tMAC;

    struct termios termBackup;

    tcgetattr(0, &termBackup);
    
    ParseCmdLine  pcl{argc, argv, flags};

    if(pcl.getErrorState()){
        string exitMsg{string("Invalid  parameter or value").append(pcl.getErrorMsg())};
        cerr << exitMsg << "\n";
        printInfo(argv[0]);
    }

    if(pcl.isSet('h'))
        printInfo(argv[0]);

    if(pcl.isSet('d')){
            unsigned long debug{ stoul(pcl.getValue('d')) };
            switch(debug){
                case 0:
                    debugMode = DEBUG_MODE::ERR_DEBUG;
                   break;
                case 1: 
                    debugMode = DEBUG_MODE::STD_DEBUG;
                   break;
                case 2: 
                    debugMode = DEBUG_MODE::VERBOSE_DEBUG;
                   break;
                default:
                    debugMode = DEBUG_MODE::STD_DEBUG;
            }
    }

    if(!pcl.isSet('i') ){
        cerr << "-i flag is mandatory" << "\n";
        printInfo(argv[0]);
    }

    if(pcl.isSet('f') )
        configFile = pcl.getValue('f');

   try{
         ConfigFile cfg(configFile);
         try{
             cfg.init();

             cfg.addLoadableVariable("hdrSenderMAC", ""); 
             cfg.addLoadableVariable("hdrTargetMAC", "");
             cfg.addLoadableVariable("frameType", 0L);
             cfg.addLoadableVariable("opcode", 0L);
             cfg.addLoadableVariable("targetMAC", "");
             cfg.addLoadableVariable("targetIp", "");
             cfg.addLoadableVariable("senderIp", "");

             cfg.addLoadableVariable("frameTypeFilter", 0L, true);
             cfg.addLoadableVariable("hardTypeFilter",  0L, true);
             cfg.addLoadableVariable("protTypeFilter",  0L, true);
             cfg.addLoadableVariable("hardSizeFilter",  0L, true);
             cfg.addLoadableVariable("protSizeFilter",  0L, true);
             cfg.addLoadableVariable("opcodeFilter",    0L, true);
             cfg.addLoadableVariable("senderMACFilter", "", true);
             cfg.addLoadableVariable("senderIpFilter",  "", true);
             cfg.addLoadableVariable("targetMACFilter", "", true);
             cfg.addLoadableVariable("targetIpFilter",  "", true);
    
             cfg.loadConfig();
    
             cfg.getConf("hdrTargetMAC").getMAC(hdMAC);
             cfg.getConf("hdrSenderMAC").getMAC(hsMAC);
             cfg.getConf("targetMAC").getMAC(tMAC);
         } catch(ConfigFileException& ex){
             ret = 1;
             string msg {"Error loading configuration file: "};
             msg.append(ex.what());
             cerr << msg << "\n";
             printInfo(argv[0]);
             throw string{"Abort."};
         }
  
  
         Debug debug{debugMode};
         try{
             debug.init("./arpchat.log.txt");

         }catch(DebugException& ex){
             ret = 1;
             cerr << "Error: " << ex.what() << "\n";
             throw string{"Abort."};
         }
 
         Capability cpb;
         try{
             cpb.init(true); 
             cpb.reducePriv("cap_net_raw+ep");
             cpb.getCredential();
             if(debugMode > 1) cpb.printStatus();
         }catch(const CapabilityException& ex){
             ret = 1;
             cerr << "Error: " << ex.what() << "\n";
             throw string{"Abort."};
         }catch(...){
             ret = 1;
             cerr << "Error: unandled exception in privilege management." << "\n";
             throw string{"Abort."};
         }

         FilterMap filterMap;
         if(!cfg.getConf("frameTypeFilter").isEmpty()) filterMap.emplace("frameType",  htons(static_cast<uint16_t>(cfg.getConf("frameTypeFilter").getInteger())));
         if(!cfg.getConf("hardTypeFilter").isEmpty())  filterMap.emplace("hardType",   htons(static_cast<uint16_t>(cfg.getConf("hardTypeFilter").getInteger())));
         if(!cfg.getConf("protTypeFilter").isEmpty())  filterMap.emplace("protType",   htons(static_cast<uint16_t>(cfg.getConf("protTypeFilter").getInteger())));
         if(!cfg.getConf("hardSizeFilter").isEmpty())  filterMap.emplace("hardSize",   htons(static_cast<uint16_t>(cfg.getConf("hardSizeFilter").getInteger())));
         if(!cfg.getConf("protSizeFilter").isEmpty())  filterMap.emplace("protSize",   htons(static_cast<uint16_t>(cfg.getConf("protSizeFilter").getInteger())));
         if(!cfg.getConf("opcodeFilter").isEmpty())    filterMap.emplace("opcode",     htons(static_cast<uint16_t>(cfg.getConf("opcodeFilter").getInteger())));
         if(!cfg.getConf("senderMACFilter").isEmpty()){
            MacAddr macAddr;
            cfg.getConf("senderMACFilter").getMAC(macAddr); 
            filterMap.emplace("senderMAC",  move(macAddr));
         }
         if(!cfg.getConf("senderIpFilter").isEmpty()){  
            IpAddr ipAddr;
            cfg.getConf("senderIpFilter").getIp(ipAddr);
            filterMap.emplace("senderIp", move(ipAddr)); 
         }
         if(!cfg.getConf("targetMACFilter").isEmpty()){
            MacAddr macAddr;
            cfg.getConf("targetMACFilter").getMAC(macAddr); 
            filterMap.emplace("targetMAC", move(macAddr)); 
         }
         if(!cfg.getConf("targetIpFilter").isEmpty()){ 
            IpAddr ipAddr;
            cfg.getConf("targetIpFilter").getIp(ipAddr);
            filterMap.emplace("targetIp",   move(ipAddr)); 
         }

         Arpsocket arps(pcl.getValue('i'), move(filterMap));

         try{
             arps.init();
             arps.open();
             arps.setDestHdrMAC(hdMAC);
             arps.setSrcHdrMAC(hsMAC);
             arps.setDestMAC(tMAC);
             arps.setDestIp(cfg.getConf("targetIp").getText());
             arps.setSrcIp(cfg.getConf("senderIp").getText());
             arps.setOpcode(static_cast<uint16_t>(cfg.getConf("opcode").getInteger()));
  
             arps.startReceiverThread();
         }catch(const ArpSocketException& ex){
             arps.shutdown(); 
             ret = 1;
             cerr << "Error: " << ex.what() << "\n";
             throw string{"Abort."};
         }catch(...){ 
             ret = 1;
             throw string{"Unmanaged Error from ArpSocket. Abort."};
         }

         Chat   chat(arps);
         try{
             chat.init();
             chat.loop();
         }catch(const ArpChatException& ex){
             chat.shutdown(); 
             ret = 1;
             cerr << "Error: " << ex.what() << "\n";
         }catch(...){
             ret = 1;
             throw string{"Unmanaged Error from Chat. Abort."};
         }

    }catch(const string& ex){
        cerr << ex << "\n";
        cout << "Program exits with error(s): check log file.\n";
    }

    tcsetattr(0, TCSANOW, &termBackup);
              
    return ret;  
}

void printInfo(char* cmd){
      cerr << cmd << " [-i<iface>] [-f <config_full_path>] [-d level] | [-h]\n\n";
      cerr << " -i  <iface>     Specify the network interface\n";
      cerr << " -f  <full_path> Specify the configuration path\n";
      cerr << " -d  <dbg_level> set debug mode\n";
      cerr << " -h              print this synopsis\n";
      exit(EXIT_FAILURE);
}

