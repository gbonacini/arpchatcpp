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

#include <ncurses.h>

#include <sys/un.h>
#include <sys/select.h>

#include <anyexcept.hpp>
#include <arplib.hpp>

#include <exception>
#include <deque>
#include <vector>
#include <string>
#include <thread>
#include <mutex>

namespace chatterminal {

    using LinesCache=std::vector<std::string>;
    using SockaddrUn=struct sockaddr_un;
    using Sockaddr=struct sockaddr;
    
    class Chat {
        private:

            static constexpr size_t   MAX_SENT_BUFFER_SIZE      {512},
                                      MAX_RECEIVED_BUFFER_SIZE  {4096},
                                      MAX_PACKET_SIZE           {6},
                                      MAX_QUEUE_LEN_STRING      {256},
                                      MIN_HEIGTH                {25},
                                      MIN_WIDE                  {30};

            static const int          C_SEQUENCE_FIRST          {0x1B},
                                      C_SEQUENCE_SECOND         {0x5B},
                                      C_SEQUENCE_THIRD          {0x07},
                                      C_BACKSPACE               {0x7F},
                                      C_KRIGHT                  {0x43},
                                      C_KLEFT                   {0x00},
                                      C_KUP                     {0x41},
                                      C_KDOWN                   {0x42},
                                      C_NEWLINE                 {'\n'},
                                      C_TAB                     {'\t'},
                                      C_F10                     {0x32};

            int                       termWide                  { 0 }, 
                                      termHeigth                { 0 },
                                      resizeWide                { 0 }, 
                                      resizeHeigth              { 0 },
                                      sentWide                  { 0 }, 
                                      sentHeigth                { 0 },
                                      histWide                  { 0 }, 
                                      histHeigth                { 0 },
                                      sentSize                  { 10 },
                                      udsfd                     { -1 },
                                      udsconn                   { -1 },
                                      nfds                      { -1 },
                                      lastLine                  { -1 },
                                      historyOffset             {  0 };

            size_t                    added                     { 0 };


            bool                      running                   { true };

            WINDOW                    *received                 { nullptr },
                                      *sent                     { nullptr },
                                      *label                    { nullptr };

            LinesCache                linesCache;

            std::deque<char>          sentBufferQueue;
            std::vector<char>         receivedBuffer;

            arplib::Arpsocket&        arpsocket;
            SockaddrUn                udsserver                 {},
                                      udsclientconn             {};
            std::string               UDDevice                  {"/tmp/.arpchat.uddsocket.server"};

            std::mutex                screenMtx,
                                      screenBufferMtx;

            fd_set                    fdset;
            struct  timeval           tvMin                    {3,0},
                                      tvMax                    {10,0};
            std::thread               *queuereader             {nullptr};

            void   drawArea(WINDOW* area, 
                            size_t heigth, 
                            size_t wide)                              noexcept;
            void   insertCharacter(char chtr,
                                   size_t maxlen)                     noexcept;
            void   updateScreenFromSent(void)                         anyexcept;
            void   updateScreenFromReceived(void)                     anyexcept;
            void   printPrompt(size_t offset=0)             const     anyexcept;
            void   printHistoryPage(void)                             anyexcept;
            void   draw(void)                                         noexcept;
            void   refresh(void)                                      anyexcept;
            void   getChar(void)                                      anyexcept;
            void   sendMessage(void)                        const     anyexcept;
            void   pollIncomingQueue(void)                            noexcept;
            void   refreshLineCache(void)                             anyexcept;

        public:

            explicit Chat(arplib::Arpsocket& arpsckt)                 noexcept;
            ~Chat(void)                                               noexcept;

            void   init(void)                                         anyexcept;
            void   loop(void)                                         anyexcept;
            void   shutdown(void)                                     noexcept;
    };
           
    class ArpChatException final : public std::exception {
        public:
           ArpChatException(std::string& errString);
           ArpChatException(std::string&& errString);
           const char* what(void)                                                        const noexcept override;
        private:
           std::string errorMessage;
    };


} // End namespace chatterminal