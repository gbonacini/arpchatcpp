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

#include <chat.hpp>
#include <debug.hpp>
#include <StringUtils.hpp>
#include <Types.hpp>

#include <unistd.h>

#include <array>

namespace chatterminal{

    using std::deque;
    using std::array;
    using std::copy;
    using std::string;
    using std::to_string;
    using std::stoul;
    using std::thread;

    using arplib::ArpPkt;
    using arplib::Arpsocket;
    using debugmode::Debug;
    using debugmode::DEBUG_MODE;
    using stringutils::mergeStrings;
    using typeutils::safeSizeT;
    using typeutils::TypesUtilsException;
    
    Chat::Chat(Arpsocket& arpsckt) noexcept 
       : arpsocket{arpsckt}
    {
        initscr();
        raw();
        noecho();
        curs_set(1);
        intrflush(stdscr, false);
        keypad(stdscr, TRUE);

        getmaxyx(stdscr, termHeigth, termWide);
        resizeWide   = termWide; 
        resizeHeigth = termHeigth; 
        sentWide     = termWide;
        sentHeigth   = sentSize;
        histWide     = termWide;
        histHeigth   = termHeigth - sentHeigth - 3 ;
        received     = newwin(histHeigth, histWide, 0, 0),
        label        = newwin(1 , termWide,  histHeigth + 1 , 0);
        sent         = newwin(sentHeigth, sentWide, termHeigth - sentSize , 0);

        udsserver.sun_family = AF_UNIX;
    }

    Chat::~Chat(void) noexcept {
        shutdown();
        if(udsconn != -1) close(udsconn);
        if(udsfd  != -1) close(udsfd);
        try{
            if(queuereader != nullptr) {
                queuereader->join();
                delete queuereader;
            }
        }catch(...){
            // Ignore all
        }
    }

    void Chat::drawArea(WINDOW* area, size_t heigth, size_t wide) noexcept{
         mvwprintw(area, 0, 0, "+");
         mvwprintw(area, heigth - 1, 0, "+");
         mvwprintw(area, 0, wide - 1, "+");
         mvwprintw(area, heigth - 1, wide - 1, "+");
    
        for (size_t i { 1 }; i < (heigth - 1); i++) {
           mvwprintw(area, i, 0, "|");
           mvwprintw(area, i, wide - 1, "|");
        }

        for (size_t i { 1 }; i < (wide - 1); i++) {
           mvwprintw(area, 0, i, "-");
           mvwprintw(area, heigth - 1, i, "-");
        }
    }

    void Chat::draw(void) noexcept{
         drawArea(received, histHeigth, histWide);
         mvwprintw(label, 0, 2, "%s", "Exit: F10  Navigate History: ARROW_UP, ARROW_DOWN, ARROW_RIGHT ( go to end )");
         drawArea(sent, sentHeigth, sentWide);
    }

    void Chat::refresh(void) anyexcept{

        bool refreshHistory { false };

        screenMtx.lock();

        getmaxyx(stdscr, termHeigth , termWide);

        if(termHeigth < static_cast<int>(MIN_HEIGTH) || termWide < static_cast<int>(MIN_WIDE)){
            histWide     = termWide;
            histHeigth   = termHeigth - sentHeigth - 3 ;

            wclear(received);
            wclear(label);
            wclear(sent);
            wclear(stdscr);

            wresize(received, histHeigth + 2, histWide);
            wresize(label, 0, 0);
            wresize(sent, 0, 0);
            mvwprintw(received, 0, 2, "%s", "Terminal too small !!!");
            wrefresh(received);
            wrefresh(label);
            wrefresh(sent);

            screenMtx.unlock();

            return; 
        }
      
        if (resizeHeigth != termHeigth || resizeWide != termWide) {
                 resizeWide   = termWide; 
                 resizeHeigth = termHeigth; 
                 sentWide     = termWide;
                 sentHeigth   = sentSize;
                 histWide     = termWide;
                 histHeigth   = termHeigth - sentHeigth - 3 ;
    
                 wresize(received, histHeigth, histWide);
                 wresize(label, 3, resizeWide);
                 wresize(sent, sentHeigth, sentWide);
                 mvwin(label, resizeHeigth - sentHeigth -3 , 0);
                 mvwin(sent, resizeHeigth - sentHeigth, 0);
    
                 wclear(stdscr);
                 wclear(received);
                 wclear(label);
                 wclear(sent);

                 linesCache.clear();
                 refreshLineCache();

                 refreshHistory = true;
        }

         draw();

         wrefresh(received);
         wrefresh(label);
         wrefresh(sent);

         screenMtx.unlock();

         if(refreshHistory) printHistoryPage();
    }

    void Chat::printPrompt(size_t offset) const anyexcept{
        try{
             const size_t MAX_CHARS  { safeSizeT<int>((sentWide-4) * (sentHeigth-2)) },
                          QUEUE_SIZE { sentBufferQueue.size() };

             wclear(sent);

             if( QUEUE_SIZE <= MAX_CHARS){
                 for (size_t row { 1 }, text { offset }; row < safeSizeT<int>(sentHeigth - 1) && text < MAX_CHARS && text < QUEUE_SIZE ; row++ ) {
                    for(size_t chr { 2 } ; chr < safeSizeT<int>( sentWide - 2 ) && text < MAX_CHARS && text < QUEUE_SIZE; chr++ , text++ )
                        mvwprintw(sent, row, chr, "%c", sentBufferQueue.at(text));
                 }
             }
        }catch(TypesUtilsException& ex){
             Debug::printLog(mergeStrings({"Error: printPrompt() : Unexpected values: H", to_string(sentHeigth).c_str()," W", to_string(sentWide).c_str() }), DEBUG_MODE::ERR_DEBUG);
             usleep(500);
             throw string{"Abort."};
        }
    }

    void Chat::refreshLineCache(void) anyexcept{
        size_t  lineSize     { 0 };
        try{
            lineSize   =  safeSizeT<int>(getmaxx(received) - 4);
        }catch(TypesUtilsException& ex){
             Debug::printLog(mergeStrings({"Error: refreshLineCache() : Unexpected  lineSize values: ", to_string(getmaxx(received) - 4).c_str(),  }), DEBUG_MODE::ERR_DEBUG);
             usleep(500);
             throw string{"Abort."};
        }

        historyOffset = 0;
        lastLine      = -1;
        added         = 0;

        screenBufferMtx.lock();
    
        for( auto chr : receivedBuffer){
                   switch(chr){
                      case 0:   
                             // Ignore
                         break;
                      case 1:
                             linesCache.push_back(" ");
                             added = 0;
                             lastLine = -1;
                         break;
                      default:
                       if(lastLine == -1){
                           linesCache.push_back("");
                           lastLine = linesCache.size() -1;
                       }  
                       linesCache.at(lastLine).push_back(chr);
                       added++;
                       if(added == lineSize) {
                           linesCache.push_back("");
                           lastLine = linesCache.size() -1;
                           added = 0;
                        }
                    }
        }

        screenBufferMtx.unlock();
        
    }

    void Chat::updateScreenFromReceived(void) anyexcept{
        ArpPkt  arpbuffer;
        string  lineBuffer   {""};
        size_t  lineSize     { 0 };
        try{
            lineSize   =  safeSizeT<int>(getmaxx(received) - 4);
        }catch(TypesUtilsException& ex){
             Debug::printLog(mergeStrings({"Error: updateScreenFromReceived() : Unexpected  lineSize values: ", to_string(getmaxx(received) - 4).c_str(),  }), DEBUG_MODE::ERR_DEBUG);
             throw ArpChatException{"Conversion Error."};
        }

        screenBufferMtx.lock();

        size_t msgLen = arpsocket.availeblePackets();

        for(size_t idx{0}; idx<msgLen; idx++){
           try{
              arpbuffer = arpsocket.popPacket();
           }catch(ArpChatException& ex){  
              screenBufferMtx.unlock();
              throw(ArpChatException(mergeStrings({"Error: updateScreenFromReceived(): tying to process empty queue : ", ex.what()})));
           }catch(...){
              screenBufferMtx.unlock();
              throw(ArpChatException("Error: updateScreenFromReceived(): unhandled exception."));
           }

           for(auto chr : arpbuffer.senderMAC){
               receivedBuffer.push_back(chr);
               switch(chr){
                  case 0:   
                         // Ignore
                     break;
                  case 1:
                         linesCache.push_back(" ");
                         added = 0;
                         lastLine = -1;
                     break;
                  default:
                   if(lastLine == -1){
                       linesCache.push_back("");
                       lastLine = linesCache.size() -1;
                   }  
                   linesCache.at(lastLine).push_back(chr);
                   added++;
                   if(added == lineSize) {
                       linesCache.push_back("");
                       lastLine = linesCache.size() -1;
                       added = 0;
                    }
                }
            }

        }

        screenBufferMtx.unlock();
    }

    void  Chat::updateScreenFromSent(void) anyexcept{
        static const string prompt {"\n>>> "};
        string line                {">>> "};
        size_t lineSize            { 0 },
               added               { 0 };

        try{
            lineSize   =  safeSizeT<int>(getmaxx(received) - 4);
        }catch(TypesUtilsException& ex){
             Debug::printLog(mergeStrings({"Error: updateScreenFromReceived() : Unexpected  lineSize values: ", to_string(getmaxx(received) - 4).c_str(),  }), DEBUG_MODE::ERR_DEBUG);
             usleep(500);
             throw string{"Abort."};
        }

        static auto pushLine       { [&](){added = 0; linesCache.push_back(line); line.clear();}};

        screenBufferMtx.lock();

        for(auto chr : prompt)
            receivedBuffer.push_back(chr);

        for(auto chr : sentBufferQueue){
            receivedBuffer.push_back(chr);

            if(chr != '\n'){
                line.push_back(chr);
                added++;
                if(added == lineSize) pushLine();
            } else {
                if(!line.empty()) pushLine();
                linesCache.push_back("");
                continue;
            }

        }
        receivedBuffer.push_back('\n');
        if(!line.empty()) pushLine();
        linesCache.push_back("");

        screenBufferMtx.unlock();
    }

    void Chat::printHistoryPage(void) anyexcept{
        size_t lines     { safeSizeT<int>(histHeigth - 3) },
               cacheSize { linesCache.size() };
        try{
            lines   =  safeSizeT<int>(histHeigth - 3);
        }catch(TypesUtilsException& ex){
             Debug::printLog(mergeStrings({"Error: printHistoryPage() : Unexpected  lines values: ", to_string(histHeigth - 3).c_str(),  }), DEBUG_MODE::ERR_DEBUG);
             usleep(500);
             throw string{"Abort."};
        }

        wclear(received);

        auto effectiveOffset { 
            [&]() -> int {
                size_t initial { cacheSize > lines ? cacheSize - lines : 0 };
                size_t shifted { initial + historyOffset };
                if (shifted > initial) {
                     historyOffset = 0;
                     return initial;
                }
                return  shifted;
            }
        };

        try{
            for(size_t ln{safeSizeT<int>(effectiveOffset())}, rel{0}; rel < lines && ln < cacheSize; ln++, rel++)
                       mvwprintw(received, rel + 2, 2, "%s", linesCache.at(ln).c_str());
        }catch(TypesUtilsException& ex){
             Debug::printLog(mergeStrings({"Error: printHistoryPage() : Unexpected  lines values: ", to_string(histHeigth - 3).c_str(),  }), DEBUG_MODE::ERR_DEBUG);
        }catch(...){
            Debug::printLog("Error: printing history.", DEBUG_MODE::ERR_DEBUG);
        }
        refresh();
    }

    void Chat::sendMessage(void) const anyexcept {
       
       array<uint8_t, MAX_PACKET_SIZE> rawbuffer{};

       if(size_t bufferLen { sentBufferQueue.size() } ; bufferLen > 0 ){
            size_t  cycles   { bufferLen / MAX_PACKET_SIZE },
                    oddBytes { bufferLen % MAX_PACKET_SIZE },
                    frag     {0}; 

            for( ; frag < cycles; frag++){
                copy(sentBufferQueue.begin() + (frag * MAX_PACKET_SIZE), sentBufferQueue.begin() + (frag * MAX_PACKET_SIZE) + MAX_PACKET_SIZE, rawbuffer.data());
                arpsocket.setSrcMAC(rawbuffer);
                arpsocket.send();
            }

            if(oddBytes != 0){
                rawbuffer =  {};
                copy(sentBufferQueue.begin() + (frag * MAX_PACKET_SIZE), sentBufferQueue.begin() + (frag * MAX_PACKET_SIZE)  + oddBytes, rawbuffer.data());
                arpsocket.setSrcMAC(rawbuffer);
                arpsocket.send();
            }

            rawbuffer =  {};
            rawbuffer.at(0) = 1;
            arpsocket.setSrcMAC(rawbuffer);
            arpsocket.send();
       }

    }

    void Chat::getChar(void)  anyexcept {
         int  chrt      { wgetch(sent) },
              secchrt   { 0 },
              terchrt   { 0 },
              delta     { 0 };
         auto abs       { [](int val) -> int { return val >= 0 ? val : val * -1;} };

         switch(chrt){
                        case C_SEQUENCE_FIRST:
                        secchrt = wgetch(sent);
                        switch(secchrt){
                            case C_SEQUENCE_SECOND:
                                terchrt = wgetch(sent);
                                switch(terchrt){
                                    case C_KLEFT:
                                        // Ignore
                                    break;
                                    case C_KRIGHT:
                                        historyOffset = 0;
                                        printHistoryPage();
                                    break;
                                    case C_KUP:
                                        delta  = linesCache.size() - histHeigth;
                                        if( delta > 0 ){
                                             if(abs(historyOffset) < delta){
                                                  historyOffset--;
                                                  printHistoryPage();
                                             }
                                        }
                                    break;
                                    case C_KDOWN:
                                        if(historyOffset < 0 ){
                                             historyOffset++;
                                             printHistoryPage();
                                        }
                                    break;
                                    case  C_F10:
                                        shutdown();
                                    break;
                                }
                            break;
                        }

                        break;
                        case C_NEWLINE:
                                sendMessage();
                                updateScreenFromSent(); 
                                sentBufferQueue.clear();
                                printPrompt();
                                printHistoryPage();
                        break;
                        case C_BACKSPACE:
                        case KEY_BACKSPACE:
                                if(sentBufferQueue.size() > 0 ){
                                     sentBufferQueue.pop_back();
                                     printPrompt();
                                }
                        break;
                        default:
                                insertCharacter(static_cast<char>(chrt), MAX_SENT_BUFFER_SIZE);
                                printPrompt();
         }
    }

    void  Chat::insertCharacter(char chtr, size_t maxlen) noexcept{
         sentBufferQueue.push_back(chtr) ;
         if(sentBufferQueue.size() > maxlen)
               sentBufferQueue.pop_front();
    }

    void Chat::shutdown(void)  noexcept{
         running = false;
    }

    void Chat::pollIncomingQueue(void) noexcept{
        try{ 
            array<uint8_t, MAX_QUEUE_LEN_STRING> pollbuffer {};
            string errmsg                                   {""};

            while(running){
                    FD_ZERO(&fdset);
                    FD_SET(udsconn, &fdset);
    
                    if(udsconn > nfds)
                        nfds = udsconn + 1;
    
                    ssize_t sret {::select(nfds, &fdset, nullptr, nullptr, &tvMin)};
                    switch(sret){
                        case -1:
                            usleep(150);
                            errmsg = mergeStrings({"Select Error: ", strerror(errno)});
                            Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
                            if(errno != EINTR)
                                    throw ArpChatException(errmsg);
                            break;
                        case  0:
                            Debug::printLog("Select Timeout.", DEBUG_MODE::STD_DEBUG);
                            usleep(150);
                            break;
                        default:
                            pollbuffer = {};
                            ssize_t  ret = read(udsconn, pollbuffer.data(), pollbuffer.size() - 1);
                            switch(ret){
                                case -2:
                                    Debug::printLog("All packed filtered with provided rule(s).", DEBUG_MODE::VERBOSE_DEBUG);
                                    break;
                                case -1:
                                    errmsg = mergeStrings({"Error: recvfrom() : ", strerror(errno)});
                                    Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
                                    throw ArpChatException(errmsg);
                                case 0:
                                    errmsg = "readLineTimeout: Connection Closed by peer.";
                                    Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
                                    throw ArpChatException(errmsg);
                                default:
                                    Debug::printLog("Packet Received.", DEBUG_MODE::VERBOSE_DEBUG);
    
                                    (void)pollbuffer.data();
                                    updateScreenFromReceived();
                                    printHistoryPage();
                            }
                    }
                    usleep(250) ;
            }

        } catch(ArpChatException& err){
            string msg = mergeStrings({"Error in pollIncomingQueue() thread : ", err.what()});
            Debug::printLog(msg, DEBUG_MODE::ERR_DEBUG);
        } catch(...){
            Debug::printLog("Unhandled Exception in pollIncomingQueue() thread.", DEBUG_MODE::ERR_DEBUG);
        }

        running = false;
    }

    void Chat::init(void)  anyexcept{
        if( UDDevice.size() > ( sizeof(udsserver.sun_path) - 1 ) ){
                string errmsg = "Error: UDS device path too long.";
                Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
                throw ArpChatException(errmsg);
        }
        copy(UDDevice.c_str(), UDDevice.c_str() + UDDevice.size(), udsserver.sun_path);

        udsfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if(udsfd == -1){
           string errmsg = mergeStrings({"Error: can't create UDS : ", strerror(errno)});
           Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
           throw ArpChatException(errmsg);
        }

        unlink(UDDevice.c_str());
        int ret = bind(udsfd, reinterpret_cast<const Sockaddr*>(&udsserver), sizeof(SockaddrUn));
        if(ret == -1){
           string errmsg = mergeStrings({"Error: can't bind UDS : ", strerror(errno)});
           Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
           throw ArpChatException(errmsg);
        }

        ret = listen(udsfd, 1);
        if (ret == -1){
           string errmsg = mergeStrings({"Error: can't listen UDS : ", strerror(errno)});
           Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
           throw ArpChatException(errmsg);
        }

        socklen_t len { sizeof(SockaddrUn) };
        udsconn = accept(udsfd, reinterpret_cast<Sockaddr*>(&udsclientconn), &len);
        if(udsconn == -1){
           string errmsg = mergeStrings({"Error: can't accept UDS : ", strerror(errno)});
           Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
           throw ArpChatException(errmsg);
        }

        try{
              queuereader = new thread([&](){ pollIncomingQueue(); } );
        }catch(...){
              Debug::printLog("Error: can't create queue reader thread", DEBUG_MODE::ERR_DEBUG);
              throw ArpChatException("Error: can't create queue reader thread" );
        }
    }

    void Chat::loop(void)  anyexcept{
        while(running){
           refresh();
           usleep(360);
           getChar();
        }
        endwin();
    }

    ArpChatException::ArpChatException(string& errString)
      : errorMessage{errString}
    {}

    ArpChatException::ArpChatException(string&& errString)
      : errorMessage{errString}
    {}
     
    const char* ArpChatException::what(void)   const noexcept {
       return errorMessage.c_str();
    }

} // End namespace chatterminal
