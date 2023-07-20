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

#include <StringUtils.hpp>

namespace stringutils{

  using std::string;
  using std::vector;
  using std::initializer_list;

  std::string mergeStrings(initializer_list<const char*> list) noexcept{
       string buff {""};

       for( auto elem : list)
           buff.append(elem);

       return buff;
   }

  static const  char      convTable[]   {
                                 'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
                                 'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
                                 'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
                                 'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/'
  };

  static const  uint8_t   checkTable[]  {
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62, 255, 255, 255,   63,
                                  52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255, 255, 255, 255, 255,
                                 255,   0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
                                  15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255, 255,
                                 255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,
                                  41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
   };

   StringUtilsException::StringUtilsException(int errNum)
        :   errorMessage{"None"}, errorCode{errNum}
   {}
   
   StringUtilsException::StringUtilsException(string& errString)
        :  errorMessage{errString}, errorCode{0}
   {}
   
   StringUtilsException::StringUtilsException(string&& errString)
        :  errorMessage{errString}, errorCode{0}
   {}
   
   StringUtilsException::StringUtilsException(int errNum, string& errString)
        :  errorMessage{errString}, errorCode{errNum}
   {}
   
   StringUtilsException::StringUtilsException(int errNum, string&& errString)
        :  errorMessage{errString}, errorCode{errNum}
   {}

   const char* StringUtilsException::what(void)    const noexcept {
           return errorMessage.c_str();
   }

   int  StringUtilsException::getErrorCode(void)  const noexcept{
           return errorCode;
   }
   
  template<class T, class T2>
  void decodeB64(const T& in, T2& out) anyexcept{
         #ifdef __GNUC__
         #pragma GCC diagnostic push
         #pragma GCC diagnostic ignored "-Wtype-limits"
         #endif

         try{
            out.resize( [&in]() -> size_t { auto i{in.cbegin()}; auto j{i}; 
                                            for(; *i != 255 && i!= in.cend(); ++i); 
                                            return ( ((static_cast<size_t>(i-j) + 2) / 4) * 3); }()
                       );
         }catch(...){
            throw StringUtilsException("decodeB64: Data error.");
         }

         #ifdef __GNUC__
         #pragma GCC diagnostic pop
         #endif
  
         auto i{in.cbegin()}; auto j{out.begin()};
         for(; i<in.cend()-4; i+=4, j+=3){
                 *j      = static_cast<uint8_t>(checkTable[static_cast<size_t>(*i)]     << 2 | 
                           checkTable[static_cast<size_t>(*(i+1))] >> 4);
                 *(j+1)  = static_cast<uint8_t>(checkTable[static_cast<size_t>(*(i+1))] << 4 | 
                           checkTable[static_cast<size_t>(*(i+2))] >> 2);
                 *(j+2)  = static_cast<uint8_t>(checkTable[static_cast<size_t>(*(i+2))] << 6 | 
                           checkTable[static_cast<size_t>(*(i+3))]     );
         }
  
         if(i < (in.cend() - 1))
                 *j      = static_cast<uint8_t>(checkTable[static_cast<size_t>(*i)]     << 2 | 
                           checkTable[static_cast<size_t>(*(i+1))] >> 4);
         if(i < (in.cend() - 2))
                 *(j+1)  = static_cast<uint8_t>(checkTable[static_cast<size_t>(*(i+1))] << 4 | 
                           checkTable[static_cast<size_t>(*(i+2))] >> 2);
         if(i < (in.cend() - 3))
                 *(j+2)  = static_cast<uint8_t>(checkTable[static_cast<size_t>(*(i+2))] << 6 | 
                           checkTable[static_cast<size_t>(*(i+3))]     );
  }
  
  template<class T, class T2>
  void encodeB64(const T& in, T2& out) anyexcept{
         try{
             out.resize((in.size() + 2) / 3 * 4);
         }catch(...){
            throw StringUtilsException("encodeB64: Data error.");
         }
  
          auto i{in.cbegin()}; auto j{out.begin()};
          for(; i<in.cend()-2; i+=3, j+=4){
                  *j     = convTable[(*i >> 2) & 0x3F];
                  *(j+1) = convTable[static_cast<size_t>(((*i     & 0x3) << 4) | 
                                                             static_cast<int>(((*(i+1) & 0xF0) >> 4 )))];
                  *(j+2) = convTable[static_cast<size_t>(((*(i+1) & 0xF) << 2) | 
                                                             static_cast<int>(((*(i+2) & 0xC0) >> 6 )))];
                  *(j+3) = convTable[  *(i+2) & 0x3F];
          }
  
          if(i < in.cend()){
                  *j     = convTable[(*i >> 2) & 0x3F];
                  if(i == (in.cend() -1)){
                          *(j+1) = convTable[static_cast<size_t>((*i  & 0x3) << 4)];
                          *(j+2) = '=';
                  }else{
                          *(j+1) = convTable[static_cast<size_t>((*i      & 0x3) << 4 |
                                                             static_cast<int>(((*(i+1) & 0xF0) >> 4 )))];
                          *(j+2) = convTable[static_cast<size_t>(((*(i+1) & 0xF) << 2))];
                  }
                  *(j+3) = '=';
          }
  }

  #ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wsign-compare"
  #pragma GCC diagnostic ignored "-Wtype-limits"
  #endif

  #if defined  __clang_major__ && __clang_major__ >= 4 && !defined __APPLE__ && __clang_major__ >= 4
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wundefined-func-template"
  #endif

  template void   encodeB64(const std::vector<uint8_t>& in, std::string& out)   anyexcept;
  template void   decodeB64(const std::string& in, std::vector<uint8_t>& out)   anyexcept;

  #ifdef __GNUC__
  #pragma GCC diagnostic pop
  #endif

  #if defined  __clang_major__ && __clang_major__ >= 4 && !defined __APPLE__ && __clang_major__ >= 4
  #pragma clang diagnostic pop
  #endif

}
