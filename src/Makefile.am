bin_PROGRAMS   = arpchatcpp
dist_man_MANS  = ../doc/arpchatcpp.1

arpchatcpp_SOURCES = arplib_main.cpp arplib.cpp parseCmdLine.cpp chat.cpp debug.cpp configFile.cpp StringUtilsImpl.cpp TypesImpl.cpp

nobase_include_HEADERS   = ../include/parseCmdLine.hpp  ../include/chat.hpp ../include/debug.hpp ../include/configFile.hpp ../include/StringUtils.hpp  ../include/Types.hpp

arpchatcpp_CPPFLAGS         = ${LUA_INCLUDE}
arpchatcpp_LDADD            = ${LUA_LIB}

install-exec-hook:
	setcap cap_net_raw=eip  $(bindir)/arpchatcpp
