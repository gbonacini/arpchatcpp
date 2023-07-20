bin_PROGRAMS   = arpchat
dist_man_MANS  = ../doc/arpchat.1

arpchat_SOURCES = arplib_main.cpp arplib.cpp parseCmdLine.cpp chat.cpp debug.cpp configFile.cpp StringUtilsImpl.cpp TypesImpl.cpp

nobase_include_HEADERS   = ../include/parseCmdLine.hpp  ../include/chat.hpp ../include/debug.hpp ../include/configFile.hpp ../include/StringUtils.hpp  ../include/Types.hpp

arpchat_CPPFLAGS         = ${LUA_INCLUDE}
arpchat_LDADD            = ${LUA_LIB}

install-exec-hook:
	chmod u+s  $(bindir)/arplibcmd
