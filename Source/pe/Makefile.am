INCLUDES = -I $(top_srcdir)/Include -I $(XSTL_PATH)/Include

if DEBUG
DBGFLAGS = -ggdb -DDEBUG
else
DBGFLAGS = -g
endif

lib_LTLIBRARIES = libpe.la

libpe_la_SOURCES = dosheader.cpp humanStringTranslation.cpp ntDirCli.cpp ntsectionheader.cpp pePrecompiledHeaders.cpp \
                   dosSection.cpp ntDirExport.cpp ntPrivateDirectory.cpp peFile.cpp section.cpp ntheader.cpp ntDirReloc.cpp

libpe_la_CFLAGS = $(CFLAGS_PELIB_COMMON) $(DBGFLAGS) $(AM_CFLAGS)
libpe_la_CPPFLAGS = $(CFLAGS_PELIB_COMMON) $(DBGFLAGS) $(AM_CFLAGS)

if UNICODE
libpe_la_CFLAGS+= -DXSTL_UNICODE -D_UNICODE
libpe_la_CPPFLAGS+= -DXSTL_UNICODE -D_UNICODE
endif

