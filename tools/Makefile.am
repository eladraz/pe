INCLUDES = -I $(top_srcdir)/Include -I $(XSTL_PATH)/Include

if DEBUG
DBGFLAGS = -ggdb -DDEBUG
else
DBGFLAGS = -g
endif

bin_PROGRAMS = dumpPE

dumpPE_SOURCES = dumpPE.cpp


dumpPE_CFLAGS = $(CFLAGS_PELIB_COMMON) $(DBGFLAGS) $(AM_CFLAGS)
dumpPE_CPPFLAGS = $(CFLAGS_PELIB_COMMON) $(DBGFLAGS) $(AM_CFLAGS)

if UNICODE
dumpPE_CFLAGS+= -DXSTL_UNICODE -D_UNICODE
dumpPE_CPPFLAGS+= -DXSTL_UNICODE -D_UNICODE
endif

dumpPE_LDADD = -L$(XSTL_PATH)/out/lib -lxstl \
               -L$(XSTL_PATH)/out/lib -lxstl_data \
               -L$(XSTL_PATH)/out/lib -lxstl_except \
               -L$(XSTL_PATH)/out/lib -lxstl_stream \
               -L$(XSTL_PATH)/out/lib -lxstl_os \
               -L$(XSTL_PATH)/out/lib -lxstl_unix \
               -L$(XSTL_PATH)/out/lib -lxstl_enc \
               -L$(XSTL_PATH)/out/lib -lxstl_digest \
               -L$(XSTL_PATH)/out/lib -lxstl_random \
               -L$(XSTL_PATH)/out/lib -lxstl_encryptions \
               -L$(XSTL_PATH)/out/lib -lxstl_utils \
               -L$(top_srcdir)/Source/pe -lpe


