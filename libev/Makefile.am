AUTOMAKE_OPTIONS = foreign

VERSION_INFO = 4:0:0

EXTRA_DIST = LICENSE Changes libev.m4 autogen.sh \
	     ev_vars.h ev_wrap.h \
	     ev_epoll.c ev_select.c ev_poll.c ev_kqueue.c ev_port.c ev_win32.c \
	     ev.3 ev.pod Symbols.ev Symbols.event

noinst_LTLIBRARIES = libev.la

libev_la_SOURCES = ev.c event.c
libev_la_LDFLAGS = -static -version-info $(VERSION_INFO)
