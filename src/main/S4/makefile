CC = clang
BUILD_DIR =  obj
TARGETDIR = ../build
TARGET = $(TARGETDIR)/libs4.a
SHARED_TARGET = $(TARGETDIR)/libs4.dylib

 
CFLAGS= -I. -I./scripts -iquote. -I$(TARGETDIR)   -I $(TARGETDIR)/skein \
	-mmacosx-version-min=10.10 \
	-Wnon-modular-include-in-framework-module -Werror=non-modular-include-in-framework-module -Wno-trigraphs -fpascal-strings -O0 -fno-common -Wno-missing-field-initializers -Wno-missing-prototypes -Werror=return-type -Wunreachable-code -Werror=deprecated-objc-isa-usage -Werror=objc-root-class -Wno-missing-braces -Wparentheses -Wswitch -Wunused-function -Wno-unused-label -Wno-unused-parameter -Wunused-variable -Wunused-value -Wempty-body -Wuninitialized -Wconditional-uninitialized -Wno-unknown-pragmas -Wno-shadow -Wno-four-char-constants -Wno-conversion -Wconstant-conversion -Wint-conversion -Wbool-conversion -Wenum-conversion -Wno-float-conversion -Wnon-literal-null-conversion -Wobjc-literal-conversion -Wshorten-64-to-32 -Wpointer-sign -Wno-newline-eof

.PHONY: all init clean distclean
 
 SRCS = \
	s4.c \
	s4hash.c \
	s4pbkdf2.c \
	s4bufferutilities.c \
	s4hashword.c \
	s4share.c \
	s4cipher.c \
	s4tbc.c \
	s4ecc.c \
	s4mac.c\
	zbase32.c \
	xxhash.c \
	xxhsum.c  \
	s4keys.c  
	 
INCLUDES = \
		s4.h \
		s4crypto.h \
		s4keys.h \
		s4bufferutilities.h	\
		s4internal.h \
		s4pubtypes.h
 
LIBS = \
		$(TARGETDIR)/libs4.a  \
		$(TARGETDIR)/libargon2.a  \
		$(TARGETDIR)/libsha3.a   \
		$(TARGETDIR)/libtomcrypt.a  \
		$(TARGETDIR)/libtommath.a  \
		$(TARGETDIR)/libyajl.a  

OBJS = $(SRCS:%.c=$(BUILD_DIR)/%.o)

all: $(TARGET) $(SHARED_TARGET)

init:
	@[ -d $(BUILD_DIR) ] || mkdir $(BUILD_DIR)
	@[ -d $(TARGETDIR)/s4 ] || mkdir $(TARGETDIR)/s4 &&  cp $(INCLUDES) $(TARGETDIR)/s4

$(BUILD_DIR)/%.o: %.c  | init 
	$(CC) -o $@ -c $(CFLAGS) $<

$(TARGET):  $(OBJS) init
	libtool -static $(OBJS) -o $(TARGET)  

$(SHARED_TARGET):  $(TARGET) init
	libtool -dynamic $(LIBS) -lSystem -o $(SHARED_TARGET)  

clean: 
	@rm -rf $(BUILD_DIR)/*
