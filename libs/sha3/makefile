CFLAGS= -I. -iquote.  \
	-mmacosx-version-min=10.10 \
	-Wnon-modular-include-in-framework-module -Werror=non-modular-include-in-framework-module -Wno-trigraphs -fpascal-strings -O0 -fno-common -Wno-missing-field-initializers -Wno-missing-prototypes -Werror=return-type -Wunreachable-code -Werror=deprecated-objc-isa-usage -Werror=objc-root-class -Wno-missing-braces -Wparentheses -Wswitch -Wunused-function -Wno-unused-label -Wno-unused-parameter -Wunused-variable -Wunused-value -Wempty-body -Wuninitialized -Wconditional-uninitialized -Wno-unknown-pragmas -Wno-shadow -Wno-four-char-constants -Wno-conversion -Wconstant-conversion -Wint-conversion -Wbool-conversion -Wenum-conversion -Wno-float-conversion -Wnon-literal-null-conversion -Wobjc-literal-conversion -Wshorten-64-to-32 -Wpointer-sign -Wno-newline-eof

CC = clang
BUILD_DIR =  obj
TARGETDIR = ../build
TARGET = $(TARGETDIR)/libsha3.a

.PHONY: all init clean distclean
 
 SRCS = \
	KeccakHash.c \
	KeccakSpongeWidth1600.c\
	KeccakP-1600-reference.c \
	SimpleFIPS202.c 

INCLUDES = \
	SimpleFIPS202.h \
	KeccakHash.h \
	KeccakSpongeWidth1600.h \
	KeccakP-1600-SnP.h \
	KeccakSponge-common.h \
	KeccakP-1600-reference.h \
	align.h \
	brg_endian.h
 
 
OBJS = $(SRCS:%.c=$(BUILD_DIR)/%.o)

all: $(TARGET)

init:
	@[ -d $(BUILD_DIR) ] || mkdir $(BUILD_DIR)
	@[ -d $(TARGETDIR)/sha3 ] || mkdir -p $(TARGETDIR)/sha3 &&  cp $(INCLUDES) $(TARGETDIR)/sha3

$(BUILD_DIR)/%.o: %.c  | init 
	$(CC) -o $@ -c $(CFLAGS) $<

$(TARGET): init $(OBJS)
	libtool -static $(OBJS) -o $(TARGET)  
 

clean: 
	@rm -rf $(BUILD_DIR)/*
