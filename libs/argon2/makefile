CC = clang
BUILD_DIR =  obj
TARGETDIR = ../build
TARGET = $(TARGETDIR)/libargon2.a
 
CFLAGS= -I. -I./scripts -iquote. -I$(TARGETDIR)  \
	-mmacosx-version-min=10.10 \
	-Wnon-modular-include-in-framework-module -Werror=non-modular-include-in-framework-module -Wno-trigraphs -fpascal-strings -O0 -fno-common -Wno-missing-field-initializers -Wno-missing-prototypes -Werror=return-type -Wunreachable-code -Werror=deprecated-objc-isa-usage -Werror=objc-root-class -Wno-missing-braces -Wparentheses -Wswitch -Wunused-function -Wno-unused-label -Wno-unused-parameter -Wunused-variable -Wunused-value -Wempty-body -Wuninitialized -Wconditional-uninitialized -Wno-unknown-pragmas -Wno-shadow -Wno-four-char-constants -Wno-conversion -Wconstant-conversion -Wint-conversion -Wbool-conversion -Wenum-conversion -Wno-float-conversion -Wnon-literal-null-conversion -Wobjc-literal-conversion -Wshorten-64-to-32 -Wpointer-sign -Wno-newline-eof

.PHONY: all init clean distclean

 SRCS = \
 	argon2.c \
 	core.c \
 	ref.c \
	blake2b.c \
	encoding.c \
	thread.c
 
INCLUDES = \
	argon2.h \
	blamka-round-opt.h \
	encoding.h \
	blake2-impl.h \
	blamka-round-ref.h	\
	ref.h \
	blake2.h \
	core.h \
	thread.h
 
 
OBJS = $(SRCS:%.c=$(BUILD_DIR)/%.o)

all: $(TARGET)

init:
	@[ -d $(BUILD_DIR) ] || mkdir $(BUILD_DIR)
	@[ -d $(TARGETDIR)/argon2 ] || mkdir $(TARGETDIR)/argon2 &&  cp $(INCLUDES) $(TARGETDIR)/argon2
 
$(BUILD_DIR)/%.o: %.c  | init 
	$(CC) -o $@ -c $(CFLAGS) $<

$(TARGET): init $(OBJS)
	libtool -static $(OBJS) -o $(TARGET)  
 
clean: 
	@rm -rf $(BUILD_DIR)/*
