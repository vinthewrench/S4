CC = clang
BUILD_DIR =  obj
TARGETDIR = ../build
TARGET = $(TARGETDIR)/cavp

CFLAGS= -I. -I./scripts -iquote. -I$(TARGETDIR) -I$(TARGETDIR)/s4    \
	-mmacosx-version-min=10.10 \
	-fpascal-strings -O0 -fno-common \
	-Wnon-modular-include-in-framework-module \
	-Werror=non-modular-include-in-framework-module \
	-Wno-trigraphs -Wno-missing-field-initializers \
	-Wno-missing-prototypes -Werror=return-type \
	-Wunreachable-code -Werror=deprecated-objc-isa-usage \
	-Werror=objc-root-class -Wno-missing-braces -Wparentheses \
	-Wswitch -Wunused-function -Wno-unused-label \
	-Wno-unused-parameter -Wunused-variable -Wunused-value \
	-Wempty-body -Wuninitialized -Wconditional-uninitialized \
	-Wno-unknown-pragmas -Wno-shadow -Wno-four-char-constants \
	-Wno-conversion -Wconstant-conversion -Wint-conversion  \
	-Wbool-conversion -Wenum-conversion -Wno-float-conversion \
	-Wnon-literal-null-conversion -Wobjc-literal-conversion \
	-Wshorten-64-to-32 -Wpointer-sign -Wno-newline-eof

.PHONY: all init clean distclean
 
 SRCS = \
		cavp.c  \
		cavpHashTest.c \
		cavputilities.c 
		
	 		
OBJS = $(SRCS:%.c=$(BUILD_DIR)/%.o)

all: $(TARGET)

init:
	@[ -d $(BUILD_DIR) ] || mkdir $(BUILD_DIR)
	@[ -d $(TARGETDIR) ] || mkdir $(TARGETDIR)

$(BUILD_DIR)/%.o: %.c  | init 
	$(CC) -o $@ -c $(CFLAGS) $<

$(TARGET): $(OBJS)
	clang $(OBJS)   \
	-mmacosx-version-min=10.10 \
	-L$(TARGETDIR) $(TARGETDIR)/libs4.dylib \
	-isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk \
	-o $(TARGETDIR)/cavp 
 
clean: 
	@rm -rf $(BUILD_DIR)/*
