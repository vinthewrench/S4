### 
### NOTE -- this needs to run before the build
### 	$(SOURCE_DIR)/scripts/fetch_git_commit_hash.sh
##  but there seems to be a problem with where it should be placed
## see fetch_git_commit_hash.s line 35
##  filepath="${SRCROOT}/src/main/Scripts/git_version_hash.h"


## also the yajl library makes reference to #include  <yajl/yajl_common.h>
## and so the following need to move somewhere into a yajl directory that is included
## yajl_common.h, yajl_gen.h and yajl_parse.h


LOCAL_DIR := $(shell pwd)

MODULE_NAME    := c4
MODULE_VERSION := 1.0.0
MODULE_BRANCH  := develop

THIRD_PARTY_DIR = $(LOCAL_DIR)/libs

SOURCE_DIR = $(LOCAL_DIR)/src

MAIN_SOURCE_DIR := $(SOURCE_DIR)/main

SOURCE_DIRS := $(THIRD_PARTY_DIR)/yajl/src \
  $(MAIN_SOURCE_DIR)/C4 \
  $(MAIN_SOURCE_DIR)/tomcrypt \
  $(MAIN_SOURCE_DIR)/tomcrypt/ciphers/aes \
  $(MAIN_SOURCE_DIR)/tomcrypt/ciphers/twofish \
  $(MAIN_SOURCE_DIR)/tomcrypt/encauth/ccm \
  $(MAIN_SOURCE_DIR)/tomcrypt/encauth/gcm \
  $(MAIN_SOURCE_DIR)/tomcrypt/hashes \
  $(MAIN_SOURCE_DIR)/tomcrypt/hashes/helper \
  $(MAIN_SOURCE_DIR)/tomcrypt/hashes/sha2 \
  $(MAIN_SOURCE_DIR)/tomcrypt/hashes/skein \
  $(MAIN_SOURCE_DIR)/tomcrypt/mac/hmac \
  $(MAIN_SOURCE_DIR)/tomcrypt/math \
  $(MAIN_SOURCE_DIR)/tomcrypt/misc \
  $(MAIN_SOURCE_DIR)/tomcrypt/misc/base64 \
  $(MAIN_SOURCE_DIR)/tomcrypt/misc/crypt \
  $(MAIN_SOURCE_DIR)/tomcrypt/misc/pkcs5 \
  $(MAIN_SOURCE_DIR)/tomcrypt/modes/cbc \
  $(MAIN_SOURCE_DIR)/tomcrypt/modes/cfb \
  $(MAIN_SOURCE_DIR)/tomcrypt/modes/ctr \
  $(MAIN_SOURCE_DIR)/tomcrypt/modes/ecb \
  $(MAIN_SOURCE_DIR)/tomcrypt/pk/asn1/der/bit \
  $(MAIN_SOURCE_DIR)/tomcrypt/pk/asn1/der/boolean \
  $(MAIN_SOURCE_DIR)/tomcrypt/pk/asn1/der/choice \
  $(MAIN_SOURCE_DIR)/tomcrypt/pk/asn1/der/ia5 \
  $(MAIN_SOURCE_DIR)/tomcrypt/pk/asn1/der/integer \
  $(MAIN_SOURCE_DIR)/tomcrypt/pk/asn1/der/object_identifier \
  $(MAIN_SOURCE_DIR)/tomcrypt/pk/asn1/der/octet \
  $(MAIN_SOURCE_DIR)/tomcrypt/pk/asn1/der/printable_string \
  $(MAIN_SOURCE_DIR)/tomcrypt/pk/asn1/der/sequence \
  $(MAIN_SOURCE_DIR)/tomcrypt/pk/asn1/der/set \
  $(MAIN_SOURCE_DIR)/tomcrypt/pk/asn1/der/short_integer \
  $(MAIN_SOURCE_DIR)/tomcrypt/pk/asn1/der/utctime \
  $(MAIN_SOURCE_DIR)/tomcrypt/pk/asn1/der/utf8 \
  $(MAIN_SOURCE_DIR)/tomcrypt/pk/dsa \
  $(MAIN_SOURCE_DIR)/tomcrypt/pk/ecc_bl \
  $(MAIN_SOURCE_DIR)/tomcrypt/pk/ecc \
  $(MAIN_SOURCE_DIR)/tomcrypt/pk/pkcs1 \
  $(MAIN_SOURCE_DIR)/tomcrypt/pk/rsa \
  $(MAIN_SOURCE_DIR)/tomcrypt/prngs \
  $(MAIN_SOURCE_DIR)/tommath

INCLUDE_DIRS := \
  C4\
  tomcrypt/hashes/skein \
  tomcrypt/headers \
  tommath \
	../../build/include \
  ../../libs/yajl/src/api

INCLUDE_FILES := \
 	c4/c4.h \
	c4/c4pubtypes.h \
	c4/c4crypto.h\
	c4/c4bufferutilities.h\
	c4/c4keys.h \
    scripts/git_version_hash.h \

WILDCARD_FIND_SOURCE_FILES = $(wildcard $(EACH_SOURCE_DIRS)/*.c)
WILDCARD_SOURCE_FILES := $(foreach EACH_SOURCE_DIRS,$(SOURCE_DIRS),$(WILDCARD_FIND_SOURCE_FILES))

TEST_SOURCE_DIR := src/optest

TEST_SOURCE_FILES := \
$(TEST_SOURCE_DIR)/optest.c\
$(TEST_SOURCE_DIR)/testHash.c\
$(TEST_SOURCE_DIR)/testHMAC.c\
$(TEST_SOURCE_DIR)/testCiphers.c\
$(TEST_SOURCE_DIR)/testTBC.c\
$(TEST_SOURCE_DIR)/testSecretSharing.c\
$(TEST_SOURCE_DIR)/testECC.c\
$(TEST_SOURCE_DIR)/testP2K.c\
$(TEST_SOURCE_DIR)/testKeys.c\
$(TEST_SOURCE_DIR)/optest.h\
$(TEST_SOURCE_DIR)/optestutilities.c

OS_ARCH=$(shell uname -m)
OS_TYPE=$(shell uname -s | tr '[:upper:]' '[:lower:]')

REL_BUILD_DIR          := build
REL_BINARY_DIR         := bin
REL_OBJECTS_DIR        := obj
REL_ANDROID_DIR        := android
REL_ARCHIVE_DIR        := dist
REL_LIBRARY_DIR        := libs/$(OS_TYPE)-$(OS_ARCH)
REL_EXPORT_HEADERS_DIR := include

BUILD_DIR              := $(LOCAL_DIR)/$(REL_BUILD_DIR)
BINARY_DIR             := $(BUILD_DIR)/$(REL_BINARY_DIR)
OBJECTS_DIR            := $(BUILD_DIR)/$(REL_OBJECTS_DIR)
ANDROID_DIR            := $(BUILD_DIR)/$(REL_ANDROID_DIR)
ARCHIVE_DIR            := $(BUILD_DIR)/$(REL_ARCHIVE_DIR)
LIBRARY_DIR            := $(BUILD_DIR)/$(REL_LIBRARY_DIR)
EXPORT_HEADERS_DIR     := $(BUILD_DIR)/$(REL_EXPORT_HEADERS_DIR)

MAIN_INCLUDE_DIRS=$(addprefix $(MAIN_SOURCE_DIR)/,$(INCLUDE_DIRS))

MAIN_INCLUDE_FILES=$(addprefix $(MAIN_SOURCE_DIR)/,$(INCLUDE_FILES))
MAIN_SOURCE_FILES=$(addprefix $(MAIN_SOURCE_DIR)/,$(SOURCE_FILES))
#MAIN_OBJECT_FILES=$(addprefix $(OBJECTS_DIR)/,$(WILDCARD_SOURCE_FILES:.c=.o))
MAIN_OBJECT_FILES=$(addprefix $(OBJECTS_DIR)/,$(WILDCARD_SOURCE_FILES:.c=.o))

ARCHIVE_FILE=$(ARCHIVE_DIR)/lib$(MODULE_NAME)-$(MODULE_VERSION)-$(OS_TYPE)-$(OS_ARCH).tar.gz
SHARED_LIBRARY_FILE=$(LIBRARY_DIR)/lib$(MODULE_NAME)-$(MODULE_VERSION).so
STATIC_LIBRARY_FILE=$(LIBRARY_DIR)/lib$(MODULE_NAME)-$(MODULE_VERSION).a
TEST_FILE=$(BINARY_DIR)/lib$(MODULE_NAME)-test

ifeq ($(OS_TYPE),darwin)
	CFLAGS+=-DDARWIN
endif

CFLAGS+=-fPIC -g -std=c99 -Wall $(addprefix -I,$(MAIN_INCLUDE_DIRS))
COMPILE.c=$(CC) -c $(CFLAGS)

LDFLAGS+=-shared -lc
LINK.c=$(CC) $(LDFLAGS)

.PHONY=\
  clean \
  all \
  host \
  archive \
  test \
  shared \
  static \
  headers \
  -mkdir- \
  android \
  ios \
  osx \
  osx-test \
  help \
  show

NDK_BUILD ?= $(shell which ndk-build)
NDK_DIR ?= $(if $(NDK_BUILD),$(shell dirname $(NDK_BUILD),))
ifeq ($(NDK_DIR),)
        NDK_DIR = $(ANDROID_NDK_HOME)
endif

ifneq ($(NDK_DIR),)
	NDK_BUILD := $(NDK_DIR)/ndk-build
endif

all: headers host android osx ios

host: shared static test archive

archive: $(ARCHIVE_FILE)

shared: $(SHARED_LIBRARY_FILE)

static: $(STATIC_LIBRARY_FILE)

clean:
	rm -fR $(BUILD_DIR)

TEST_CFLAGS := $(CFLAGS)

ifeq ($(OS_TYPE),linux)
TEST_CFLAGS+=-DOPTEST_LINUX_SPECIFIC
TEST_PLATFORM_LIBS := -lpthread
endif

ifeq ($(OS_TYPE),darwin)
TEST_CFLAGS+=-DOPTEST_OSX_SPECIFIC
endif

test: $(TEST_FILE)
ifeq ($(IGNORE_TESTS),)
	$(TEST_FILE)
endif

android: $(ANDROID_DIR)/jni

ifeq ($(NDK_DIR),)
	@printf "Path to your Android NDK not found.\n"
	@printf "Either add the Android NDK to your PATH, or specify the NDK_DIR environment variable.\n"
	exit 1
endif

	$(NDK_BUILD) -C $(ANDROID_DIR)

ANDROID_LIB_DIR = ../../android/silent-text-android/libs
android-deploy:	android
	for arch in armeabi armeabi-v7a mips x86; do \
		cp build/android/libs/$${arch}/libc4.so $(ANDROID_LIB_DIR)/$${arch}/ ; \
		cp build/android/libs/$${arch}/libc4-jni.so $(ANDROID_LIB_DIR)/$${arch}/ ; \
	done

ios:

ifeq ($(OS_TYPE),darwin)
	xcodebuild -target "C4-ios static" -project c4.xcodeproj
endif

osx:

ifeq ($(OS_TYPE),darwin)
	xcodebuild -target C4-osx -project c4.xcodeproj
endif

osx-test: osx

ifeq ($(OS_TYPE),darwin)
	xcodebuild test -scheme C4-osx -project c4.xcodeproj
endif

optest: osx

ifeq ($(OS_TYPE),darwin)
	xcodebuild -target C4-optest-osx  -project c4.xcodeproj
	DYLD_FRAMEWORK_PATH=./build/osx/Release/ ./build/osx/Release/c4-optest-osx 
endif

run-optest: osx

ifeq ($(OS_TYPE),darwin)
	xcodebuild -target C4-optest-osx  -project c4.xcodeproj
	DYLD_FRAMEWORK_PATH=./build/osx/Release/ ./build/osx/Release/c4-optest-osx 
endif

help:
	@printf '+---------------------------------------------------------------+\n'
	@printf '| TARGETS                                                       |\n'
	@printf '+---------------------------------------------------------------+\n'
	@printf '|                                                               |\n'
	@printf '| clean: Cleans output from previous builds.                    |\n'
	@printf '|                                                               |\n'
	@printf '| host: Compiles for the host architecture.                     |\n'
	@printf '|                                                               |\n'
	@printf '| android: Cross-compiles for Android architectures.            |\n'
	@printf '|                                                               |\n'
	@printf '| ios: Cross-compiles for iOS using Xcode.                      |\n'
	@printf '|                                                               |\n'
	@printf '| osx: Cross-compiles for Mac OS X using Xcode.                 |\n'
	@printf '|                                                               |\n'
	@printf '| osx-test: Runs tests for Mac OS X using Xcode.                |\n'
	@printf '|                                                               |\n'
	@printf '| archive: Produces a tarball archive for distribution.         |\n'
	@printf '|                                                               |\n'
	@printf '| headers: Exports header files.                                |\n'
	@printf '|                                                               |\n'
	@printf '| shared: Compiles a shared library.                            |\n'
	@printf '|                                                               |\n'
	@printf '| static: Compiles a static library.                            |\n'
	@printf '|                                                               |\n'
	@printf '| test: Compiles and runs tests.                                |\n'
	@printf '|                                                               |\n'
	@printf '| help: Display this help message.                              |\n'
	@printf '|                                                               |\n'
	@printf '| all: Compiles for all known architectures.                    |\n'
	@printf '|                                                               |\n'
	@printf '| show: Show the values of important Makefile variables.        |\n'
	@printf '|                                                               |\n'
	@printf '+---------------------------------------------------------------+\n'

show:
	@printf "NDK_DIR = '$(NDK_DIR)'\n"
	@printf "NDK_BUILD = '$(NDK_BUILD)'\n"
	@printf "BUILD_DIR = '$(BUILD_DIR)'\n"
	@printf "BINARY_DIR = '$(BINARY_DIR)'\n"
	@printf "OBJECTS_DIR = '$(OBJECTS_DIR)'\n"
	@printf "ANDROID_DIR = '$(ANDROID_DIR)'\n"
	@printf "ARCHIVE_DIR = '$(ARCHIVE_DIR)'\n"
	@printf "LIBRARY_DIR = '$(LIBRARY_DIR)'\n"
	@printf "EXPORT_HEADERS_DIR = '$(EXPORT_HEADERS_DIR)'\n"
	@printf "MAIN_INCLUDE_DIRS = '$(MAIN_INCLUDE_DIRS)'\n"
	@printf "MAIN_INCLUDE_FILES = '$(MAIN_INCLUDE_FILES)'\n"
	@printf "MAIN_OBJECT_FILES = '$(MAIN_OBJECT_FILES)'\n"

headers: | $(EXPORT_HEADERS_DIR)
	cp -fR $(SOURCE_DIR)/../libs/yajl/src/api/yajl_common.h $(EXPORT_HEADERS_DIR)/yajl/
	cp -fR $(SOURCE_DIR)/../libs/yajl/build/yajl-2.1.1/include/yajl/yajl_version.h $(EXPORT_HEADERS_DIR)/yajl/
	cp -fR $(MAIN_INCLUDE_FILES) $(EXPORT_HEADERS_DIR)
	chmod -x $(addsuffix /*.h,$(EXPORT_HEADERS_DIR))

$(ANDROID_DIR)/jni: | $(ANDROID_DIR)
	rm -f $(ANDROID_DIR)/jni
	ln -s $(MAIN_SOURCE_DIR) $(ANDROID_DIR)/jni

$(STATIC_LIBRARY_FILE): $(MAIN_OBJECT_FILES) | $(LIBRARY_DIR)
	ar cr $(STATIC_LIBRARY_FILE) $(MAIN_OBJECT_FILES)
	ranlib $(STATIC_LIBRARY_FILE)

$(SHARED_LIBRARY_FILE): $(MAIN_OBJECT_FILES) | $(LIBRARY_DIR)
	$(LINK.c) -o $(SHARED_LIBRARY_FILE) $(MAIN_OBJECT_FILES)

$(EXPORT_HEADERS_DIR):
	$(MAIN_SOURCE_DIR)/scripts/fetch_git_commit_hash.sh
	mkdir -p $(EXPORT_HEADERS_DIR)
	mkdir -p $(EXPORT_HEADERS_DIR)/yajl/

$(ARCHIVE_FILE): shared static headers | $(ARCHIVE_DIR)
	cd $(BUILD_DIR) && tar -c -z -f $(ARCHIVE_FILE) $(REL_EXPORT_HEADERS_DIR) $(REL_LIBRARY_DIR)

vpath %.c $(MAIN_SOURCE_DIR)

$(OBJECTS_DIR)/%.o: %.c
	mkdir -p $(dir $@)
	$(COMPILE.c) -o $@ $^

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(ANDROID_DIR):
	mkdir -p $(ANDROID_DIR)

$(LIBRARY_DIR):
	mkdir -p $(LIBRARY_DIR)

$(ARCHIVE_DIR):
	mkdir -p $(ARCHIVE_DIR)

$(BINARY_DIR):
	mkdir -p $(BINARY_DIR)

$(TEST_FILE): headers static | $(BINARY_DIR)
	$(CC) $(TEST_CFLAGS) -o $(TEST_FILE) -I$(EXPORT_HEADERS_DIR) -I$(TEST_SOURCE_DIR) $(TEST_SOURCE_FILES) $(STATIC_LIBRARY_FILE) $(TEST_PLATFORM_LIBS)
