
LOCAL_DIR := $(shell pwd)

MODULE_NAME    := s4
MODULE_VERSION := 2.2.0
MODULE_BRANCH  := develop

CC = clang
 
EMCC = $(EMSDK)/emscripten/1.38.12/emcc
EMRUN = $(EMSDK)/emscripten/1.38.12/emrun

EMCC_FLAGS = -O2 -s ALLOW_MEMORY_GROWTH=1

BUILD_DIR =  obj
TARGETDIR =  build
S4_BUILD_DIR =  $(BUILD_DIR)/s4
S4_TARGET = $(TARGETDIR)/libs4.a
S4_SHARED_TARGET = $(TARGETDIR)/libs4.dylib


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
  
S4_INCLUDES = \
	src/main/S4/S4Crypto.h \
	src/main/S4/s4pubtypes.h \
	src/main/S4/s4rng.h \
	src/main/S4/s4hash.h \
	src/main/S4/s4mac.h \
	src/main/S4/s4cipher.h \
	src/main/S4/s4p2k.h \
	src/main/S4/s4tbc.h \
	src/main/S4/s4ecc.h \
	src/main/S4/s4share.h \
	src/main/S4/s4keys.h \
	src/main/S4/s4utilities.h	\
	src/main/S4/s4keysinternal.h  


CFLAGS= -I. \
	-Wnon-modular-include-in-framework-module\
	-Werror=non-modular-include-in-framework-module\
	-Wno-trigraphs -fpascal-strings -O0 -fno-common\
	-Wno-missing-field-initializers\
	-Wno-missing-prototypes\
	-Werror=return-type\
	-Wunreachable-code\
	-Werror=deprecated-objc-isa-usage\
	-Werror=objc-root-class\
	-Wno-missing-braces\
	-Wparentheses\
	-Wswitch\
	-Wunused-function\
	-Wno-unused-label\
	-Wno-unused-parameter\
	-Wunused-variable\
	-Wunused-value\
	-Wempty-body\
	-Wuninitialized\
	-Wconditional-uninitialized\
	-Wno-unknown-pragmas\
	-Wno-shadow\
	-Wno-four-char-constants\
	-Wno-conversion\
	-Wconstant-conversion\
	-Wint-conversion\
	-Wbool-conversion\
	-Wenum-conversion\
	-Wno-float-conversion\
	-Wnon-literal-null-conversion\
	-Wobjc-literal-conversion\
	-Wshorten-64-to-32\
	-Wpointer-sign\
	-Wno-newline-eof

S4_FLAGS = $(CFLAGS) \
	-Isrc/main/scripts \
	-Isrc/main/S4 \
	-Ilibs/tomcrypt/headers \
	-Ilibs/tommath  \
	-Ilibs/tomcrypt/hashes/skein \
	-Ilibs/xxHash \
	-Ilibs/argon2 \
	-Ilibs/sha3 \
	-Ilibs/yajl/src \
	-Ilibs/yajl/src/api \
	-Ilibs/jsmn \
	-I$(BUILD_DIR)/includes  

TOMCRYPT_SRC = \
	libs/tomcrypt/ciphers/aes/aes.c \
	libs/tomcrypt/ciphers/twofish/twofish.c \
	libs/tomcrypt/hashes/helper/hash_memory.c \
	libs/tomcrypt/hashes/md5.c \
	libs/tomcrypt/hashes/sha1.c \
	libs/tomcrypt/hashes/sha2/sha256.c \
	libs/tomcrypt/hashes/sha2/sha512.c \
	libs/tomcrypt/hashes/skein/skein.c \
	libs/tomcrypt/hashes/skein/threefish512Block.c \
	libs/tomcrypt/hashes/skein/skeinApi.c \
	libs/tomcrypt/hashes/skein/threefish1024Block.c \
	libs/tomcrypt/hashes/skein/threefishApi.c \
	libs/tomcrypt/hashes/skein/skein_block.c \
	libs/tomcrypt/hashes/skein/threefish256Block.c \
	libs/tomcrypt/hashes/skein/threefish_tc.c \
	libs/tomcrypt/hashes/skein/skein_tc.c \
	libs/tomcrypt/mac/hmac/hmac_done.c \
	libs/tomcrypt/mac/hmac/hmac_file.c \
	libs/tomcrypt/mac/hmac/hmac_init.c \
	libs/tomcrypt/mac/hmac/hmac_memory_multi.c \
	libs/tomcrypt/mac/hmac/hmac_memory.c \
	libs/tomcrypt/mac/hmac/hmac_process.c \
	libs/tomcrypt/math/ltm_desc.c \
	libs/tomcrypt/math/multi.c \
	libs/tomcrypt/misc/base64/base64_decode.c \
	libs/tomcrypt/misc/base64/base64_encode.c \
	libs/tomcrypt/misc/burn_stack.c \
	libs/tomcrypt/misc/crypt/crypt_argchk.c \
	libs/tomcrypt/misc/crypt/crypt_argchk.c \
	libs/tomcrypt/misc/crypt/crypt_cipher_descriptor.c \
	libs/tomcrypt/misc/crypt/crypt_cipher_is_valid.c \
	libs/tomcrypt/misc/crypt/crypt_find_cipher_any.c \
	libs/tomcrypt/misc/crypt/crypt_find_cipher_id.c \
	libs/tomcrypt/misc/crypt/crypt_find_cipher.c \
	libs/tomcrypt/misc/crypt/crypt_find_hash_any.c \
	libs/tomcrypt/misc/crypt/crypt_find_hash_id.c \
	libs/tomcrypt/misc/crypt/crypt_find_hash_oid.c \
	libs/tomcrypt/misc/crypt/crypt_find_hash.c \
	libs/tomcrypt/misc/crypt/crypt_find_prng.c \
	libs/tomcrypt/misc/crypt/crypt_hash_descriptor.c \
	libs/tomcrypt/misc/crypt/crypt_hash_is_valid.c \
	libs/tomcrypt/misc/crypt/crypt_ltc_mp_descriptor.c \
	libs/tomcrypt/misc/crypt/crypt_prng_descriptor.c \
	libs/tomcrypt/misc/crypt/crypt_prng_is_valid.c \
	libs/tomcrypt/misc/crypt/crypt_register_cipher.c \
	libs/tomcrypt/misc/crypt/crypt_register_hash.c \
	libs/tomcrypt/misc/crypt/crypt_register_hash.c \
	libs/tomcrypt/misc/crypt/crypt_register_prng.c \
	libs/tomcrypt/misc/pkcs5/pkcs_5_2.c \
	libs/tomcrypt/misc/zeromem.c \
	libs/tomcrypt/misc/pk_get_oid.c \
	libs/tomcrypt/modes/cbc/cbc_decrypt.c \
	libs/tomcrypt/modes/cbc/cbc_done.c \
	libs/tomcrypt/modes/cbc/cbc_encrypt.c \
	libs/tomcrypt/modes/cbc/cbc_getiv.c \
	libs/tomcrypt/modes/cbc/cbc_setiv.c \
	libs/tomcrypt/modes/cbc/cbc_start.c \
	libs/tomcrypt/modes/ecb/ecb_decrypt.c \
	libs/tomcrypt/modes/ecb/ecb_done.c \
	libs/tomcrypt/modes/ecb/ecb_encrypt.c \
	libs/tomcrypt/modes/ecb/ecb_start.c \
	libs/tomcrypt/pk/asn1/der/bit/der_decode_bit_string.c \
	libs/tomcrypt/pk/asn1/der/bit/der_decode_raw_bit_string.c \
	libs/tomcrypt/pk/asn1/der/bit/der_encode_bit_string.c \
	libs/tomcrypt/pk/asn1/der/bit/der_encode_raw_bit_string.c \
	libs/tomcrypt/pk/asn1/der/bit/der_length_bit_string.c \
	libs/tomcrypt/pk/asn1/der/boolean/der_decode_boolean.c \
	libs/tomcrypt/pk/asn1/der/boolean/der_encode_boolean.c \
	libs/tomcrypt/pk/asn1/der/boolean/der_length_boolean.c \
	libs/tomcrypt/pk/asn1/der/choice/der_decode_choice.c \
	libs/tomcrypt/pk/asn1/der/ia5/der_decode_ia5_string.c \
	libs/tomcrypt/pk/asn1/der/ia5/der_encode_ia5_string.c \
	libs/tomcrypt/pk/asn1/der/ia5/der_length_ia5_string.c \
	libs/tomcrypt/pk/asn1/der/integer/der_decode_integer.c \
	libs/tomcrypt/pk/asn1/der/integer/der_encode_integer.c \
	libs/tomcrypt/pk/asn1/der/integer/der_length_integer.c \
	libs/tomcrypt/pk/asn1/der/object_identifier/der_decode_object_identifier.c \
	libs/tomcrypt/pk/asn1/der/object_identifier/der_encode_object_identifier.c \
	libs/tomcrypt/pk/asn1/der/object_identifier/der_length_object_identifier.c \
	libs/tomcrypt/pk/asn1/der/octet/der_decode_octet_string.c \
	libs/tomcrypt/pk/asn1/der/octet/der_encode_octet_string.c \
	libs/tomcrypt/pk/asn1/der/octet/der_length_octet_string.c \
	libs/tomcrypt/pk/asn1/der/printable_string/der_decode_printable_string.c \
	libs/tomcrypt/pk/asn1/der/printable_string/der_encode_printable_string.c \
	libs/tomcrypt/pk/asn1/der/printable_string/der_length_printable_string.c \
	libs/tomcrypt/pk/asn1/der/sequence/der_decode_sequence_ex.c \
	libs/tomcrypt/pk/asn1/der/sequence/der_decode_sequence_flexi.c \
	libs/tomcrypt/pk/asn1/der/sequence/der_decode_sequence_multi.c \
	libs/tomcrypt/pk/asn1/der/sequence/der_encode_sequence_ex.c \
	libs/tomcrypt/pk/asn1/der/sequence/der_encode_sequence_multi.c \
	libs/tomcrypt/pk/asn1/der/sequence/der_encode_subject_public_key_info.c \
	libs/tomcrypt/pk/asn1/der/sequence/der_length_sequence.c \
	libs/tomcrypt/pk/asn1/der/sequence/der_sequence_free.c \
	libs/tomcrypt/pk/asn1/der/set/der_encode_set.c \
	libs/tomcrypt/pk/asn1/der/set/der_encode_setof.c \
	libs/tomcrypt/pk/asn1/der/short_integer/der_decode_short_integer.c \
	libs/tomcrypt/pk/asn1/der/short_integer/der_encode_short_integer.c \
	libs/tomcrypt/pk/asn1/der/short_integer/der_length_short_integer.c \
	libs/tomcrypt/pk/asn1/der/utctime/der_decode_utctime.c \
	libs/tomcrypt/pk/asn1/der/utctime/der_encode_utctime.c \
	libs/tomcrypt/pk/asn1/der/utctime/der_length_utctime.c \
	libs/tomcrypt/pk/asn1/der/utf8/der_decode_utf8_string.c \
	libs/tomcrypt/pk/asn1/der/utf8/der_encode_utf8_string.c \
	libs/tomcrypt/pk/asn1/der/utf8/der_length_utf8_string.c \
	libs/tomcrypt/pk/ecc_bl/ecc_bl_ansi_x963_import.c \
	libs/tomcrypt/pk/ecc_bl/ecc_bl_decrypt_key.c \
	libs/tomcrypt/pk/ecc_bl/ecc_bl_encrypt_key.c \
	libs/tomcrypt/pk/ecc_bl/ecc_bl_import.c \
	libs/tomcrypt/pk/ecc_bl/ecc_bl_make_key.c \
	libs/tomcrypt/pk/ecc_bl/ecc_bl_sign_hash.c \
	libs/tomcrypt/pk/ecc_bl/ecc_bl_verify_hash.c \
	libs/tomcrypt/pk/ecc_bl/ecc_bl.c \
	libs/tomcrypt/pk/ecc/ecc_ansi_x963_export.c \
	libs/tomcrypt/pk/ecc/ecc_ansi_x963_import.c \
	libs/tomcrypt/pk/ecc/ecc_decrypt_key.c \
	libs/tomcrypt/pk/ecc/ecc_encrypt_key.c \
	libs/tomcrypt/pk/ecc/ecc_export.c \
	libs/tomcrypt/pk/ecc/ecc_free.c \
	libs/tomcrypt/pk/ecc/ecc_get_size.c \
	libs/tomcrypt/pk/ecc/ecc_import.c \
	libs/tomcrypt/pk/ecc/ecc_make_key.c \
	libs/tomcrypt/pk/ecc/ecc_shared_secret.c \
	libs/tomcrypt/pk/ecc/ecc_sign_hash.c \
	libs/tomcrypt/pk/ecc/ecc_sizes.c \
	libs/tomcrypt/pk/ecc/ecc_test.c \
	libs/tomcrypt/pk/ecc/ecc_verify_hash.c \
	libs/tomcrypt/pk/ecc/ecc.c \
	libs/tomcrypt/pk/ecc/ltc_ecc_is_valid_idx.c \
	libs/tomcrypt/pk/ecc/ltc_ecc_map.c \
	libs/tomcrypt/pk/ecc/ltc_ecc_mulmod.c \
	libs/tomcrypt/pk/ecc/ltc_ecc_points.c \
	libs/tomcrypt/pk/ecc/ltc_ecc_projective_add_point.c \
	libs/tomcrypt/pk/ecc/ltc_ecc_projective_dbl_point.c \
	libs/tomcrypt/prngs/rng_get_bytes.c \
	libs/tomcrypt/prngs/sprng.c 

TOMMATH_SRC = \
	libs/tommath/bn_mp_and.c \
	libs/tommath/bn_mp_signed_bin_size.c \
	libs/tommath/bn_mp_exteuclid.c \
	libs/tommath/bncore.c \
	libs/tommath/bn_fast_s_mp_sqr.c \
	libs/tommath/bn_mp_rshd.c \
	libs/tommath/bn_mp_read_unsigned_bin.c \
	libs/tommath/bn_fast_mp_invmod.c \
	libs/tommath/bn_mp_prime_is_prime.c \
	libs/tommath/bn_mp_radix_smap.c \
	libs/tommath/bn_mp_div_2d.c \
	libs/tommath/bn_s_mp_sqr.c \
	libs/tommath/bn_mp_mod.c \
	libs/tommath/bn_mp_n_root.c \
	libs/tommath/bn_mp_cmp_d.c \
	libs/tommath/bn_mp_clear.c \
	libs/tommath/bn_mp_div_2.c \
	libs/tommath/bn_mp_sub.c \
	libs/tommath/bn_mp_copy.c \
	libs/tommath/bn_mp_to_unsigned_bin.c \
	libs/tommath/bn_mp_read_radix.c \
	libs/tommath/bn_mp_prime_fermat.c \
	libs/tommath/bn_mp_mod_d.c \
	libs/tommath/bn_mp_lcm.c \
	libs/tommath/bn_mp_cnt_lsb.c \
	libs/tommath/bn_error.c \
	libs/tommath/bn_mp_abs.c \
	libs/tommath/bn_mp_reduce.c \
	libs/tommath/bn_s_mp_mul_digs.c \
	libs/tommath/bn_mp_montgomery_setup.c \
	libs/tommath/bn_mp_reduce_2k_setup.c \
	libs/tommath/bn_mp_mul_d.c \
	libs/tommath/bn_mp_shrink.c \
	libs/tommath/bn_mp_clear_multi.c \
	libs/tommath/bn_prime_tab.c \
	libs/tommath/bn_mp_cmp.c \
	libs/tommath/bn_mp_sqrmod.c \
	libs/tommath/bn_mp_reduce_2k_setup_l.c \
	libs/tommath/bn_mp_neg.c \
	libs/tommath/bn_mp_addmod.c \
	libs/tommath/bn_mp_init.c \
	libs/tommath/bn_mp_prime_miller_rabin.c \
	libs/tommath/bn_mp_invmod.c \
	libs/tommath/bn_s_mp_sub.c \
	libs/tommath/bn_mp_exch.c \
	libs/tommath/bn_mp_sqrt.c \
	libs/tommath/bn_mp_toradix.c \
	libs/tommath/bn_mp_init_set_int.c \
	libs/tommath/bn_mp_init_multi.c \
	libs/tommath/bn_mp_mulmod.c \
	libs/tommath/bn_mp_add.c \
	libs/tommath/bn_mp_karatsuba_mul.c \
	libs/tommath/bn_mp_expt_d.c \
	libs/tommath/bn_mp_read_signed_bin.c \
	libs/tommath/bn_mp_reduce_is_2k_l.c \
	libs/tommath/bn_mp_submod.c \
	libs/tommath/bn_mp_init_set.c \
	libs/tommath/bn_mp_exptmod.c \
	libs/tommath/bn_mp_grow.c \
	libs/tommath/bn_mp_prime_rabin_miller_trials.c \
	libs/tommath/bn_mp_sqr.c \
	libs/tommath/bn_reverse.c \
	libs/tommath/bn_mp_dr_is_modulus.c \
	libs/tommath/bn_mp_sub_d.c \
	libs/tommath/bn_mp_count_bits.c \
	libs/tommath/bn_s_mp_exptmod.c \
	libs/tommath/bn_mp_montgomery_calc_normalization.c \
	libs/tommath/bn_mp_get_int.c \
	libs/tommath/bn_mp_unsigned_bin_size.c \
	libs/tommath/bn_mp_mul_2d.c \
	libs/tommath/bn_fast_s_mp_mul_digs.c \
	libs/tommath/bn_mp_lshd.c \
	libs/tommath/bn_mp_to_unsigned_bin_n.c \
	libs/tommath/bn_fast_mp_montgomery_reduce.c \
	libs/tommath/bn_mp_reduce_2k.c \
	libs/tommath/bn_mp_toom_sqr.c \
	libs/tommath/bn_mp_mul_2.c \
	libs/tommath/bn_mp_2expt.c \
	libs/tommath/bn_mp_dr_setup.c \
	libs/tommath/bn_mp_clamp.c \
	libs/tommath/bn_mp_karatsuba_sqr.c \
	libs/tommath/bn_mp_exptmod_fast.c \
	libs/tommath/bn_mp_jacobi.c \
	libs/tommath/bn_mp_fread.c \
	libs/tommath/bn_mp_toradix_n.c \
	libs/tommath/bn_mp_zero.c \
	libs/tommath/bn_mp_mul.c \
	libs/tommath/bn_mp_prime_next_prime.c \
	libs/tommath/bn_s_mp_mul_high_digs.c \
	libs/tommath/bn_mp_div_d.c \
	libs/tommath/bn_mp_radix_size.c \
	libs/tommath/bn_mp_gcd.c \
	libs/tommath/bn_mp_invmod_slow.c \
	libs/tommath/bn_mp_is_square.c \
	libs/tommath/bn_mp_set.c \
	libs/tommath/bn_mp_to_signed_bin_n.c \
	libs/tommath/bn_mp_div.c \
	libs/tommath/bn_mp_prime_is_divisible.c \
	libs/tommath/bn_mp_reduce_is_2k.c \
	libs/tommath/bn_mp_init_copy.c \
	libs/tommath/bn_fast_s_mp_mul_high_digs.c \
	libs/tommath/bn_mp_fwrite.c \
	libs/tommath/bn_mp_set_int.c \
	libs/tommath/bn_mp_cmp_mag.c \
	libs/tommath/bn_mp_rand.c \
	libs/tommath/bn_mp_reduce_2k_l.c \
	libs/tommath/bn_mp_or.c \
	libs/tommath/bn_mp_prime_random_ex.c \
	libs/tommath/bn_mp_div_3.c \
	libs/tommath/bn_mp_to_signed_bin.c \
	libs/tommath/bn_s_mp_add.c \
	libs/tommath/bn_mp_dr_reduce.c \
	libs/tommath/bn_mp_xor.c \
	libs/tommath/bn_mp_reduce_setup.c \
	libs/tommath/bn_mp_add_d.c \
	libs/tommath/bn_mp_montgomery_reduce.c \
	libs/tommath/bn_mp_mod_2d.c \
	libs/tommath/bn_mp_toom_mul.c \
	libs/tommath/bn_mp_init_size.c 
	
ARGON2_SRCS = \
	libs/argon2/argon2.c \
	libs/argon2/core.c \
	libs/argon2/ref.c \
	libs/argon2/blake2b.c \
	libs/argon2/encoding.c \
	libs/argon2/thread.c  

SHA3_SRCS = \
	libs/sha3/KeccakHash.c \
	libs/sha3/KeccakSpongeWidth1600.c\
	libs/sha3/KeccakP-1600-reference.c \
	libs/sha3/SimpleFIPS202.c  

S4_SRCS = \
	src/main/S4/s4.c \
	src/main/S4/s4hash.c \
	src/main/S4/s4pbkdf2.c \
	src/main/S4/s4bufferutilities.c \
	src/main/S4/s4hashword.c \
	src/main/S4/s4share.c \
	src/main/S4/s4cipher.c \
	src/main/S4/s4tbc.c \
	src/main/S4/s4ecc.c \
	src/main/S4/s4mac.c\
	src/main/S4/zbase32.c \
	src/main/S4/s4keys.c  \
	src/main/S4/s4P2K.c \
	libs/xxHash/xxhash.c \
	libs/jsmn/jsmn.c \
	libs/yajl/src/yajl.c \
	libs/yajl/src/yajl_alloc.c \
	libs/yajl/src/yajl_buf.c \
	libs/yajl/src/yajl_encode.c \
	libs/yajl/src/yajl_gen.c \
	libs/yajl/src/yajl_lex.c \
	libs/yajl/src/yajl_parser.c \
	libs/yajl/src/yajl_tree.c \
	${TOMCRYPT_SRC} ${TOMMATH_SRC} ${ARGON2_SRCS} ${SHA3_SRCS}

#################################################################
#  S4 
#################################################################

S4_OBJS = $(S4_SRCS:%.c=$(S4_BUILD_DIR)/%.o)
 
$(S4_BUILD_DIR)/%.o: %.c  | init 
	$(CC) -o $(addprefix $(S4_BUILD_DIR)/, $(notdir $(@))) -c $(S4_FLAGS) \
	-mmacosx-version-min=10.10 \
	$<

$(S4_TARGET):  $(S4_OBJS) init
	libtool -static   $(S4_BUILD_DIR)/*.o -o $(S4_TARGET)  

$(S4_SHARED_TARGET):  $(S4_TARGET) init
	libtool -dynamic $(S4_TARGET) -lSystem -o $(S4_SHARED_TARGET)  

s4: $(S4_TARGET) $(S4_SHARED_TARGET)

#################################################################
#  OPTEST 
#################################################################

#OPTEST_BUILD_DIR  =  $(BUILD_DIR)/optest
#OPTEST_TARGET = $(TARGETDIR)/optest

OPTEST_SRCS = \
	src/optest/testECC.c \
	src/optest/testSecretSharing.c \
	src/optest/optest.c \
	src/optest/testHMAC.c \
	src/optest/testTBC.c \
	src/optest/testHash.c \
	src/optest/testUtilties.c \
	src/optest/optestutilities.c \
	src/optest/testKeys.c \
	src/optest/testCiphers.c \
	src/optest/testP2K.c 

#OPTEST_OBJS = $(OPTEST_SRCS:%.c=$(OPTEST_BUILD_DIR)/%.o)

#$(OPTEST_BUILD_DIR)/%.o: %.c  | init 
#	$(CC) -o $(addprefix $(OPTEST_BUILD_DIR)/, $(notdir $(@))) -c $(CFLAGS) \
#		-mmacosx-version-min=10.10 \
#		-I$(TARGETDIR) $<

#$(OPTEST_TARGET): $(OPTEST_OBJS)  init 
#	clang $(OPTEST_BUILD_DIR)/*.o -L$(TARGETDIR) $(TARGETDIR)/libs4.dylib \
#	-isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk \
#	-o $(OPTEST_TARGET) 

#optest: $(OPTEST_TARGET)

#run_optest : optest
#	DYLD_LIBRARY_PATH=$(TARGETDIR) $(OPTEST_TARGET)

#################################################################
#  CAVP 
#################################################################

CAVP_BUILD_DIR =  $(BUILD_DIR)/cavp
CAVP_TARGET = $(TARGETDIR)/cavp

CAVP_SRCS = \
	src/cavp/cavp.c  \
	src/cavp/cavpHashTest.c \
	src/cavp/cavpCipherTest.c \
	src/cavp/cavpHMACtest.c \
	src/cavp/cavputilities.c 
 
#CAVP_OBJS = $(CAVP_SRCS:%.c=$(CAVP_BUILD_DIR)/%.o)

#$(CAVP_BUILD_DIR)/%.o: %.c  | init 
#	$(CC) -o $(addprefix $(CAVP_BUILD_DIR)/, $(notdir $(@))) -c $(CFLAGS)  \
#		-mmacosx-version-min=10.10 \
#		-I$(TARGETDIR) $<

#$(CAVP_TARGET): $(CAVP_OBJS) init 
#	clang $(CAVP_BUILD_DIR)/*.o -L$(TARGETDIR) $(TARGETDIR)/libs4.dylib \
#	-isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk \
#	-o $(CAVP_TARGET) 

#cavp: $(CAVP_TARGET)

#run_cavp : cavp
#	DYLD_LIBRARY_PATH=$(TARGETDIR) $(CAVP_TARGET)  $(TARGETDIR)/KAT

#################################################################
#  minittest 
#################################################################

MINITEST_BUILD_DIR =  $(BUILD_DIR)/minitest
MINITEST_TARGET = $(TARGETDIR)/minitest

MINITEST_SRCS = \
	minitest/minitest.c  \
	${TOMCRYPT_SRC} ${TOMMATH_SRC} 

MINITEST_FLAGS = $(CFLAGS) \
	-Ilibs/tomcrypt/headers \
	-Ilibs/tommath  \
	-Ilibs/tomcrypt/hashes/skein \
	-Ilibs/xxHash \
	-Ilibs/argon2 \
	-Ilibs/sha3 \
	-Ilibs/jsmn \
	-Ilibs/common \
	-I$(BUILD_DIR)/includes  
  
MINITEST_OBJS = $(MINITEST_SRCS:%.c=$(MINITEST_BUILD_DIR)/%.o)

$(MINITEST_BUILD_DIR)/%.o: %.c  | init 
	$(CC) -o $(addprefix $(MINITEST_BUILD_DIR)/, $(notdir $(@))) -c $(MINITEST_FLAGS) \
		-mmacosx-version-min=10.10 \
		 -I$(TARGETDIR) $<

$(MINITEST_TARGET): $(MINITEST_OBJS) init 
	clang $(MINITEST_BUILD_DIR)/*.o -L$(TARGETDIR)   \
	-isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk \
	-o $(MINITEST_TARGET) 

minitest: $(MINITEST_TARGET)

run_minitest: minitest
	$(MINITEST_TARGET)

#################################################################
#  libS4.bc 
#################################################################
EM_S4_BUILD_DIR =  $(BUILD_DIR)/em_s4
EM_S4_TARGET = $(TARGETDIR)/libS4.bc

EM_S4_SRCS = \
	${S4_SRCS} 

EM_S4_FLAGS = $(CFLAGS) \
	-Ilibs/tomcrypt/headers \
	-Ilibs/tommath  \
	-Ilibs/tomcrypt/hashes/skein \
	-Ilibs/xxHash \
	-Ilibs/argon2 \
	-Ilibs/sha3 \
	-Ilibs/yajl/src \
	-Ilibs/yajl/src/api \
	-Ilibs/jsmn \
	-Ilibs/common \
	-I$(BUILD_DIR)/includes  
	
EM_S4_OBJS = $(EM_S4_SRCS:%.c=$(EM_S4_BUILD_DIR)/%.bc)


$(EM_S4_BUILD_DIR)/%.bc: %.c  | init 
	$(EMCC) $(EMCC_FLAGS) -o $(addprefix $(EM_S4_BUILD_DIR)/, $(notdir $(@))) -c $(EM_S4_FLAGS) -I$(TARGETDIR) $<

$(EM_S4_TARGET): $(EM_S4_OBJS) init 
	$(EMCC) $(EMCC_FLAGS)  $(EM_S4_BUILD_DIR)/*.bc  -o $(EM_S4_TARGET)
	$(EMCC) $(EMCC_FLAGS) -s 'EXPORT_NAME=ModuleS4' -s 'EXTRA_EXPORTED_RUNTIME_METHODS=["HEAPU8", "_malloc", "free", "_free", "ccall", "setValue", "getValue", "UTF8ToString"]' $(EM_S4_TARGET)  -o $(TARGETDIR)/libS4.js

ifndef EMSDK
em_s4:
	@printf '\temscripten SDK is not defined\n'
	@printf '\tinstall the emsdk\n'
	@printf '\thttps://kripken.github.io/emscripten-site/docs/getting_started/downloads.html\n'
	@printf '\tsetup the var EMCC \n \texport EMSDK="/Users/vinnie/Desktop/emsdk"  \n\n'
else
em_s4: $(EM_S4_TARGET)
endif

#################################################################
#  em_optest 
#################################################################


EM_OPTEST_BUILD_DIR  =  $(BUILD_DIR)/em_optest
EM_OPTEST_TARGET = $(TARGETDIR)/optest.html

EM_OPTEST_OBJS = $(OPTEST_SRCS:%.c=$(EM_OPTEST_BUILD_DIR)/%.bc)

$(EM_OPTEST_BUILD_DIR)/%.bc: %.c  | init 
	$(EMCC) $(EMCC_FLAGS) -o $(addprefix $(EM_OPTEST_BUILD_DIR)/, $(notdir $(@))) -c -I$(TARGETDIR) $<

$(EM_OPTEST_TARGET): $(EM_OPTEST_OBJS) $(EM_S4_TARGET) init 
	$(EMCC) $(EMCC_FLAGS) -s WASM=1  $(EM_OPTEST_BUILD_DIR)/*.bc -L$(TARGETDIR) $(TARGETDIR)/libS4.bc \
 	-o $(EM_OPTEST_TARGET) 
	
em_optest: $(EM_OPTEST_TARGET) 

run_em_optest:
	$(EMRUN) $(EM_OPTEST_TARGET)



#################################################################
#  minittest  emsdk
#################################################################

EM_MINITEST_BUILD_DIR =  $(BUILD_DIR)/em_test
EM_MINITEST_TARGET = $(TARGETDIR)/em_test.html

EM_MINITEST_SRCS = \
	minitest/minitest.c  \
	${TOMCRYPT_SRC} ${TOMMATH_SRC} 

EM_MINITEST_FLAGS = $(CFLAGS) \
	-Ilibs/tomcrypt/headers \
	-Ilibs/tommath  \
	-Ilibs/tomcrypt/hashes/skein \
	-Ilibs/xxHash \
	-Ilibs/argon2 \
	-Ilibs/sha3 \
	-Ilibs/jsmn \
	-Ilibs/common \
	-I$(BUILD_DIR)/includes  
	
EM_MINITEST_OBJS = $(EM_MINITEST_SRCS:%.c=$(EM_MINITEST_BUILD_DIR)/%.bc)

$(EM_MINITEST_BUILD_DIR)/%.bc: %.c  | init 
	$(EMCC) $(EMCC_FLAGS) -o $(addprefix $(EM_MINITEST_BUILD_DIR)/, $(notdir $(@))) -c $(EM_MINITEST_FLAGS) -I$(TARGETDIR) $<

$(EM_MINITEST_TARGET): $(EM_MINITEST_OBJS) init 
	$(EMCC) $(EMCC_FLAGS) -s WASM=1  $(EM_MINITEST_BUILD_DIR)/*.bc  -o $(EM_MINITEST_TARGET)

ifndef EMSDK
em_test:
	@printf '\temscripten SDK is not defined\n'
	@printf '\tinstall the emsdk\n'
	@printf '\thttps://kripken.github.io/emscripten-site/docs/getting_started/downloads.html\n'
	@printf '\tsetup the var EMCC \n \texport EMSDK="/Users/vinnie/Desktop/emsdk"  \n\n'
else
em_test: $(EM_MINITEST_TARGET)
endif

run_em_test:
	$(EMRUN) $(EM_MINITEST_TARGET)

#################################################################

S4_FRAMEWORK_NAME = S4Crypto.framework

S4_OSX_DEBUG =  $(TARGETDIR)/Debug/$(S4_FRAMEWORK_NAME)
S4_IOS_DEBUG =  $(TARGETDIR)/Debug-iphoneos/$(S4_FRAMEWORK_NAME)
S4_OSX =  $(TARGETDIR)/Release/$(S4_FRAMEWORK_NAME)
S4_IOS =  $(TARGETDIR)/Release-iphoneos/$(S4_FRAMEWORK_NAME)

OPTEST_OSX =  $(TARGETDIR)/Debug/S4Crypto-optest
CAVP_OSX =  $(TARGETDIR)/Debug/S4Crypto-cavp

$(S4_OSX_DEBUG) : $(S4_SRCS)
	xcodebuild -project S4Crypto.xcodeproj -target S4Crypto-osx -configuration Debug

$(S4_IOS_DEBUG) : $(S4_SRCS)
	xcodebuild -project S4Crypto.xcodeproj -target S4Crypto-ios -configuration Debug

$(S4_OSX) : ${S4_SRCS}
	xcodebuild -project S4Crypto.xcodeproj -target S4Crypto-osx -configuration Release

$(S4_IOS) : ${S4_SRCS}
	xcodebuild -project S4Crypto.xcodeproj -target S4Crypto-ios -configuration Release

$(OPTEST_OSX) : $(S4_OSX_DEBUG) $(OPTEST_SRCS)
	xcodebuild -project S4Crypto.xcodeproj -target S4Crypto-optest -configuration Debug

$(CAVP_OSX) : $(S4_OSX_DEBUG) #$(OPTEST_SRCS)
	xcodebuild -project S4Crypto.xcodeproj -target S4Crypto-cavp -configuration Debug

S4Crypto_osx: $(S4_OSX)

S4Crypto_ios: $(S4_IOS)

optest_osx: $(OPTEST_OSX)

cavp_osx: $(CAVP_OSX)

run_optest : $(OPTEST_OSX)
	DYLD_FRAMEWORK_PATH=$(TARGETDIR)/Debug/ $(TARGETDIR)/Debug/S4Crypto-optest

run_cavp : $(CAVP_OSX) 
	DYLD_FRAMEWORK_PATH=$(TARGETDIR)/Debug/ $(TARGETDIR)/Debug/S4Crypto-cavp  $(TARGETDIR)/Debug/KAT

#################################################################

all: $(S4_TARGET) $(S4_SHARED_TARGET) $(OPTEST_TARGET)
 
init:
	@[ -d $(BUILD_DIR) ] || mkdir $(BUILD_DIR)
	@[ -d $(S4_BUILD_DIR) ] || mkdir $(S4_BUILD_DIR)
	@[ -d $(EM_S4_BUILD_DIR) ] || mkdir $(EM_S4_BUILD_DIR)
	@[ -d $(OPTEST_BUILD_DIR) ] || mkdir $(OPTEST_BUILD_DIR)
	@[ -d $(EM_OPTEST_BUILD_DIR) ] || mkdir $(EM_OPTEST_BUILD_DIR)
	@[ -d $(CAVP_BUILD_DIR) ] || mkdir $(CAVP_BUILD_DIR)
	@[ -d $(BUILD_DIR)/includes ] || mkdir $(BUILD_DIR)/includes 
	@[ -d $(BUILD_DIR)/includes/yajl ] || mkdir $(BUILD_DIR)/includes/yajl &&  cp libs/yajl/src/api/*.h $(BUILD_DIR)/includes/yajl
	@[ -d $(TARGETDIR) ] || mkdir $(TARGETDIR)  
	@[ -d $(TARGETDIR)/s4 ] || mkdir $(TARGETDIR)/s4 &&  cp $(S4_INCLUDES) $(TARGETDIR)/s4
	@[ -d $(TARGETDIR)/KAT ] || mkdir $(TARGETDIR)/KAT &&  cp src/cavp/KAT/* $(TARGETDIR)/KAT
	@[ -d $(MINITEST_BUILD_DIR) ] || mkdir $(MINITEST_BUILD_DIR)
	@[ -d $(EM_MINITEST_BUILD_DIR) ] || mkdir $(EM_MINITEST_BUILD_DIR)

clean: 
	@rm -rf $(BUILD_DIR)
	@rm -rf $(TARGETDIR)

help:
	@printf '+---------------------------------------------------------------+\n'
	@printf '| TARGETS                                                       |\n'
	@printf '+---------------------------------------------------------------+\n'
	@printf '|                                                               |\n'
	@printf '| clean: Cleans output from previous builds.                    |\n'
	@printf '|                                                               |\n'
	@printf '| optest: Runs tests for Mac OS X  .                            |\n'
	@printf '|                                                               |\n'
	@printf '| cavp: Runs CAVP tests for Mac OS X  .                         |\n'
	@printf '|                                                               |\n'
	@printf '| shared: Compiles a shared library.                            |\n'
	@printf '|                                                               |\n'
	@printf '| static: Compiles a static library.                            |\n'
	@printf '|                                                               |\n'
	@printf '|                                                               |\n'
	@printf '| help: Display this help message.                              |\n'
	@printf '|                                                               |\n'
	@printf '| all: Compiles for all known architectures.                    |\n'
	@printf '|                                                               |\n'
	@printf '+---------------------------------------------------------------+\n'

 
