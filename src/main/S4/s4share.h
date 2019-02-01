//
//  s4share.h
//  S4Crypto
//
//  Created by vinnie on 1/31/19.
//  Copyright © 2019 4th-A Technologies, LLC. All rights reserved.
//

/**
 * @file s4share.h
 * @author 4th-A Technologies, LLC
 * @brief S4Crypto Low level Shamir key splitting functions
 *
 */

#ifndef s4share_h
#define s4share_h
#include "s4pubtypes.h"

S4_ASSUME_NONNULL_BEGIN

#ifdef __clang__
#pragma mark - Shamir Secret Sharing
#endif

typedef struct S4SharesContext *      S4SharesContextRef;

#define	kInvalidS4SharesContextRef		((S4SharesContextRef) NULL)
#define S4SharesContextRefIsValid( ref )		( (ref) != kInvalidS4SharesContextRef )


#define kS4ShareInfo_HashBytes      8
#define kS4ShareInfo_MaxSecretBytes      128

typedef struct  S4SharesContext
{
#define kS4SharesContextMagic		0x53345343
	uint32_t                magic;
	size_t                  shareLen;
	uint32_t                totalShares;
	uint32_t                threshold;

	// If the share secret is a encyption key then these are valid
	Cipher_Algorithm    encyptAlgor;
	uint8_t             *encrypted;
	size_t              encryptedLen;

	uint8_t					shareID[kS4ShareInfo_HashBytes];     	 /* Share owner  -serial number */
	uint8_t                 shareData[];
} S4SharesContext;


typedef struct S4SharesPartContext *      S4SharesPartContextRef;

#define	kInvalidS4SharesPartContextRef		((S4SharesPartContextRef) NULL)
#define S4SharesPartContextRefIsValid( ref )		( (ref) != kInvalidS4SharesPartContextRef )

typedef struct S4SharesPartContext
{
#define kS4SharesPartContextMagic		0x53345350
	uint32_t        magic;

	uint8_t			shareOwner[kS4ShareInfo_HashBytes];      /* Share owner  - serial number */
	uint8_t			shareID[kS4ShareInfo_HashBytes];     	 /* Share ID -serial number */
	uint8_t         threshold;                              /* Number of shares needed to combine */
	uint8_t			xCoordinate;                            /* X coordinate of share  AKA the share index */
	size_t          shareSecretLen;
	uint8_t         shareSecret[kS4ShareInfo_MaxSecretBytes];                        /* the actual share secret */
} S4SharesPartContext;


S4Err S4Shares_New( const void       *key,
				   size_t           keyLen,
				   uint32_t         totalShares,
				   uint32_t         threshold,
				   S4SharesContextRef __NULLABLE_REF_POINTER ctx);


void  S4Shares_Free(S4SharesContextRef  ctx);

S4Err  S4Shares_GetPart( S4SharesContextRef  ctx,
						uint32_t            shareNumber,
						S4SharesPartContext   __NULLABLE_XFREE_P_P shareInfo);

void  S4SharesPart_Free(S4SharesPartContextRef  ctx);

S4Err  SHARES_CombineShareInfo( uint32_t            numberShares,
							   S4SharesPartContext* __S4_NONNULL   sharesInfoIn[__S4_NONNULL],
							   void                     *outData,
							   size_t                   bufSize,
							   size_t                   *outDataLen);

S4Err SHARES_GetShareHash( const uint8_t *key,
						  size_t         keyLenIn,
						  uint32_t       thresholdIn,
						  uint8_t        *mac_buf,
						  unsigned long  mac_len);


S4_ASSUME_NONNULL_END

#endif /* s4share_h */
