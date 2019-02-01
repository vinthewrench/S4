//
//  s4rng.h
//  S4Crypto
//
//  Created by vinnie on 1/31/19.
//  Copyright © 2019 4th-A Technologies, LLC. All rights reserved.
//

#ifndef s4rng_h
#define s4rng_h

#include "s4pubtypes.h"

/**
 * @file s4rng.h
 * @author 4th-A Technologies, LLC
 * @brief S4Crypto Random Number/String Generation
 *
 */

S4_ASSUME_NONNULL_BEGIN

#ifdef __clang__
#pragma mark - RNG function wrappers
#endif

S4Err RNG_GetBytes(	  void *         out,
				   size_t         outLen
				   );

S4Err RNG_GetPassPhrase( size_t         bits,
						char __NULLABLE_XFREE_P_P outPassPhrase );


S4_ASSUME_NONNULL_END


#endif /* s4rng_h */
