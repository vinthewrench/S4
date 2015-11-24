# libc4

C4 is an extensive cross platform library of cryptographic functions that can be called 
from the C API. It was designed to be portable, such that it can be cross-compiled 
for different architectures,  including OS X, IOS,  Linux, Android, and Windows.


# Building for OS X

The OS X version of C4 is built using Xcode 7.1. and uses the C4-osx target. This will
 produce the C4.Framework  in the build/osx/Debug or build/osx/Release directory.  
 Both Xcode tests and Operational tests have been provided. The Operational tests can
  be built and run using the C4-optest Xcode target.

# Building for IOS

The IOS  version of C4 is built using Xcode 7.1. and uses the 'C4-ios static' target.
 This will produce the libC4.a in the build/ios/Debug or build/ios/Release directory. 
  Only the Xcode tests which calls the Operational tests have been provided. The Xcode
   test Operational tests can be built and run using the C4-ios Test  target.


# Building for the unix OS (Linux)

The simplest way to build this project is simply to run `make host`. This will
perform a build for the host OS, and should work out-of-the-box on most operating
systems, assuming standard C build tools are available.


# Features

C4 allows the programmer to make high level C calls without having to have expertise 
in the low level cryptography algorithms. It presents the interface in a consistant 
usable structure.

#HASH algorithms 

The following Hash Algorithms are supported:

- MD5
- SHA-1, 224, 256, 384, 512, 512/256
- SKEIN-256, 512, 1024 
 
 The following Hash API

- HASH_Init
- HASH_Free 
- HASH_Update
- HASH_Final 
- HASH_GetSize 
- HASH_Export 
- HASH_Import 
- HASH_DO 

#Message Authentication Code

Both HMAC and SKEIN version of MAC is supported. Across all the appropriate hash algorithms.
 
- MAC_Init
- MAC_Free
- MAC_Update
- MAC_Final
- MAC_HashSize

There is also a MAC_KDF utility function that is helpful for doing key derivation 
 
#Symmetric Cryptography functions

The following ciphers are supported:	AES-128, AES-192, AES-256, 2FISH-256
   
EBC mode calls include
- ECB_Encrypt
- ECB_Decrypt 

CBC mode is available via:

- CBC_Init
- CBC_Free
- CBC_Encrypt
- CBC_Decrypt 

and a  higher level CBC encode/decode with padding  

- CBC_EncryptPAD
- CBC_DecryptPAD

#Tweekable Block cipher

Threefish is supported in 256, 512 and 1024 bit mode.

- TBC_Init 
- TBC_Free
- TBC_SetTweek
- TBC_Encrypt
- TBC_Decrypt 

#ECC Public Key functions

supported Keysizes are ECC-384 and 414 (Bernstien/Lange Curve41417) 

- ECC_Init
- ECC_Free
- ECC_Generate
- ECC_isPrivate
- ECC_Export 
- ECC_Export_ANSI_X963
- ECC_Import_Info
- ECC_Import
- ECC_Import_ANSI_X963
- ECC_CurveName
- ECC_KeySize
- ECC_PubKeyHash
- ECC_SharedSecret 
- ECC_Encrypt
- ECC_Decrypt
- ECC_Verify
- ECC_Sign

# Shamir secret Splitting 

- SHARES_Init
- SHARES_Free
- SHARES_GetShareInfo
- SHARES_CombineShareInfo

# Generate PGP hash codes
- PGPWordEncode
- PGPWordEncode64

#C4 Keys API

C4 also provides a higher level API to take cryptographic keys and convert back and forth
from a JSON representation.

Keys are maintained in an internal C4KeyContextRef format and can be created and manipulated
using the following API calls.

- C4Key_NewSymmetric
- C4Key_NewTBC
- C4Key_NewShare
- C4Key_Free
- C4Key_SetProperty
- C4Key_GetProperty, SCKeyGetAllocatedProperty

Keys pointed to by the C4KeyContextRef can be converted back and forth to JSON using

- C4Key_SerializeToPubKey
- C4Key_SerializeToPassPhrase
- C4Key_DeserializeKeys

and can be decoded back to original format using

- C4Key_DecryptFromPassPhrase
- C4Key_DecryptFromPubKey 
- C4Key_VerifyPassPhrase






 



