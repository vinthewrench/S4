# [S4Crypto](https://github.com/4th-ATechnologies/S4)

S4Crypto is a modern extensive cross platform library of cryptographic functions that can be called 
from the C API as well as JavaScript. It was designed to be portable, such that it can be cross-compiled for different architectures,  including macOS, iOS,  Linux, Android, and Windows.

S4Crypto also builds as a JavaScript  [webassembly](https://webassembly.org)  library.

S4Crypto also comes with a complete set of FIPS-140 compatible operation and [CAVP](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program)  tests. 

S4Crypto  is the crypto library  used by [storm4](https://https://www.storm4.cloud)  and zerodark.cloud

### Features

S4 allows the programmer to make high level C calls without having to have expertise 
in the low level cryptography algorithms. It presents the interface in a consistent 
usable structure.

##### HASH algorithms 

The following Hash Algorithms are supported:

- MD5

- SHA-1
- SHA-2 224/256/384/512  
- SHA-3 224/256/384/512
- KECCAK_256  (as seen in Ethereum)
- SKEIN-256, 512, 1024 
- xxHash 32/64

##### Message Authentication Code

Both HMAC and SKEIN version of MAC is supported. Across all the appropriate hash algorithms.

#####  Symmetric Cryptography functions

The following ciphers are supported:	
- AES 128/192/256
- 2FISH-256

Modes supported include EBC, CBC and a CBC encode/decode with padding  

##### Tweekable Block cipher

Threefish is supported in 256, 512 and 1024 bit mode.

##### Public Key functions
The following public key algorithms are supported:	
- ECC-384
- Curve41417  ([Bernstien/Lange Curve41417](https://safecurves.cr.yp.to)) 

##### Key Splitting

- Splitting and reassembling  keys using [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)  up to 1024 bits 


##### S4Crypto Keys API

S4Crypto also provides a higher level API to manage and process symmetric, public and split cryptographic keys using a JSON representation. 

Example of keys encoded using S4Crypto:

```JSON
#AES-128 key wrapped by Argon2 encoded passphrase
"{
    "version": 1,
    "encoding": "p2k",
    "keySuite": "AES-128",
    "p2k-params": "$Argon2d$m=65536,t=2,p=1,k=16$wzXNtftfk/s=",
    "mac": "YqEnigy+Y78=",
    "esk": "mC564p9mn7AXP/qmFI9l6A==",
    "iv": "FplyP4pAdcBoAkLgbIOGng==",
    "encrypted": "GktZqypxDbZUuCW5WfhGcw==",
    "encodedObject": "AES-128"
}
```

```JSON
#AES-256 key wrapped by ECC public key
 { 
     "version": 1,
    "encoding": "Curve41417",
    "keyID": "I0zFCdE4foQamhXa/f1u4Q==",
    "keySuite": "AES-256",
    "mac": "wHgedFID0nQ=",
    "encrypted": "MIGkBglghkgBZQMEAgEE...vtdB+wVgNQcufVkoork3mY="
 }
 ```

```JSON
#AES-128 key split into 8 shares with payload and one of the shares
{ 
    "version": 1,
    "encoding": "Shamir-AES256",
    "keySuite": "AES-128",
    "mac": "POStvPXgTXA=",
    "threshold": 6,
    "totalShares": 8,
    "shareOwner": "qRiYlopAc3w=",
    "iv": "xsbKvBr8bh3BprWy+pZnqhO6Gwj035RyNKgOcpmHiuE=",
    "encrypted": "t/L35MhILRR2cBh2QHeKqw==",
    "shareIDs": [
        "/uVqyD/TCw8=",
        "MN9PaXCEMug=",
        "Te/h6RWNV+A=",
        "HY7veIQBRwQ=",
        "bF20c6keLJQ=",
        "R4i5eWjeGIs=",
        "DDnQNZhnCHk=",
        "kUuV20lxNvM="
    ],
}
{
    "version": 1,
    "keySuite": "Shamir",
    "shareOwner": "qRiYlopAc3w=",
    "shareID": "/uVqyD/TCw8=",
    "threshold": 6,
    "index": 5,
    "encrypted": "mkfi6TjyBi1lGzFEwZ9+dJJoKXpWz2Xk6SxMX6t/Vos=",
} 
```

```JSON
#Curve41417 self-signed public key 
{
	"version":1,
	"keySuite":"Curve41417",
	"keyID":"k/Ot8M1rrE9gsAQ52wfatQ==",
	"pubKey":"BB1oTbiIzXvKAeoEGGpDNs1L25++9fD...eENIcVdgbFSnN0U1n1r",
	"start-date":"2018-10-31T16:51:11Z",
	"signable-properties":["keyID","keySuite","pubKey","start-date"],
	"signatures":[
		{
			"sigID":"rGXAFobko5RCinIFBRkMoA==",
			"hashAlgorithm":"SHA-256",
			"signature":"MGwCNAUY8MbJv0XnvB0C...8xDradimCNzVpTr+sr54=",
			"issuer":"k/Ot8M1rrE9gsAQ52wfatQ==",
			"issue-date":"2018-10-31T16:51:11Z",
			"sig-expire":0,
			"signed-properties":["keyID","keySuite","pubKey","start-date"]
		}
	]
}
```


### Getting Started

The minimum deployment target is iOS 9.2 / macOS 10.10 / tvOS 9.0 / watchOS 2.0.

#### CocoaPods

The easiest way to install `S4Crypto` is using CocoaPods.

```ruby
use_frameworks!
pod 'S4Crypto', :git=>'https://github.com/4th-ATechnologies/S4'

```

After `pod install` open your `.xcworkspace` and import:

```objc
// Swift
import S4Crypto     
// Objective-C on iOS 8+ with `use_frameworks!`
@import S4Crypto;
```

#### Carthage

The `S4Crypto.xcodeproj` project contains framework targets for iOS, macOS, tvOS, and watchOS.

### Building  S4Crypto

If you wish to build the frameworks yourself you can either use the makefile or the   'S4Crypto.xcodeproj' file

#### Building for macOS

The macOS version of S4Crypto is built using Xcode 10.1. and uses the S4Crypto-osx target. This will  produce the S4Crypto.Framework  in the build/osx/Debug or build/osx/Release directory.  Both Xcode tests and Operational tests have been provided. The Operational tests can  be built and run using the S4-optest Xcode target.

#### Building for iOS

The iOS  version of S4Crypto is built using Xcode Xcode 10.1.. and  can produce either a static  library or a framework. Only the Xcode tests which calls the Operational tests have been provided. The Xcode  test Operational tests can be built and run using the S4Crypto-ios-static  test  target.


#### Building for JavaScript using Web Assembly

S4Crypto can be built for JavaScript  using the [emsdk](https://kripken.github.io/emscripten-site/docs/getting_started/downloads.html)
The simplest way to build this project is simply to run `make em_s4`.  This will produce  libS4.js, libS4.wasm, and libS4.bc files.



### Operational Tests

S4Crypto includes a complete set of operational tests that exercises all of the logical interfaces and  can be used as part of a [FIPS-140](https://csrc.nist.gov/csrc/media/projects/cryptographic-module-validation-program/documents/fips140-2/fips1402dtr.pdf) validation. 

On macOS the operation tests can be created  by `make optest_osx` and then run by make `make run_optest_osx`.

### CAVP Tests

S4Crypto has the ability to process the follow test vectors produced by the [CAVP](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program)  
- AES block cipher in ECB, CBC modes
- Secure Hashing SHA-1, SHA-2 and SHA-3
- Message Authentication (HMAC)

On macOS the operation tests can be created  by `make cavp_osx` and then run by make `make run_cavp`.  A set of known answer tests (KAT) are provided.



 


