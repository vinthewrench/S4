//
//  c4Share.c
//  C4
//
//  Created by vincent Moscaritolo on 11/5/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//


#include "c4Internal.h"

#ifdef __clang__
#pragma mark - Shamir's Secret Sharing.
#endif


#define CREATE_SHAMIR_TABLES 0

/*
 https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing
 
 Shamir's Secret Sharing is an algorithm in cryptography created by Adi Shamir. It is a form of secret sharing, where a secret is divided into parts, giving each participant its own unique part, where some of the parts or all of them are needed in order to reconstruct the secret.
 
 Counting on all participants to combine the secret might be impractical, and therefore sometimes the threshold scheme is used where any k of the parts are sufficient to reconstruct the original secret.
 
 https://en.wikipedia.org/wiki/Secret_sharing
 
 The system relies on the idea that you can fit a unique polynomial of degree (t-1) to any set of t points that lie on the polynomial. It takes two points to define a straight line, three points to fully define a quadratic, four points to define a cubic curve, and so on. That is, it takes t points to define a polynomial of degree t-1. The method is to create a polynomial of degree t-1 with the secret as the first coefficient and the remaining coefficients picked at random. Next find n points on the curve and give one to each of the players. When at least t out of the n players reveal their points, there is sufficient information to fit a (t-1)t
 
 
 Also See 
 http://crypto.stackexchange.com/questions/24969/benefit-of-using-random-key-in-shamirs-secret-sharing
 
  The key (usually understood as the secret value of a share, or shares, or the secret shared), 
  and index (the identifier of a share, usually public), ... ask if there is benefit in using random index 
 in Shamir secret sharing?
 
    There are no security advantages to evaluating the polynomial at random places instead of sequential. 
    The information theoretic security proof of Shamir secret sharing does not depend on the evaluation 
    points being chosen in any specific manner.
 
 http://crypto.stackexchange.com/questions/29945/security-guarantees-of-shamirs-secret-sharing-when-some-co-efficients-are-zero
 
    The coefficients must be uniformly chosen. If you do not choose your coefficients uniformly, then by 
 Kerckhoff's principle, the attacker knows this, and that makes it easier than normal to reconstruct the 
 polynomial, and thus to obtain the secret.
 
    For a polynomial f of degree n and randomly chosen coefficients, you need n+1 values of f to uniquely 
    determine the coefficients. If you know m coefficients, you need only n-m+1 values of f to calculate 
 the coefficients. For the secret sharing, this implies that fewer shares will suffice to caclulate the secret.
 */

/* X coordinate of secret value */
#define X0		0

#define FIELD_SIZE 256
#define FIELD_POLY 0x169

#define f_add(x,y) ((x)^(y))
#define f_sub(x,y) f_add(x,y)

#if !CREATE_SHAMIR_TABLES

/* Code to dynamically construct these arrays is below as an alternative */

static const uint8_t f_exp[2*FIELD_SIZE] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x69, 0xD2, 0xCD, 0xF3, 0x8F, 0x77, 0xEE, 0xB5,
    0x03, 0x06, 0x0C, 0x18, 0x30, 0x60, 0xC0, 0xE9,
    0xBB, 0x1F, 0x3E, 0x7C, 0xF8, 0x99, 0x5B, 0xB6,
    0x05, 0x0A, 0x14, 0x28, 0x50, 0xA0, 0x29, 0x52,
    0xA4, 0x21, 0x42, 0x84, 0x61, 0xC2, 0xED, 0xB3,
    0x0F, 0x1E, 0x3C, 0x78, 0xF0, 0x89, 0x7B, 0xF6,
    0x85, 0x63, 0xC6, 0xE5, 0xA3, 0x2F, 0x5E, 0xBC,
    0x11, 0x22, 0x44, 0x88, 0x79, 0xF2, 0x8D, 0x73,
    0xE6, 0xA5, 0x23, 0x46, 0x8C, 0x71, 0xE2, 0xAD,
    0x33, 0x66, 0xCC, 0xF1, 0x8B, 0x7F, 0xFE, 0x95,
    0x43, 0x86, 0x65, 0xCA, 0xFD, 0x93, 0x4F, 0x9E,
    0x55, 0xAA, 0x3D, 0x7A, 0xF4, 0x81, 0x6B, 0xD6,
    0xC5, 0xE3, 0xAF, 0x37, 0x6E, 0xDC, 0xD1, 0xCB,
    0xFF, 0x97, 0x47, 0x8E, 0x75, 0xEA, 0xBD, 0x13,
    0x26, 0x4C, 0x98, 0x59, 0xB2, 0x0D, 0x1A, 0x34,
    0x68, 0xD0, 0xC9, 0xFB, 0x9F, 0x57, 0xAE, 0x35,
    0x6A, 0xD4, 0xC1, 0xEB, 0xBF, 0x17, 0x2E, 0x5C,
    0xB8, 0x19, 0x32, 0x64, 0xC8, 0xF9, 0x9B, 0x5F,
    0xBE, 0x15, 0x2A, 0x54, 0xA8, 0x39, 0x72, 0xE4,
    0xA1, 0x2B, 0x56, 0xAC, 0x31, 0x62, 0xC4, 0xE1,
    0xAB, 0x3F, 0x7E, 0xFC, 0x91, 0x4B, 0x96, 0x45,
    0x8A, 0x7D, 0xFA, 0x9D, 0x53, 0xA6, 0x25, 0x4A,
    0x94, 0x41, 0x82, 0x6D, 0xDA, 0xDD, 0xD3, 0xCF,
    0xF7, 0x87, 0x67, 0xCE, 0xF5, 0x83, 0x6F, 0xDE,
    0xD5, 0xC3, 0xEF, 0xB7, 0x07, 0x0E, 0x1C, 0x38,
    0x70, 0xE0, 0xA9, 0x3B, 0x76, 0xEC, 0xB1, 0x0B,
    0x16, 0x2C, 0x58, 0xB0, 0x09, 0x12, 0x24, 0x48,
    0x90, 0x49, 0x92, 0x4D, 0x9A, 0x5D, 0xBA, 0x1D,
    0x3A, 0x74, 0xE8, 0xB9, 0x1B, 0x36, 0x6C, 0xD8,
    0xD9, 0xDB, 0xDF, 0xD7, 0xC7, 0xE7, 0xA7, 0x27,
    0x4E, 0x9C, 0x51, 0xA2, 0x2D, 0x5A, 0xB4, 0x01,
    0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x69,
    0xD2, 0xCD, 0xF3, 0x8F, 0x77, 0xEE, 0xB5, 0x03,
    0x06, 0x0C, 0x18, 0x30, 0x60, 0xC0, 0xE9, 0xBB,
    0x1F, 0x3E, 0x7C, 0xF8, 0x99, 0x5B, 0xB6, 0x05,
    0x0A, 0x14, 0x28, 0x50, 0xA0, 0x29, 0x52, 0xA4,
    0x21, 0x42, 0x84, 0x61, 0xC2, 0xED, 0xB3, 0x0F,
    0x1E, 0x3C, 0x78, 0xF0, 0x89, 0x7B, 0xF6, 0x85,
    0x63, 0xC6, 0xE5, 0xA3, 0x2F, 0x5E, 0xBC, 0x11,
    0x22, 0x44, 0x88, 0x79, 0xF2, 0x8D, 0x73, 0xE6,
    0xA5, 0x23, 0x46, 0x8C, 0x71, 0xE2, 0xAD, 0x33,
    0x66, 0xCC, 0xF1, 0x8B, 0x7F, 0xFE, 0x95, 0x43,
    0x86, 0x65, 0xCA, 0xFD, 0x93, 0x4F, 0x9E, 0x55,
    0xAA, 0x3D, 0x7A, 0xF4, 0x81, 0x6B, 0xD6, 0xC5,
    0xE3, 0xAF, 0x37, 0x6E, 0xDC, 0xD1, 0xCB, 0xFF,
    0x97, 0x47, 0x8E, 0x75, 0xEA, 0xBD, 0x13, 0x26,
    0x4C, 0x98, 0x59, 0xB2, 0x0D, 0x1A, 0x34, 0x68,
    0xD0, 0xC9, 0xFB, 0x9F, 0x57, 0xAE, 0x35, 0x6A,
    0xD4, 0xC1, 0xEB, 0xBF, 0x17, 0x2E, 0x5C, 0xB8,
    0x19, 0x32, 0x64, 0xC8, 0xF9, 0x9B, 0x5F, 0xBE,
    0x15, 0x2A, 0x54, 0xA8, 0x39, 0x72, 0xE4, 0xA1,
    0x2B, 0x56, 0xAC, 0x31, 0x62, 0xC4, 0xE1, 0xAB,
    0x3F, 0x7E, 0xFC, 0x91, 0x4B, 0x96, 0x45, 0x8A,
    0x7D, 0xFA, 0x9D, 0x53, 0xA6, 0x25, 0x4A, 0x94,
    0x41, 0x82, 0x6D, 0xDA, 0xDD, 0xD3, 0xCF, 0xF7,
    0x87, 0x67, 0xCE, 0xF5, 0x83, 0x6F, 0xDE, 0xD5,
    0xC3, 0xEF, 0xB7, 0x07, 0x0E, 0x1C, 0x38, 0x70,
    0xE0, 0xA9, 0x3B, 0x76, 0xEC, 0xB1, 0x0B, 0x16,
    0x2C, 0x58, 0xB0, 0x09, 0x12, 0x24, 0x48, 0x90,
    0x49, 0x92, 0x4D, 0x9A, 0x5D, 0xBA, 0x1D, 0x3A,
    0x74, 0xE8, 0xB9, 0x1B, 0x36, 0x6C, 0xD8, 0xD9,
    0xDB, 0xDF, 0xD7, 0xC7, 0xE7, 0xA7, 0x27, 0x4E,
    0x9C, 0x51, 0xA2, 0x2D, 0x5A, 0xB4, 0x01, 0x02
};

static const uint8_t f_log[FIELD_SIZE] =
{
    0xFF, 0x00, 0x01, 0x10, 0x02, 0x20, 0x11, 0xCC,
    0x03, 0xDC, 0x21, 0xD7, 0x12, 0x7D, 0xCD, 0x30,
    0x04, 0x40, 0xDD, 0x77, 0x22, 0x99, 0xD8, 0x8D,
    0x13, 0x91, 0x7E, 0xEC, 0xCE, 0xE7, 0x31, 0x19,
    0x05, 0x29, 0x41, 0x4A, 0xDE, 0xB6, 0x78, 0xF7,
    0x23, 0x26, 0x9A, 0xA1, 0xD9, 0xFC, 0x8E, 0x3D,
    0x14, 0xA4, 0x92, 0x50, 0x7F, 0x87, 0xED, 0x6B,
    0xCF, 0x9D, 0xE8, 0xD3, 0x32, 0x62, 0x1A, 0xA9,
    0x06, 0xB9, 0x2A, 0x58, 0x42, 0xAF, 0x4B, 0x72,
    0xDF, 0xE1, 0xB7, 0xAD, 0x79, 0xE3, 0xF8, 0x5E,
    0x24, 0xFA, 0x27, 0xB4, 0x9B, 0x60, 0xA2, 0x85,
    0xDA, 0x7B, 0xFD, 0x1E, 0x8F, 0xE5, 0x3E, 0x97,
    0x15, 0x2C, 0xA5, 0x39, 0x93, 0x5A, 0x51, 0xC2,
    0x80, 0x08, 0x88, 0x66, 0xEE, 0xBB, 0x6C, 0xC6,
    0xD0, 0x4D, 0x9E, 0x47, 0xE9, 0x74, 0xD4, 0x0D,
    0x33, 0x44, 0x63, 0x36, 0x1B, 0xB1, 0xAA, 0x55,
    0x07, 0x65, 0xBA, 0xC5, 0x2B, 0x38, 0x59, 0xC1,
    0x43, 0x35, 0xB0, 0x54, 0x4C, 0x46, 0x73, 0x0C,
    0xE0, 0xAC, 0xE2, 0x5D, 0xB8, 0x57, 0xAE, 0x71,
    0x7A, 0x1D, 0xE4, 0x96, 0xF9, 0xB3, 0x5F, 0x84,
    0x25, 0xA0, 0xFB, 0x3C, 0x28, 0x49, 0xB5, 0xF6,
    0x9C, 0xD2, 0x61, 0xA8, 0xA3, 0x4F, 0x86, 0x6A,
    0xDB, 0xD6, 0x7C, 0x2F, 0xFE, 0x0F, 0x1F, 0xCB,
    0x90, 0xEB, 0xE6, 0x18, 0x3F, 0x76, 0x98, 0x8C,
    0x16, 0x8A, 0x2D, 0xC9, 0xA6, 0x68, 0x3A, 0xF4,
    0x94, 0x82, 0x5B, 0x6F, 0x52, 0x0A, 0xC3, 0xBF,
    0x81, 0x6E, 0x09, 0xBE, 0x89, 0xC8, 0x67, 0xF3,
    0xEF, 0xF0, 0xBC, 0xF1, 0x6D, 0xBD, 0xC7, 0xF2,
    0xD1, 0xA7, 0x4E, 0x69, 0x9F, 0x3B, 0x48, 0xF5,
    0xEA, 0x17, 0x75, 0x8B, 0xD5, 0x2E, 0x0E, 0xCA,
    0x34, 0x53, 0x45, 0x0B, 0x64, 0xC4, 0x37, 0xC0,
    0x1C, 0x95, 0xB2, 0x83, 0xAB, 0x5C, 0x56, 0x70
};

#else	/* CREATE_SHAMIR_TABLES */

static uint8_t f_exp[2*FIELD_SIZE];
static uint8_t f_log[FIELD_SIZE];


/* Code to dynamically struct f_log and f_exp arrays */
/*
 * Initialize the f_exp and f_log arrays (if necessary).
 * Safe (and fast) to call redundantly, so any convenient time will do.
 */

static void sCreateTables(void)
{
    unsigned i, x;
    
    if (!f_log[0]) {
        x = 1;
        for (i = 0; i < FIELD_SIZE-1; i++) {
            f_exp[i] = x;
            f_exp[i+FIELD_SIZE-1] = x;
            f_log[x] = i;
            x <<= 1;
            if (x & FIELD_SIZE)
                x ^= FIELD_POLY;
        }
        /* x should be 1 here */
        f_exp[2*FIELD_SIZE-2] = f_exp[0];
        f_exp[2*FIELD_SIZE-1] = f_exp[1];
        f_log[0] = i;	/* Bogus value, FIELD_SIZE-1 */
    }
}

#endif	/* CREATE_SHAMIR_TABLES */


#pragma pack(push)  /* push current alignment to stack */
#pragma pack(1)     /* set alignment to 1 byte boundary */

typedef struct ShareHeader
{
#define kSHARES_HeaderMagic		0x63345348
    uint32_t        magic;
    uint32_t        shareDataLen;

    uint8_t			xCoordinate;	/* X coordinate of share  AKA the share index */
    uint8_t         threshold;		/* Number of shares needed to combine */
    uint8_t			lagrange;		/* Temp value used during split/join */
    uint8_t         data[];         /* the actual share secret */

} ShareHeader;


typedef struct SHARES_Context    SHARES_Context;

struct SHARES_Context
{
#define kSHARES_ContextMagic		0x63345353
    uint32_t                magic;
    size_t                  shareLen;
    uint32_t                totalShares;
    uint32_t                threshold;
    uint8_t                 shareHash[kC4ShareInfo_HashBytes];      /* Share data Hash - AKA serial number */
    uint8_t                 shareData[];
};

#pragma pack(pop)   /* restore original alignment from stack */


static  inline ShareHeader* sGetShareData(void* shareData, size_t shareLen,  uint32_t shareNumber)
{
    size_t offset =  (sizeof(ShareHeader) + shareLen) * shareNumber;
    return(  (ShareHeader*) (shareData + offset)  ) ;
}


static bool sSHARES_ContextIsValid( const SHARES_ContextRef  ref)
{
    bool	valid	= false;
    
    valid	= IsntNull( ref ) && ref->magic	 == kSHARES_ContextMagic;
    
    return( valid );
}

#define validateSHARESContext( s )		\
ValidateParam( sSHARES_ContextIsValid( s ) )


static C4Err sSHARE_HASH( const uint8_t *key,
                         size_t         keyLenIn,
                         uint32_t       thresholdIn,
                         uint8_t        *mac_buf,
                         unsigned long  mac_len)
{
    C4Err           err = kC4Err_NoErr;
    
    MAC_ContextRef  macRef     = kInvalidMAC_ContextRef;
    
    uint32_t        secretLength    =  (uint32_t) keyLenIn;
    uint32_t        threshold       = thresholdIn;
    
    char*           label = "share-hash";
    
    err = MAC_Init(kMAC_Algorithm_SKEIN,
                   kHASH_Algorithm_SKEIN256,
                   key, keyLenIn, &macRef); CKERR
    
    MAC_Update(macRef,  "\x00\x00\x00\x01",  4);
    MAC_Update(macRef,  label,  strlen(label));
    
    err = MAC_Update( macRef, &secretLength, sizeof(secretLength)); CKERR;
    MAC_Update(macRef,  "\x00\x00\x00\x04",  4);
    
    err = MAC_Update( macRef, &threshold, sizeof(threshold)); CKERR;
    MAC_Update(macRef,  "\x00\x00\x00\x04",  4);
    
    size_t mac_len_SZ = (size_t)mac_len;
    err = MAC_Final( macRef, mac_buf, &mac_len_SZ); CKERR;
    
done:
    
    MAC_Free(macRef);
    
    return err;
}

/*
 * This is the core of secret sharing.  This computes the coefficients
 * used in Lagrange polynomial interpolation, returning the
 * vector of logarithms of b1(xtarget), b2(xtarget), ..., bn(xtarget).
 * Takes values from the "xCoordinate" header element, inserts the
 * results in the "lagrange" header element.
 * The interpolation values come from the headers of the "shares" array,
 * plus one additional value, xInput, which is the value we are going
 * to interpolate to.
 *
 * Returns kC4Err_NoErr on success, error if not all x[i] are unique.
 */

static C4Err sComputeLagrange(void* shareData, size_t shareLen, uint32_t nShares, uint8_t xInput)
{
    uint32_t		i, j;
    uint8_t			xi, xj;
    uint32_t		numer, denom;
    
 #if CREATE_SHAMIR_TABLES
    sCreateTables();
#endif
    
    /* First, accumulate the numerator, Prod(xInput-x[i],i=0..n) */
    numer = 0;
    for (i = 0; i < nShares; i++)
    {
        xi = sGetShareData(shareData, shareLen, i)->xCoordinate;
        numer += f_log[ f_sub(xi, xInput) ];
    }
    /* Preliminary partial reduction */
    numer = (numer%FIELD_SIZE) + (numer/FIELD_SIZE);
    
    /* Then, for each coefficient, compute the corresponding denominator */
    for (i = 0; i < nShares; i++) {
        xi = sGetShareData(shareData, shareLen, i)->xCoordinate;
       denom = 0;
        for (j = 0; j < nShares; j++) {
            xj = (i == j) ? xInput : sGetShareData(shareData, shareLen, j)->xCoordinate;
            if (xi == xj)
                return kC4Err_AssertFailed;
            denom += f_log[f_sub(xi,xj)];
        }
        denom = (denom%FIELD_SIZE)+(denom/FIELD_SIZE);
        /* 0 <= denom < 2*FIELD_SIZE-1. */
        
        /* Now find numer/denom.  In log form, that's a subtract. */
        denom = numer + 2*FIELD_SIZE-2 - denom;
        denom = (denom%FIELD_SIZE)+(denom/FIELD_SIZE);
        denom = (denom%FIELD_SIZE)+(denom/FIELD_SIZE);
        
        sGetShareData(shareData, shareLen, i)->lagrange = (uint8_t)denom;
    }
    return kC4Err_NoErr;	/* Success */
}



/*
 * This actually does the interpolation, using the coefficients
 * computed by sComputeLagrange().   
 */


static C4Err sInterpolation(void* shareData, size_t shareLen, uint32_t nShares, uint32_t byteNumber)
{
    uint8_t x, y;
    uint8_t lagrange;
    uint32_t i;
    
    x = 0;
    for( i=0; i < nShares; ++i )
    {
        y = sGetShareData(shareData, shareLen, i)->data[byteNumber];
        if (y != 0)
        {
            lagrange = sGetShareData(shareData, shareLen, i)->lagrange;
            y = f_exp[lagrange + f_log[y]];
        }
        x = f_add(x,y);
    }
    
    return x;
}


#define SHARE_DATA(_context_, _shareNum_) (sGetShareData(&_context_->shareData, _context_->shareLen, _shareNum_))

C4Err SHARES_Init( const void       *key,
                   size_t           keyLen,
                   uint32_t         totalShares,
                   uint32_t         threshold,
                   SHARES_ContextRef *ctx)
{
    C4Err               err = kC4Err_NoErr;
    SHARES_Context*    shareCTX = NULL;
    
    size_t          allocSize = 0;
    uint32_t			i, j;
    uint8_t				xupdate;
   
    ValidateParam(key);
    ValidateParam(ctx);
    ValidateParam(keyLen <= 64)
    
    *ctx = NULL;
    
    allocSize = sizeof (SHARES_Context) + ((sizeof(ShareHeader) + keyLen) * totalShares);
    
    shareCTX = XMALLOC( allocSize); CKNULL(shareCTX);
    ZERO(shareCTX, allocSize);
    
    shareCTX->magic         = kSHARES_ContextMagic;
    shareCTX->shareLen      = keyLen;
    shareCTX->totalShares   = totalShares;
    shareCTX->threshold     = threshold;

    err = sSHARE_HASH(key, keyLen, shareCTX->threshold,  shareCTX->shareHash, kC4ShareInfo_HashBytes ); CKERR;
                     
    /* Set X coordinate randomly for each share */
    for( i=0; i<totalShares; ++i )
    {
        bool found = false;
        /* Pick a unique, random x coordinate != X0 */
        while( !found )
        {
            ShareHeader* hdr =   SHARE_DATA(shareCTX, i);
            
            RNG_GetBytes( &hdr->xCoordinate , 1 );
            
            if( hdr->xCoordinate != X0 )
            {
                for( j=0; j<i; ++j )
                {
                     ShareHeader* hdr1 =   SHARE_DATA(shareCTX, j);
                    
                    if( hdr->xCoordinate == hdr1->xCoordinate )
                        break;
                }
                if( j == i )
                {
                    found = true;
                }
            }
        }
        
        ShareHeader* hdr =   SHARE_DATA(shareCTX, i);
        
        hdr->magic            = kSHARES_HeaderMagic;
        hdr->shareDataLen     = (uint32_t)shareCTX->shareLen;
        hdr->threshold        = (uint32_t)shareCTX->threshold;
        
     }


    /* Initialize thresh-1 bodies to random numbers */
    for( i=0; i<threshold-1; ++i )
    {
        ShareHeader* hdr =   SHARE_DATA(shareCTX, i);
        RNG_GetBytes( &hdr->data, keyLen );
    }

    {
        ShareHeader* hdr =   SHARE_DATA(shareCTX, threshold-1);
      
        /* Copy input to the first share body past the random ones */
          COPY( key, hdr->data , keyLen );
        
        /* Put X0 into xCoordinate for that header */
        /* xupdate holds the X value for the share we will be updating */
        xupdate = hdr->xCoordinate;
        hdr->xCoordinate = X0;
    }
    

    /*
     * Now set each of the remaining bodies via interpolation.
     * Work from last to threshold-1 so we can leave our input copy in
     * the threshold slot.
     */
    for( i=totalShares-1; i!=threshold-2; --i )
    {
        uint8_t tmp;
        
        /* Interpolate to that value */
        sComputeLagrange(&shareCTX->shareData, shareCTX->shareLen,shareCTX->threshold, xupdate );
        
        for( j=0; j<keyLen; ++j )
        {
            SHARE_DATA(shareCTX, i)->data[j]
                    =  sInterpolation(&shareCTX->shareData, shareCTX->shareLen,shareCTX->threshold, j);
        }
        /* Swap in xupdate value for share we just calculated */
        tmp = SHARE_DATA(shareCTX, i)->xCoordinate;
        SHARE_DATA(shareCTX, i)->xCoordinate = xupdate;
        xupdate = tmp;
    }
 
    /* Zero lagrange values, were just temporary */
    for( i=0; i<totalShares; ++i )
    {
        SHARE_DATA(shareCTX, i)->lagrange = 0;
   }

    
    *ctx = shareCTX;
    
done:
    
    return err;
}


void  SHARES_Free(SHARES_ContextRef  ctx)
{
    if(sSHARES_ContextIsValid(ctx))
    {
         size_t allocSize = sizeof (SHARES_Context) + (sizeof(ShareHeader) + ctx->shareLen) * ctx->totalShares;
        
        ZERO(ctx, allocSize);
        XFREE(ctx);
    }
}

C4Err  SHARES_GetShareInfo( SHARES_ContextRef  ctx,
                           uint32_t            shareNumber,
                           SHARES_ShareInfo    **shareInfoOut,
                           size_t              *shareInfoLen)
{
    C4Err               err = kC4Err_NoErr;
    size_t              bufSize = 0;
    SHARES_ShareInfo*   shareInfo = NULL;
    
    validateSHARESContext(ctx);
    ValidateParam(shareInfoOut);
    ValidateParam( shareNumber < ctx->totalShares);
    
    bufSize = sizeof(SHARES_ShareInfo);
    
    ShareHeader* hdr =   SHARE_DATA(ctx, shareNumber);
    
    shareInfo = XMALLOC(bufSize); CKNULL(shareInfo);
    ZERO(shareInfo, bufSize);
 
     shareInfo->threshold = ctx->threshold;
    COPY(ctx->shareHash, shareInfo->shareHash, kC4ShareInfo_HashBytes);
 
    shareInfo->xCoordinate = hdr->xCoordinate;
    shareInfo->shareSecretLen = hdr->shareDataLen;
    COPY(hdr->data, shareInfo->shareSecret, hdr->shareDataLen);
    
    *shareInfoOut = shareInfo;
    
    if(shareInfoLen)
        *shareInfoLen = bufSize;
    
done:
    
    return err;
   
}

C4Err  SHARES_CombineShareInfo( uint32_t            numberShares,
                           SHARES_ShareInfo*        sharesInfoIn[],
                           void                     *outData,
                           size_t                   bufSize,
                           size_t                   *outDataLen)
{
    C4Err       err = kC4Err_NoErr;
    
    size_t              keyLen = 0;
    uint8_t				threshold = 0;
    uint8_t             *shareTable = NULL;
    size_t              allocSize = 0;
    uint8_t             shareHash[kC4ShareInfo_HashBytes];      /* Share data Hash - AKA serial number */
    uint8_t             calculatedHash[kC4ShareInfo_HashBytes];

    uint32_t			i, j;
    
    ValidateParam(outData);
    ValidateParam(sharesInfoIn);
    
    /* check all shares for consistancy */
    
    for(i = 0; i< numberShares; i++)
    {
        SHARES_ShareInfo* info = sharesInfoIn[i];
        
        // pickup the keylength from first share
        if(i == 0)
        {
            keyLen = info->shareSecretLen;
            threshold = info->threshold;
            
            if(numberShares < threshold)
                RETERR(kC4Err_NotEnoughShares);
            
            // copy the share Hash
            COPY(info->shareHash, shareHash, kC4ShareInfo_HashBytes);
            
            ValidateParam(bufSize >= keyLen);
         }
        else
        {
            // they all need to be the same size
            ValidateParam(info->shareSecretLen == keyLen);
            // they all need to be the same size
            ValidateParam(info->threshold == threshold);
            // Compare the shareHash
            ValidateParam(CMP(info->shareHash, shareHash, kC4ShareInfo_HashBytes));
        }
    }
    
    // recreate data structure with existng shares.
    allocSize =  (sizeof(ShareHeader) + keyLen) * numberShares ;
    shareTable = XMALLOC( allocSize); CKNULL(shareTable);
    ZERO(shareTable, allocSize);
    
    for(i = 0; i< numberShares; i++)
    {
        SHARES_ShareInfo* info = sharesInfoIn[i];
         ShareHeader     *hdr = sGetShareData(shareTable, keyLen, i);
        
        hdr->xCoordinate    = info->xCoordinate;
        hdr->threshold      = info->threshold;
        hdr->shareDataLen   = (uint_32t) info->shareSecretLen;
        COPY(info->shareSecret, hdr->data, info->shareSecretLen);
    }
    
    /* Set up Lagrange coefficients to interpolate to x=X0 */
    sComputeLagrange(shareTable, keyLen, threshold, X0 );
    
    /* For each byte j, interpolate to output[j] using coordinates */
    for( j=0; j<bufSize; ++j )
    {
        ((uint8_t *)outData)[j] =  sInterpolation(shareTable, keyLen ,threshold, j);
    }
  
    // check for valid secret
    err = sSHARE_HASH(outData, keyLen, threshold, calculatedHash, kC4ShareInfo_HashBytes ); CKERR;
    
     if (!CMP(calculatedHash, shareHash, kC4ShareInfo_HashBytes) )
            RETERR(kC4Err_CorruptData);

    if(outDataLen)
        *outDataLen = keyLen;
done:
    
    if(shareTable)
    {
        ZERO(shareTable, allocSize);
        XFREE(shareTable);
        
    }
    return err;
    
}
