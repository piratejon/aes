#ifndef AES_H
#define AES_H

#include "aesutils.h"

enum {
  FIPS_AES_128 = 0,
  FIPS_AES_192,
  FIPS_AES_256
};

typedef unsigned char Byte;

typedef struct _tag_bytestr {
  Byte * raw;
  int length;
} ByteStr;

typedef struct _tag_block {
  Byte b[4][4];
} Block;

typedef struct _tag_word {
  Byte W[4];
} Word;

void KeyExpansion ( const Byte [], Word [] );
void SetMode ( int );
void Cipher ( Byte [], Byte [] );
void InvCipher ( Byte [], Byte [] );
void CBC_Forward ( ByteStr *, ByteStr *, ByteStr * [], int );
ByteStr * HexString_To_Array ( Byte * );
void XorString ( Byte *, Byte *, int );

void free_bytestr ( ByteStr * );

#endif // AES_H

