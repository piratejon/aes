
#include <string.h>
#include <stdio.h>

#include "aes_test.h"

#include "aesutils.h"
#include "aes.h"

static const Byte sbox[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static const Byte invsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const int Nk[3] = { 4, 6, 8 };
static const int Nb[3] = { 4, 4, 4 };
static const int Nr[3] = {10,12,14 };

static const int Rcon[11] = { 0, 1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
static const int GF_Irred = 0x11b;

static int Mode;

void dumpbytes ( Byte * b, int count ) {
  while ( count -- > 0 ) {
    printf("%02x", *b ++);
  }
  printf("\n");
}

TEST_OR_STATIC void dumpstate ( char * label, Block * b ) {
  int i, j;

  printf("%s: ", label);
  for ( j = 0; j < 4; j += 1 ) {
    for ( i = 0; i < 4; i += 1 ) {
      printf("%02x", b->b[i][j]);
    }
  }
  printf("\n");
}

static void dumpwords ( char * label, Word * w, int count ) {
  int i;

  printf("%s: ", label);
  for ( i = 0; i < count; i += 1 ) {
    printf("%02x", w[i].W[0]);
    printf("%02x", w[i].W[1]);
    printf("%02x", w[i].W[2]);
    printf("%02x", w[i].W[3]);
  }
  printf("\n");
}

TEST_OR_STATIC Byte GF_xtime ( const Byte a ) {
  if ( a & 0x80 ) {
    return (a << 1) ^ GF_Irred;
  } else {
    return (a << 1) ^ 0;
  }
}

TEST_OR_STATIC Byte GF_mult ( const Byte a, const Byte b ) {
  int i;
  Byte sum = 0;
  Byte powers[8];
  Byte c = b;

  powers[0] = a;
  powers[1] = GF_xtime ( powers[0] ); // 02
  powers[2] = GF_xtime ( powers[1] ); // 04
  powers[3] = GF_xtime ( powers[2] ); // 08
  powers[4] = GF_xtime ( powers[3] ); // 10
  powers[5] = GF_xtime ( powers[4] ); // 20
  powers[6] = GF_xtime ( powers[5] ); // 40
  powers[7] = GF_xtime ( powers[6] ); // 80

  for ( i = 0; c > 0; i += 1, c >>= 1 ) {
    if ( c & 1 ) {
      sum ^= powers[i];
    }
  }

  return sum;
}

TEST_OR_STATIC void SubWord ( Word * w ) {
  w->W[0] = sbox[w->W[0]];
  w->W[1] = sbox[w->W[1]];
  w->W[2] = sbox[w->W[2]];
  w->W[3] = sbox[w->W[3]];
}

TEST_OR_STATIC void RotWord ( Word * w ) {
  // [a,b,c,d] -> [b,c,d,a]
  Byte tmp;

  tmp = w->W[0];
  w->W[0] = w->W[1];
  w->W[1] = w->W[2];
  w->W[2] = w->W[3];
  w->W[3] = tmp;
}

TEST_OR_STATIC void XorWord ( Word * w, Word * x ) {
  w->W[0] ^= x->W[0];
  w->W[1] ^= x->W[1];
  w->W[2] ^= x->W[2];
  w->W[3] ^= x->W[3];
}

static void XorRconWord ( Word * w, int i ) {
  w->W[0] ^= Rcon[i];
}

TEST_OR_STATIC void KeyExpansion ( const Byte keystream[], Word w[] ) {
  Word temp;
  int i = 0;

  for ( i = 0; i < Nk[Mode]; i += 1 ) {
    w[i].W[0] = keystream[4*i + 0];
    w[i].W[1] = keystream[4*i + 1];
    w[i].W[2] = keystream[4*i + 2];
    w[i].W[3] = keystream[4*i + 3];
  }

  dumpwords ( "words", w, Nk[Mode] );

  for ( ; i < Nb[Mode] * (Nr[Mode] + 1); i += 1 ) {
    memcpy(&temp, &(w[i-1]), sizeof(temp));
    if ( i % Nk[Mode] == 0 ) {
      RotWord(&temp);
      dumpwords ( "RotWord", &temp, 1 );
      SubWord(&temp);
      dumpwords ( "SubWord", &temp, 1 );
      XorRconWord(&temp, i / Nk[Mode]);
      dumpwords ( "XorRcon", &temp, 1 );
    } else if ( Nk[Mode] > 6 && i % Nk[Mode] == 4 ) {
      SubWord(&temp);
      dumpwords ( "SubWord2", &temp, 1 );
    }
    XorWord (&temp, &(w[i-Nk[Mode]]));
    dumpwords ( "XorLast", &temp, 1 );
    memcpy(&(w[i]), &temp, sizeof(temp));
  }
}

TEST_OR_STATIC void AddRoundKey ( Block * state, Word * w ) {
  int i, j;

  for ( i = 0; i < 4; i += 1 ) {
    for ( j = 0; j < 4; j += 1 ) {
      state->b[j][i] ^= w[i].W[j];
    }
  }
}

static void ByteSwap ( Byte * a, Byte * b ) {
  *a ^= *b;
  *b ^= *a;
  *a ^= *b;
}

static void SubBytes ( Block * state ) {
  int i, j;

  for ( i = 0; i < 4; i += 1 ) {
    for ( j = 0; j < 4; j +=1 ) {
      state->b[i][j] = sbox[state->b[i][j]];
    }
  }
}

static void InvSubBytes ( Block * state ) {
  int i, j;

  for ( i = 0; i < 4; i += 1 ) {
    for ( j = 0; j < 4; j +=1 ) {
      state->b[i][j] = invsbox[state->b[i][j]];
    }
  }
}

static void LeftShiftRow1 ( Block * B, int row ) {
  Byte tmp;
  Byte (*b)[4] = B->b;

  tmp = b[row][0];
  b[row][0] = b[row][1];
  b[row][1] = b[row][2];
  b[row][2] = b[row][3];
  b[row][3] = tmp;
}

static void LeftShiftRow2 ( Block * B, int row ) {
  Byte (*b)[4] = B->b;

  ByteSwap ( &(b[row][0]), &(b[row][2]) );
  ByteSwap ( &(b[row][1]), &(b[row][3]) );
}

static void LeftShiftRow3 ( Block * B, int row ) {
  Byte tmp;
  Byte (*b)[4] = B->b;

  tmp = b[row][3];
  b[row][3] = b[row][2];
  b[row][2] = b[row][1];
  b[row][1] = b[row][0];
  b[row][0] = tmp;
}

static void (*LeftShiftDispatch[3]) (Block *, int) = {
  LeftShiftRow1,
  LeftShiftRow2,
  LeftShiftRow3
};

TEST_OR_STATIC void LeftShiftRow ( Block * b, int row, int count ) {
  (*LeftShiftDispatch[count-1])(b, row);
}

TEST_OR_STATIC void ShiftRows ( Block * s ) {
  LeftShiftRow ( s, 1, 1 );
  LeftShiftRow ( s, 2, 2 );
  LeftShiftRow ( s, 3, 3 );
}

static void InvShiftRows ( Block * s ) {
  LeftShiftRow ( s, 1, 3 );
  LeftShiftRow ( s, 2, 2 );
  LeftShiftRow ( s, 3, 1 );
}

static void MixColumn ( Block * B, int column ) {
  Byte (*b)[4] = B->b;
  Byte p[4];

  p[0] = GF_mult ( b[0][column], 2 ) ^ GF_mult ( b[1][column], 3 ) ^           b[2][column]      ^           b[3][column];
  p[1] =           b[0][column]      ^ GF_mult ( b[1][column], 2 ) ^ GF_mult ( b[2][column], 3 ) ^           b[3][column];
  p[2] =           b[0][column]      ^           b[1][column]      ^ GF_mult ( b[2][column], 2 ) ^ GF_mult ( b[3][column], 3);
  p[3] = GF_mult ( b[0][column], 3 ) ^           b[1][column]      ^           b[2][column]      ^ GF_mult ( b[3][column], 2);

  b[0][column] = p[0];
  b[1][column] = p[1];
  b[2][column] = p[2];
  b[3][column] = p[3];
}

static void InvMixColumn ( Block * B, int column ) {
  Byte (*b)[4] = B->b;
  Byte p[4];

  p[0] = GF_mult ( b[0][column], 0x0e ) ^ GF_mult ( b[1][column], 0x0b ) ^ GF_mult ( b[2][column], 0x0d ) ^ GF_mult ( b[3][column], 0x09 );
  p[1] = GF_mult ( b[0][column], 0x09 ) ^ GF_mult ( b[1][column], 0x0e ) ^ GF_mult ( b[2][column], 0x0b ) ^ GF_mult ( b[3][column], 0x0d );
  p[2] = GF_mult ( b[0][column], 0x0d ) ^ GF_mult ( b[1][column], 0x09 ) ^ GF_mult ( b[2][column], 0x0e ) ^ GF_mult ( b[3][column], 0x0b );
  p[3] = GF_mult ( b[0][column], 0x0b ) ^ GF_mult ( b[1][column], 0x0d ) ^ GF_mult ( b[2][column], 0x09 ) ^ GF_mult ( b[3][column], 0x0e );

  b[0][column] = p[0];
  b[1][column] = p[1];
  b[2][column] = p[2];
  b[3][column] = p[3];
}

TEST_OR_STATIC void MixColumns ( Block * s ) {
  int i;
  for ( i = 0; i < 4; i += 1 ) {
    MixColumn ( s, i );
  }
}

static void InvMixColumns ( Block * s ) {
  int i;
  for ( i = 0; i < 4; i += 1 ) {
    InvMixColumn ( s, i );
  }
}

TEST_OR_STATIC void StreamToBlock ( Byte s[], Block * B ) {
  Byte (*b)[4] = B->b;
  b[0][0] = s[0];
  b[1][0] = s[1];
  b[2][0] = s[2];
  b[3][0] = s[3];
  b[0][1] = s[4];
  b[1][1] = s[5];
  b[2][1] = s[6];
  b[3][1] = s[7];
  b[0][2] = s[8];
  b[1][2] = s[9];
  b[2][2] = s[10];
  b[3][2] = s[11];
  b[0][3] = s[12];
  b[1][3] = s[13];
  b[2][3] = s[14];
  b[3][3] = s[15];
}

TEST_OR_STATIC void BlockToStream ( Block * B, Byte s[] ) {
  Byte (*b)[4] = B->b;
  s[0] = b[0][0];
  s[1] = b[1][0];
  s[2] = b[2][0];
  s[3] = b[3][0];
  s[4] = b[0][1];
  s[5] = b[1][1];
  s[6] = b[2][1];
  s[7] = b[3][1];
  s[8] = b[0][2];
  s[9] = b[1][2];
  s[10] = b[2][2];
  s[11] = b[3][2];
  s[12] = b[0][3];
  s[13] = b[1][3];
  s[14] = b[2][3];
  s[15] = b[3][3];
}

void Cipher ( Byte input_stream[], Byte key_stream[] ) {
  int i;

  Word w[60];
  Block state;

  StreamToBlock ( input_stream, &state );

  KeyExpansion ( key_stream, w );

  dumpstate ( "input", &state );
  dumpwords ( "k_sch", w, Nk[Mode] );

  AddRoundKey ( &state, w );
  dumpstate ( "start", &state );

  for ( i = 1; i < Nr[Mode]; i += 1 ) {
    SubBytes ( &state );
    dumpstate ( "s_box", &state );
    ShiftRows ( &state );
    dumpstate ( "s_row", &state );
    MixColumns ( &state );
    dumpstate ( "m_col", &state );
    AddRoundKey ( &state, w + i * Nb[Mode] );
    dumpwords ( "k_sch", w + i * Nb[Mode], Nk[Mode] );
  }

  SubBytes ( &state );
  dumpstate ( "s_box", &state );
  ShiftRows ( &state );
  dumpstate ( "s_row", &state );
  AddRoundKey ( &state, w + i * Nb[Mode] );
  dumpwords ( "k_sch", w + i * Nb[Mode], Nk[Mode] );
  dumpstate ( "outpt", &state );

  BlockToStream ( &state, input_stream );
}

void SetMode ( int mode ) {
  Mode = mode;
}

void InvCipher ( Byte input_stream[], Byte key_stream[] ) {
  int i;

  Word w[60];
  Block state;

  StreamToBlock ( input_stream, &state );

  dumpstate ( "ainput", &state );

  KeyExpansion ( key_stream, w );

  AddRoundKey ( &state, w + Nr[Mode] * Nb[Mode] );

  for ( i = Nr[Mode] - 1; i > 0; i -= 1 ) {
    InvShiftRows ( &state );
    InvSubBytes ( &state );
    AddRoundKey ( &state, w + i * Nb[Mode] );
    InvMixColumns ( &state );
  }

  InvShiftRows ( &state );
  InvSubBytes ( &state );
  AddRoundKey ( &state, w + i * Nb[Mode] );

  dumpstate ( "binput", &state );

  BlockToStream ( &state, input_stream );
}

Byte char_to_nibble ( Byte hex ) {
  if ( hex >= 'a' && hex <= 'f' ) return hex - 'a' + 0xa;
  if ( hex >= 'A' && hex <= 'F' ) return hex - 'A' + 0xa;
  if ( hex >= '0' && hex <= '9' ) return hex - '0';
  return 0;
}

void free_bytestr ( ByteStr * out ) {
  free ( out->raw );
  free ( out );
}

ByteStr * HexString_To_Array ( Byte * hexes ) {
  int i;
  ByteStr * out = NULL;

  for ( i = 0; hexes[i]; i += 1 );

  out = malloc(sizeof(*out));
  if ( i & 1 ) out->length = (i/2) + 1;
  else out->length = i/2;
  out->raw = malloc(sizeof(*(out->raw))*i);

  printf("len: %d, out: %p, out->raw: %p\n", i, out, out->raw);

  for ( i = 0; hexes[i]; i += 2 ) {
    out->raw[i/2] = (char_to_nibble(hexes[i]) << 4);

    if ( hexes[i+1] ) {
      out->raw[i/2] |= char_to_nibble(hexes[i+1]);
    }
  }

  return out;
}

