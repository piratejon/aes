#include "aes_test.h"
#include "aes.h"
#include "tests.h"

static void sanity_check_zero ( void )
{
  ASSERT ( 0 == 0, "Zero failed to be equal to zero." );
}

static void sanity_check_one ( void )
{
  ASSERT ( 1 == 1, "One failed to be equal to one." );
}

static void test_GF_xtime ( void )
{
  ASSERT ( 0xae == GF_xtime ( 0x57 ), "GF_xtime fault" );
  ASSERT ( 0x47 == GF_xtime ( 0xae ), "GF_xtime fault" );
  ASSERT ( 0x8e == GF_xtime ( 0x47 ), "GF_xtime fault" );
  ASSERT ( 0x07 == GF_xtime ( 0x8e ), "GF_xtime fault" );
}

static void test_GF_mult ( void )
{
  ASSERT ( 0xfe == GF_mult ( 0x57, 0x13 ), "GF_mult fault" );
}

static void test_key_expansion ( void )
{
  int i;

  Word w128[44];
  Word w192[52];
  Word w256[60];

  Byte k128[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
  };

  Byte k128_2[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  };

  Word w128_2[4] = {
    {{ 0x00, 0x01, 0x02, 0x03 }},
    {{ 0x04, 0x05, 0x06, 0x07 }},
    {{ 0x08, 0x09, 0x0a, 0x0b }},
    {{ 0x0c, 0x0d, 0x0e, 0x0f }}
  };

  Byte k192[24] = {
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
    0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
  };

  Byte k256[32] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
  };

  const Word c128[44] = {
    {{ 0x2b, 0x7e, 0x15, 0x16 }},
    {{ 0x28, 0xae, 0xd2, 0xa6 }},
    {{ 0xab, 0xf7, 0x15, 0x88 }},
    {{ 0x09, 0xcf, 0x4f, 0x3c }},
    {{ 0xa0, 0xfa, 0xfe, 0x17 }},
    {{ 0x88, 0x54, 0x2c, 0xb1 }},
    {{ 0x23, 0xa3, 0x39, 0x39 }},
    {{ 0x2a, 0x6c, 0x76, 0x05 }},
    {{ 0xf2, 0xc2, 0x95, 0xf2 }},
    {{ 0x7a, 0x96, 0xb9, 0x43 }},
    {{ 0x59, 0x35, 0x80, 0x7a }},
    {{ 0x73, 0x59, 0xf6, 0x7f }},
    {{ 0x3d, 0x80, 0x47, 0x7d }},
    {{ 0x47, 0x16, 0xfe, 0x3e }},
    {{ 0x1e, 0x23, 0x7e, 0x44 }},
    {{ 0x6d, 0x7a, 0x88, 0x3b }},
    {{ 0xef, 0x44, 0xa5, 0x41 }},
    {{ 0xa8, 0x52, 0x5b, 0x7f }},
    {{ 0xb6, 0x71, 0x25, 0x3b }},
    {{ 0xdb, 0x0b, 0xad, 0x00 }},
    {{ 0xd4, 0xd1, 0xc6, 0xf8 }},
    {{ 0x7c, 0x83, 0x9d, 0x87 }},
    {{ 0xca, 0xf2, 0xb8, 0xbc }},
    {{ 0x11, 0xf9, 0x15, 0xbc }},
    {{ 0x6d, 0x88, 0xa3, 0x7a }},
    {{ 0x11, 0x0b, 0x3e, 0xfd }},
    {{ 0xdb, 0xf9, 0x86, 0x41 }},
    {{ 0xca, 0x00, 0x93, 0xfd }},
    {{ 0x4e, 0x54, 0xf7, 0x0e }},
    {{ 0x5f, 0x5f, 0xc9, 0xf3 }},
    {{ 0x84, 0xa6, 0x4f, 0xb2 }},
    {{ 0x4e, 0xa6, 0xdc, 0x4f }},
    {{ 0xea, 0xd2, 0x73, 0x21 }},
    {{ 0xb5, 0x8d, 0xba, 0xd2 }},
    {{ 0x31, 0x2b, 0xf5, 0x60 }},
    {{ 0x7f, 0x8d, 0x29, 0x2f }},
    {{ 0xac, 0x77, 0x66, 0xf3 }},
    {{ 0x19, 0xfa, 0xdc, 0x21 }},
    {{ 0x28, 0xd1, 0x29, 0x41 }},
    {{ 0x57, 0x5c, 0x00, 0x6e }},
    {{ 0xd0, 0x14, 0xf9, 0xa8 }},
    {{ 0xc9, 0xee, 0x25, 0x89 }},
    {{ 0xe1, 0x3f, 0x0c, 0xc8 }},
    {{ 0xb6, 0x63, 0x0c, 0xa6 }},
  };

  const Word c192[52] = {
    {{ 0x8e, 0x73, 0xb0, 0xf7 }},
    {{ 0xda, 0x0e, 0x64, 0x52 }},
    {{ 0xc8, 0x10, 0xf3, 0x2b }},
    {{ 0x80, 0x90, 0x79, 0xe5 }},
    {{ 0x62, 0xf8, 0xea, 0xd2 }},
    {{ 0x52, 0x2c, 0x6b, 0x7b }},
    {{ 0xfe, 0x0c, 0x91, 0xf7 }},
    {{ 0x24, 0x02, 0xf5, 0xa5 }},
    {{ 0xec, 0x12, 0x06, 0x8e }},
    {{ 0x6c, 0x82, 0x7f, 0x6b }},
    {{ 0x0e, 0x7a, 0x95, 0xb9 }},
    {{ 0x5c, 0x56, 0xfe, 0xc2 }},
    {{ 0x4d, 0xb7, 0xb4, 0xbd }},
    {{ 0x69, 0xb5, 0x41, 0x18 }},
    {{ 0x85, 0xa7, 0x47, 0x96 }},
    {{ 0xe9, 0x25, 0x38, 0xfd }},
    {{ 0xe7, 0x5f, 0xad, 0x44 }},
    {{ 0xbb, 0x09, 0x53, 0x86 }},
    {{ 0x48, 0x5a, 0xf0, 0x57 }},
    {{ 0x21, 0xef, 0xb1, 0x4f }},
    {{ 0xa4, 0x48, 0xf6, 0xd9 }},
    {{ 0x4d, 0x6d, 0xce, 0x24 }},
    {{ 0xaa, 0x32, 0x63, 0x60 }},
    {{ 0x11, 0x3b, 0x30, 0xe6 }},
    {{ 0xa2, 0x5e, 0x7e, 0xd5 }},
    {{ 0x83, 0xb1, 0xcf, 0x9a }},
    {{ 0x27, 0xf9, 0x39, 0x43 }},
    {{ 0x6a, 0x94, 0xf7, 0x67 }},
    {{ 0xc0, 0xa6, 0x94, 0x07 }},
    {{ 0xd1, 0x9d, 0xa4, 0xe1 }},
    {{ 0xec, 0x17, 0x86, 0xeb }},
    {{ 0x6f, 0xa6, 0x49, 0x71 }},
    {{ 0x48, 0x5f, 0x70, 0x32 }},
    {{ 0x22, 0xcb, 0x87, 0x55 }},
    {{ 0xe2, 0x6d, 0x13, 0x52 }},
    {{ 0x33, 0xf0, 0xb7, 0xb3 }},
    {{ 0x40, 0xbe, 0xeb, 0x28 }},
    {{ 0x2f, 0x18, 0xa2, 0x59 }},
    {{ 0x67, 0x47, 0xd2, 0x6b }},
    {{ 0x45, 0x8c, 0x55, 0x3e }},
    {{ 0xa7, 0xe1, 0x46, 0x6c }},
    {{ 0x94, 0x11, 0xf1, 0xdf }},
    {{ 0x82, 0x1f, 0x75, 0x0a }},
    {{ 0xad, 0x07, 0xd7, 0x53 }},
    {{ 0xca, 0x40, 0x05, 0x38 }},
    {{ 0x8f, 0xcc, 0x50, 0x06 }},
    {{ 0x28, 0x2d, 0x16, 0x6a }},
    {{ 0xbc, 0x3c, 0xe7, 0xb5 }},
    {{ 0xe9, 0x8b, 0xa0, 0x6f }},
    {{ 0x44, 0x8c, 0x77, 0x3c }},
    {{ 0x8e, 0xcc, 0x72, 0x04 }},
    {{ 0x01, 0x00, 0x22, 0x02 }},
  };

  const Word c256[60] = {
    {{ 0x60, 0x3d, 0xeb, 0x10 }},
    {{ 0x15, 0xca, 0x71, 0xbe }},
    {{ 0x2b, 0x73, 0xae, 0xf0 }},
    {{ 0x85, 0x7d, 0x77, 0x81 }},
    {{ 0x1f, 0x35, 0x2c, 0x07 }},
    {{ 0x3b, 0x61, 0x08, 0xd7 }},
    {{ 0x2d, 0x98, 0x10, 0xa3 }},
    {{ 0x09, 0x14, 0xdf, 0xf4 }},
    {{ 0x9b, 0xa3, 0x54, 0x11 }},
    {{ 0x8e, 0x69, 0x25, 0xaf }},
    {{ 0xa5, 0x1a, 0x8b, 0x5f }},
    {{ 0x20, 0x67, 0xfc, 0xde }},
    {{ 0xa8, 0xb0, 0x9c, 0x1a }},
    {{ 0x93, 0xd1, 0x94, 0xcd }},
    {{ 0xbe, 0x49, 0x84, 0x6e }},
    {{ 0xb7, 0x5d, 0x5b, 0x9a }},
    {{ 0xd5, 0x9a, 0xec, 0xb8 }},
    {{ 0x5b, 0xf3, 0xc9, 0x17 }},
    {{ 0xfe, 0xe9, 0x42, 0x48 }},
    {{ 0xde, 0x8e, 0xbe, 0x96 }},
    {{ 0xb5, 0xa9, 0x32, 0x8a }},
    {{ 0x26, 0x78, 0xa6, 0x47 }},
    {{ 0x98, 0x31, 0x22, 0x29 }},
    {{ 0x2f, 0x6c, 0x79, 0xb3 }},
    {{ 0x81, 0x2c, 0x81, 0xad }},
    {{ 0xda, 0xdf, 0x48, 0xba }},
    {{ 0x24, 0x36, 0x0a, 0xf2 }},
    {{ 0xfa, 0xb8, 0xb4, 0x64 }},
    {{ 0x98, 0xc5, 0xbf, 0xc9 }},
    {{ 0xbe, 0xbd, 0x19, 0x8e }},
    {{ 0x26, 0x8c, 0x3b, 0xa7 }},
    {{ 0x09, 0xe0, 0x42, 0x14 }},
    {{ 0x68, 0x00, 0x7b, 0xac }},
    {{ 0xb2, 0xdf, 0x33, 0x16 }},
    {{ 0x96, 0xe9, 0x39, 0xe4 }},
    {{ 0x6c, 0x51, 0x8d, 0x80 }},
    {{ 0xc8, 0x14, 0xe2, 0x04 }},
    {{ 0x76, 0xa9, 0xfb, 0x8a }},
    {{ 0x50, 0x25, 0xc0, 0x2d }},
    {{ 0x59, 0xc5, 0x82, 0x39 }},
    {{ 0xde, 0x13, 0x69, 0x67 }},
    {{ 0x6c, 0xcc, 0x5a, 0x71 }},
    {{ 0xfa, 0x25, 0x63, 0x95 }},
    {{ 0x96, 0x74, 0xee, 0x15 }},
    {{ 0x58, 0x86, 0xca, 0x5d }},
    {{ 0x2e, 0x2f, 0x31, 0xd7 }},
    {{ 0x7e, 0x0a, 0xf1, 0xfa }},
    {{ 0x27, 0xcf, 0x73, 0xc3 }},
    {{ 0x74, 0x9c, 0x47, 0xab }},
    {{ 0x18, 0x50, 0x1d, 0xda }},
    {{ 0xe2, 0x75, 0x7e, 0x4f }},
    {{ 0x74, 0x01, 0x90, 0x5a }},
    {{ 0xca, 0xfa, 0xaa, 0xe3 }},
    {{ 0xe4, 0xd5, 0x9b, 0x34 }},
    {{ 0x9a, 0xdf, 0x6a, 0xce }},
    {{ 0xbd, 0x10, 0x19, 0x0d }},
    {{ 0xfe, 0x48, 0x90, 0xd1 }},
    {{ 0xe6, 0x18, 0x8d, 0x0b }},
    {{ 0x04, 0x6d, 0xf3, 0x44 }},
    {{ 0x70, 0x6c, 0x63, 0x1e }},
  };

  SetMode ( FIPS_AES_128 );
  KeyExpansion ( k128, w128 );
  for ( i = 0; i < sizeof(w128)/sizeof(w128[0]); i += 1 ) {
    ASSERT ( w128[i].W[0] == c128[i].W[0], "Key expansion failed" );
    ASSERT ( w128[i].W[1] == c128[i].W[1], "Key expansion failed" );
    ASSERT ( w128[i].W[2] == c128[i].W[2], "Key expansion failed" );
    ASSERT ( w128[i].W[3] == c128[i].W[3], "Key expansion failed" );
  }

  KeyExpansion ( k128_2, w128 );
  for ( i = 0; i < 4; i += 1 ) {
    ASSERT ( w128[i].W[0] == w128_2[i].W[0], "Key expansion failed" );
    ASSERT ( w128[i].W[1] == w128_2[i].W[1], "Key expansion failed" );
    ASSERT ( w128[i].W[2] == w128_2[i].W[2], "Key expansion failed" );
    ASSERT ( w128[i].W[3] == w128_2[i].W[3], "Key expansion failed" );
  }

  SetMode ( FIPS_AES_192 );
  KeyExpansion ( k192, w192 );
  for ( i = 0; i < sizeof(w192)/sizeof(w192[0]); i += 1 ) {
    ASSERT ( w192[i].W[0] == c192[i].W[0], "Key expansion failed" );
    ASSERT ( w192[i].W[1] == c192[i].W[1], "Key expansion failed" );
    ASSERT ( w192[i].W[2] == c192[i].W[2], "Key expansion failed" );
    ASSERT ( w192[i].W[3] == c192[i].W[3], "Key expansion failed" );
  }


  SetMode ( FIPS_AES_256 );
  KeyExpansion ( k256, w256 );
  for ( i = 0; i < sizeof(w256)/sizeof(w256[0]); i += 1 ) {
    ASSERT ( w256[i].W[0] == c256[i].W[0], "Key expansion failed" );
    ASSERT ( w256[i].W[1] == c256[i].W[1], "Key expansion failed" );
    ASSERT ( w256[i].W[2] == c256[i].W[2], "Key expansion failed" );
    ASSERT ( w256[i].W[3] == c256[i].W[3], "Key expansion failed" );
  }
}

static void test_RotWord ( void )
{
  Word w = {{0x09, 0xcf, 0x4f, 0x3c }};

  RotWord ( &w );

  ASSERT ( w.W[0] == 0xcf, "RotWord fault" );
  ASSERT ( w.W[1] == 0x4f, "RotWord fault" );
  ASSERT ( w.W[2] == 0x3c, "RotWord fault" );
  ASSERT ( w.W[3] == 0x09, "RotWord fault" );
}

static void test_AddRoundKey ( void )
{
  int i;

  Block state;
  Byte output[16];

  Byte stream[16] = {
    0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
    0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
  };

  Word key[4] = {
    {{ 0x2b, 0x7e, 0x15, 0x16 }}, // column 1
    {{ 0x28, 0xae, 0xd2, 0xa6 }}, // column 2
    {{ 0xab, 0xf7, 0x15, 0x88 }}, // column 3
    {{ 0x09, 0xcf, 0x4f, 0x3c }}, // column 4
  };

  const Byte result[16] = {
    0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b,
    0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8, 0x48, 0x08
  };

  SetMode ( FIPS_AES_128 );

  StreamToBlock ( stream, &state );

  AddRoundKey ( &state, key );

  BlockToStream ( &state, output );

  // dumpbytes ( output, 16 );
  // dumpbytes ( result, 16 );

  for ( i = 0; i < 16; i += 1 ) {
    ASSERT ( output[i] == result[i], "AddRoundKey fault" );
  }
}

static void test_Cipher ( void )
{
  int i;

  Byte input_stream_128[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  };

  Byte key_stream_128[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  };

  Byte result_stream_128[16] = {
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
  };

  Byte input_stream_192[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  };

  Byte key_stream_192[24] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
  };

  Byte result_stream_192[16] = {
    0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
    0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91
  };

  Byte input_stream_256[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  };

  Byte key_stream_256[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
  };

  Byte result_stream_256[16] = {
    0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
    0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89
  };

  SetMode ( FIPS_AES_128 );
  Cipher ( input_stream_128, key_stream_128 );
  for ( i = 0; i < sizeof(input_stream_128)/sizeof(input_stream_128[0]); i += 1 ) {
    ASSERT ( input_stream_128[i] == result_stream_128[i], "cipher fault" );
  }

  SetMode ( FIPS_AES_192 );
  Cipher ( input_stream_192, key_stream_192 );
  for ( i = 0; i < sizeof(input_stream_192)/sizeof(input_stream_192[0]); i += 1 ) {
    ASSERT ( input_stream_192[i] == result_stream_192[i], "cipher fault" );
  }

  SetMode ( FIPS_AES_256 );
  Cipher ( input_stream_256, key_stream_256 );
  for ( i = 0; i < sizeof(input_stream_256)/sizeof(input_stream_256[0]); i += 1 ) {
    ASSERT ( input_stream_256[i] == result_stream_256[i], "cipher fault" );
  }
}

static void test_MixColumns ( void )
{
  int i, j;

  Block state = {
    {
    { 0xd4, 0xe0, 0xb8, 0x1e },
    { 0xbf, 0xb4, 0x41, 0x27 },
    { 0x5d, 0x52, 0x11, 0x98 },
    { 0x30, 0xae, 0xf1, 0xe5 }
    }
  };

  Block correct = {
    {
    { 0x04, 0xe0, 0x48, 0x28 },
    { 0x66, 0xcb, 0xf8, 0x06 },
    { 0x81, 0x19, 0xd3, 0x26 },
    { 0xe5, 0x9a, 0x7a, 0x4c },
    }
  };

  MixColumns ( &state );

  // dumpstate ( "MixColumns result", &state );
  // dumpstate ( "MixColumns expect", &correct );

  for ( i = 0; i < 4; i += 1 ) {
    for ( j = 0; j < 4; j += 1 ) {
      ASSERT ( state.b[i][j] == correct.b[i][j], "MixColumns fault" );
    }
  }
}

static void test_ShiftRow ( void )
{
  Byte stream[16] = {
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
    0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf
  };

  Block block;

  StreamToBlock ( stream, &block );

  LeftShiftRow ( &block, 1, 1 );
  ASSERT ( block.b[1][0] == 5, "LeftShiftRow fault" );
  ASSERT ( block.b[1][1] == 9, "LeftShiftRow fault" );
  ASSERT ( block.b[1][2] == 0xd, "LeftShiftRow fault" );
  ASSERT ( block.b[1][3] == 1, "LeftShiftRow fault" );

  LeftShiftRow ( &block, 2, 2 );
  ASSERT ( block.b[2][0] == 0xa, "LeftShiftRow fault" );
  ASSERT ( block.b[2][1] == 0xe, "LeftShiftRow fault" );
  ASSERT ( block.b[2][2] == 2, "LeftShiftRow fault" );
  ASSERT ( block.b[2][3] == 6, "LeftShiftRow fault" );

  LeftShiftRow ( &block, 3, 3 );
  ASSERT ( block.b[3][0] == 0xf, "LeftShiftRow fault" );
  ASSERT ( block.b[3][1] == 3, "LeftShiftRow fault" );
  ASSERT ( block.b[3][2] == 7, "LeftShiftRow fault" );
  ASSERT ( block.b[3][3] == 0xb, "LeftShiftRow fault" );
}

static void test_ShiftRows ( void )
{
  int i;

  Byte input_stream[16] = {
    0x63, 0xca, 0xb7, 0x04, 0x09, 0x53, 0xd0, 0x51,
    0xcd, 0x60, 0xe0, 0xe7, 0xba, 0x70, 0xe1, 0x8c
  };

  Byte result_stream[16] = {
    0x63, 0x53, 0xe0, 0x8c, 0x09, 0x60, 0xe1, 0x04,
    0xcd, 0x70, 0xb7, 0x51, 0xba, 0xca, 0xd0, 0xe7
  };

  Block state;
  Byte output_stream[16];

  StreamToBlock ( input_stream, &state );

  // dumpstate ( "ShiftRows before", &state );
  ShiftRows ( &state );
  // dumpstate ( "ShiftRows  after", &state );

  BlockToStream ( &state, output_stream );

  for ( i = 0; i < 16; i += 1 ) {
    ASSERT ( output_stream[i] == result_stream[i], "ShiftRows fault" );
  }
}

static void test_StreamToBlock ( void )
{
  Byte s[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };

  Block b;

  StreamToBlock ( s, &b );

  ASSERT ( b.b[0][0] == 0x0, "StreamToBlock fault" );
  ASSERT ( b.b[1][0] == 0x1, "StreamToBlock fault" );
  ASSERT ( b.b[2][0] == 0x2, "StreamToBlock fault" );
  ASSERT ( b.b[3][0] == 0x3, "StreamToBlock fault" );
  ASSERT ( b.b[0][1] == 0x4, "StreamToBlock fault" );
  ASSERT ( b.b[1][1] == 0x5, "StreamToBlock fault" );
  ASSERT ( b.b[2][1] == 0x6, "StreamToBlock fault" );
  ASSERT ( b.b[3][1] == 0x7, "StreamToBlock fault" );
  ASSERT ( b.b[0][2] == 0x8, "StreamToBlock fault" );
  ASSERT ( b.b[1][2] == 0x9, "StreamToBlock fault" );
  ASSERT ( b.b[2][2] == 0xa, "StreamToBlock fault" );
  ASSERT ( b.b[3][2] == 0xb, "StreamToBlock fault" );
  ASSERT ( b.b[0][3] == 0xc, "StreamToBlock fault" );
  ASSERT ( b.b[1][3] == 0xd, "StreamToBlock fault" );
  ASSERT ( b.b[2][3] == 0xe, "StreamToBlock fault" );
  ASSERT ( b.b[3][3] == 0xf, "StreamToBlock fault" );
}

static void test_BlockToStream ( void )
{
  int i;

  Byte s[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
  Byte t[16];

  Block b;

  StreamToBlock ( s, &b );
  BlockToStream ( &b, t );

  // dumpbytes ( s, sizeof(s)/sizeof(s[0]) );
  // dumpbytes ( t, sizeof(t)/sizeof(t[0]) );

  for ( i = 0; i < sizeof(t)/sizeof(t[0]); i += 1 ) {
    ASSERT ( s[i] == t[i], "BlockToStream fault" );
  }
}

static void test_InvCipher ( void )
{
  int i;

  Byte key_stream_128[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  };

  Byte input_stream_128[16] = {
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
  };

  Byte output_stream_128[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  };

  Byte key_stream_192[24] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
  };

  Byte input_stream_192[16] = {
    0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
    0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91
  };

  Byte output_stream_192[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  };

  Byte key_stream_256[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
  };

  Byte input_stream_256[16] = {
    0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
    0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89
  };

  Byte output_stream_256[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  };


  SetMode ( FIPS_AES_128 );
  InvCipher ( input_stream_128, key_stream_128 );
  for ( i = 0; i < sizeof(input_stream_128)/sizeof(input_stream_128[0]); i += 1 ) {
    ASSERT ( input_stream_128[i] == output_stream_128[i], "InvCipher fail" );
  }

  SetMode ( FIPS_AES_192 );
  InvCipher ( input_stream_192, key_stream_192 );
  for ( i = 0; i < sizeof(input_stream_192)/sizeof(input_stream_192[0]); i += 1 ) {
    ASSERT ( input_stream_192[i] == output_stream_192[i], "InvCipher fail" );
  }

  SetMode ( FIPS_AES_256 );
  InvCipher ( input_stream_256, key_stream_256 );
  for ( i = 0; i < sizeof(input_stream_256)/sizeof(input_stream_256[0]); i += 1 ) {
    ASSERT ( input_stream_256[i] == output_stream_256[i], "InvCipher fail" );
  }
}

static void test_NIST_SP_800_38A_CBC_Enc_128 ( void ) {
  char * key_128_cbc_enc = "2b7e151628aed2a6abf7158809cf4f3c";
  char * iv_128_cbc_enc = "000102030405060708090a0b0c0d0e0f";
  char * pt_128_cbc_enc[] = {
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
  };
  char * ct_128_cbc_enc[] = {
    "7649abac8119b246cee98e9b12e9197d",
    "5086cb9b507219ee95db113a917678b2",
    "73bed6b8e3c1743b7116e69e22229516",
    "3ff1caa1681fac09120eca307586e1a7",
  };

  int i, b;
  ByteStr * key, * iv;
  ByteStr * pt[4], * ct[4], * ct_cmp[4];

  SetMode(FIPS_AES_128);
  key = HexString_To_Array ( key_128_cbc_enc );
  iv = HexString_To_Array ( iv_128_cbc_enc );
  for ( i = 0; i < 4; i += 1 ) {
    pt[i] = HexString_To_Array ( pt_128_cbc_enc[i] );
    ct_cmp[i] = HexString_To_Array ( ct_128_cbc_enc[i] );
    ct[i] = AllocateByteStr ( 16 );
  }
  CBC_Forward(iv, key, pt, ct, 4);
  for ( i = 0; i < 4; i += 1 ) {
    for ( b = 0; b < 16; b += 1 ) {
      ASSERT ( ct[i]->raw[b] == ct[i]->raw[b], "Wrong ciphertext." );
    }
  }
  for ( i = 0; i < 4; i += 1 ) {
    free_bytestr(pt[i]);
    free_bytestr(ct[i]);
    free_bytestr(ct_cmp[i]);
  }
  free_bytestr(key);
  free_bytestr(iv);
}

static void test_NIST_SP_800_38A_CBC_Dec_128 ( void ) {
  char * key_128_cbc_dec = "2b7e151628aed2a6abf7158809cf4f3c";
  char * iv_128_cbc_dec = "000102030405060708090a0b0c0d0e0f";
  char * ct_128_cbc_dec[] = {
    "7649abac8119b246cee98e9b12e9197d",
    "5086cb9b507219ee95db113a917678b2",
    "73bed6b8e3c1743b7116e69e22229516",
    "3ff1caa1681fac09120eca307586e1a7",
  };
  char * pt_128_cbc_dec[] = {
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710", 
  };

  int i, b;
  ByteStr * key, * iv;
  ByteStr * pt[4], * ct[4], * pt_cmp[4];

  SetMode(FIPS_AES_128);
  key = HexString_To_Array ( key_128_cbc_dec );
  iv = HexString_To_Array ( iv_128_cbc_dec );
  for ( i = 0; i < 4; i += 1 ) {
    ct[i] = HexString_To_Array ( ct_128_cbc_dec[i] );
    pt_cmp[i] = HexString_To_Array ( pt_128_cbc_dec[i] );
    pt[i] = AllocateByteStr ( 16 );
  }
  CBC_Reverse(iv, key, ct, pt, 4);
  for ( i = 0; i < 4; i += 1 ) {
    for ( b = 0; b < 16; b += 1 ) {
      ASSERT ( pt[i]->raw[b] == pt_cmp[i]->raw[b], "Wrong ciphertext." );
    }
  }
  for ( i = 0; i < 4; i += 1 ) {
    free_bytestr(pt[i]);
    free_bytestr(ct[i]);
    free_bytestr(pt_cmp[i]);
  }
  free_bytestr(key);
  free_bytestr(iv);
}

static void test_NIST_SP_800_38A_CBC_Enc_192 ( void ) {
  char * key_192_cbc_enc = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
  char * iv_192_cbc_enc = "000102030405060708090a0b0c0d0e0f";
  char * pt_192_cbc_enc[] = {
    "6bc1bee22e409f96e93d7e117393172a", 
    "ae2d8a571e03ac9c9eb76fac45af8e51", 
    "30c81c46a35ce411e5fbc1191a0a52ef", 
    "f69f2445df4f9b17ad2b417be66c3710", 
  };
  char * ct_192_cbc_enc[] = {
    "4f021db243bc633d7178183a9fa071e8",
    "b4d9ada9ad7dedf4e5e738763f69145a", 
    "571b242012fb7ae07fa9baac3df102e0", 
    "08b0e27988598881d920a9e64f5615cd",
  };

  int i, b;
  ByteStr * key, * iv;
  ByteStr * pt[4], * ct[4], * ct_cmp[4];

  SetMode(FIPS_AES_192);
  key = HexString_To_Array ( key_192_cbc_enc );
  iv = HexString_To_Array ( iv_192_cbc_enc );
  for ( i = 0; i < 4; i += 1 ) {
    pt[i] = HexString_To_Array ( pt_192_cbc_enc[i] );
    ct_cmp[i] = HexString_To_Array ( ct_192_cbc_enc[i] );
    ct[i] = AllocateByteStr ( 16 );
  }
  CBC_Forward(iv, key, pt, ct, 4);
  for ( i = 0; i < 4; i += 1 ) {
    for ( b = 0; b < 16; b += 1 ) {
      ASSERT ( ct[i]->raw[b] == ct[i]->raw[b], "Wrong ciphertext." );
    }
  }
  for ( i = 0; i < 4; i += 1 ) {
    free_bytestr(pt[i]);
    free_bytestr(ct[i]);
    free_bytestr(ct_cmp[i]);
  }
  free_bytestr(key);
  free_bytestr(iv);
}

static void test_NIST_SP_800_38A_CBC_Dec_192 ( void ) {
  char * key_192_cbc_dec = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
  char * iv_192_cbc_dec = "000102030405060708090a0b0c0d0e0f";
  char * ct_192_cbc_dec[] = {
    "4f021db243bc633d7178183a9fa071e8",
    "b4d9ada9ad7dedf4e5e738763f69145a",
    "571b242012fb7ae07fa9baac3df102e0",
    "08b0e27988598881d920a9e64f5615cd",
  };
  char * pt_192_cbc_dec[] = {
    "6bc1bee22e409f96e93d7e117393172a", 
    "ae2d8a571e03ac9c9eb76fac45af8e51", 
    "30c81c46a35ce411e5fbc1191a0a52ef", 
    "f69f2445df4f9b17ad2b417be66c3710", 
  };

  int i, b;
  ByteStr * key, * iv;
  ByteStr * pt[4], * ct[4], * pt_cmp[4];

  SetMode(FIPS_AES_192);
  key = HexString_To_Array ( key_192_cbc_dec );
  iv = HexString_To_Array ( iv_192_cbc_dec );
  for ( i = 0; i < 4; i += 1 ) {
    ct[i] = HexString_To_Array ( ct_192_cbc_dec[i] );
    pt_cmp[i] = HexString_To_Array ( pt_192_cbc_dec[i] );
    pt[i] = AllocateByteStr ( 16 );
  }
  CBC_Reverse(iv, key, ct, pt, 4);
  for ( i = 0; i < 4; i += 1 ) {
    for ( b = 0; b < 16; b += 1 ) {
      ASSERT ( pt[i]->raw[b] == pt_cmp[i]->raw[b], "Wrong ciphertext." );
    }
  }
  for ( i = 0; i < 4; i += 1 ) {
    free_bytestr(pt[i]);
    free_bytestr(ct[i]);
    free_bytestr(pt_cmp[i]);
  }
  free_bytestr(key);
  free_bytestr(iv);
}

static void test_NIST_SP_800_38A_CBC_Enc_256 ( void ) {
  char * key_256_cbc_enc = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
  char * iv_256_cbc_enc = "000102030405060708090a0b0c0d0e0f";
  char * pt_256_cbc_enc[] = {
    "6bc1bee22e409f96e93d7e117393172a", 
    "ae2d8a571e03ac9c9eb76fac45af8e51", 
    "30c81c46a35ce411e5fbc1191a0a52ef", 
    "f69f2445df4f9b17ad2b417be66c3710", 
  };
  char * ct_256_cbc_enc[] = {
    "f58c4c04d6e5f1ba779eabfb5f7bfbd6", 
    "9cfc4e967edb808d679f777bc6702c7d", 
    "39f23369a9d9bacfa530e26304231461", 
    "b2eb05e2c39be9fcda6c19078c6a9d1b", 
  };

  int i, b;
  ByteStr * key, * iv;
  ByteStr * pt[4], * ct[4], * ct_cmp[4];

  SetMode(FIPS_AES_256);
  key = HexString_To_Array ( key_256_cbc_enc );
  iv = HexString_To_Array ( iv_256_cbc_enc );
  for ( i = 0; i < 4; i += 1 ) {
    pt[i] = HexString_To_Array ( pt_256_cbc_enc[i] );
    ct_cmp[i] = HexString_To_Array ( ct_256_cbc_enc[i] );
    ct[i] = AllocateByteStr ( 16 );
  }
  CBC_Forward(iv, key, pt, ct, 4);
  for ( i = 0; i < 4; i += 1 ) {
    for ( b = 0; b < 16; b += 1 ) {
      ASSERT ( ct[i]->raw[b] == ct[i]->raw[b], "Wrong ciphertext." );
    }
  }
  for ( i = 0; i < 4; i += 1 ) {
    free_bytestr(pt[i]);
    free_bytestr(ct[i]);
    free_bytestr(ct_cmp[i]);
  }
  free_bytestr(key);
  free_bytestr(iv);
}

static void test_NIST_SP_800_38A_CBC_Dec_256 ( void ) {
  char * key_256_cbc_dec = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
  char * iv_256_cbc_dec = "000102030405060708090a0b0c0d0e0f";
  char * ct_256_cbc_dec[] = {
    "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
    "9cfc4e967edb808d679f777bc6702c7d",
    "39f23369a9d9bacfa530e26304231461",
    "b2eb05e2c39be9fcda6c19078c6a9d1b",
  };
  char * pt_256_cbc_dec[] = {
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
  };

  int i, b;
  ByteStr * key, * iv;
  ByteStr * pt[4], * ct[4], * pt_cmp[4];

  SetMode(FIPS_AES_256);
  key = HexString_To_Array ( key_256_cbc_dec );
  iv = HexString_To_Array ( iv_256_cbc_dec );
  for ( i = 0; i < 4; i += 1 ) {
    ct[i] = HexString_To_Array ( ct_256_cbc_dec[i] );
    pt_cmp[i] = HexString_To_Array ( pt_256_cbc_dec[i] );
    pt[i] = AllocateByteStr ( 16 );
  }
  CBC_Reverse(iv, key, ct, pt, 4);
  for ( i = 0; i < 4; i += 1 ) {
    for ( b = 0; b < 16; b += 1 ) {
      ASSERT ( pt[i]->raw[b] == pt_cmp[i]->raw[b], "Wrong ciphertext." );
    }
  }
  for ( i = 0; i < 4; i += 1 ) {
    free_bytestr(pt[i]);
    free_bytestr(ct[i]);
    free_bytestr(pt_cmp[i]);
  }
  free_bytestr(key);
  free_bytestr(iv);
}

static void test_NIST_SP_800_38A_ECB_Enc_128 ( void ) {
  char * key_ecb_128_enc = "2b7e151628aed2a6abf7158809cf4f3c";
  char * tv_ecb_128_enc[] = {
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
  };
  char * ct_ecb_128_enc[] = {
    "3ad77bb40d7a3660a89ecaf32466ef97",
    "f5d3d58503b9699de785895a96fdbaaf",
    "43b1cd7f598ece23881b00e3ed030688",
    "7b0c785e27e8ad3f8223207104725dd4",
  };

  int i, j;
  ByteStr * key, * ct, * tv;

  SetMode(FIPS_AES_128);
  key = HexString_To_Array(key_ecb_128_enc);
  for ( i = 0; i < 4; i += 1 ) {
    tv = HexString_To_Array(tv_ecb_128_enc[i]);
    ct = HexString_To_Array(ct_ecb_128_enc[i]);

    Cipher ( tv->raw, key->raw );

    for ( j = 0; j < tv->length; j += 1 ) {
      ASSERT ( tv->raw[j] == ct->raw[j], "Wrong ciphertext." );
    }

    free_bytestr ( ct );
    free_bytestr ( tv );
  }
  free_bytestr(key);
}

static void test_NIST_SP_800_38A_ECB_Dec_128 ( void ) {
  char * key_ecb_128_dec = "2b7e151628aed2a6abf7158809cf4f3c";
  char * tv_ecb_128_dec[] = {
    "3ad77bb40d7a3660a89ecaf32466ef97",
    "f5d3d58503b9699de785895a96fdbaaf",
    "43b1cd7f598ece23881b00e3ed030688",
    "7b0c785e27e8ad3f8223207104725dd4",
  };
  char * pt_ecb_128_dec[] = {
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
  };

  int i, j;
  ByteStr * key, * ct, * tv;

  SetMode(FIPS_AES_128);
  key = HexString_To_Array(key_ecb_128_dec);

  for ( i = 0; i < 4; i += 1 ) {
    tv = HexString_To_Array(tv_ecb_128_dec[i]);
    ct = HexString_To_Array(pt_ecb_128_dec[i]);

    InvCipher ( tv->raw, key->raw );

    for ( j = 0; j < tv->length; j += 1 ) {
      ASSERT ( tv->raw[j] == ct->raw[j], "Wrong plaintext." );
    }

    free_bytestr ( ct );
    free_bytestr ( tv );
  }
  free_bytestr(key);
}

static void test_NIST_SP_800_38A_ECB_Enc_192 ( void ) {
  char * key_ecb_192_enc = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
  char * tv_ecb_192_enc[] = {
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
  };
  char * ct_ecb_192_enc[] = {
    "bd334f1d6e45f25ff712a214571fa5cc",
    "974104846d0ad3ad7734ecb3ecee4eef",
    "ef7afd2270e2e60adce0ba2face6444e",
    "9a4b41ba738d6c72fb16691603c18e0e",
  };

  int i, j;
  ByteStr * key, * ct, * tv;

  SetMode(FIPS_AES_192);
  key = HexString_To_Array(key_ecb_192_enc);
  for ( i = 0; i < 4; i += 1 ) {
    tv = HexString_To_Array(tv_ecb_192_enc[i]);
    ct = HexString_To_Array(ct_ecb_192_enc[i]);

    Cipher ( tv->raw, key->raw );

    for ( j = 0; j < tv->length; j += 1 ) {
      ASSERT ( tv->raw[j] == ct->raw[j], "Wrong ciphertext." );
    }

    free_bytestr ( ct );
    free_bytestr ( tv );
  }
  free_bytestr(key);
}

static void test_NIST_SP_800_38A_ECB_Dec_192 ( void ) {
  char * key_ecb_192_dec = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
  char * tv_ecb_192_dec[] = {
    "bd334f1d6e45f25ff712a214571fa5cc",
    "974104846d0ad3ad7734ecb3ecee4eef",
    "ef7afd2270e2e60adce0ba2face6444e",
    "9a4b41ba738d6c72fb16691603c18e0e",
  };
  char * pt_ecb_192_dec[] = {
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
  };

  int i, j;
  ByteStr * key, * ct, * tv;

  SetMode(FIPS_AES_192);
  key = HexString_To_Array(key_ecb_192_dec);
  for ( i = 0; i < 4; i += 1 ) {
    tv = HexString_To_Array(tv_ecb_192_dec[i]);
    ct = HexString_To_Array(pt_ecb_192_dec[i]);

    InvCipher ( tv->raw, key->raw );

    for ( j = 0; j < tv->length; j += 1 ) {
      ASSERT ( tv->raw[j] == ct->raw[j], "Wrong plaintext." );
    }

    free_bytestr ( ct );
    free_bytestr ( tv );
  }
  free_bytestr(key);
}

static void test_NIST_SP_800_38A_ECB_Enc_256 ( void ) {
  char * key_ecb_256_enc = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
  char * tv_ecb_256_enc[] = {
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
  };
  char * ct_ecb_256_enc[] = {
    "f3eed1bdb5d2a03c064b5a7e3db181f8",
    "591ccb10d410ed26dc5ba74a31362870",
    "b6ed21b99ca6f4f9f153e7b1beafed1d",
    "23304b7a39f9f3ff067d8d8f9e24ecc7",
  };

  int i, j;
  ByteStr * key, * ct, * tv;

  SetMode(FIPS_AES_256);
  key = HexString_To_Array(key_ecb_256_enc);
  for ( i = 0; i < 4; i += 1 ) {
    tv = HexString_To_Array(tv_ecb_256_enc[i]);
    ct = HexString_To_Array(ct_ecb_256_enc[i]);

    Cipher ( tv->raw, key->raw );

    for ( j = 0; j < tv->length; j += 1 ) {
      ASSERT ( tv->raw[j] == ct->raw[j], "Wrong ciphertext." );
    }

    free_bytestr ( ct );
    free_bytestr ( tv );
  }
  free_bytestr(key);
}

static void test_NIST_SP_800_38A_ECB_Dec_256 ( void ) {
  char * key_ecb_256_dec = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
  char * tv_ecb_256_dec[] = {
    "f3eed1bdb5d2a03c064b5a7e3db181f8",
    "591ccb10d410ed26dc5ba74a31362870",
    "b6ed21b99ca6f4f9f153e7b1beafed1d",
    "23304b7a39f9f3ff067d8d8f9e24ecc7",
  };
  char * pt_ecb_256_dec[] = {
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
  };

  int i, j;
  ByteStr * key, * ct, * tv;

  SetMode(FIPS_AES_256);
  key = HexString_To_Array(key_ecb_256_dec);
  for ( i = 0; i < 4; i += 1 ) {
    tv = HexString_To_Array(tv_ecb_256_dec[i]);
    ct = HexString_To_Array(pt_ecb_256_dec[i]);

    InvCipher ( tv->raw, key->raw );

    for ( j = 0; j < tv->length; j += 1 ) {
      ASSERT ( tv->raw[j] == ct->raw[j], "Wrong plaintext." );
    }

    free_bytestr ( ct );
    free_bytestr ( tv );
  }
  free_bytestr(key);
}

static void test_HexString_To_Array ( void )
{
  char * str = "6bc1bee22e409f96e93d7e117393172a";
  ByteStr * out;
  Byte hex[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };

  int i;

  out = HexString_To_Array(str);

  ASSERT ( out != NULL, "wtf out" );

  ASSERT ( out->length == 16, "Wrong length of ByteStr" );

  for ( i = 0; i < sizeof(hex); i += 1 ) {
    ASSERT ( hex[i] == out->raw[i], "Wrong byte" );
  }

  free_bytestr(out);
 
  out = HexString_To_Array("01");
  ASSERT ( out->length == 1, "Wrong length on single byte hex string." );
  ASSERT ( out->raw[0] == 0x01, "Wrong value on single byte hex string." );
  free_bytestr ( out );
 
  out = HexString_To_Array("0");
  ASSERT ( out->length == 1, "Wrong length on single byte hex string." );
  ASSERT ( out->raw[0] == 0x00, "Wrong value on single byte hex string." );
  free_bytestr ( out );
}

static void test_NIST_SP_800_38A_CFB1_Enc_128 ( void ) {
  char * key_cfb1_enc_128 = "2b7e151628aed2a6abf7158809cf4f3c";
  char * iv_cfb1_enc_128 = "000102030405060708090a0b0c0d0e0f";

  char * input_block_cfb1_enc_128[] = {
    "000102030405060708090a0b0c0d0e0f",
    "00020406080a0c0e10121416181a1c1e",
    "0004080c1014181c2024282c3034383d",
    "0008101820283038404850586068707b",
    "00102030405060708090a0b0c0d0e0f6",
    "0020406080a0c0e10121416181a1c1ed",
    "004080c1014181c2024282c3034383da",
    "008101820283038404850586068707b4",
    "0102030405060708090a0b0c0d0e0f68",
    "020406080a0c0e10121416181a1c1ed1",
    "04080c1014181c2024282c3034383da2",
    "08101820283038404850586068707b45",
    "102030405060708090a0b0c0d0e0f68b",
    "20406080a0c0e10121416181a1c1ed16",
    "4080c1014181c2024282c3034383da2c",
    "8101820283038404850586068707b459",
  };

  char * output_block_cfb1_enc_128[] = {
    "50fe67cc996d32b6da0937e99bafec60",
    "19cf576c7596e702f298b35666955c79",
    "59e17759acd02b801fa321ea059e331f",
    "71f415b0cc109e8b0faa14ab740c22f4",
    "3fb76d3d1048179964597a0f64d5adad",
    "4c943b4bac54ab974e3e52326d29aaa1",
    "c94da41eb3d3acf1993a512ab1e8203f",
    "e07f5e98778f75dbb2691c3f582c3953",
    "02ef5fc8961efcce8568bc0731262dc7",
    "9f5a30367065efbe914b53698c8716b7",
    "d018cfb81d0580edbff955ed74d382db",
    "81272ab351e08e0b695b94b8164d86f4",
    "094d33f856483d3fa01ba94f7e5ab3e7",
    "609900ad61923c8c102cd8d0d7947a2c",
    "9e5a154de966ab4db9c88b22a398134e",
    "7fe16252b338bc4de3725c4156dfed20",
  };

  char * pt_cfb1_enc_128[] = { // only use lsb
    "0","01","01","0","01","0","01","01","01","01","0","0","0","0","0","01"
  };

  char * ct_cfb1_enc_128[] = { // only use lsb
    "0","01","01","0","01","0","0","0","01","0","01","01","0","0","01","01",
  };

  int i;
  ByteStr * key, * iv, *pt[16], *ct[16], *out[16];

  key = HexString_To_Array ( key_cfb1_enc_128 );
  iv = HexString_To_Array ( iv_cfb1_enc_128 );

  for ( i = 0; i < 16; i += 1 ) {
    ct[i] = HexString_To_Array ( ct_cfb1_enc_128[i] );
  }
  for ( i = 0; i < 16; i += 1 ) {
    pt[i] = HexString_To_Array ( pt_cfb1_enc_128[i] );
  }
  for ( i = 0; i < 16; i += 1 ) {
    out[i] = HexString_To_Array ( output_block_cfb1_enc_128[i] );
  }

  SetMode(FIPS_AES_128);
  Cipher(iv->raw, key->raw);
  for ( i = 0; i < 16; i += 1 ) ASSERT(iv->raw[i] == out[0]->raw[i], "Wrong output from CFB1 cipher iter 1.");
  XorString ( iv->raw, pt[0]->raw, pt[0]->length );
  ASSERT( (iv->raw[0] & 0x01) == (ct[0]->raw[0] & 0x01), "Wrong ct" );

  // ByteCopy ( bip->raw, iv->raw, 16 );

  for ( i = 0; i < 16; i += 1 ) {
    free_bytestr(ct[i]);
    free_bytestr(pt[i]);
    free_bytestr(out[i]);
  }

  free_bytestr(key);
  free_bytestr(iv);
}

void do_tests ( void )
{
  TEST ( sanity_check_zero );
  TEST ( sanity_check_one );
  TEST ( test_GF_xtime );
  TEST ( test_GF_mult );
  TEST ( test_RotWord );
  TEST ( test_key_expansion );
  TEST ( test_StreamToBlock );
  TEST ( test_BlockToStream );
  TEST ( test_AddRoundKey );
  TEST ( test_MixColumns );
  TEST ( test_ShiftRow );
  TEST ( test_ShiftRows );
  TEST ( test_Cipher );
  TEST ( test_InvCipher );
  TEST ( test_NIST_SP_800_38A_ECB_Enc_128 );
  TEST ( test_NIST_SP_800_38A_ECB_Enc_192 );
  TEST ( test_NIST_SP_800_38A_ECB_Enc_256 );
  TEST ( test_NIST_SP_800_38A_CBC_Enc_128 );
  TEST ( test_NIST_SP_800_38A_CBC_Enc_192 );
  TEST ( test_NIST_SP_800_38A_CBC_Enc_256 );
  TEST ( test_NIST_SP_800_38A_ECB_Dec_128 );
  TEST ( test_NIST_SP_800_38A_ECB_Dec_192 );
  TEST ( test_NIST_SP_800_38A_ECB_Dec_256 );
  TEST ( test_NIST_SP_800_38A_CBC_Dec_128 );
  TEST ( test_NIST_SP_800_38A_CBC_Dec_192 );
  TEST ( test_NIST_SP_800_38A_CBC_Dec_256 );
  TEST ( test_NIST_SP_800_38A_CFB1_Enc_128 );
  TEST ( test_HexString_To_Array );
}

