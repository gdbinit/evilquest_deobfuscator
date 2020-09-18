//
// Latest EvilQuest/ThiefQuest strings decrypt/deobfuscator
//
// reference: https://reverse.put.as/2020/09/17/evilquest-revisited/
//
// python implementation for previous sample(s) by Scott Knight
// https://github.com/carbonblack/tau-tools/tree/master/malware_specific/ThiefQuest
//
// (c) Pedro Vilaça 2020, All rights reserved.
// reverser@put.as - https://reverse.put.as
//
package main

import (
	"os"
	"fmt"
	"flag"
	"bytes"
	"strings"
	"encoding/binary"
	"debug/macho"
	_ "encoding/hex"
)

// https://qvault.io/2019/10/21/golang-constant-maps-slices/
func getLookupTable() []byte {
	return []byte{0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0xA,0xB,0xC,0xD,0xE,0xF,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,0x21,0x22,0x23,0x0,0x0,0x0,0x0,0x0,0x0,0x24,0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F,0x0,0x0,0x0}
}

func getLookupTable2() []byte {
	return []byte{0xD9,0x78,0xF9,0xC4,0x19,0xDD,0xB5,0xED,0x28,0xE9,0xFD,0x79,0x4A,0xA0,0xD8,0x9D,0xC6,0x7E,0x37,0x83,0x2B,0x76,0x53,0x8E,0x62,0x4C,0x64,0x88,0x44,0x8B,0xFB,0xA2,0x17,0x9A,0x59,0xF5,0x87,0xB3,0x4F,0x13,0x61,0x45,0x6D,0x8D,0x09,0x81,0x7D,0x32,0xBD,0xC9,0x40,0xEB,0x86,0xB7,0x7B,0x0B,0xF0,0x95,0x21,0x22,0x5C,0x6B,0x4E,0x82,0x54,0xD6,0x65,0x93,0xCE,0x60,0xB2,0x1C,0x73,0x56,0x71,0x14,0xA7,0x8C,0xF1,0xDC,0x12,0x75,0xCA,0x1F,0x3B,0xBE,0xE4,0xD1,0x42,0x3D,0xD4,0x30,0xA3,0x3C,0xB6,0x26,0x6F,0xBF,0x0E,0xDA,0x46,0x69,0x07,0x57,0x27,0xF2,0xD2,0x9B,0xBC,0x94,0x43,0x03,0xF8,0x11,0x6C,0xF6,0x90,0xEF,0x3E,0xE7,0x06,0xC3,0xD5,0x2F,0xC8,0x66,0x1E,0xD7,0x08,0xE8,0xEA,0xDE,0x80,0x52,0xEE,0xF7,0x84,0xAA,0x72,0xAC,0x35,0x4D,0x6A,0x2A,0x96,0x1A,0x1D,0xC0,0x5A,0x15,0x49,0x74,0x4B,0x9F,0xD0,0x5E,0x04,0x18,0xA4,0xEC,0xC2,0xE0,0x41,0x6E,0x0F,0x51,0xCB,0xCC,0x24,0x91,0xAF,0x50,0xA1,0xF4,0x70,0x39,0x99,0x7C,0x3A,0x85,0x23,0xB8,0xB4,0x7A,0xFC,0x02,0x36,0x5B,0x25,0x55,0x97,0x31,0x2D,0x5D,0xFA,0x98,0xE3,0x8A,0x92,0xAE,0x05,0xDF,0x29,0x10,0x67,0xC7,0xBA,0x8F,0xD3,0x00,0xE6,0xCF,0xE1,0x9E,0xA8,0x2C,0x63,0x16,0x01,0x3F,0x58,0xE2,0x89,0xA9,0x0D,0x38,0x34,0x1B,0xAB,0x33,0xFF,0xB0,0xBB,0x7F,0x0C,0x5F,0xB9,0xB1,0xCD,0x2E,0xC5,0xF3,0xDB,0x47,0xE5,0xA5,0x9C,0x77,0x0A,0xA6,0x20,0x68,0xFE,0x48,0xC1,0xAD}
}

func getLookupTable3() []byte {
	return []byte{0x02,0x03,0x05,0x07,0x0B,0x0D,0x11,0x13,0x17,0x1D,0x1F,0x25,0x29,0x2B,0x2F,0x35,0x3B,0x3D,0x43,0x47,0x49,0x4F,0x53,0x59,0x61,0x65,0x67,0x6B,0x6D,0x71,0x7F,0x83}
}

/*
0x1002001c0: 0x000000000000babe 0x00000001002028b0
0x1002001d0: 0x0000000000000008 0x00000001002026a0
0x1002001e0: 0x0000000000000009 0x0000000000000001

0x1002028b0: 0x74676c6f31684855 0x0000000000000000

0x1002026a0: 0x2fb8fca463b73521 0x0000000000000005

{47806 UHh1olgt 8 [33 53 183 99 164 252 184 47 5] 9 1}

struct {
	int64 magic; 			// 0x0
	char *key; 				// 0x8
	int64 key_len; 			// 0x10
	char *encrypted_data; 	// 0x18
	int64 encrypted_size;	// 0x20
	int64 marker;			// 0x28 == 1
}
*/
type todecrypt struct {
	magic int64
	key string
	key_len int64
	encrypted_data []byte
	encrypted_size int64
	end_marker int64
}

/*
void *__fastcall fg__eib_decode(__int64 a1, __int64 a2, size_t *a3)
{
  int v4; // [rsp+1Ch] [rbp-44h]
  void *v5; // [rsp+20h] [rbp-40h]
  _DWORD *v6; // [rsp+28h] [rbp-38h]
  unsigned __int64 v7; // [rsp+30h] [rbp-30h]
  size_t encrypted_size; // [rsp+48h] [rbp-18h]

  encrypted_size = a2 - 1;
  v7 = (a2 - 1) / 6uLL;
  *a3 = 4 * v7 - (*(unsigned __int8 *)(a1 + a2 - 1) - 48);
  if ( *a3 > a2 - 1 )
    return 0LL;
  v6 = calloc(1uLL, encrypted_size);
  v5 = calloc(1uLL, *a3);
  v4 = 0;
  __memset_chk(v6, 0LL, encrypted_size, -1LL);
  while ( v4 < v7 )
  {
    v6[v4] = fg__eib_unpack_i(6 * v4 + a1);
    ++v4;
  }
  __memcpy_chk(v5, v6, *a3, -1LL);
  free(v6);
  return v5;
}
*/
func eib_decode(input string, input_len int) (todecrypt, error) {
	// it takes one character for a reason - nothing to do with NUL byte
	size := input_len - 1
	elements := size / 6
	output_len := 4 * elements - (int(byte(input[input_len - 1])) - 48)

	if output_len < 0 || output_len > size {
		return todecrypt{}, fmt.Errorf("Bad input")
	}

	output := new(bytes.Buffer)
	buf := make([]byte, 4)
	for x := 0; x < elements; x++ {
		bslice := input[x*6:x*6+6]
		unpacked := eib_unpack_i(bslice)
		binary.LittleEndian.PutUint32(buf, uint32(unpacked))
		output.Write(buf)
	}

	// output bytes buffer layout 
	// magic size_of_encrypted_data key encrypted_data
	//   4             4             8    variable
	ret := todecrypt{}
	output.Read(buf)
	ret.magic = int64(binary.LittleEndian.Uint32(buf))

	output.Read(buf)
	ret.encrypted_size = int64(binary.LittleEndian.Uint32(buf))

	keybuf := make([]byte, 8)
	output.Read(keybuf)
	ret.key = string(keybuf)
	ret.key_len = 8

	ret.encrypted_data = make([]byte, ret.encrypted_size)
	output.Read(ret.encrypted_data)

	ret.end_marker = 1

	return ret, nil
}

/*
_int64 __fastcall sub_100020890(__int64 a1)
{
  int i; // [rsp+4h] [rbp-14h]
  unsigned int v3; // [rsp+Ch] [rbp-Ch]

  v3 = 0;
  for ( i = 0; i < 6; ++i )
    v3 += (byte_100027E20[*(unsigned __int8 *)(a1 + 5 - i) - 48] & 0x3F) << (6 * i);
  return v3;
}
*/
func eib_unpack_i(data string) int {
	ret := 0
	table := getLookupTable()
	for i := 0; i < 6; i++ {
		index := data[5 - i] - 48
		value := table[index] & 0x3F
		fvalue := int(value) << (6 * i)
		ret += fvalue
	}
	return ret
}

/*
__int64 __fastcall fg___tp_decrypt(__int64 a1, __int64 a2, unsigned __int8 *a3)
{
  __int64 result; // rax
  int v5; // [rsp+0h] [rbp-2Ch]
  int v6; // [rsp+4h] [rbp-28h]
  int v7; // [rsp+8h] [rbp-24h]
  int v8; // [rsp+Ch] [rbp-20h]
  unsigned int v9; // [rsp+10h] [rbp-1Ch]

  LOWORD(v9) = a3[6] + (a3[7] << 8);
  v8 = a3[4] + (a3[5] << 8);
  v7 = a3[2] + (a3[3] << 8);
  v6 = *a3 + (a3[1] << 8);
  v5 = 15;
  do
  {
    v9 = ((unsigned __int16)v9 >> 5)
       + ((unsigned __int16)v9 << 11)
       - (*(unsigned __int16 *)(a1 + 2LL * (unsigned int)(4 * v5 + 3))
        + (v8 & v7)
        + (~v8 & v6));
    v8 = ((unsigned __int16)v8 >> 3)
       + ((unsigned __int16)v8 << 13)
       - (*(unsigned __int16 *)(a1 + 2LL * (unsigned int)(4 * v5 + 2))
        + (v7 & v6)
        + (~v7 & v9));
    v7 = ((unsigned __int16)v7 >> 2)
       + ((unsigned __int16)v7 << 14)
       - (*(unsigned __int16 *)(a1 + 2LL * (unsigned int)(4 * v5 + 1))
        + (v6 & v9)
        + (~v6 & v8));
    v6 = ((unsigned __int16)v6 >> 1)
       + ((unsigned __int16)v6 << 15)
       - (*(unsigned __int16 *)(a1 + 2LL * (unsigned int)(4 * v5))
        + (v9 & v8)
        + (~v9 & v7));
    if ( v5 == 5 || v5 == 11 )
    {
      v9 -= *(unsigned __int16 *)(a1 + 2LL * (v8 & 0x3F));
      v8 -= *(unsigned __int16 *)(a1 + 2LL * (v7 & 0x3F));
      v7 -= *(unsigned __int16 *)(a1 + 2LL * (v6 & 0x3F));
      v6 -= *(unsigned __int16 *)(a1 + 2LL * (v9 & 0x3F));
    }
  }
  while ( v5-- );
  *(_WORD *)a2 = v6;
  *(_WORD *)(a2 + 2) = v7;
  *(_WORD *)(a2 + 4) = v8;
  *(_BYTE *)(a2 + 6) = v9;
  result = v9 >> 8;
  *(_BYTE *)(a2 + 7) = BYTE1(v9);
  return result;
}
*/
func tp_decrypt(derived_key []byte, input []byte) []byte {
	v9 := uint32(binary.LittleEndian.Uint16(input[6:8]))
	v8 := uint32(binary.LittleEndian.Uint16(input[4:6]))
	v7 := uint32(binary.LittleEndian.Uint16(input[2:4]))
	v6 := uint32(binary.LittleEndian.Uint16(input[0:2]))
	v5 := 15

	for {
		v9 = v9 & 0xFFFF
		key := uint32(binary.LittleEndian.Uint16(derived_key[(2*(4*v5+3)):(2*(4*v5+3))+2]))
		v9 = ((v9 >> 5) + (v9 << 11)) - (((v8 & v7) + (^v8 & v6)) + key)
		
		v8 = v8 & 0xFFFF
		key = uint32(binary.LittleEndian.Uint16(derived_key[(2*(4*v5+2)):(2*(4*v5+2))+2]))
        v8 = ((v8 >> 3) + (v8 << 13)) - (((v7 & v6) + (^v7 & v9)) + key)

        v7 = v7 & 0xFFFF
        key = uint32(binary.LittleEndian.Uint16(derived_key[(2*(4*v5+1)):(2*(4*v5+1))+2]))
        v7 = ((v7 >> 2) + (v7 << 14)) - (((v6 & v9) + (^v6 & v8)) + key)

        v6 = v6 & 0xFFFF
        key = uint32(binary.LittleEndian.Uint16(derived_key[(2*(4*v5+0)):(2*(4*v5+0))+2]))
		v6 = ((v6 >> 1) + (v6 << 15)) - (((v9 & v8) + (^v9 & v7)) + key)

        if v5 == 5 || v5 == 11 {
        	keyx := binary.LittleEndian.Uint16(derived_key[(2*(v8 & 0x3f)):(2*(v8 & 0x3f))+2])
            v9 -= uint32(keyx)
            keyx = binary.LittleEndian.Uint16(derived_key[(2*(v7 & 0x3f)):(2*(v7 & 0x3f))+2])
            v8 -= uint32(keyx)
            keyx = binary.LittleEndian.Uint16(derived_key[(2*(v6 & 0x3f)):(2*(v6 & 0x3f))+2])
            v7 -= uint32(keyx)
            keyx = binary.LittleEndian.Uint16(derived_key[(2*(v9 & 0x3f)):(2*(v9 & 0x3f))+2])
            v6 -= uint32(keyx)
        }
        if v5 <= 0 {
            break
        }
        v5 -=1
	}

    v9 = v9 & 0xffff
    v8 = v8 & 0xffff
    v7 = v7 & 0xffff
    v6 = v6 & 0xffff

	buf := make([]byte, 8)
	binary.LittleEndian.PutUint16(buf, uint16(v6))
	// is there easier/nicer way to make this instead of using the slide reference?
	sl := buf[2:4]
	binary.LittleEndian.PutUint16(sl, uint16(v7))
	sl = buf[4:6]
	binary.LittleEndian.PutUint16(sl, uint16(v8))
	sl = buf[6:8]
	binary.LittleEndian.PutUint16(sl, uint16(v9))
	return buf
}

/*
returns decrypted string and its size

tpdcrypt(char *key, char* encrypted_data, int encrypted_data_size, char **decrypted, int *decrypted_size)

_int64 __fastcall sub_100011DA0(char *a1, __int64 a2, __int64 a3, void **a4, size_t *a5)
{
  int v6; // [rsp+10h] [rbp-D0h]
  int v7; // [rsp+14h] [rbp-CCh]
  void *__ptr; // [rsp+18h] [rbp-C8h]
  size_t __size; // [rsp+38h] [rbp-A8h]
  char v12[136]; // [rsp+50h] [rbp-90h] BYREF

  if ( a2 && a3 )
  {
    __size = a3 - 1;
    *a5 = a3 - 1 - *(unsigned __int8 *)(a2 + a3 - 1);
    __ptr = calloc(1uLL, a3 - 1);
    v7 = 0;
    v6 = 2;
    __memcpy_chk(__ptr, a2, __size, -1LL);
    while ( v7 < __size )
    {
      fg___generate_xkey((__int64)v12, a1, 0x400u, v6);
      fg___tp_decrypt((__int64)v12, (__int64)__ptr + v7, (unsigned __int8 *)(v7 + a2));
      v7 += 8;
      ++v6;
    }
    *a4 = realloc(__ptr, *a5);
  }
  return __stack_chk_guard;
}
*/
func tpdcrypt(key string, input []byte, input_len int64) []byte {
	size := input_len - 1
	output_len := size - int64(input[size])
	// fmt.Printf("tpdcrypt output_len: %d\n", output_len)
	v6 := 2
	var i int64
	// Hex-Rays gives 136 bytes size because of alignment
	// but it's 128
	derived_key := make([]byte, 128)
	output := new(bytes.Buffer)

	for i = 0; i < size; i += 8 {
		generate_xkey(derived_key, key, 0x400, v6)
		ret := tp_decrypt(derived_key, input[i:i+8])
		output.Write(ret)
		v6++
	}
	final_string := output.Bytes()
	// fmt.Println(string(final_string[0:output_len]))
	return final_string[0:output_len]
}

/*
__int64 __fastcall fg___generate_xkey(__int64 a1, char *a2, unsigned int a3, unsigned __int8 a4)
{
  unsigned int v4; // edx
  unsigned int v5; // eax
  __int64 v9; // [rsp+20h] [rbp-140h]
  __int16 i; // [rsp+2Eh] [rbp-132h]
  unsigned int v11; // [rsp+30h] [rbp-130h]
  unsigned int v12; // [rsp+30h] [rbp-130h]
  unsigned int v13; // [rsp+34h] [rbp-12Ch]
  unsigned int v14; // [rsp+34h] [rbp-12Ch]
  unsigned int v15; // [rsp+34h] [rbp-12Ch]
  char v16; // [rsp+3Ah] [rbp-126h]
  unsigned __int8 v17; // [rsp+3Ah] [rbp-126h]
  unsigned __int8 v19; // [rsp+3Bh] [rbp-125h]
  char *__s; // [rsp+40h] [rbp-120h]
  char __dst[264]; // [rsp+50h] [rbp-110h] BYREF

  __s = a2;
  v11 = strlen(a2);
  memcpy(__dst, &fg_lookupTable2, 0x100uLL);
  if ( a4 >= 0x20uLL )
    v9 = a4 & 0x1F;
  else
    v9 = a4;
  v19 = fg_lookupTable3[v9];
  for ( i = 0; i < 256; i += v19 )
    __dst[i] = ((unsigned __int8)__dst[i] % (int)v19 + (unsigned __int8)__dst[i]) % 255;
  if ( v11 )
  {
    if ( v11 > 0x80 )
    {
      __s = (char *)realloc(a2, 0x80uLL);
      v11 = 128;
    }
    if ( a3 > 0x400 )
      __assert_rtn("_16fUggs", "/e/toidievitceffe/libtpyrc/tpyrc.c", 87, "bits <= 1024");
    if ( !a3 )
      a3 = 1024;
    __memcpy_chk(a1, __s, v11, -1LL);
    if ( v11 < 0x80 )
    {
      v13 = 0;
      v16 = *(_BYTE *)(a1 + v11 - 1);
      do
      {
        v4 = v13++;
        v16 = __dst[(unsigned __int8)(*(_BYTE *)(a1 + v4) + v16)];
        v5 = v11++;
        *(_BYTE *)(a1 + v5) = v16;
      }
      while ( v11 < 0x80 );
    }
    v12 = (a3 + 7) >> 3;
    v14 = 128 - v12;
    v17 = __dst[(255 >> (-(char)a3 & 7)) & *(unsigned __int8 *)(a1 + 128 - v12)];
    *(_BYTE *)(a1 + 128 - v12) = v17;
    while ( v14-- )
    {
      v17 = __dst[*(unsigned __int8 *)(a1 + v12 + v14) ^ v17];
      *(_BYTE *)(a1 + v14) = v17;
    }
    v15 = 63;
    do
      *(_WORD *)(a1 + 2LL * v15) = (*(unsigned __int8 *)(a1 + 2 * v15 + 1) << 8) + *(unsigned __int8 *)(a1 + 2 * v15);
    while ( v15-- );
  }
  return __stack_chk_guard;
}
*/
func generate_xkey(a1 []byte, a2 string, bits int, a4 int) {
	table2 := getLookupTable2()
	table3 := getLookupTable3()
	
	/*
    if ( a3 > 0x400 )
      __assert_rtn("_16fUggs", "/e/toidievitceffe/libtpyrc/tpyrc.c", 87, "bits <= 1024");

    if ( !a3 )
      a3 = 1024;

	*/
	if bits > 1024 {
		fmt.Printf("[-] ERROR: bits can't be higher than 1024")
		return
	} else if bits == 0 {
		bits = 1024
	}

	key_len := len(a2)
	
	/*
	if ( v11 )
  	{
    	if ( v11 > 0x80 )
    	{
      	__s = (char *)realloc(a2, 0x80uLL);
      	v11 = 128;
    	}
    	...
    }
    */
	if key_len == 0 {
		return
	} else if key_len > 128 {
		key_len = 128
	}

	/*
	if ( a4 >= 0x20uLL )
    	v9 = a4 & 0x1F;
  	else
    	v9 = a4;
    */
	v9 := a4
	if a4 >= 0x20 {
		v9 = a4 & 0x1F
	}

	// v19 = fg_lookupTable3[v9];
	v19 := table3[v9]

	//for ( i = 0; i < 256; i += v19 )
    //	__dst[i] = ((unsigned __int8)__dst[i] % (int)v19 + (unsigned __int8)__dst[i]) % 255;
	for i := 0; i < 256; i += int(v19) {
		// argh to Go pain in the ass with mixing types
		lookupElem := int(table2[i])
		table2[i] = byte((lookupElem % int(v19) + lookupElem) % 255)
	}
	// copy the key into the first bytes of the derived key
	copy(a1, a2)

	/*
    if ( v11 < 0x80 )
    {
      v13 = 0;
      v16 = *(_BYTE *)(a1 + v11 - 1);
      do
      {
        v4 = v13++;
        v16 = __dst[(unsigned __int8)(*(_BYTE *)(a1 + v4) + v16)];
        v5 = v11++;
        *(_BYTE *)(a1 + v5) = v16;
      }
      while ( v11 < 0x80 );
    }
	*/
	// this basically expands the key size
	if key_len < 128 {
		v13 := 0
		v16 := a1[key_len - 1]
		for {
			v4 := v13
			v13++
			index := (a1[v4] + v16) & 0xFF
			v16 = table2[index]
			a1[key_len] = v16
			key_len++
			if key_len >= 128 {
				break
			}
		}
	}

/*
    v12 = (a3 + 7) >> 3;
    v14 = 128 - v12;
    v17 = __dst[(255 >> (-(char)a3 & 7)) & *(unsigned __int8 *)(a1 + 128 - v12)];
    *(_BYTE *)(a1 + 128 - v12) = v17;
*/
	v12 := (bits + 7) >> 3
	v14 := 128 - v12
	index := (255 >> (-bits & 7)) & (a1[128 - v12])
	v17 := table2[index]
	a1[128 - v12] = v17
	
/*
   while ( v14-- )
    {
      v17 = __dst[*(unsigned __int8 *)(a1 + v12 + v14) ^ v17];
      *(_BYTE *)(a1 + v14) = v17;
    }
*/
	for ; v14 > 0; v14-- {
		index = a1[v12 + v14] ^ v17
		v17 = table2[index]
		a1[v14] = v17
	}
	// fmt.Println("derived key ", hex.EncodeToString(a1))
}

func decryptString(input string, input_len int) string {	
	// first we need to decode the string
	crypt_buf, err := eib_decode(input, input_len)
	if err != nil {
		fmt.Printf("[-] ERROR: failed to decode input string\n")
		return ""
	}
	decrypted := tpdcrypt(crypt_buf.key, crypt_buf.encrypted_data, crypt_buf.encrypted_size)
	return string(decrypted)
}

func parseAndDecryptBinary(path string) {
    r, err := os.Open(path)
    if err != nil {
        fmt.Printf("[-] Error: %s @ %s\n", err.Error(), path)
        return
    }

    defer r.Close()
    machoFile, err := macho.NewFile(r)
    // maybe fat - don't care :P
    if err != nil {
        return
    } 
    defer machoFile.Close()

    sec := machoFile.Section("__cstring")
    if sec != nil {
        b := make([]byte, sec.Size)
        r := sec.Open()
        if _, err := r.Read(b); err != nil {
            return
        }
        start := 0
        end := 0
        // there is probably an easier/nicer way to do this :P
        for i := 0; i < len(b); i++ {
            if b[i] == 0 {
                end = i
                // encrypted := b[start:end]
                s := string(b[start:end])
                start = end + 1
                if strings.HasPrefix(s, "000Bg{") {
                    decrypted := decryptString(s, len(s))
                    fmt.Println(s, "->", decrypted)
                }
            }
        }
    }
}

func main() {
    fmt.Printf("EvilQuest/ThiefQuest String Deobfuscator\n")
    fmt.Printf("(c) 2020 Pedro Vilaca. All Rights Reserved\n\n")

    var input_string string
    var input_file string

    flag.StringVar(&input_string, "s", "", "string to decrypt")
    flag.StringVar(&input_file, "f", "", "file to decrypt all strings")
    flag.Parse()

    switch {
    case input_string != "" && input_file != "":
    	fmt.Printf("[-] ERROR: please select only a string or a file\n")
    	fmt.Println("Usage:")
    	flag.PrintDefaults()
    	os.Exit(1)    	    	

    case input_string != "":
		decrypted := decryptString(input_string, len(input_string))
		if decrypted == "" {
			os.Exit(1)
		}
		fmt.Println(input_string, "->", decrypted)    	

	case input_file != "":
		parseAndDecryptBinary(input_file)

	default:
    	fmt.Printf("[-] ERROR: missing input string or file\n")
    	fmt.Println("Usage:")
    	flag.PrintDefaults()
    	os.Exit(1)
    }
}
