/*
  Xtea.cpp - Xtea encryption/decryption
  Written by Frank Kienast in November, 2010
*/
#include "Arduino.h"

#include "XteaEngine.h"

#define NUM_ROUNDS 32

XteaEngine::XteaEngine(uint8_t key[], int size)
{
	_key[0] = ((unsigned long)key[0]) << 24  | ((unsigned long)key[1]) << 16  | ((unsigned long)key[2]) << 8  | ((unsigned long)key[3]);
	_key[1] = ((unsigned long)key[4]) << 24  | ((unsigned long)key[5]) << 16  | ((unsigned long)key[6]) << 8  | ((unsigned long)key[7]);
	_key[2] = ((unsigned long)key[8]) << 24  | ((unsigned long)key[9]) << 16  | ((unsigned long)key[10]) << 8 | ((unsigned long)key[11]);
	_key[3] = ((unsigned long)key[12]) << 24 | ((unsigned long)key[13]) << 16 | ((unsigned long)key[14]) << 8 | ((unsigned long)key[15]);

    int i, j;
    unsigned long delta=0x9E3779B9;
    for (i = j = 0; i < NUM_ROUNDS; i++,j+=4)
    {
        _sum0[i] = (j + _key[j & 3]);
        j += delta;
        _sum1[i] = (j + _key[j >> 11 & 3]);
    }
}


void XteaEngine::encrypt(uint8_t v[], int size) 
{

    unsigned int i,j;
    unsigned long v0, v1, sum=0, delta=0x9E3779B9;

	v0 = ((unsigned long)v[0]) << 24  | ((unsigned long)v[1]) << 16  | ((unsigned long)v[2]) << 8  | ((unsigned long)v[3]);
	v1 = ((unsigned long)v[4]) << 24  | ((unsigned long)v[5]) << 16  | ((unsigned long)v[6]) << 8  | ((unsigned long)v[7]);

    // v0 ^= 0x6a4ea5b2;
    // v1 ^= 0xebccfbcc;

    for (i=0; i < NUM_ROUNDS; i++) 
    {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + _key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + _key[(sum>>11) & 3]);
    }
    v[0] = (v0 & 0xff000000) >> 24;
    v[1] = (v0 & 0x00ff0000) >> 16;
    v[2] = (v0 & 0x0000ff00) >> 8;
    v[3] = (v0 & 0x000000ff);
    v[4] = (v1 & 0xff000000) >> 24;
    v[5] = (v1 & 0x00ff0000) >> 16;
    v[6] = (v1 & 0x0000ff00) >> 8;
    v[7] = (v1 & 0x000000ff);
}
 
void XteaEngine::decrypt(uint8_t v[], int size) 
{
    unsigned int i;
    unsigned long v0, v1, delta=0x9E3779B9, sum=delta*NUM_ROUNDS;
    
	v0 = ((unsigned long)v[0]) << 24  | ((unsigned long)v[1]) << 16  | ((unsigned long)v[2]) << 8  | ((unsigned long)v[3]);
	v1 = ((unsigned long)v[4]) << 24  | ((unsigned long)v[5]) << 16  | ((unsigned long)v[6]) << 8  | ((unsigned long)v[7]);

    for (i=0; i < NUM_ROUNDS; i++) 
    {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + _key[(sum>>11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + _key[sum & 3]);
    }
    
    v[0] = (v0 & 0xff000000) >> 24;
    v[1] = (v0 & 0x00ff0000) >> 16;
    v[2] = (v0 & 0x0000ff00) >> 8;
    v[3] = (v0 & 0x000000ff);
    v[4] = (v1 & 0xff000000) >> 24;
    v[5] = (v1 & 0x00ff0000) >> 16;
    v[6] = (v1 & 0x0000ff00) >> 8;
    v[7] = (v1 & 0x000000ff);
}
 
int XteaEngine::getBlockLength() {
    return 8;
}
