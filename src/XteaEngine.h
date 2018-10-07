/*
  Xtea.h - Crypto library
  Written by Frank Kienast in November, 2010
*/
#ifndef Xtea_Engine_h
#define Xtea_Engine_h

#include "BlockCipher.h"

class XteaEngine : public BlockCipher
{
  public:
    XteaEngine(uint8_t key[], int size);
    void encrypt(uint8_t data[], int size);
    void decrypt(uint8_t data[], int size);
    int getBlockLength();

  private:
    unsigned long _key[4];
    unsigned long _sum0[32] = {0}, _sum1[32] = {0};
};

#endif

