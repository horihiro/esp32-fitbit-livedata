#ifndef CMAC_H
#define CMAC_H

#include <stdint.h>

#ifndef NULL
#define NULL 0
#endif
class CMac {
  CMac();

public:
  static bool encrypt(int encType, uint8_t key[], int keyLength, uint8_t in[], int inLength, uint8_t out[], int outLength);
  static const int ENCTYPE_XTEA = 1;
  static const int ENCTYPE_AES = 2;
private:
  static int shiftLeft(uint8_t in[], uint8_t out[], int size);
  static void doubleLu(uint8_t in[], uint8_t out[], int size);
  static void lookupPoly(uint8_t blockSizeLength, uint8_t out[4]);
};

#endif // CMAC_H
