#ifndef Block_Cipher_h
#define Block_Cipher_h

#include <stdint.h>

class BlockCipher {
public:
  virtual void encrypt(uint8_t data[], int size);
  virtual void decrypt(uint8_t data[], int size);
  virtual int getBlockLength();
};

#endif
