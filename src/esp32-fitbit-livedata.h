#ifndef ESP32_FITBIT_LIVEDATA_H
#define ESP32_FITBIT_LIVEDATA_H

#include <Arduino.h>
#include <FS.h>
#include <SPIFFS.h>
#include <WiFiClientSecure.h>

// ESP32 BLE Arduino
#include "BLEDevice.h"
#include "BLECharacteristic.h"
#include "BLEUtils.h"
#include "BLEServer.h"
#include "BLE2902.h"

// Json Streaming Parser
#include "JsonStreamingParser.h"
#include "JsonListener.h"

// CRC32
#include "CRC32.h"

#include "CMac.h"

typedef struct FitbitLiveData {
  uint32_t time = 0;
  uint32_t step = 0;
  uint32_t distance = 0;
  uint16_t calories = 0;
  uint16_t elevation = 0;
  uint16_t vActive = 0;
  uint16_t heartRate = 0;
} LiveData;

// typedef struct FitbitAccount {
//   char* username;
//   char* password;
//   char* trackerName;
// } FitbitAccount;

class FitbitLiveDataClass {

public:

  // bool init(WiFiClientSecure* pWifiClientSecure, FitbitAccount* fitbitAccounts);
  bool init(WiFiClientSecure* pWifiClientSecure, const char* username, const char* password, const char* tracker);
  bool scan(uint32_t timeout = 10000);
  bool isConnected();
  bool connect(void (*cb)(LiveData liveData), uint32_t timeout = 10000);

protected:
  bool auth(WiFiClientSecure* pWifiClientSecure, const char* username, const char* password, const char* tracker);
  bool openSession(BLERemoteCharacteristic* pRemoteCharacteristic);
  bool authTracker(BLERemoteCharacteristic* pRemoteCharacteristic);
  bool sendAuth(BLERemoteCharacteristic* pRemoteCharacteristic);
  bool closeSession(BLERemoteCharacteristic* pRemoteCharacteristic);
  static void livedataCallback(BLERemoteCharacteristic* pBLERemoteCharacteristic, uint8_t* pData, size_t length, bool isNotify);
  void (*m_liveDataCallback)(LiveData liveData);
  bool loadCredential(const char* path);
  bool saveCredential(const char* path, const char* content);

  char* m_token = nullptr;
  char* m_wireId = nullptr;
  char m_mac[18] = "";

  long long int m_nonce = 0;
  uint8_t* m_authSubCode = nullptr;
  int m_codeLength = 0;

  BLEAddress* m_pTrackerAddress = nullptr;
  BLEClient*  m_pClient = nullptr;

  class AdvertisedDeviceCallbacks: public BLEAdvertisedDeviceCallbacks {
    FitbitLiveDataClass* m_pFitbitLiveDataClass;
  public:
    AdvertisedDeviceCallbacks(FitbitLiveDataClass* pFitbitLiveDataClass) {
      m_pFitbitLiveDataClass = pFitbitLiveDataClass;
    }
    /**
     * Called for each advertising BLE server.
     */
    void onResult(BLEAdvertisedDevice advertisedDevice); // onResult

  }; // AdvertisedDeviceCallbacks

  // class ClientCallbacks: public BLEClientCallbacks {
  //   FitbitLiveDataClass* m_pFitbitLiveDataClass;
  // public:
  //   ClientCallbacks() {
  //   };
  //   ClientCallbacks(FitbitLiveDataClass* pFitbitLiveDataClass) {
  //     m_pFitbitLiveDataClass = pFitbitLiveDataClass;
  //   };
  //   void onConnect(BLEClient* pClient);
  //   void onDisconnect(BLEClient* pClient);
  // }; // ClientCallbacks

  class JsonEventListener : public JsonListener {
  protected:
    FitbitLiveDataClass* m_pFitbitLiveDataClass = nullptr;
    char* m_currentKey = nullptr;
  public:
    JsonEventListener(FitbitLiveDataClass* pFitbitLiveDataClass) {
      m_pFitbitLiveDataClass = pFitbitLiveDataClass;
    }
    void whitespace(char c);
    void startDocument();
    void key(String key);
    void value(String value);
    void endArray();
    void endObject();
    void endDocument();
    void startArray();
    void startObject();
  }; // JsonEventListener

  class CredentialJsonEventListener : protected JsonEventListener {
  public:
    CredentialJsonEventListener(FitbitLiveDataClass* pFitbitLiveDataClass) : JsonEventListener(pFitbitLiveDataClass) {};
    void value(String value);
  };

  class Oauth2TokenJsonEventListener : protected JsonEventListener {
  public:
    Oauth2TokenJsonEventListener(FitbitLiveDataClass* pFitbitLiveDataClass) : JsonEventListener(pFitbitLiveDataClass) {};
    void value(String value);
  };

  class DevicesJsonEventListener : protected JsonEventListener {
  protected:
    char* m_pTrackerName = nullptr;
    char* m_pWireId = nullptr;
    char* m_pMac = nullptr;
    char* m_pDeviceVersion = nullptr;
    
  public:
    DevicesJsonEventListener(FitbitLiveDataClass* pFitbitLiveDataClass, const char* pTracker) : JsonEventListener(pFitbitLiveDataClass) {
      m_pTrackerName = (char*)pTracker;
    };
    void value(String value);
    void startObject();
    void endObject();
  };
};

extern FitbitLiveDataClass FitbitLiveData;

#endif //ESP32_FITBIT_LIVEDATA_H
