#include "esp32-fitbit-livedata.h"

#define LIB_NAME_FITBIT_LIVEDATA "ESP32_Fitbit"
#define LIB_VERSION_FITBIT_LIVEDATA "0.0.1"
#define HOST_FITBIT_AUTH "android-api.fitbit.com"
#define HOST_FITBIT_CDN "android-cdn-api.fitbit.com"
#define PATH_FITBIT_OAUTH2 "/oauth2/token"
#define PATH_FITBIT_DEVICES "/1/user/-/devices.json"
#define PATH_FITBIT_CRED "/1/user/-/devices/tracker/generateBtleClientAuthCredentials.json"
#define HEADER_FITBIT_BASICAUTH "Basic MjI4VlNSOjQ1MDY4YTc2Mzc0MDRmYzc5OGEyMDhkNmMxZjI5ZTRm"

const BLEUUID UUID_CONTROL_SERVICE("adabfb00-6e7d-4601-bda2-bffaa68956ba");
const char* UUID_CHARACTERISTIC_READ_DATA = "adabfb01-6e7d-4601-bda2-bffaa68956ba";
const char* UUID_CHARACTERISTIC_WRITE_DATA = "adabfb02-6e7d-4601-bda2-bffaa68956ba";

const char* UUID_LIVE_SERVICE = "558dfa00-4fa8-4105-9f02-4eaa93e62980";
const char* UUID_CHARACTERISTIC_LIVE_DATA = "558dfa01-4fa8-4105-9f02-4eaa93e62980";

const char* UUID_SERVICE_NOTIFICATION_CENTER = "16bcfd00-253f-c348-e831-0db3e334d580";
const char* UUID_CHARACTERISTICS_NOTIFICATION_SOURCE = "16bcfd02-253f-c348-e831-0db3e334d580";

// const char* UUID_CHARACTERISTIC_DEVICENAME = "2a00-0000-1000-8000-00805f9b34fb";


// const BLEUUID UUID_SERVICE_1("1800-0000-1000-8000-00805f9b34f");
// const BLEUUID UUID_CHARACTERISTIC_1_1("2a00-0000-1000-8000-00805f9b34f");
// const BLEUUID UUID_CHARACTERISTIC_1_2("2a01-0000-1000-8000-00805f9b34f");
// const BLEUUID UUID_CHARACTERISTIC_1_3("2a04-0000-1000-8000-00805f9b34f");
// const BLEUUID UUID_SERVICE_2("1801-0000-1000-8000-00805f9b34f"); // '2a05'
// const BLEUUID UUID_CHARACTERISTIC_2_1("2a05-0000-1000-8000-00805f9b34f");
// const BLEUUID UUID_SERVICE_3("180a-0000-1000-8000-00805f9b34f"); // '2a29', 'fb00'
// const BLEUUID UUID_CHARACTERISTIC_3_1("2a29-0000-1000-8000-00805f9b34f");
// const BLEUUID UUID_CHARACTERISTIC_3_2("fb00-0000-1000-8000-00805f9b34f");
// const BLEUUID UUID_SERVICE_4("180f-0000-1000-8000-00805f9b34f"); // '2a19'
// const BLEUUID UUID_CHARACTERISTIC_4_1("2a19-0000-1000-8000-00805f9b34f");

int connectionStatus = 0; // 0:INIT, 1:SESSION_OPENED, 2:TRACKER_AUTHED
bool procCallback = false;
uint8_t authIn[4];

// static void livedataCallback(
void FitbitLiveDataClass::livedataCallback(
  BLERemoteCharacteristic* pBLERemoteCharacteristic,
  uint8_t* pData,
  size_t length,
  bool isNotify) {
  LiveData liveData;
  liveData.time = (pData[3] << 24 & 0xff000000) | (pData[2] << 16 & 0xff0000) | (pData[1] << 8 & 0xff00) | (pData[0] & 0xff);
  liveData.step = (pData[7] << 24 & 0xff000000) | (pData[6] << 16 & 0xff0000) | (pData[5] << 8 & 0xff00) | (pData[4] & 0xff);
  liveData.distance = (pData[11] << 24 & 0xff000000) | (pData[10] << 16 & 0xff0000) | (pData[9] << 8 & 0xff00) | (pData[8] & 0xff);
  liveData.calories = (pData[13] << 8 & 0xff00) | (pData[12] & 0xff);
  liveData.elevation = (pData[15] << 8 & 0xff00) | (pData[14] & 0xff) / 10;
  liveData.vActive = (pData[17] << 8 & 0xff00) | (pData[16] & 0xff);
  liveData.heartRate = -1;
  if (length > 18) {
    liveData.heartRate = pData[18] & 0xff;
  }
  if (FitbitLiveData.m_liveDataCallback != nullptr) {
    FitbitLiveData.m_liveDataCallback(liveData);
  }
};

static void writeRequestCallback(
  BLERemoteCharacteristic* pBLERemoteCharacteristic,
  uint8_t* pData,
  size_t length,
  bool isNotify) {
Serial.printf("<- (%d) ",connectionStatus);
for(int i = 0;i < length; i++) {
  Serial.printf("%02x",pData[i]);
}
Serial.println();
  if (procCallback == false) return;
  if (
      connectionStatus == 0 && pData[0] == 0xc0 && pData[1] == 0x14 && length == 14
  ||  connectionStatus == 1 && pData[0] == 0xc0 && pData[1] == 0x51 && length == 14
  ||  connectionStatus == 2 && length == 2
  ||  connectionStatus == 3 && length == 2
  ) {
    procCallback = false;
    connectionStatus++;
    if (connectionStatus == 2) {
      for(int i = 0;i < sizeof (authIn); i++) {
        authIn[i] = pData[i + length - sizeof (authIn)];
      }
    }
  }
};

static const char* httpRequest(WiFiClient* pWifiClient, const char* host, uint16_t port, const char* method, const char* path, std::map<std::string, std::string> headers, std::string body) {
  if (!pWifiClient->connect(host, port)) {
    Serial.println("connection failed");
    return "_ERROR";
  }

  pWifiClient->print(method);pWifiClient->print(" ");pWifiClient->print(path);pWifiClient->print(" HTTP/1.0\r\n");
  pWifiClient->print("Host: ");pWifiClient->print(host);pWifiClient->print("\r\n");
  for (const auto header : headers){
    std::string headerLine = header.first + ": " + header.second + "\r\n";
    pWifiClient->print(headerLine.c_str());
  }
  pWifiClient->print("Content-Length: ");pWifiClient->print(body.length());pWifiClient->print("\r\n\r\n");
  pWifiClient->print(body.c_str());

  int timeout = millis() + 5000;
  pWifiClient->flush();

  while (pWifiClient->available() == 0) {
    if (timeout < millis()) {
      pWifiClient->stop();
      return "_TIMEOUT";
    }
  }

  bool isHeader = true;
  String responseBody = "", line;
  do {
    line = pWifiClient->readStringUntil('\r');
    line.trim();
    if (line.length() == 0) {
      isHeader = false;
    }
  } while(isHeader == true);
  while (pWifiClient->available()) {
    responseBody += pWifiClient->readStringUntil('\r');
  }
  pWifiClient->stop();
  responseBody.trim();
  return responseBody.c_str();
}

bool FitbitLiveDataClass::auth(WiFiClientSecure* pWifiClientSecure, const char* username, const char* password, const char* tracker) {

  int i;
  String response;
  std::map<std::string, std::string> headers;
  std::string body = "username=";
  body += username;
  body += "&password=";
  body += password;
  body += "&grant_type=password";

  headers.clear();
  headers["User-Agent"] = LIB_NAME_FITBIT_LIVEDATA;
  headers["User-Agent"] += "/";
  headers["User-Agent"] += LIB_VERSION_FITBIT_LIVEDATA;
  headers["Accept"] = "*/*";
  headers["Authorization"] = HEADER_FITBIT_BASICAUTH;
  headers["Content-Type"] = "application/x-www-form-urlencoded";

  JsonStreamingParser parser;

  Oauth2TokenJsonEventListener oauthListener(this);
  parser.setListener((JsonListener*) &oauthListener);
  do {
    response = httpRequest(pWifiClientSecure, HOST_FITBIT_AUTH, 443, "POST", PATH_FITBIT_OAUTH2, headers, body);
// Serial.println(response);

    parser.reset();
    for(i=0;i<response.length();i++) {
      parser.parse(response.charAt(i));
    }
// Serial.print("token: ");
// Serial.println(this->m_token);
    delay(1000);
  } while(this->m_token == nullptr);

  headers["Authorization"] = "Bearer ";
  headers["Authorization"] += this->m_token;
  headers.erase("Content-Type");

  DevicesJsonEventListener deviceListener(this, tracker);
  parser.setListener((JsonListener*) &deviceListener);
  do {
    response = httpRequest(pWifiClientSecure, HOST_FITBIT_CDN, 443, "GET", PATH_FITBIT_DEVICES, headers, "");
// Serial.println(response);
    parser.reset();
    for(i=0;i<response.length();i++) {
      parser.parse(response.charAt(i));
    }
    delay(1000);
  } while(this->m_wireId == nullptr);

// Serial.print("wireId: ");
// Serial.println(this->m_wireId);
// Serial.print("mac: ");
// Serial.println(this->m_mac);

  body = "serialNumber=";
  body += m_wireId;
  headers["Content-Type"] = "application/x-www-form-urlencoded";

  CredentialJsonEventListener credentialListener(this);
  parser.setListener((JsonListener*) &credentialListener);
  do {
    response = httpRequest(pWifiClientSecure, HOST_FITBIT_CDN, 443, "POST", PATH_FITBIT_CRED, headers, body);
// Serial.println(response);
    parser.reset();
    for(i=0;i<response.length();i++) {
      parser.parse(response.charAt(i));
    }
    delay(1000);
  } while(this->m_authSubCode == nullptr);

// Serial.printf("nonce: %lld\n", m_nonce);
// Serial.printf("authCode: ");
// for (int i=0;i<m_codeLength;i++) {
//   Serial.printf("%x", m_authSubCode[i]);
// }
// Serial.println();

  return true;
}

bool FitbitLiveDataClass::loadCredential(const char* path) {
  if (!SPIFFS.begin(true))  return false;
  File json = SPIFFS.open(path, "r");
  if (!json) {
    SPIFFS.end();
    return false;
  }

  JsonStreamingParser parser;
  CredentialJsonEventListener listener(this);
  parser.setListener((JsonListener*) &listener);
  parser.reset();

  char c;
  while (json.available()) {
    c = json.read();
    parser.parse(c);
  }
  json.close();
  SPIFFS.end();
  return true;
}

bool FitbitLiveDataClass::saveCredential(const char* path, const char* content) {
  if (!SPIFFS.begin(true))  return false;
  File json = SPIFFS.open(path, "w");
  if (!json) {
    SPIFFS.end();
    return false;
  }

  json.print(content);
  json.close();

  SPIFFS.end();
  return true;
}

bool FitbitLiveDataClass::init(WiFiClientSecure* pWifiClientSecure, const char* username, const char* password, const char* tracker) {
  int length = strlen(username) + strlen(tracker) + 41;
  char* path = (char*)malloc(length);

  sprintf(path, "/esp32-fitbit-livedata/%s/%s/credential.json", username, tracker);
  sprintf(path, "/%x", CRC32::calculate(path, length - 1));

  loadCredential(path);
// Serial.printf("nonce: %lld\n", m_nonce);
// Serial.printf("authCode: ");
// for (int i=0;i<m_codeLength;i++) {
// Serial.printf("%x", m_authSubCode[i]);
// }
// Serial.println();
// Serial.printf("mac: %s\n", m_mac);

  if (m_nonce != 0) {
    free(path);
    return true;
  }
Serial.println("Can't get nonce/authSubCode, trying to get them from Fitbit.com...");
  if (!auth(pWifiClientSecure, username, password, tracker)) {
    free(path);
    return false;
  }

  char authSubCodeStr[100] = "";
  char buf[100] = "";
  for (int i=0;i<m_codeLength;i++) {
    sprintf(buf, "%s%X", authSubCodeStr, m_authSubCode[i]);
    sprintf(authSubCodeStr, "%s", buf);
  }

  char data[256];
  sprintf(data, "{\"btleClientAuthCredentials\":{\"authSubKey\":\"%s\",\"nonce\":%lld},\"mac\":\"%s\"}", authSubCodeStr, m_nonce, m_mac);
  bool ret = saveCredential(path, data);
  free(path);
  return ret;
}

bool FitbitLiveDataClass::scan(uint32_t timeout) {

  BLEDevice::init(LIB_NAME_FITBIT_LIVEDATA);
  BLEScan* pBLEScan = BLEDevice::getScan();
  pBLEScan->setInterval(300); // msec between start of BT scans
  pBLEScan->setWindow(300); // msec scan time - must be <= interval
  pBLEScan->setAdvertisedDeviceCallbacks(new AdvertisedDeviceCallbacks(this));
  pBLEScan->setActiveScan(true);

  BLEServer *pServer = BLEDevice::createServer();
  BLEService *pService = pServer->createService(UUID_SERVICE_NOTIFICATION_CENTER);
  BLECharacteristic *pCharacteristic = pService->createCharacteristic(
    UUID_CHARACTERISTICS_NOTIFICATION_SOURCE,
    BLECharacteristic::PROPERTY_NOTIFY
  );

  BLE2902* p2902Descriptor = new BLE2902();
  p2902Descriptor->setNotifications(true);
  pCharacteristic->addDescriptor(p2902Descriptor);
  pService->start();

  Serial.println("start BLE scan");
  pBLEScan->start(timeout);
  if (m_pTrackerAddress == nullptr) {
    Serial.println("Tracker not found");
    return false;
  }
  Serial.println("tracker found");
  return true;
}

bool FitbitLiveDataClass::isConnected() {
  return m_pClient == nullptr ? false : m_pClient->isConnected();
}

bool FitbitLiveDataClass::connect(void (*cb)(LiveData liveData), uint32_t timeout) {
  m_liveDataCallback = cb;
  uint32_t to = (uint32_t)millis() + timeout;

  if (m_pClient == nullptr) m_pClient  = BLEDevice::createClient();
  m_pClient->disconnect();
  // pClient->setClientCallbacks( new ClientCallbacks(this));
  Serial.printf("Trying to connect to '%s' ...", m_mac);
  if (m_pClient->connect(*m_pTrackerAddress) != true) {
    Serial.println(" failed to connect to tracker.");
    return false;
  }
  while(m_pClient->isConnected() == false) {
    delay(100);
  }
  // delete pTrackerAddress;
  Serial.println(" connected.");
  delay(100);
  const uint8_t CMD_SUBSCRIBE_REQUEST[] = {0x01, 0x00};
  const uint8_t CMD_UNSUBSCRIBE_REQUEST[] = {0x00, 0x00};
  BLERemoteCharacteristic* pRemoteWritableCharacteristic;
  BLERemoteCharacteristic* pRemoteReadableCharacteristic;
  BLERemoteCharacteristic* pRemoteLivedataCharacteristic;

  if (m_pClient->isConnected() == false) return false;
  BLERemoteService* pRemoteControlService = nullptr/* = m_pClient->getService(UUID_CONTROL_SERVICE) */;
  std::map<std::string, BLERemoteService*>* services;
  do {
    if (to < millis()) return false;
    services  = m_pClient->getServices();
    for(auto itr = services->begin(); itr != services->end(); ++itr) {
      if (itr->second->getUUID().equals(UUID_CONTROL_SERVICE)) {
        pRemoteControlService = itr->second;
      }
    }
  } while(pRemoteControlService == nullptr);

  if (m_pClient->isConnected() == false) return false;
  pRemoteReadableCharacteristic = pRemoteControlService->getCharacteristic(UUID_CHARACTERISTIC_READ_DATA);
  pRemoteReadableCharacteristic->registerForNotify(writeRequestCallback);

  Serial.print("Subscribing control channel... ");
  std::map<std::string, BLERemoteDescriptor *>* pRemoteNotifyableDescriptors;
  pRemoteNotifyableDescriptors = pRemoteReadableCharacteristic->getDescriptors();
  for(auto itr = pRemoteNotifyableDescriptors->begin(); itr != pRemoteNotifyableDescriptors->end(); ++itr) {
    itr->second->writeValue((uint8_t*)CMD_SUBSCRIBE_REQUEST, sizeof (CMD_SUBSCRIBE_REQUEST));
    Serial.println("subscribed");
  }

  if (m_pClient->isConnected() == false) return false;
  pRemoteWritableCharacteristic = pRemoteControlService->getCharacteristic(UUID_CHARACTERISTIC_WRITE_DATA);

  BLERemoteService* pRemoteLivedataService = m_pClient->getService(UUID_LIVE_SERVICE);
  pRemoteLivedataCharacteristic = pRemoteLivedataService->getCharacteristic(UUID_CHARACTERISTIC_LIVE_DATA);

  connectionStatus = 0;
  openSession(pRemoteWritableCharacteristic);
  while(connectionStatus != 1) {
    if (to < millis()) return false;
    delay(100);
  }
  authTracker(pRemoteWritableCharacteristic);
  while(connectionStatus != 2) {
    if (to < millis()) return false;
    delay(100);
  }

  sendAuth(pRemoteWritableCharacteristic);
  while(connectionStatus != 3) {
    if (to < millis()) return false;
    delay(100);
  }

  closeSession(pRemoteWritableCharacteristic);
  while(connectionStatus != 4) {
    if (to < millis()) return false;
    delay(100);
  }

  // Serial.print("Unsubscribing control channel... ");
  // pRemoteNotifyableDescriptors = pRemoteReadableCharacteristic->getDescriptors();
  // for(auto itr = pRemoteNotifyableDescriptors->begin(); itr != pRemoteNotifyableDescriptors->end(); ++itr) {
  //   itr->second->writeValue((uint8_t*)CMD_UNSUBSCRIBE_REQUEST, sizeof (CMD_UNSUBSCRIBE_REQUEST));
  //   Serial.println("unsubscribed");
  // }
  // pRemoteReadableCharacteristic->registerForNotify(nullptr);

  delay(1);
  if (m_pClient->isConnected() == false) return false;
  Serial.print("Subscribing liveData channel... ");
  pRemoteLivedataCharacteristic->registerForNotify(nullptr);
  delay(1);
  pRemoteLivedataCharacteristic->registerForNotify(FitbitLiveDataClass::livedataCallback);
  delay(1);
  pRemoteNotifyableDescriptors = pRemoteLivedataCharacteristic->getDescriptors();
  for(auto itr = pRemoteNotifyableDescriptors->begin(); itr != pRemoteNotifyableDescriptors->end(); ++itr) {
    itr->second->writeValue((uint8_t*)CMD_SUBSCRIBE_REQUEST, sizeof (CMD_SUBSCRIBE_REQUEST));
    Serial.println("subscribed");
  }
  return true;
}

bool FitbitLiveDataClass::openSession(BLERemoteCharacteristic* pRemoteCharacteristic) {
  const uint8_t CMD_OPEN_SESSION[] = {0xc0, 0x0a, 0x0a, 0x00, 0x08, 0x00, 0x10, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x01};

  procCallback = true;
  Serial.print("-> ");
  for(int i=0; i< sizeof (CMD_OPEN_SESSION);i++) {
    Serial.printf("%02x",CMD_OPEN_SESSION[i]);
  }
  Serial.println();
  pRemoteCharacteristic->writeValue((uint8_t*)CMD_OPEN_SESSION, sizeof (CMD_OPEN_SESSION));
}


bool FitbitLiveDataClass::authTracker(BLERemoteCharacteristic* pRemoteCharacteristic) {
  randomSeed(analogRead(0));
  uint8_t CMD_AUTH_TRACKER[] = {0xc0, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  CMD_AUTH_TRACKER[2] = random(255);
  CMD_AUTH_TRACKER[3] = random(255);
  CMD_AUTH_TRACKER[4] = random(255);
  CMD_AUTH_TRACKER[5] = random(255);
  CMD_AUTH_TRACKER[6] = m_nonce % 256;
  CMD_AUTH_TRACKER[7] = (m_nonce >> 8) % 256;
  CMD_AUTH_TRACKER[8] = (m_nonce >> 16) % 256;
  CMD_AUTH_TRACKER[9] = (m_nonce >> 24) % 256;

  Serial.print("-> ");
  for(int i=0; i< sizeof (CMD_AUTH_TRACKER);i++) {
    Serial.printf("%02x",CMD_AUTH_TRACKER[i]);
  }
  Serial.println();
  procCallback = true;
  pRemoteCharacteristic->writeValue(CMD_AUTH_TRACKER, sizeof (CMD_AUTH_TRACKER));
}


bool FitbitLiveDataClass::sendAuth(BLERemoteCharacteristic* pRemoteCharacteristic) {
  uint8_t CMD_SEND_AUTH[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  CMac::encrypt(CMac::ENCTYPE_XTEA, m_authSubCode, m_codeLength, authIn, sizeof (authIn), CMD_SEND_AUTH + 2, sizeof (CMD_SEND_AUTH) - 2);

  CMD_SEND_AUTH[0] = 0xC0;
  CMD_SEND_AUTH[1] = 0x52;

  Serial.print("-> ");
  for(int i=0; i< sizeof (CMD_SEND_AUTH);i++) {
    Serial.printf("%02x",CMD_SEND_AUTH[i]);
  }
  Serial.println();

  procCallback = true;
  pRemoteCharacteristic->writeValue(CMD_SEND_AUTH, sizeof (CMD_SEND_AUTH));
}

bool FitbitLiveDataClass::closeSession(BLERemoteCharacteristic* pRemoteCharacteristic) {
  uint8_t CMD_CLOSE_SESSION[] = {0xc0, 0x01};
  Serial.print("-> ");
  for(int i=0; i< sizeof (CMD_CLOSE_SESSION);i++) {
    Serial.printf("%02x",CMD_CLOSE_SESSION[i]);
  }
  Serial.println();

  procCallback = true;
  pRemoteCharacteristic->writeValue(CMD_CLOSE_SESSION, sizeof (CMD_CLOSE_SESSION));
}

void FitbitLiveDataClass::AdvertisedDeviceCallbacks::onResult(BLEAdvertisedDevice advertisedDevice) {
  // We have found a device, let us now see if it contains the service we are looking for.
  if (advertisedDevice.haveServiceUUID() && advertisedDevice.getServiceUUID().equals(UUID_CONTROL_SERVICE) && strcmp(advertisedDevice.getAddress().toString().c_str(), m_pFitbitLiveDataClass->m_mac) == 0) {
Serial.printf("Found!\n  address: %s\n", advertisedDevice.getAddress().toString().c_str()); 
    m_pFitbitLiveDataClass->m_pTrackerAddress = new BLEAddress(advertisedDevice.getAddress());
    advertisedDevice.getScan()->stop();
  } // Found our server
}

// void FitbitLiveDataClass::ClientCallbacks::onConnect(BLEClient* pClient) {
//   Serial.println("Connected");
//   m_pFitbitLiveDataClass->m_isConnected = true;
// }

// void FitbitLiveDataClass::ClientCallbacks::onDisconnect(BLEClient* pClient) {
//   Serial.println("Disconnected");
//   m_pFitbitLiveDataClass->m_isConnected = false;
// }

void FitbitLiveDataClass::JsonEventListener::whitespace(char c) {
  // Serial.println("whitespace");
  if (m_currentKey) free(m_currentKey);
  m_currentKey = nullptr;
}

void FitbitLiveDataClass::JsonEventListener::startDocument() {
  // Serial.println("start document");
  if (m_currentKey) free(m_currentKey);
  m_currentKey = nullptr;
}

void FitbitLiveDataClass::JsonEventListener::key(String key) {
  if (m_currentKey) free(m_currentKey);
  m_currentKey = (char*)malloc(key.length() + 1);
  key.toCharArray(m_currentKey, key.length() + 1);
}

void FitbitLiveDataClass::CredentialJsonEventListener::value(String val) {
  if (strcmp(m_currentKey, "authSubKey") == 0) {
    if (m_pFitbitLiveDataClass->m_authSubCode != nullptr) free(m_pFitbitLiveDataClass->m_authSubCode);
    m_pFitbitLiveDataClass->m_codeLength = val.length() / 2;
    m_pFitbitLiveDataClass->m_authSubCode = (uint8_t*) malloc(m_pFitbitLiveDataClass->m_codeLength);
    for (int i=0;i<val.length();i+=2) {
      m_pFitbitLiveDataClass->m_authSubCode[i/2] = strtol(val.substring(i, i+2).c_str(), NULL, 16) & 0xff;
    }
  } else if (strcmp(m_currentKey, "nonce") == 0) {
    m_pFitbitLiveDataClass->m_nonce = strtoll(val.c_str(), nullptr, 10);
  } else if (strcmp(m_currentKey, "mac") == 0) {
    sprintf(m_pFitbitLiveDataClass->m_mac, "%s", val.c_str());
  }
  JsonEventListener::value(val);
}

void FitbitLiveDataClass::Oauth2TokenJsonEventListener::value(String val) {
  if (strcmp(m_currentKey, "access_token") == 0) {
    if (m_pFitbitLiveDataClass->m_token != nullptr) free(m_pFitbitLiveDataClass->m_token);
    m_pFitbitLiveDataClass->m_token = (char*) malloc(val.length() + 1);
    sprintf(m_pFitbitLiveDataClass->m_token, "%s", val.c_str());
  }
  JsonEventListener::value(val);
}

void FitbitLiveDataClass::DevicesJsonEventListener::value(String val) {
  if (m_currentKey != nullptr) {
    if (strcmp(m_currentKey, "deviceVersion") == 0) {
      m_pDeviceVersion = (char*)malloc(val.length() + 1);
      sprintf(m_pDeviceVersion, "%s", val.c_str());
    } else if (strcmp(m_currentKey, "mac") == 0) {
      m_pMac = (char*)malloc(val.length() + 1);
      sprintf(m_pMac, "%s", val.c_str());
    } else if (strcmp(m_currentKey, "wireId") == 0) {
      m_pWireId = (char*)malloc(val.length() + 1);
      sprintf(m_pWireId, "%s", val.c_str());
    }
  }
  JsonEventListener::value(val);
}

void FitbitLiveDataClass::DevicesJsonEventListener::startObject() {
  JsonEventListener::startObject();
}

void FitbitLiveDataClass::DevicesJsonEventListener::endObject() {
  if (strcmp(m_pDeviceVersion, m_pTrackerName) == 0) {
    int i;
    if (m_pFitbitLiveDataClass->m_wireId != nullptr) free(m_pFitbitLiveDataClass->m_wireId);
    for(i=0; ;i++) {
      if (m_pWireId[i] == '\0') {
        break;
      }
    }
    m_pFitbitLiveDataClass->m_wireId = (char*) malloc(i + 1);
    sprintf(m_pFitbitLiveDataClass->m_wireId, "%s", m_pWireId);

    m_pFitbitLiveDataClass->m_mac[2] = m_pFitbitLiveDataClass->m_mac[5] = m_pFitbitLiveDataClass->m_mac[8] = m_pFitbitLiveDataClass->m_mac[11] = m_pFitbitLiveDataClass->m_mac[14] = ':';
    for(i=0;i<12;i+=2) {
      m_pFitbitLiveDataClass->m_mac[i/2*3  ] = m_pMac[10-i] >= 65 && m_pMac[10-i] < 91 ? m_pMac[10-i] + 32: m_pMac[10-i];
      m_pFitbitLiveDataClass->m_mac[i/2*3+1] = m_pMac[11-i] >= 65 && m_pMac[11-i] < 91 ? m_pMac[11-i] + 32: m_pMac[11-i];
    }
  }
  if (m_pDeviceVersion) {
    free(m_pDeviceVersion);
    m_pDeviceVersion = nullptr;
  }
  if (m_pWireId) {
    free(m_pWireId);
    m_pWireId = nullptr;
  }
  if (m_pMac) {
    free(m_pMac);
    m_pMac = nullptr;
  }
  JsonEventListener::endObject();
}

void FitbitLiveDataClass::JsonEventListener::value(String val) {
  if (m_currentKey) free(m_currentKey);
  m_currentKey = nullptr;
}

void FitbitLiveDataClass::JsonEventListener::endArray() {
  // Serial.println("end array. ");
  if (m_currentKey) free(m_currentKey);
  m_currentKey = nullptr;
}

void FitbitLiveDataClass::JsonEventListener::endObject() {
  // Serial.println("end object. ");
  if (m_currentKey) free(m_currentKey);
  m_currentKey = nullptr;
}

void FitbitLiveDataClass::JsonEventListener::endDocument() {
  // Serial.println("end document. ");
  if (m_currentKey) free(m_currentKey);
  m_currentKey = nullptr;
}

void FitbitLiveDataClass::JsonEventListener::startArray() {
  // Serial.println("start array. ");
  if (m_currentKey) free(m_currentKey);
  m_currentKey = nullptr;
}

void FitbitLiveDataClass::JsonEventListener::startObject() {
  // Serial.println("start object. ");
  if (m_currentKey) free(m_currentKey);
  m_currentKey = nullptr;
}


FitbitLiveDataClass FitbitLiveData;
