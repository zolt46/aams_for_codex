// ===== Fingerprint JSON Bridge (UI Core Only) =====
// Commands (each line is one JSON object):
// {"cmd":"open"}
// {"cmd":"identify"}
// {"cmd":"verify","id":12}
// {"cmd":"enroll","id":12}
// {"cmd":"delete","id":12}
// {"cmd":"clear"}
// {"cmd":"count"}
// {"cmd":"buzzer","state":"on"}
// {"cmd":"buzzer","state":"off"}

#include <Arduino.h>
#include <limits.h>
#include <Adafruit_Fingerprint.h>

// ---------- Relay/Buzzer control ----------
#ifndef BUZZER_PIN
#define BUZZER_PIN 10
#endif

#ifndef FINGERPRINT_LED_COLOR_RED
  #ifdef FINGERPRINT_LED_RED
    #define FINGERPRINT_LED_COLOR_RED FINGERPRINT_LED_RED
  #else
    #define FINGERPRINT_LED_COLOR_RED 0x01
  #endif
#endif
#ifndef FINGERPRINT_LED_COLOR_BLUE
  #ifdef FINGERPRINT_LED_BLUE
    #define FINGERPRINT_LED_COLOR_BLUE FINGERPRINT_LED_BLUE
  #else
    #define FINGERPRINT_LED_COLOR_BLUE 0x02
  #endif
#endif
#ifndef FINGERPRINT_LED_COLOR_PURPLE
  #ifdef FINGERPRINT_LED_PURPLE
    #define FINGERPRINT_LED_COLOR_PURPLE FINGERPRINT_LED_PURPLE
  #else
    #define FINGERPRINT_LED_COLOR_PURPLE 0x03
  #endif
#endif


// ---------- Board/Serial selection ----------
#if defined(__AVR_ATmega2560__) || defined(ARDUINO_AVR_MEGA2560)
// Mega 2560: use Serial1 (pins 19=RX1, 18=TX1)
  #define FP_USE_HWSERIAL 1
  HardwareSerial &FP_HW = Serial1;
#else
// UNO (optional): use AltSoftSerial (pins fixed: RX=8, TX=9)
// Install "AltSoftSerial" by Paul Stoffregen if you need UNO.
  #include <AltSoftSerial.h>
  AltSoftSerial FP_SW;          // RX=8, TX=9 (UNO fixed)
  #define FP_USE_HWSERIAL 0
#endif

// Build the Adafruit driver on selected serial
#if FP_USE_HWSERIAL
  Adafruit_Fingerprint finger = Adafruit_Fingerprint(&FP_HW);
#else
  Adafruit_Fingerprint finger = Adafruit_Fingerprint(&FP_SW);
#endif

// ---------- IO helpers ----------
String rxbuf;
void jprintln(const String &s){ Serial.println(s); }
void ok(const String &type, const String &kv=""){
  String o = String("{\"ok\":true,\"type\":\"")+type+"\"";
  if (kv.length()){ o+=','; o+=kv; }
  o+='}'; jprintln(o);
}
void err(const String &m){ jprintln(String("{\"ok\":false,\"error\":\"")+m+"\"}"); }

bool buzzerActive = false;

void setBuzzer(bool on){
#if defined(BUZZER_PIN)
  digitalWrite(BUZZER_PIN, on ? HIGH : LOW);
#endif
  buzzerActive = on;
}

int parseIntField(const String &line, const char *key){
  String k = String("\"")+key+"\"";
  int p = line.indexOf(k); if (p<0) return INT_MIN;
  int c = line.indexOf(':', p+k.length()); if (c<0) return INT_MIN;
  int i = c+1; while (i<(int)line.length() && isspace(line[i])) i++;
  bool neg=false; if (i<(int)line.length() && line[i]=='-'){ neg=true; i++; }
  long v=0; bool got=false;
  while (i<(int)line.length() && isDigit(line[i])){ v=v*10+(line[i]-'0'); i++; got=true; }
  if (!got) return INT_MIN; return (int)(neg ? -v : v);
}
String parseStringField(const String &line, const char *key){
  String k = String("\"") + key + "\"";
  int p = line.indexOf(k); if (p < 0) return String();
  int c = line.indexOf(':', p + k.length()); if (c < 0) return String();
  int i = c + 1;
  while (i < (int)line.length() && isspace(line[i])) i++;
  if (i >= (int)line.length() || line[i] != '"') return String();
  int start = ++i;
  while (i < (int)line.length() && line[i] != '"') i++;
  if (i >= (int)line.length()) return String();
  return line.substring(start, i);
}


// ---------- Sensor helpers ----------
uint8_t waitImage(uint32_t timeout_ms=8000){
  uint32_t t0 = millis();
  while (millis()-t0 < timeout_ms){
    uint8_t p = finger.getImage();
    if (p==FINGERPRINT_OK) return p;
    if (p==FINGERPRINT_NOFINGER) { delay(30); continue; }
    delay(30);
  }
  return FINGERPRINT_NOFINGER;
}

bool doIdentify(){
  if (waitImage()!=FINGERPRINT_OK){ err("timeout_or_no_finger"); return false; }
  if (finger.image2Tz(1)!=FINGERPRINT_OK){ err("image2tz_failed"); return false; }
  uint8_t p = finger.fingerFastSearch();
  if (p==FINGERPRINT_OK){
    ok("identify", String("\"matchId\":")+finger.fingerID+",\"confidence\":"+finger.confidence);
    return true;
  }
  if (p==FINGERPRINT_NOTFOUND){ err("no_match"); return false; }
  err("search_error"); return false;
}

bool doVerify(uint16_t id){
  if (waitImage()!=FINGERPRINT_OK){ err("timeout_or_no_finger"); return false; }
  if (finger.image2Tz(1)!=FINGERPRINT_OK){ err("image2tz_failed"); return false; }
  uint8_t p = finger.fingerFastSearch();
  bool matched = (p==FINGERPRINT_OK && finger.fingerID==id);
  if (p==FINGERPRINT_OK){
    ok("verify", String("\"id\":")+id+",\"matched\":"+(matched?"true":"false")+",\"confidence\":"+finger.confidence);
  } else {
    ok("verify", String("\"id\":")+id+",\"matched\":false");
  }
  return matched;
}

bool doEnroll(uint16_t id){
  jprintln("{\"stage\":\"place\",\"msg\":\"Place finger #1\"}");
  while (finger.getImage()!=FINGERPRINT_OK){}
  if (finger.image2Tz(1)!=FINGERPRINT_OK){ err("image2tz_failed_1"); return false; }
  while (finger.getImage()!=FINGERPRINT_NOFINGER){} // lift
  jprintln("{\"stage\":\"place\",\"msg\":\"Place same finger #2\"}");
  while (finger.getImage()!=FINGERPRINT_OK){}
  if (finger.image2Tz(2)!=FINGERPRINT_OK){ err("image2tz_failed_2"); return false; }
  if (finger.createModel()!=FINGERPRINT_OK){ err("create_model_failed"); return false; }
  if (finger.storeModel(id)!=FINGERPRINT_OK){ err("store_model_failed"); return false; }
  ok("enroll", String("\"id\":")+id); return true;
}

bool doDelete(uint16_t id){
  if (finger.deleteModel(id)==FINGERPRINT_OK){ ok("delete", String("\"id\":")+id); return true; }
  err("delete_failed"); return false;
}
bool doClear(){
  if (finger.emptyDatabase()==FINGERPRINT_OK){ ok("clear"); return true; }
  err("clear_failed"); return false;
}
bool doCount(){
  if (finger.getTemplateCount()==FINGERPRINT_OK){ ok("count", String("\"count\":")+finger.templateCount); return true; }
  err("count_failed"); return false;
}

bool doLed(const String &modeRaw, const String &colorRaw, int speed, int cycles){
  String mode = modeRaw; mode.trim(); mode.toLowerCase();
  String color = colorRaw; color.trim(); color.toLowerCase();

  uint8_t ledMode = FINGERPRINT_LED_ON;
  String modeOut = "on";
  if (mode.length() == 0) { ledMode = FINGERPRINT_LED_ON; modeOut = "on"; }
  else if (mode == "off" || mode == "stop") { ledMode = FINGERPRINT_LED_OFF; modeOut = "off"; }
  else if (mode == "flash" || mode == "flashing" || mode == "blink") { ledMode = FINGERPRINT_LED_FLASHING; modeOut = "flash"; }
  else if (mode == "breathing" || mode == "breathe" || mode == "pulse") { ledMode = FINGERPRINT_LED_BREATHING; modeOut = "breathing"; }
  else if (mode == "gradual" || mode == "gradual_on" || mode == "fade") { ledMode = FINGERPRINT_LED_GRADUAL_ON; modeOut = "gradual"; }
  else { ledMode = FINGERPRINT_LED_ON; modeOut = mode.length() ? mode : "on"; }

  uint8_t ledColor = FINGERPRINT_LED_COLOR_BLUE;
  String colorOut = color.length() ? color : "blue";
  if (color == "red") { ledColor = FINGERPRINT_LED_COLOR_RED; colorOut = "red"; }
  else if (color == "purple" || color == "violet") { ledColor = FINGERPRINT_LED_COLOR_PURPLE; colorOut = "purple"; }
  else if (color == "blue" || color == "cyan" || color == "teal") { ledColor = FINGERPRINT_LED_COLOR_BLUE; colorOut = "blue"; }
  else if (color == "off") { ledColor = FINGERPRINT_LED_COLOR_BLUE; colorOut = "off"; }

  uint8_t ledSpeed = (speed >= 0 && speed <= 255) ? (uint8_t)speed : 0;
  uint8_t ledCycles = (cycles >= 0 && cycles <= 255) ? (uint8_t)cycles : 0;

  bool okb = finger.LEDcontrol(ledMode, ledSpeed, ledColor, ledCycles);
  if (okb){
    ok("led", String("\"mode\":\"") + modeOut + "\",\"color\":\"" + colorOut + "\",\"speed\":" + (int)ledSpeed + ",\"cycles\":" + (int)ledCycles);
    return true;
  }
  err("led_failed");
  return false;
}


// ---------- open (baud autoscan 57600/9600) ----------
bool tryAt(uint32_t br){
#if FP_USE_HWSERIAL
  FP_HW.end(); delay(30); FP_HW.begin(br);
#else
  FP_SW.end(); delay(30); FP_SW.begin(br);
#endif
  finger.begin(br); delay(80);
  return finger.verifyPassword();
}

// ---------- Dispatcher ----------
void handleLine(const String &line){
  if (line.indexOf("\"cmd\"")<0){ err("bad_request"); return; }

  if (line.indexOf("\"open\"")>=0){
    bool okb=false; uint32_t chosen=0;
    const uint32_t speeds[] = {57600, 9600, 115200, 19200};
    for (uint8_t i=0;i<sizeof(speeds)/sizeof(speeds[0]) && !okb;i++){
      okb = tryAt(speeds[i]); if (okb) chosen=speeds[i];
    }
    if (!okb){ err("sensor_open_failed"); return; }
    finger.getTemplateCount();
    ok("open", String("\"baud\":")+chosen+",\"capacity\":"+(int)finger.capacity+",\"count\":"+(int)finger.templateCount);
    return;
  }

  if (line.indexOf("\"identify\"")>=0){ doIdentify(); return; }

  if (line.indexOf("\"verify\"")>=0){
    int id = parseIntField(line,"id"); if (id==INT_MIN || id<=0){ err("missing_or_bad_id"); return; }
    doVerify((uint16_t)id); return;
  }

  if (line.indexOf("\"enroll\"")>=0){
    int id = parseIntField(line,"id"); if (id==INT_MIN || id<=0){ err("missing_or_bad_id"); return; }
    doEnroll((uint16_t)id); return;
  }

  if (line.indexOf("\"delete\"")>=0){
    int id = parseIntField(line,"id"); if (id==INT_MIN || id<=0){ err("missing_or_bad_id"); return; }
    doDelete((uint16_t)id); return;
  }

  if (line.indexOf("\"clear\"")>=0){ doClear(); return; }
  if (line.indexOf("\"count\"")>=0){ doCount(); return; }
  if (line.indexOf("\"led\"")>=0){
    String mode = parseStringField(line, "mode");
    if (!mode.length()) mode = parseStringField(line, "state");
    String color = parseStringField(line, "color");
    int speed = parseIntField(line, "speed"); if (speed == INT_MIN) speed = parseIntField(line, "brightness");
    int cycles = parseIntField(line, "cycles");
    doLed(mode, color, speed == INT_MIN ? -1 : speed, cycles == INT_MIN ? -1 : cycles);
    return;
  }

  if (line.indexOf("\"buzzer\"")>=0){
    String state = parseStringField(line, "state");
    if (!state.length()) state = parseStringField(line, "mode");
    if (!state.length()) state = parseStringField(line, "command");
    bool turnOn = false;
    bool hasState = state.length();
    if (hasState){
      String lower = state; lower.toLowerCase();
      turnOn = (lower == "on" || lower == "1" || lower == "true" || lower == "high");
    } else {
      int value = parseIntField(line, "value");
      if (value == INT_MIN) value = parseIntField(line, "on");
      if (value != INT_MIN) { turnOn = (value != 0); hasState = true; }
    }
    if (!hasState){
      err("missing_buzzer_state");
      return;
    }
    setBuzzer(turnOn);
    ok("buzzer", String("\"state\":\"") + (turnOn ? "on" : "off") + "\",\"active\":" + (buzzerActive ? "true" : "false"));
    return;
  }

  err("unknown_cmd");
}

// ---------- setup/loop ----------
void setup(){
  Serial.begin(115200);
  delay(200);
#if defined(BUZZER_PIN)
  pinMode(BUZZER_PIN, OUTPUT);
  digitalWrite(BUZZER_PIN, LOW);
#endif
#if FP_USE_HWSERIAL
  FP_HW.begin(57600); finger.begin(57600);
#else
  FP_SW.begin(57600); finger.begin(57600);
#endif
  delay(60);
  jprintln("{\"hello\":\"fp-bridge\",\"version\":\"ui-core-1.0\"}");
}

void loop(){
  while (Serial.available()){
    char c = Serial.read();
    if (c=='\n' || c=='\r'){
      if (rxbuf.length()){ handleLine(rxbuf); rxbuf=""; }
    } else {
      rxbuf += c;
      if (rxbuf.length()>480) rxbuf=""; // flood guard
    }
  }
}
