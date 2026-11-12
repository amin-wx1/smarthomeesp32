#pragma once
#include <Arduino.h>

namespace Settings {
// Flag Cloud Or Local
constexpr bool USE_CLOUD_MQTT = true;

// نام و رمز وای‌فای و رمز MQTT در Secrets.h هستند، نه اینجا.

//   Mosquitto Properties In RunFlare 
constexpr char MQTT_HOST[] = "mosquitto-lyo-smarthome.runflare.cloud";
constexpr uint16_t MQTT_PORT = 443;          // WSS روی دامنه‌ی Runflare (با MQTTX تست شد)
// اتصال برد از بیرون Runflare فقط از طریق WebSocket امن ممکن است (پورت 1883 عمومی نیست).
// برای بروکر محلی/بدون TLS false کنید و MQTT_PORT را 1883 بگذارید.
constexpr bool MQTT_USE_WSS = true;
constexpr char MQTT_WS_PATH[] = "/mqtt";

//Topic MQTT
constexpr char MQTT_TOPIC_REQ[] = "smarthome/api/request";
constexpr char MQTT_TOPIC_RES[] = "smarthome/api/response";
constexpr char MQTT_TOPIC_STATUS[] = "smarthome/status";
constexpr char MQTT_STATUS_ONLINE[] = "online";
constexpr char MQTT_STATUS_OFFLINE[] = "offline";   // پیام LWT
constexpr unsigned long MQTT_STATUS_INTERVAL_MS = 1500;
constexpr int MQTT_BUFFER_SIZE = 8192;
constexpr size_t MQTT_MAX_REQUEST_BYTES = 4096;
constexpr size_t MQTT_MAX_RESPONSE_BYTES = 6000;
constexpr uint8_t MQTT_RX_QUEUE_DEPTH = 4;
constexpr int MQTT_KEEPALIVE_S = 30;
constexpr int MQTT_RECONNECT_MS = 5000;

// راه‌اندازی اولیه (ساخت رمز مدیر) فقط از شبکه‌ی محلی مجاز است.
// برای فعال کردن از طریق ابر true کنید (توصیه نمی‌شود).
constexpr bool ALLOW_REMOTE_SETUP = false;

// پاسخ /api/history: حداکثر تعداد رویداد و سقف حجم JSON
constexpr uint16_t HISTORY_API_LIMIT = 30;
constexpr size_t HISTORY_MAX_BYTES = 5500;

constexpr char AP_SSID[] = "SmartHome-Final";
constexpr char AP_PASSWORD[] = "12345678";
constexpr uint16_t WEB_SERVER_PORT = 80;

constexpr unsigned long SENSOR_READ_INTERVAL_MS = 2000;
constexpr unsigned long DHT_READ_INTERVAL_MS = 2000;
constexpr unsigned long PIR_WARMUP_MS = 30000;
constexpr unsigned long MQ2_WARMUP_MS = 60000;
constexpr unsigned long DHT_STALE_TIMEOUT_MS = 10000;

constexpr float FAN_ON_TEMP = 30.0f;
constexpr float FAN_OFF_TEMP = 28.0f;
constexpr float HEATING_ON_TEMP = 18.0f;
constexpr float HEATING_OFF_TEMP = 20.0f;

constexpr unsigned long DOOR_OPEN_WARNING_MS = 10000;
constexpr unsigned long DOOR_REMINDER_INTERVAL_MS = 30000;
constexpr unsigned long SECURITY_EVENT_DEBOUNCE_MS = 300;
constexpr unsigned long PIR_EVENT_COOLDOWN_MS = 2000;

constexpr unsigned long DASHBOARD_REFRESH_MS = 1500;

constexpr uint8_t MAX_LOGIN_ATTEMPTS = 5;
constexpr unsigned long LOGIN_LOCKOUT_MS = 60000;
constexpr unsigned long SESSION_TIMEOUT_MS = 30UL * 60UL * 1000UL;
constexpr uint8_t MAX_ACTIVE_SESSIONS = 8;
constexpr uint8_t MIN_PASSWORD_LENGTH = 10;

constexpr uint16_t MAX_EVENT_HISTORY = 100;
constexpr unsigned long RAIN_STABILITY_MS = 3000;

constexpr uint16_t RAIN_DRY_RAW = 4095;
constexpr uint16_t RAIN_WET_RAW = 0;

constexpr bool LDR_DARK_LEVEL = false;
}
