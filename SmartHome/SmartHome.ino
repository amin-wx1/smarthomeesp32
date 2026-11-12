#include <Arduino.h>
#include <WiFi.h>

#include "Pins.h"
#include "Settings.h"
#include "Secrets.h"
#include "Models.h"
#include "SensorManager.h"
#include "RelayManager.h"
#include "BuzzerManager.h"
#include "EventManager.h"
#include "SecurityManager.h"
#include "AutomationEngine.h"
#include "AuthManager.h"
#include "ApiManager.h"

SensorManager sensorManager;
RelayManager relayManager;
BuzzerManager buzzerManager;
EventManager eventManager;
SecurityManager securityManager;
AutomationEngine automationEngine;
AuthManager authManager;
ApiManager apiManager;

unsigned long lastWifiCheck = 0;

void setup() {
    Serial.begin(115200);
    delay(500);

    relayManager.begin();
    buzzerManager.begin();

    sensorManager.begin();
    securityManager.begin();
    authManager.begin();

    eventManager.addEvent(
        Models::EventType::SYSTEM_START,
        "سیستم خانه هوشمند راه اندازی شد"
    );

    if (Settings::USE_CLOUD_MQTT) {
        // persistent باید قبل از mode تنظیم شود. اتصال بدون انتظار شروع می‌شود تا
        // منطق ایمنی (گاز، دزدگیر) در صورت نبود وای‌فای متوقف نماند.
        WiFi.persistent(false);
        WiFi.mode(WIFI_STA);
        WiFi.setAutoReconnect(true);
        WiFi.begin(Secrets::WIFI_SSID, Secrets::WIFI_PASSWORD);
        lastWifiCheck = millis();
        Serial.println("Wi-Fi connection started (non-blocking)");
    } else {
        WiFi.disconnect(true);
        delay(200);
        WiFi.mode(WIFI_AP);
        const bool apStarted = WiFi.softAP(
            Settings::AP_SSID,
            Settings::AP_PASSWORD
        );

        if (apStarted) {
            Serial.println("Smart Home access point started");
            Serial.println(WiFi.softAPIP());
        }
    }

    apiManager.begin(
        sensorManager,
        relayManager,
        buzzerManager,
        securityManager,
        automationEngine,
        eventManager,
        authManager
    );
}

void loop() {
    if (Settings::USE_CLOUD_MQTT) {
        // اتصال مجدد را setAutoReconnect انجام می‌دهد؛ فقط اگر مدت زیادی قطع بود
        // یک reconnect نرم می‌زنیم (بدون disconnect/begin دستی).
        const unsigned long now = millis();
        if (WiFi.status() == WL_CONNECTED) {
            lastWifiCheck = now;
        } else if (now - lastWifiCheck > 30000) {
            lastWifiCheck = now;
            Serial.println("Wi-Fi still down, requesting reconnect...");
            WiFi.reconnect();
        }
    }

    sensorManager.update(eventManager);

    automationEngine.update(
        sensorManager.getData(),
        relayManager,
        eventManager,
        buzzerManager
    );

    securityManager.update(
        sensorManager.getData(),
        eventManager,
        buzzerManager
    );

    buzzerManager.update();
    apiManager.update();

    delay(2);
}
