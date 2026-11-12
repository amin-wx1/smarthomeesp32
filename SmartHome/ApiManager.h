#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <mqtt_client.h>
#include <esp_crt_bundle.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <ArduinoJson.h>

#include "Settings.h"
#include "Secrets.h"
#include "Models.h"
#include "SensorManager.h"
#include "RelayManager.h"
#include "BuzzerManager.h"
#include "SecurityManager.h"
#include "AutomationEngine.h"
#include "EventManager.h"
#include "AuthManager.h"
#include "WebDashboard.h"

class ApiManager {
private:
    WebServer server;
    // MQTT غیرهمزمان (esp-mqtt). رویدادها در تسک MQTT می‌آیند و فقط داخل صف می‌روند؛
    // همه‌ی handlerهای API در loop() اجرا می‌شوند، پس به قفل نیازی نیست.
    esp_mqtt_client_handle_t mqttClient = nullptr;
    QueueHandle_t mqttRxQueue = nullptr;
    volatile bool mqttConnected = false;
    bool mqttStarted = false;
    String mqttClientId;
    String rxAssembly;            // فقط در تسک MQTT استفاده می‌شود
    bool rxOverflow = false;      // فقط در تسک MQTT استفاده می‌شود
    volatile uint32_t mqttDroppedRequests = 0;

    SensorManager* sensors = nullptr;
    RelayManager* relays = nullptr;
    BuzzerManager* buzzer = nullptr;
    SecurityManager* security = nullptr;
    AutomationEngine* automation = nullptr;
    EventManager* events = nullptr;
    AuthManager* auth = nullptr;

    String activeToken = "";
    String activeBody = "";
    bool isMqttContext = false;
    int lastStatusCode = 200;
    String lastResponseJson = "";

    String getToken() {
        if (isMqttContext) return activeToken;
        if (!server.hasHeader("Authorization")) return "";
        const String header = server.header("Authorization");
        return header.startsWith("Bearer ") ? header.substring(7) : "";
    }

    void sendJson(JsonDocument& doc, int code = 200) {
        String output;
        serializeJson(doc, output);
        if (isMqttContext) {
            lastStatusCode = code;
            lastResponseJson = output;
        } else {
            server.send(code, "application/json; charset=utf-8", output);
        }
    }

    void sendError(int code, const char* message) {
        JsonDocument response;
        response["success"] = false;
        response["message"] = message;
        sendJson(response, code);
    }

    bool parseRequest(JsonDocument& doc) {
        const String rawBody = isMqttContext ? activeBody : (server.hasArg("plain") ? server.arg("plain") : "");
        if (rawBody.length() == 0) {
            sendError(400, "Empty request body");
            return false;
        }
        const DeserializationError error = deserializeJson(doc, rawBody);
        if (error) {
            sendError(400, "Invalid JSON");
            return false;
        }
        return true;
    }

    bool dependenciesReady() {
        return sensors && relays && buzzer && security && automation && events && auth;
    }

    bool requireAuth() {
        if (!dependenciesReady() || !auth->isInitialized()) {
            sendError(503, "Server not ready");
            return false;
        }
        if (!auth->validateSession(getToken(), *events)) {
            sendError(401, "Unauthorized");
            return false;
        }
        return true;
    }

    void handleRoot() {
        server.send_P(200, "text/html; charset=utf-8", DASHBOARD_HTML);
    }

    void handleSetupStatus() {
        if (!auth || !auth->isInitialized()) {
            sendError(503, "Authentication storage is unavailable");
            return;
        }
        JsonDocument response;
        response["success"] = true;
        response["setupRequired"] = auth->isSetupRequired();
        response["remoteSetupAllowed"] = Settings::ALLOW_REMOTE_SETUP;
        response["loginBlocked"] = auth->isLoginBlocked();
        response["lockoutRemainingSeconds"] = auth->getLockoutRemainingSeconds();
        sendJson(response);
    }

    void handleSetup() {
        if (!auth || !events || !auth->isInitialized()) {
            sendError(503, "Server not ready");
            return;
        }
        if (!auth->isSetupRequired()) {
            sendError(409, "Initial setup has already been completed");
            return;
        }
        if (isMqttContext && !Settings::ALLOW_REMOTE_SETUP) {
            sendError(403, "راه‌اندازی اولیه فقط از شبکه‌ی محلی مجاز است. به آدرس IP برد در وای‌فای خانه وصل شوید.");
            return;
        }

        JsonDocument doc;
        if (!parseRequest(doc)) return;

        const String password = doc["password"].as<String>();
        const String confirmation = doc["confirmation"].as<String>();
        if (password.length() < Settings::MIN_PASSWORD_LENGTH) {
            sendError(400, "Password must contain at least 10 characters");
            return;
        }
        if (password != confirmation) {
            sendError(400, "Password confirmation does not match");
            return;
        }
        if (!auth->setupPassword(password, confirmation, *events)) {
            sendError(500, "Could not save the administrator password");
            return;
        }

        JsonDocument response;
        response["success"] = true;
        response["message"] = "Initial setup completed. Please log in.";
        sendJson(response);
    }

    void handleLogin() {
        if (!auth || !events || !auth->isInitialized()) {
            sendError(503, "Server not ready");
            return;
        }
        if (auth->isSetupRequired()) {
            sendError(409, "Initial setup is required");
            return;
        }
        if (auth->isLoginBlocked()) {
            sendError(429, "Login is temporarily blocked");
            return;
        }

        JsonDocument doc;
        if (!parseRequest(doc)) return;

        const String password = doc["password"].as<String>();
        const String device = doc["device"] | "Unknown device";
        String token;

        if (!auth->login(password, device, token, *events)) {
            if (auth->isLoginBlocked()) {
                sendError(429, "Too many attempts. Try again later.");
            } else {
                sendError(401, "Login failed");
            }
            return;
        }

        JsonDocument response;
        response["success"] = true;
        response["token"] = token;
        sendJson(response);
    }

    void handleLogout() {
        if (!requireAuth()) return;
        auth->logout(getToken(), *events);
        JsonDocument response;
        response["success"] = true;
        sendJson(response);
    }

    void handlePasswordChange() {
        if (!requireAuth()) return;
        JsonDocument doc;
        if (!parseRequest(doc)) return;

        const String currentPassword = doc["currentPassword"].as<String>();
        const String newPassword = doc["newPassword"].as<String>();
        const String confirmation = doc["confirmation"].as<String>();

        if (newPassword.length() < Settings::MIN_PASSWORD_LENGTH) {
            sendError(400, "New password must contain at least 10 characters");
            return;
        }
        if (newPassword != confirmation) {
            sendError(400, "Password confirmation does not match");
            return;
        }
        if (!auth->changePassword(currentPassword, newPassword, confirmation, *events)) {
            sendError(400, "Current password is incorrect or new password is invalid");
            return;
        }

        auth->logoutOtherSessions(getToken(), *events);
        JsonDocument response;
        response["success"] = true;
        response["message"] = "Password changed. Other sessions were signed out.";
        sendJson(response);
    }

    void handleSessions() {
        if (!requireAuth()) return;
        auth->purgeExpiredSessions(*events);
        JsonDocument response;
        response["success"] = true;
        JsonArray list = response["sessions"].to<JsonArray>();
        const Models::Session* sessions = auth->getSessions();
        const uint32_t now = millis();

        for (uint8_t i = 0; i < Settings::MAX_ACTIVE_SESSIONS; ++i) {
            if (!sessions[i].active) continue;
            JsonObject item = list.add<JsonObject>();
            item["device"] = sessions[i].deviceInfo;
            item["lastActivitySecondsAgo"] = (now - sessions[i].lastActivity) / 1000;
            item["current"] = sessions[i].token == getToken();
        }
        sendJson(response);
    }

    void handleLogoutOthers() {
        if (!requireAuth()) return;
        auth->logoutOtherSessions(getToken(), *events);
        JsonDocument response;
        response["success"] = true;
        sendJson(response);
    }

    void handleStatus() {
        if (!requireAuth()) return;
        const Models::SensorData& s = sensors->getData();
        const Models::RelayState& r = relays->getState();

        JsonDocument response;
        response["success"] = true;

        JsonObject sensor = response["sensors"].to<JsonObject>();
        sensor["temperature"] = s.temperature;
        sensor["humidity"] = s.humidity;
        sensor["pirMotion"] = s.pirMotion;
        sensor["gasDetected"] = s.gasDetected;
        sensor["mainDoorOpen"] = s.mainDoorOpen;
        sensor["garageDoorOpen"] = s.garageDoorOpen;
        sensor["rainRaw"] = s.rainRaw;
        sensor["rainPercent"] = s.rainPercent;
        sensor["rainLevel"] = static_cast<uint8_t>(s.rainLevel);
        sensor["rainDetected"] = s.rainDetected;
        sensor["ldrState"] = s.ldrState;
        sensor["pirStatus"] = static_cast<uint8_t>(s.pirStatus);
        sensor["mq2Status"] = static_cast<uint8_t>(s.mq2Status);
        sensor["dhtStatus"] = static_cast<uint8_t>(s.dhtStatus);
        sensor["rainStatus"] = static_cast<uint8_t>(s.rainStatus);
        sensor["ldrStatus"] = static_cast<uint8_t>(s.ldrStatus);

        JsonObject relay = response["relays"].to<JsonObject>();
        relay["fan"] = r.fan;
        relay["yardLight"] = r.yardLight;
        relay["gasValve"] = r.gasValve;
        relay["heating"] = r.heating;

        response["smartMode"] = automation->isSmartModeEnabled();
        response["securityMode"] = static_cast<uint8_t>(security->getMode());
        response["securityAlert"] = security->isAlertActive();
        response["gasAlert"] = automation->isGasAlertActive();
        response["gasValveLocked"] = automation->isGasValveLocked();
        response["uptimeSeconds"] = millis() / 1000;
        sendJson(response);
    }

    void handleHistory() {
        if (!requireAuth()) return;
        JsonDocument response;
        const uint16_t total = events->getCount();
        uint16_t count = total < Settings::HISTORY_API_LIMIT ? total : Settings::HISTORY_API_LIMIT;

        // اگر JSON از سقف حجم بزرگ‌تر شد، تعداد رویدادها را کم می‌کنیم تا پاسخ هرگز بی‌صدا حذف نشود.
        for (;;) {
            response.clear();
            response["success"] = true;
            response["total"] = total;
            JsonArray history = response["events"].to<JsonArray>();
            for (uint16_t i = 0; i < count; ++i) {
                const Models::EventRecord* event = events->getEventAt(i);
                if (!event) continue;
                JsonObject item = history.add<JsonObject>();
                item["id"] = event->id;
                item["uptimeSeconds"] = event->uptimeSeconds;
                item["type"] = static_cast<uint8_t>(event->type);
                item["message"] = event->message;
                item["details"] = event->details;
            }
            if (measureJson(response) <= Settings::HISTORY_MAX_BYTES || count <= 1) break;
            count = (count * 2) / 3;
            if (count < 1) count = 1;
        }
        sendJson(response);
    }

    void handleRelay() {
        if (!requireAuth()) return;
        if (automation->isSmartModeEnabled()) {
            sendError(403, "Manual relay control is disabled while Smart Mode is active");
            return;
        }

        JsonDocument doc;
        if (!parseRequest(doc)) return;
        if (!doc["name"].is<const char*>() || !doc["enabled"].is<bool>()) {
            sendError(400, "Relay name and enabled state are required");
            return;
        }

        const String name = doc["name"].as<String>();
        const bool enabled = doc["enabled"].as<bool>();

        if (name == "fan") relays->setFan(enabled);
        else if (name == "yardLight") relays->setYardLight(enabled);
        else if (name == "heating") relays->setHeating(enabled);
        else {
            sendError(400, "Invalid relay");
            return;
        }

        events->addEvent(Models::EventType::RELAY_CHANGED, "وضعیت رله تغییر کرد", name);
        JsonDocument response;
        response["success"] = true;
        sendJson(response);
    }

    void handleSecurityMode() {
        if (!requireAuth()) return;
        JsonDocument doc;
        if (!parseRequest(doc)) return;
        const int mode = doc["mode"] | -1;
        if (mode < 0 || mode > 2) {
            sendError(400, "Invalid security mode");
            return;
        }
        security->setMode(static_cast<Models::SecurityMode>(mode), *events, *buzzer);
        JsonDocument response;
        response["success"] = true;
        sendJson(response);
    }

    void handleSecurityReset() {
        if (!requireAuth()) return;
        security->resetAlert(*events, *buzzer);
        JsonDocument response;
        response["success"] = true;
        sendJson(response);
    }

    void handleSmartMode() {
        if (!requireAuth()) return;
        JsonDocument doc;
        if (!parseRequest(doc)) return;
        if (!doc["enabled"].is<bool>()) {
            sendError(400, "Enabled state is required");
            return;
        }
        automation->setSmartMode(doc["enabled"].as<bool>(), *events);
        JsonDocument response;
        response["success"] = true;
        sendJson(response);
    }

    void handleGasOpen() {
        if (!requireAuth()) return;
        JsonDocument doc;
        if (!parseRequest(doc)) return;
        const bool confirmed = doc["confirmed"] | false;
        const bool result = automation->requestGasValveOpen(
            confirmed, sensors->getData(), *relays, *events);

        if (!result) {
            sendError(403, "Gas valve opening rejected by safety checks");
            return;
        }
        JsonDocument response;
        response["success"] = true;
        sendJson(response);
    }

    static bool isKnownPath(const String& path) {
        static const char* const paths[] = {
            "/api/setup-status", "/api/setup", "/api/login", "/api/logout",
            "/api/auth/password", "/api/auth/sessions", "/api/auth/logout-others",
            "/api/status", "/api/history", "/api/relay", "/api/security/mode",
            "/api/security/reset", "/api/automation/smart-mode", "/api/gas/open"};
        for (const char* p : paths) {
            if (path == p) return true;
        }
        return false;
    }

    void dispatchMqttRoute(const String& path, const String& method) {
        const bool get = method == "GET";
        const bool post = method == "POST";

        if (path == "/api/setup-status" && get) handleSetupStatus();
        else if (path == "/api/setup" && post) handleSetup();
        else if (path == "/api/login" && post) handleLogin();
        else if (path == "/api/logout" && post) handleLogout();
        else if (path == "/api/auth/password" && post) handlePasswordChange();
        else if (path == "/api/auth/sessions" && get) handleSessions();
        else if (path == "/api/auth/logout-others" && post) handleLogoutOthers();
        else if (path == "/api/status" && get) handleStatus();
        else if (path == "/api/history" && get) handleHistory();
        else if (path == "/api/relay" && post) handleRelay();
        else if (path == "/api/security/mode" && post) handleSecurityMode();
        else if (path == "/api/security/reset" && post) handleSecurityReset();
        else if (path == "/api/automation/smart-mode" && post) handleSmartMode();
        else if (path == "/api/gas/open" && post) handleGasOpen();
        else if (isKnownPath(path)) sendError(405, "Method not allowed");
        else sendError(404, "Endpoint not found");
    }

    // در loop() صدا زده می‌شود (نه در تسک MQTT).
    void processMqttRequest(const char* raw) {
        JsonDocument reqDoc;
        if (deserializeJson(reqDoc, raw)) return;

        const String reqId = reqDoc["reqId"] | "";
        const String path = reqDoc["path"] | "";
        const String method = reqDoc["method"] | "";
        if (reqId.length() == 0) return;

        activeToken = reqDoc["token"] | "";
        activeBody = "";
        if (!reqDoc["body"].isNull()) {
            serializeJson(reqDoc["body"], activeBody);
        }

        isMqttContext = true;
        lastStatusCode = 200;
        lastResponseJson = "{}";

        dispatchMqttRoute(path, method);

        isMqttContext = false;

        // پاسخ بزرگ‌تر از سقف را بی‌صدا رها نکن؛ خطای مشخص بفرست.
        if (lastResponseJson.length() > Settings::MQTT_MAX_RESPONSE_BYTES) {
            lastStatusCode = 507;
            lastResponseJson = "{\"success\":false,\"message\":\"Response too large\"}";
        }

        JsonDocument resEnvelope;
        resEnvelope["reqId"] = reqId;
        resEnvelope["status"] = lastStatusCode;
        resEnvelope["payload"] = lastResponseJson;

        String out;
        serializeJson(resEnvelope, out);
        publishResponse(out);

        activeToken = "";
        activeBody = "";
        lastResponseJson = "";
    }

    void publishResponse(const String& out) {
        if (!mqttClient || !mqttConnected) {
            Serial.println("MQTT: response dropped (not connected)");
            return;
        }
        // enqueue غیرمسدودکننده است و از تسک MQTT ارسال می‌شود.
        const int id = esp_mqtt_client_enqueue(
            mqttClient, Settings::MQTT_TOPIC_RES, out.c_str(), out.length(), 0, 0, true);
        if (id < 0) {
            Serial.println("MQTT: response enqueue failed");
        }
    }

    // ---- تسک MQTT: فقط کپی داده و گذاشتن در صف ----
    void onMqttData(esp_mqtt_event_handle_t event) {
        if (event->current_data_offset == 0) {
            rxAssembly = "";
            rxOverflow = static_cast<size_t>(event->total_data_len) > Settings::MQTT_MAX_REQUEST_BYTES;
            if (!rxOverflow) rxAssembly.reserve(event->total_data_len + 1);
        }
        if (rxOverflow) {
            if (event->current_data_offset + event->data_len >= event->total_data_len) {
                mqttDroppedRequests = mqttDroppedRequests + 1;
                rxOverflow = false;
            }
            return;
        }
        for (int i = 0; i < event->data_len; ++i) {
            rxAssembly += event->data[i];
        }
        if (event->current_data_offset + event->data_len < event->total_data_len) return;

        char* copy = static_cast<char*>(malloc(rxAssembly.length() + 1));
        if (!copy) {
            mqttDroppedRequests = mqttDroppedRequests + 1;
            rxAssembly = "";
            return;
        }
        memcpy(copy, rxAssembly.c_str(), rxAssembly.length() + 1);
        rxAssembly = "";
        if (xQueueSend(mqttRxQueue, &copy, 0) != pdTRUE) {
            free(copy);
            mqttDroppedRequests = mqttDroppedRequests + 1;
        }
    }

    void onMqttEvent(esp_mqtt_event_handle_t event, int32_t eventId) {
        switch (static_cast<esp_mqtt_event_id_t>(eventId)) {
            case MQTT_EVENT_CONNECTED:
                mqttConnected = true;
                esp_mqtt_client_subscribe(mqttClient, Settings::MQTT_TOPIC_REQ, 0);
                // وضعیت آنلاین (retained)؛ نسخه‌ی آفلاین را بروکر به‌عنوان LWT منتشر می‌کند.
                esp_mqtt_client_publish(mqttClient, Settings::MQTT_TOPIC_STATUS,
                                        Settings::MQTT_STATUS_ONLINE, 0, 1, 1);
                Serial.println("MQTT: connected");
                break;
            case MQTT_EVENT_DISCONNECTED:
                mqttConnected = false;
                rxAssembly = "";
                rxOverflow = false;
                Serial.println("MQTT: disconnected (auto-reconnect)");
                break;
            case MQTT_EVENT_DATA:
                onMqttData(event);
                break;
            default:
                break;
        }
    }

    static void mqttEventTrampoline(void* arg, esp_event_base_t, int32_t eventId, void* eventData) {
        static_cast<ApiManager*>(arg)->onMqttEvent(
            static_cast<esp_mqtt_event_handle_t>(eventData), eventId);
    }

    void setupMqtt() {
        // 3 بایت‌ی آخر MAC (بایت‌های بالایی efuse بعد از >>24) برای شناسه‌ی یکتا
        char idBuf[40];
        snprintf(idBuf, sizeof(idBuf), "ESP32-SmartHome-%06X",
                 static_cast<unsigned>((ESP.getEfuseMac() >> 24) & 0xFFFFFF));
        mqttClientId = idBuf;

        mqttRxQueue = xQueueCreate(Settings::MQTT_RX_QUEUE_DEPTH, sizeof(char*));
        if (!mqttRxQueue) {
            Serial.println("MQTT: queue creation failed, cloud disabled");
            return;
        }

        esp_mqtt_client_config_t cfg = {};
#if ESP_ARDUINO_VERSION_MAJOR >= 3
        cfg.broker.address.hostname = Settings::MQTT_HOST;
        cfg.broker.address.port = Settings::MQTT_PORT;
        if (Settings::MQTT_USE_WSS) {
            cfg.broker.address.transport = MQTT_TRANSPORT_OVER_WSS;
            cfg.broker.address.path = Settings::MQTT_WS_PATH;
            // گواهی سرور با فهرست CAهای داخلی ESP32 بررسی می‌شود (بدون غیرفعال کردن تأیید)
            cfg.broker.verification.crt_bundle_attach = esp_crt_bundle_attach;
        } else {
            cfg.broker.address.transport = MQTT_TRANSPORT_OVER_TCP;
        }
        cfg.credentials.username = Secrets::MQTT_USER;
        cfg.credentials.client_id = mqttClientId.c_str();
        cfg.credentials.authentication.password = Secrets::MQTT_PASS;
        cfg.session.keepalive = Settings::MQTT_KEEPALIVE_S;
        cfg.session.last_will.topic = Settings::MQTT_TOPIC_STATUS;
        cfg.session.last_will.msg = Settings::MQTT_STATUS_OFFLINE;
        cfg.session.last_will.msg_len = strlen(Settings::MQTT_STATUS_OFFLINE);
        cfg.session.last_will.qos = 1;
        cfg.session.last_will.retain = 1;
        cfg.network.reconnect_timeout_ms = Settings::MQTT_RECONNECT_MS;
        cfg.buffer.size = Settings::MQTT_BUFFER_SIZE;
        cfg.buffer.out_size = Settings::MQTT_BUFFER_SIZE;
#else
        cfg.host = Settings::MQTT_HOST;
        cfg.port = Settings::MQTT_PORT;
        if (Settings::MQTT_USE_WSS) {
            cfg.transport = MQTT_TRANSPORT_OVER_WSS;
            cfg.path = Settings::MQTT_WS_PATH;
            cfg.crt_bundle_attach = esp_crt_bundle_attach;
        } else {
            cfg.transport = MQTT_TRANSPORT_OVER_TCP;
        }
        cfg.username = Secrets::MQTT_USER;
        cfg.client_id = mqttClientId.c_str();
        cfg.password = Secrets::MQTT_PASS;
        cfg.keepalive = Settings::MQTT_KEEPALIVE_S;
        cfg.lwt_topic = Settings::MQTT_TOPIC_STATUS;
        cfg.lwt_msg = Settings::MQTT_STATUS_OFFLINE;
        cfg.lwt_msg_len = strlen(Settings::MQTT_STATUS_OFFLINE);
        cfg.lwt_qos = 1;
        cfg.lwt_retain = 1;
        cfg.reconnect_timeout_ms = Settings::MQTT_RECONNECT_MS;
        cfg.buffer_size = Settings::MQTT_BUFFER_SIZE;
        cfg.out_buffer_size = Settings::MQTT_BUFFER_SIZE;
#endif

        mqttClient = esp_mqtt_client_init(&cfg);
        if (!mqttClient) {
            Serial.println("MQTT: client init failed, cloud disabled");
            return;
        }
        esp_mqtt_client_register_event(
            mqttClient, MQTT_EVENT_ANY, &ApiManager::mqttEventTrampoline, this);
    }

    void updateMqtt() {
        if (!Settings::USE_CLOUD_MQTT || !mqttClient || !mqttRxQueue) return;

        // کلاینت فقط یک‌بار بعد از اولین اتصال وای‌فای شروع می‌شود؛
        // اتصال مجدد بعدی را خود esp-mqtt بدون مسدود کردن loop انجام می‌دهد.
        if (!mqttStarted && WiFi.status() == WL_CONNECTED) {
            if (esp_mqtt_client_start(mqttClient) == ESP_OK) {
                mqttStarted = true;
            }
        }

        // حداکثر دو درخواست در هر دور loop
        for (uint8_t i = 0; i < 2; ++i) {
            char* msg = nullptr;
            if (xQueueReceive(mqttRxQueue, &msg, 0) != pdTRUE) break;
            processMqttRequest(msg);
            free(msg);
        }
    }

public:
    ApiManager() : server(Settings::WEB_SERVER_PORT) {}

    void begin(SensorManager& sensorManager, RelayManager& relayManager,
               BuzzerManager& buzzerManager, SecurityManager& securityManager,
               AutomationEngine& automationEngine, EventManager& eventManager,
               AuthManager& authManager) {
        sensors = &sensorManager;
        relays = &relayManager;
        buzzer = &buzzerManager;
        security = &securityManager;
        automation = &automationEngine;
        events = &eventManager;
        auth = &authManager;

        const char* headerKeys[] = {"Authorization"};
        server.collectHeaders(headerKeys, 1);

        server.on("/", HTTP_GET, [this]() { handleRoot(); });
        server.on("/api/setup-status", HTTP_GET, [this]() { handleSetupStatus(); });
        server.on("/api/setup", HTTP_POST, [this]() { handleSetup(); });
        server.on("/api/login", HTTP_POST, [this]() { handleLogin(); });
        server.on("/api/logout", HTTP_POST, [this]() { handleLogout(); });
        server.on("/api/auth/password", HTTP_POST, [this]() { handlePasswordChange(); });
        server.on("/api/auth/sessions", HTTP_GET, [this]() { handleSessions(); });
        server.on("/api/auth/logout-others", HTTP_POST, [this]() { handleLogoutOthers(); });
        server.on("/api/status", HTTP_GET, [this]() { handleStatus(); });
        server.on("/api/history", HTTP_GET, [this]() { handleHistory(); });
        server.on("/api/relay", HTTP_POST, [this]() { handleRelay(); });
        server.on("/api/security/mode", HTTP_POST, [this]() { handleSecurityMode(); });
        server.on("/api/security/reset", HTTP_POST, [this]() { handleSecurityReset(); });
        server.on("/api/automation/smart-mode", HTTP_POST, [this]() { handleSmartMode(); });
        server.on("/api/gas/open", HTTP_POST, [this]() { handleGasOpen(); });

        server.onNotFound([this]() { sendError(404, "Endpoint not found"); });
        server.begin();

        if (Settings::USE_CLOUD_MQTT) {
            setupMqtt();
        }
    }

    void update() {
        server.handleClient();
        updateMqtt();
    }
};