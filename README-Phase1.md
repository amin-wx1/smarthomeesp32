# SmartHome – فاز ۱

## قبل از هر چیز
1. رمز MQTT، رمز وای‌فای و (در صورت استفاده) رمز مدیر داشبورد را عوض کنید؛ مقادیر قبلی در کد و در چت بوده‌اند.
2. `SmartHome/Secrets.h` را با مقادیر جدید پر کنید و در گیت/زیپ قرار ندهید.
3. روی هاست Node متغیرهای `MQTT_URL`، `MQTT_USER`، `MQTT_PASS` (و `TRUST_PROXY`) را تنظیم کنید. نسخه‌ی Node باید ۲۰ یا بالاتر باشد.

## فریمور (Arduino IDE / PlatformIO)
- کتابخانه‌ی PubSubClient دیگر لازم نیست. `ArduinoJson` نسخه ۷ همچنان لازم است.
- کلاینت MQTT از esp-mqtt داخل core ESP32 است. برای core نسخه ۳.x و ۲.x کد جداگانه (`#if`) دارد.
- در حالت ابری، راه‌اندازی اولیه (`/api/setup`) فقط از شبکه‌ی محلی (`http://IP-برد/`) انجام می‌شود. برای تغییر: `Settings::ALLOW_REMOTE_SETUP`.

## Node
```
cd node
npm install
npm start          # یا: npm run dev (با فایل .env)
```

## اتصال برد به بروکر (به‌روزرسانی)
برد از بیرون Runflare فقط با WebSocket امن به بروکر می‌رسد: `MQTT_HOST` همان دامنه، `MQTT_PORT = 443`، مسیر `/mqtt` (در `Settings.h`).
این ترکیب با MQTTX CLI تست و وصل شد. Node داخل Runflare با `MQTT_URL=mqtt://mosquitto-xsq-service:1883` وصل می‌شود.
