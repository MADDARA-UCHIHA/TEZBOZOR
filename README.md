# TEZBOZOR — OLX uslubidagi sayt (Flask + SQLite)

## Ishga tushirish

```bash
pip install -r requirements.txt
python app.py
```

Brauzerda oching: http://127.0.0.1:5000

Birinchi ishga tushirishda `bozor.db` fayli avtomatik yaratiladi (bo'sh baza —
oldindan hech qanday foydalanuvchi yoki e'lon yo'q, hammasini foydalanuvchilar
o'zi qo'shadi).

## Nima qilingan

- **Maxfiy admin panel**: `/admin` manzilida alohida admin sessiyasi bilan
  foydalanuvchilar, e'lonlar va xabarlar statistikasi ko'rsatiladi. Kirish
  ma'lumotlari faqat `ADMIN_USERNAME` va `ADMIN_PASSWORD` environment
  o'zgaruvchilaridan olinadi; ularni kodga yoki GitHub'ga yozmang. Oddiy login
  sahifasida admin ma'lumotlari to'g'ri kiritilsa, foydalanuvchi avtomatik
  `/admin` paneliga o'tadi. Admin username oddiy ro'yxatdan o'tishda band
  qilinadi. Admin kirishi uchun bitta kuchli parol yetarli; noto'g'ri loginlar
  rate-limit orqali vaqtincha bloklanadi. Admin panel uchun HTTPS, kuchli noyob
  parol va production'da `REQUIRE_SECRET_KEY=1` ishlatish shart.

- Login va ro'yxatdan o'tish oynalarida Foydalanish shartlari hamda Maxfiylik
  siyosati ko'rsatiladi; yangi akkaunt yaratishda ularni qabul qilish majburiy.

- **Ma'lumotlar bazasi**: SQLite (`bozor.db`) — users, ads, messages, call_logs
  jadvallari.
- **Ro'yxatdan o'tish/kirish**: parollar `werkzeug.security` bilan hash qilinadi
  (hech qachon ochiq matnda saqlanmaydi), sessiya cookie orqali autentifikatsiya.

### Xavfsizlik choralari
- Parollarni hash qilish (PBKDF2/Werkzeug); parol kamida 8 belgi, harf+raqam
  bo'lishi shart
- Foydalanuvchi nomi harf bilan boshlanishi kerak (SQL/skript in'ektsiyasi
  ehtimolini kamaytiradi)
- CSRF himoyasi (Flask-WTF) — har bir o'zgartiruvchi so'rov token talab qiladi;
  token eskirsa endi tushunarli JSON xabar qaytadi va frontend uni avtomatik
  yangilaydi (login/register/logout'dan keyin)
- SQL-injection'dan himoya — barcha so'rovlar parametrlangan (`?` placeholder)
- **Rasm yuklashni haqiqiy tekshirish**: fayl kengaytmasi emas, balki fayl
  tarkibi Pillow bilan ochib ko'riladi — soxta rasm (masalan ichiga skript
  yashiringan ".jpg") rad etiladi, haqiqiy rasm bo'lsa metadatasi tozalanib
  qayta kodlanadi
- Login uchun rate-limit (IP bo'yicha 5 marta noto'g'ri urinishdan keyin 60
  soniya bloklash)
- **Yangi**: ro'yxatdan o'tish, e'lon joylashtirish, xabar yuborish va
  qo'ng'iroq qilish uchun ham alohida rate-limit (spam/bot hujumlaridan himoya)
- Sessiya cookie `HttpOnly`, `SameSite=Strict` va production'da `Secure`;
  `SECURE_COOKIES=1` cookie'ni faqat HTTPS orqali yuborishga majburlaydi
- Xavfsizlik headerlari: `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `Content-Security-Policy`, `Permissions-Policy`
- HTML chiqishda `escapeHtml()` va dinamik event handlerlarda context-safe
  `data-*` qiymatlar orqali XSS'dan himoya
- So'rov hajmi cheklangan (6MB)

### Chat — endi to'g'ri ishlaydi
Avvalgi versiyada agar bitta e'longa bir nechta xaridor yozsa, sotuvchi
tarafida ularning xabarlari **bitta suhbatga aralashib ketardi**. Endi:
- Har bir suhbat `(e'lon, xaridor)` juftligi bo'yicha alohida saqlanadi
- Sotuvchi o'z e'loniga chat ochsa, avval **kim bilan gaplashmoqchi ekanini
  tanlaydi** (agar bir nechta xaridor yozgan bo'lsa)
- Xaridorlar bir-birining suhbatini ko'rolmaydi
- Xabar yuborishda spam-himoya (1 daqiqada 20 tadan ortiq xabar yuborib
  bo'lmaydi)

### Qo'ng'iroq — endi to'g'ri ishlaydi
- Agar e'londa telefon raqami ko'rsatilmagan bo'lsa, qo'ng'iroq tugmasi endi
  aniq xato beradi ("Bu e'londa telefon raqami ko'rsatilmagan")
- O'zining e'loniga o'zi qo'ng'iroq qila olmaydi
- Qo'ng'iroq spam-himoyasi (5 daqiqada 6 tadan ortiq qo'ng'iroq urinishi
  bloklanadi)
- **Diqqat**: bu hali ham demo signal (`call_logs` jadvaliga yoziladi) — real
  ovozli/videoqo'ng'iroq uchun WebRTC + signaling server (STUN/TURN,
  Socket.IO) kerak bo'ladi, bu alohida katta loyiha.

## Xavfsizlik — yangi qo'shilgan (production uchun)

- **`REQUIRE_SECRET_KEY=1`** — o'rnatilsa, `SECRET_KEY` muhit o'zgaruvchisi
  berilmagan holda ilova ishga tushmaydi (xato bilan to'xtaydi), tasodifiy
  kalit bilan "sukut saqlab" ishlashning oldini oladi. Productionda doim
  ikkalasini ham bering: `SECRET_KEY=<tasodifiy uzun qator>` va
  `REQUIRE_SECRET_KEY=1`.
- **`REDIS_URL`** — berilsa (masalan `redis://localhost:6379/0`), login
  bloklash va barcha rate-limit hisoblagichlari Redis orqali saqlanadi va
  **barcha Gunicorn/uWSGI worker'lari orasida umumiy** bo'ladi. Berilmasa,
  eski xotiradagi (in-memory) usulga tushib qoladi — bu faqat bitta worker
  bilan ishlaydigan lokal/dev muhit uchun xavfsiz, ko'p worker'li production
  uchun EMAS (har bir worker o'z hisoblagichiga ega bo'lib, hujumchining
  amaldagi urinish limiti worker sonига ko'payadi).
- **HSTS header** — HTTPS so'rovlarida `Strict-Transport-Security` headeri
  qo'shiladi; Render kabi reverse proxy uchun `X-Forwarded-Proto` ishonchli
  tarzda hisobga olinadi.
- **`/api/ads`** endi `limit` va `offset` query parametrlarini qabul qiladi
  (standart `limit=30`, maksimal `100`) — natijalar jimgina kesilib
  qolmaydi, sahifalab olish mumkin.
- Ma'lumotlar bazasi jadvallari endi modul yuklanganda (`init_db()`)
  yaratiladi — shuning uchun Gunicorn orqali (`wsgi.py`) ishga tushirilganda
  ham `bozor.db` avtomatik tayyor bo'ladi, faqat `python app.py` orqali emas.

## Productionga chiqarish

```bash
pip install -r requirements.txt

export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export REQUIRE_SECRET_KEY=1
export SECURE_COOKIES=1
export REDIS_URL="redis://localhost:6379/0"   # Redis ishga tushirilgan bo'lsin

gunicorn -w 4 -b 127.0.0.1:8000 wsgi:app
```

Buning oldiga nginx (yoki boshqa reverse-proxy) qo'yib, TLS'ni shu yerda
tugating va faqat `127.0.0.1:8000` ga proksi qiling — Flask/Gunicorn'ni
to'g'ridan-to'g'ri internetga ochiq qoldirmang.

### SSL/TLS sertifikati (Let's Encrypt + nginx, misol)

Domeningiz DNS orqali serveringizga yo'naltirilgan bo'lishi shart. Keyin:

```bash
sudo apt install nginx certbot python3-certbot-nginx
```

`/etc/nginx/sites-available/tezbozor` fayliga:

```nginx
server {
    listen 80;
    server_name sizning-domeningiz.uz;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    client_max_body_size 6M;   # app.py'dagi MAX_CONTENT_LENGTH bilan mos
}
```

```bash
sudo ln -s /etc/nginx/sites-available/tezbozor /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# Sertifikatni avtomatik oladi, nginx konfiguratsiyasini HTTPS'ga
# moslab qayta yozadi va 80→443 redirectni ham qo'shadi:
sudo certbot --nginx -d sizning-domeningiz.uz
```

Certbot sertifikatni avtomatik yangilab turadi (`certbot renew` cron/timer
orqali). Sertifikat o'rnatilgach, ilovani `SECURE_COOKIES=1` bilan ishga
tushiring (yuqorida ko'rsatilgan) — shunda sessiya cookie faqat HTTPS orqali
yuboriladi va `Strict-Transport-Security` headeri ham qo'shiladi.

## Eslatma

- `SECRET_KEY` production'da doim environment variable orqali berilishi
  kerak (yuqoridagi bo'limga qarang) — aks holda har restart'da yangi
  tasodifiy kalit yaratiladi va barcha sessiyalar bekor bo'ladi; bir nechta
  worker bilan esa har birida BOSHQA-BOSHQA kalit bo'ladi.
- Bu loyiha ta'lim/demo maqsadida yozilgan. SQLite hozircha kichik
  yuklamalar uchun yetarli; katta trafik kutilsa PostgreSQL'ga o'tish
  tavsiya etiladi (so'rovlar allaqachon parametrlangan, portlash oson
  bo'ladi).
- CSP hali ham `'unsafe-inline'`ni ishlatadi (script/style uchun), chunki
  butun frontend bitta `index.html` faylida inline holda yozilgan. Buni
  yopish uchun JS/CSS'ni alohida statik fayllarga chiqarib, nonce yoki
  hash-asosidagi CSP qo'llash kerak bo'ladi — bu alohida, kattaroq refaktor.
