# Easy SAML – Codebase Genel Özet

Bu doküman, `easy-saml` reposunun (Node.js + Express) **genel mimarisini**, **dosya yapısını**, **çalışma akışlarını** ve **SAML eğitim senaryosunun** kod seviyesinde nasıl kurgulandığını hızlıca anlatır.

## Projenin amacı

Bu proje, SAML 2.0 Service Provider (SP) tarafını **öğrenmek/test etmek** için hazırlanmış eğitim odaklı bir uygulamadır.

- **SAML SSO**: `@node-saml/passport-saml` ile IdP’ye yönlenme ve callback üzerinden Assertion doğrulama
- **Dinamik SAML konfigürasyonu**: `/admin` arayüzünden `saml-config.json` içeriğini güncelleme ve strategy’yi runtime’da yeniden kurma
- **Attribute mapping**: IdP’den dönen claim/attribute’ları uygulama modeline eşleştirme
- **Yetkilendirme**: IdP’den gelen grup/rol bilgisini uygulama “permission”larına map’leme
- **Eğitim ilerleme takibi**: görevlerin (`src/tasks.json`) tamamlanma durumunu dashboard’da gösterme
- **Olay günlüğü**: SAML akışı boyunca event’leri `saml-events.json` içine yazıp UI’da canlı gösterme

## Teknoloji yığını

- **Runtime**: Node.js (Docker imajı `node:18-alpine`)
- **Web framework**: Express (`express@^5`)
- **View/UI**: EJS + Bootstrap (CDN) + basit custom CSS (`public/css/style.css`)
- **Auth**:
  - Local demo auth: `passport-local`
  - SAML SSO: `@node-saml/passport-saml`
  - Session: `express-session`
- **Logging**: `winston` (JSON format; `logs/error.log`, `logs/combined.log`)
- **Geliştirme**: `nodemon`

## Hızlı çalıştırma

### Docker (önerilen)

`docker-compose.yml` tek bir servis kaldırır ve bazı dosyaları host ile container arasında kalıcı olacak şekilde map’ler:

- `./saml-config.json` → `/app/saml-config.json`
- `./src/tasks.json` → `/app/src/tasks.json`
- `./saml-events.json` → `/app/saml-events.json`
- `./logs/` → `/app/logs/`

Komutlar proje README’sinde ve `DOCKER_GUIDE.md` içinde var.

### Lokal (Node)

- `npm install`
- `npm run dev` (veya `npm start`)
- Uygulama varsayılan olarak `http://localhost:3000`

## Klasör yapısı (yüksek seviye)

- `src/app.js`: Uygulamanın ana giriş noktası (Express + Passport + route’lar + SAML akışı)
- `src/logger.js`: Winston logger kurulumu (dosyaya + dev’de console)
- `src/task-manager.js`: Eğitim görevlerini `src/tasks.json` üzerinden okuma/yazma
- `views/*.ejs`: EJS sayfaları (login, dashboard, admin paneli, sözlük, hata)
- `public/`: statik varlıklar (CSS/JS)
- `saml-config.json`: SAML/SP/IdP/security/mapping/permission konfigürasyonu
- `saml-events.json`: son event’lerin kalıcı tutulduğu dosya (dashboard/admin UI bunu okur)
- `logs/`: uygulama log dosyaları

## Uygulama akışları

### 1) Local login (demo)

- `/login` sayfası basit bir form gösterir.
- `passport-local` ile kullanıcı doğrulaması yapılır (kod içinde “mock” kullanıcı: `admin/password123`).
- Başarılı olunca `/dashboard`.

### 2) SAML SSO (SP → IdP → SP)

Temel rotalar:

- **SSO başlatma**: `GET /login/sso`
  - `passport.authenticate('saml')` tetiklenir.
  - Redirect URL’si “wrap” edilerek **SAMLRequest** yakalanır, inflate edilip XML olarak session/global’e yazılır.
  - Event log’a “flow started / request generated / redirecting” gibi kayıtlar düşer.
- **Callback/ACS**: `POST /login/sso/callback`
  - `SAMLResponse` base64 decode edilip XML olarak session/global’e yazılır.
  - (Eğitsel) response içinden StatusCode/StatusMessage regex ile okunup event’e yazılır.
  - `passport.authenticate('saml', customCallback)` ile doğrulama yapılır.
  - `req.logIn()` ile session oluşturulur ve `/dashboard`’a yönlenir.

Yanlış IdP ayarı için “guard”:

- `POST /login/sso`: Eğer IdP yanlışlıkla response’u buraya POST ederse, uygulama **400** dönüp “doğru ACS URL”’yi anlatan HTML hata sayfası gösterir.

### 3) Dinamik SAML konfigürasyon yönetimi

- **Admin ekranı**: `GET /admin`
  - Local `admin` veya SAML tarafında `iammert_admin` permission’a sahip kullanıcı görebilir.
  - UI, SP/IdP/security/mapping/permission alanlarını düzenletir.
- **Kaydet/Uygula**: `POST /admin/save-saml`
  - Form’dan gelen alanlarla `samlConfig` objesi güncellenir.
  - `saml-config.json` dosyasına yazılır.
  - `passport.unuse('saml')` + yeni option’larla `passport.use('saml', new SamlStrategy(...))` yapılarak runtime’da strategy yeniden kurulur.

### 4) Attribute mapping (Task 2)

SAML verify callback içinde:

- `samlConfig.attributeMapping` üzerinden `email/username/firstName/lastName/department/roles` alanları okunur.
- IdP attribute’ları hem root’ta hem `profile.attributes` içinde, case-insensitive aranır.
- “Gerekli alanlar” doluysa eğitim görevi olan `attribute-mapping` tamamlanır.

### 5) Yetkilendirme / Permission mapping (Task 3)

SAML verify callback içinde:

- `samlConfig.permissions.sourceAttribute` (varsayılan: `groups`) okunur.
- `samlConfig.permissions.rules` ile gelen değerler permission string’lerine eşlenir.

Protected sayfalar:

- `/admin`: local admin veya `iammert_admin`
- `/sozluk`: `checkPermission('iammert_sozluk')`

Not: `checkPermission` local `admin` kullanıcısını “bypass” eder.

### 6) Event log (UI’da canlı)

Backend:

- `addSamlEvent(...)` event’i `saml-events.json` içine yazar (maks 200).
- `GET /api/events`: Authenticated kullanıcıya event listesi döner.
- `POST /api/events/clear`: Authenticated kullanıcı için event’leri temizler.

Frontend (`public/js/script.js`):

- Dashboard/Admin içinde event tablosu varsa `/api/events`’ten çekip render eder.
- “Otomatik yenile” (3 saniyede bir polling) ve “temizle” butonu desteklenir.

## Route özeti

- **GET `/`**: ana sayfa
- **GET `/glossary`**: SAML sözlüğü (public)
- **GET `/login`**, **POST `/login`**: local login
- **GET `/login/sso`**: SAML login başlatma (SP → IdP)
- **POST `/login/sso`**: yanlış IdP POST’unu yakalayan guard endpoint
- **POST `/login/sso/callback`**: ACS callback (IdP → SP)
- **GET `/dashboard`**: authenticated alan; profil + eğitim görevleri + SAML analiz + event log
- **GET `/admin`**, **POST `/admin/save-saml`**: SAML config yönetimi (yetkili)
- **POST `/admin/reset-tasks`**: eğitim görevlerini sıfırla (local admin)
- **GET `/sozluk`**: permission-protected demo sayfa
- **GET `/logout`**: çıkış
- **GET `/api/events`**, **POST `/api/events/clear`**: event API

## Kalıcılık (dosya bazlı state)

- **SAML config**: `saml-config.json` (admin panel değişiklikleri buraya yazılır)
- **Eğitim görevleri**: `src/tasks.json` (tamamlanma bilgisi dosyada saklanır)
- **SAML event log**: `saml-events.json` (son ~200 olay)
- **Uygulama logları**: `logs/combined.log`, `logs/error.log`

## Dikkat edilmesi gerekenler (pratik notlar)

- **Session secret**: `src/app.js` içinde hardcoded bir `secret` var. Docker compose environment’da `SESSION_SECRET` set edilmiş görünse de, kod şu an bu env’i okumuyor; prod için env’den okumaya uygun hale getirmek gerekir.
- **IdP ACS URL**: Bu projede kritik nokta `.../login/sso/callback`. `/login/sso` sadece “başlatma” endpoint’i; yanlış ayarlandığında uygulama bilerek açıklayıcı hata döner.
- **node_modules**: repo içinde mevcut; normalde VCS’de tutulmaz (ama bu özet sadece mevcut durumun fotoğrafını çıkarır).

---

Kaynak dosyalar: `src/app.js`, `src/task-manager.js`, `src/logger.js`, `views/*.ejs`, `public/*`, `saml-config.json`, `docker-compose.yml`, `Dockerfile`, `README.md`.
