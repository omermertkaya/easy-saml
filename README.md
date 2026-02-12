# 🚀 Easy SAML - Node.js SAML Service Provider

Easy SAML, Node.js ve Passport.js kullanılarak geliştirilmiş, basit ve eğitici bir SAML 2.0 Service Provider (SP) uygulamasıdır. Bu proje, SAML entegrasyonlarını test etmek, öğrenmek veya hızlıca bir SP ayağa kaldırmak için tasarlanmıştır.

🔗 **Canlı Demo:** [https://easy-samli.onrender.com/](https://easy-samli.onrender.com/)

---

## ✨ Özellikler

*   **SAML 2.0 Desteği:** `@node-saml/passport-saml` kütüphanesi ile tam uyumlu.
*   **Dinamik Yapılandırma:** Uygulamayı yeniden başlatmadan yönetici panelinden SAML ayarlarını (IdP URL, Sertifikalar vb.) değiştirebilme.
*   **Kolay Kurulum:** Docker Compose ile tek komutla çalıştırılabilir.
*   **Debug Modu:** SAML Redirect döngülerini ve hataları algılayan gelişmiş loglama ve hata sayfaları.
*   **Modern Arayüz:** EJS ve CSS ile temiz, anlaşılır bir kullanıcı arayüzü.

---

## 🛠️ Kurulum ve Çalıştırma

Projeyi çalıştırmanın en kolay yolu Docker kullanmaktır.

### Ön Gereksinimler

*   Docker ve Docker Compose
*   (Alternatif olarak) Node.js v18+

### 1. Docker ile Çalıştırma (Önerilen)

```bash
# Projeyi klonlayın
git clone https://github.com/omermertkaya/easy-saml.git
cd easy-saml

# Konteyneri başlatın
docker compose up -d --build
```

Uygulama `http://localhost:3000` adresinde çalışmaya başlayacaktır.

### 2. Yerel Ortamda Çalıştırma (Node.js)

```bash
# Bağımlılıkları yükleyin
npm install

# Uygulamayı başlatın
npm run dev
# veya
npm start
```

---

## ⚙️ Yapılandırma

Uygulama varsayılan olarak `saml-config.json` dosyasındaki ayarları kullanır.

1.  **Yönetici Paneli:** `/admin` sayfasına giderek (Giriş: `admin` / `password123`) SAML ayarlarını görsel arayüzden güncelleyebilirsiniz.
2.  **Dosya Üzerinden:** `saml-config.json` dosyasını doğrudan düzenleyerek IdP (Identity Provider) bilgilerinizi girebilirsiniz.

### Örnek IdP Ayarları (Auth0, Okta vb.)

IdP tarafında SP (Service Provider) ayarlarınızı şu şekilde yapmalısınız:

*   **ACS (Callback) URL:** `https://sizin-domaininiz.com/login/sso/callback` (veya `http://localhost:3000/login/sso/callback`)
*   **Entity ID (Audience):** `passport-saml` (Panelden değiştirilebilir)

> **⚠️ Önemli:** Eğer IdP girişinden sonra "SAMLRequest detected at /login/sso" hatası alıyorsanız, IdP panelindeki ACS URL'nizin sonunun `/callback` ile bittiğinden emin olun.

---

## 📂 Proje Yapısı

*   `src/app.js`: Ana sunucu dosyası ve SAML mantığı.
*   `views/`: EJS şablon dosyaları (Login, Dashboard, Admin paneli).
*   `saml-config.json`: SAML yapılandırma dosyası.
*   `public/`: Statik dosyalar (CSS, resimler).

---

## 🤝 Katkıda Bulunma

Hataları bildirmek veya özellik eklemek için lütfen bir "Issue" açın veya "Pull Request" gönderin.

---

## 📝 Lisans

Bu proje ISC lisansı ile lisanslanmıştır.