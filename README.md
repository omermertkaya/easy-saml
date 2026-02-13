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

## 🎯 Eğitim Görevleri

Bu proje, SAML entegrasyonunu adım adım öğrenmeniz için tasarlanmış 3 temel görev içerir. Görevleri tamamladıkça sistemdeki ilerleme çubuğu güncellenecektir.

### Görev 1: IDP Ayarlarını Yapılandır
*   **Amaç:** Bir Identity Provider (Örn: Auth0, Okta, Keycloak) ile temel SAML bağlantısını kurmak.
*   **Nasıl Yapılır:** Yönetici paneline (`/admin`) gidin ve IdP'den aldığınız `SSO URL` ve `X.509 Sertifikası`nı girin.
*   **Başarı Kriteri:** "SAML ile Giriş Yap" butonuna tıkladığınızda IdP giriş ekranına yönlendirilip başarılı bir şekilde geri dönebilmek.

### Görev 2: Attribute Eşleştirmesi (Mapping)
*   **Amaç:** IdP'den dönen kullanıcı bilgilerini (Claims) uygulamanın beklediği formata eşleştirmek.
*   **Gereksinimler:** Uygulama şu alanları bekler: `email`, `username`, `firstname` (ad), `lastname` (soyad), `department`.
*   **Nasıl Yapılır:** Yönetici panelindeki "Özellik Eşleştirme" sekmesinden IdP'nizin gönderdiği parametre isimlerini (örn: `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` -> `email`) girin.
*   **Başarı Kriteri:** Giriş yaptıktan sonra Dashboard'da profil bilgilerinizin eksiksiz görünmesi.

### Görev 3: Yetki Kontrolü (Role Based Access)
*   **Amaç:** Kullanıcı gruıplarına göre yetkilendirme (Authorization) yapmak.
*   **Senaryo:** `admin` grubundaki kullanıcılar Yönetici Paneline, `dev` grubundakiler Sözlük sayfasına erişebilmelidir.
*   **Nasıl Yapılır:** IdP'den dönen grup bilgisini (örn: `groups` veya `roles`) "Yetki Ayarları" sekmesinden eşleştirin.
*   **Başarı Kriteri:** SAML ile giriş yapmış bir kullanıcının yetkisi olan özel sayfalara erişebilmesi.

---

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

cd src

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

## 📊 Log Yapısı

Uygulama, hata ayıklamayı kolaylaştırmak için detaylı loglama yapar. Log dosyaları `logs/` dizini altında toplanır.

*   **`logs/combined.log`**: Tüm uygulama aktivitelerini içerir (Bilgi, Uyarı ve Hatalar). SAML istek/yanıt döngüleri, oturum açma işlemleri ve genel sunucu durumu buraya kaydedilir. JSON formatındadır.
*   **`logs/error.log`**: Sadece hata mesajlarını içerir. Kritik hataları veya yakalanan istisnaları (Exceptions) hızlıca bulmak için kullanılır.
*   **`saml-events.json`**: Dashboard üzerindeki "Canlı Olay Günlüğü" tablosunu besleyen, son 50 SAML olayını tutan geçici veri dosyasıdır.

### Log Örneği (Combined)
```json
{
  "level": "info",
  "message": "[REQUEST] POST /login/sso/callback",
  "service": "easy-saml-service",
  "timestamp": "2026-02-12T20:00:02.218Z"
}
```

---

## 🤝 Katkıda Bulunma

Hataları bildirmek veya özellik eklemek için lütfen bir "Issue" açın veya "Pull Request" gönderin.

---

## 📝 Lisans

Bu proje ISC lisansı ile lisanslanmıştır.