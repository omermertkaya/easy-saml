# 🚀 IAMERT - DevSSO Hub (SAML, OAuth 2.0 & OIDC)

IAMERT, Node.js ve Passport.js kullanılarak geliştirilmiş, son derece kapsamlı bir Kimlik Erişim Yönetimi (IAM) test merkezidir. Önceden sadece SAML 2.0 Service Provider (SP) olarak hizmet veren bu proje, artık **OAuth 2.0** ve **OIDC (JWT)** protokollerini de tam destekleyerek uçtan uca bir entegrasyon laboratuvarına dönüşmüştür.

🔗 **Canlı Demo:** [https://easy-samli.onrender.com/](https://easy-samli.onrender.com/)

---

## ✨ Özellikler

*   **Çoklu Protokol:** Tek ekranda SAML 2.0, OAuth 2.0 ve OpenID Connect (OIDC/JWT) ile SSO testleri yapabilme.
*   **Dinamik Yapılandırma:** Uygulamayı yeniden başlatmaya gerek kalmadan tüm IdP, Client ID/Secret, Entity ID ayarlarını yönetici panelinden değiştirme.
*   **Factory Reset / Kısmi Sıfırlama:** Eğitim bitiminde tek bir butona basarak sadece görevleri, SAML kısmını veya komple tüm projeyi ilk indirildiği boş haline döndürebilme.
*   **Sade ve Modern Clean UI:** Vercel ve GitHub stiline benzeyen beyaz/gri ağırlıklı, minimalist, üretkenliği artıran şık ekranlar.
*   **Docker Kalıcılığı:** Sunucu/Container baştan başlasa dahi tüm Identity ayarlarınız hacim bağlaması (volume bind) sayesinde korunur.


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

*   `src/app.js`: Ana sunucu dosyası ve temel SSO yönlendirmeleri (SAML, OAuth 2.0, JWT).
*   `views/`: EJS şablon dosyaları (Login, Dashboard, Admin paneli).
*   `*config.json`: `saml-config.json`, `oauth-config.json`, `jwt-config.json` dosyaları. Docker'a ve uygulamaya kalıcı olarak map edilmiştir.
*   `public/`: Sadelik felsefesiyle güçlendirilmiş statik CSS dosyaları.

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