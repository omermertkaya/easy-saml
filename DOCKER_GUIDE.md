# Docker Kurulum ve Kullanım Rehberi 🐳

Bu proje, Docker ve Docker Compose kullanılarak kolayca çalıştırılabilir. Aşağıdaki adımları takip ederek uygulamanızı konteyner ortamında ayağa kaldırabilirsiniz.

## Gereksinimler

-   [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows, Mac veya Linux için)

## Hızlı Başlangıç

1.  **Terminali Açın:** Proje dizininde (`easy-saml`) terminali açın.
2.  **Uygulamayı Başlatın:** Aşağıdaki komutu çalıştırın:

    ```bash
    docker-compose up --build -d
    ```

    -   `--build`: İmajı yeniden oluşturur (kod değişikliklerini yansıtmak için).
    -   `-d`: Arka planda çalıştırır (terminali meşgul etmez).

3.  **Erişim:** Tarayıcınızdan `http://localhost:3000` adresine gidin.

## Yönetim Komutları

### Logları İzleme
Uygulamanın çalışırken ürettiği logları (hatalar, SAML istekleri vb.) görmek için:

```bash
docker-compose logs -f
```
(`Ctrl+C` ile çıkabilirsiniz)

### Uygulamayı Durdurma
Konteyneri durdurmak ve kaldırmak için:

```bash
docker-compose down
```

### Konfigürasyon Dosyası
`saml-config.json` dosyası, Docker konteyneri ile **eşleştirilmiştir (volume mapping)**. Yani:
-   Admin panelinden (`/admin`) yaptığınız değişiklikler, yerel bilgisayarınızdaki `saml-config.json` dosyasına **anında yazılır**.
-   Konteyneri silip tekrar başlatsanız bile ayarlarınız **kaybolmaz**.

## Sorun Giderme

-   **Port Çatışması:** Eğer `3000` portu doluysa, `docker-compose.yml` dosyasındaki `ports` kısmını değiştirin (örn: `"8080:3000"`).
-   **Dosya İzinleri:** Eğer "permission denied" hatası alırsanız, `saml-config.json` dosyasına yazma izni olduğundan emin olun.

## Geliştirme Modu (İleri Seviye)
Eğer kodu geliştirirken sunucunun otomatik yeniden başlamasını istiyorsanız (nodemon ile), `Dockerfile` ve `docker-compose.yml` dosyalarında `CMD` komutunu `npm run dev` olarak değiştirebilirsiniz, ancak prodüksiyon için mevcut ayarlar önerilir.
