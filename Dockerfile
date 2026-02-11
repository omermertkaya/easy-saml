FROM node:18-alpine

# Çalışma dizinini ayarla
WORKDIR /app

# Paket dosyalarını kopyala
COPY package*.json ./

# Sadece production bağımlılıklarını yükle (CI ortamı gibi davranır)
RUN npm ci --only=production

# Kaynak kodları kopyala
COPY . .

# Uygulamanın çalışacağı port
EXPOSE 3000

# Uygulamayı başlat
CMD ["node", "src/app.js"]
