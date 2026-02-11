FROM node:18-alpine

# Çalışma dizinini oluştur
WORKDIR /app

# Paket dosyalarını kopyala
COPY package*.json ./

# Bağımlılıkları yükle
RUN npm install

# Kaynak kodları kopyala
COPY . .

# Uygulama portunu dışarı aç
EXPOSE 3000

# Uygulamayı başlat
CMD ["npm", "start"]
