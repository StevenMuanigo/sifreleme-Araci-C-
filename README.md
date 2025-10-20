# sifreleme-Araci-C++
Bu proje, metinleri basit bir Caesar Cipher algoritmasıyla şifreleyen ve çözebilen bir konsol uygulamasıdır. İsteğe bağlı olarak OpenSSL AES ile güçlü şifreleme desteği de eklenebilir ayrıca şifrelenmiş metni dosyaya kaydedip tekrar okuyabilir


Özellikler

 Caesar Cipher tabanlı temel şifreleme ve çözme işlemi

 Dosyaya yazma ve dosyadan okuma desteği (encrypted.txt)
 
 (Opsiyonel) AES 128-bit şifreleme (OpenSSL üzerinden)

kolayca genişletilebilir yapı

Kurulum ve Çalıştırma
🔸 Windows:

OpenSSL kurulu değilse indirin (örn. https://slproweb.com/products/Win32OpenSSL.html
).

Projeyi derleyin:

g++ -o encrypt main.cpp -lssl -lcrypto


Çalıştırın:

encrypt.exe

🔸 Linux/macOS:

OpenSSL yüklü değilse kurun:

sudo apt install libssl-dev   # Debian/Ubuntu


Derleyin:

g++ -o encrypt main.cpp -lssl -lcrypto


Çalıştırın:

./encrypt

 Klasör Yapısı
EncryptionTool/
├── main.cpp
├── encrypted.txt
└── README.md

KOD:

```cpp
#include <iostream>
#include <fstream>
#include <string>
#include <openssl/aes.h>

// Function for Caesar Cipher-like shift encryption
std::string caesarEncrypt(const std::string &text, int shift) {
    std::string encrypted = text;
    for (char &c : encrypted) {
        if (isalpha(c)) {
            char offset = isupper(c) ? 'A' : 'a';
            c = static_cast<char>((c - offset + shift) % 26 + offset);
        }
    }
    return encrypted;
}

std::string caesarDecrypt(const std::string &encryptedText, int shift) {
    return caesarEncrypt(encryptedText, 26 - (shift % 26));
}

void saveToFile(const std::string &filename, const std::string &content) {
    std::ofstream file(filename, std::ios::out | std::ios::binary);
    if (file.is_open()) {
        file << content;
        file.close();
        std::cout << "File \"" << filename << "\" saved successfully.\n";
    } else {
        std::cerr << "Error opening file for writing.\n";
    }
}

std::string loadFromFile(const std::string &filename) {
    std::ifstream file(filename, std::ios::in | std::ios::binary);
    std::string content;
    if (file.is_open()) {
        std::getline(file, content, '\0'); // Read entire file as string
        file.close();
        return content;
    } else {
        std::cerr << "Error opening file for reading.\n";
        return "";
    }
}

int main() {
    std::string text = "Hello, World!";
    int shift = 3;
    
    // Perform Caesar cipher encryption
    std::string encryptedText = caesarEncrypt(text, shift);
    std::cout << "Encrypted Text: " << encryptedText << std::endl;

    // Save to file
    saveToFile("encrypted.txt", encryptedText);

    // Load from file
    std::string loadedText = loadFromFile("encrypted.txt");
    
    // Perform Caesar cipher decryption
    std::string decryptedText = caesarDecrypt(loadedText, shift);
    std::cout << "Decrypted Text: " << decryptedText << std::endl;

    // Example showing OpenSSL AES encryption (optional, uncomment if AES usage needed)
    // unsigned char aes_key[16] = "testkeytestkey12"; // 128 bit key (16 bytes)
    // unsigned char iv[AES_BLOCK_SIZE];
    // memset(iv, 0x00, AES_BLOCK_SIZE);
    // std::string toEncrypt = "Top secret text!";
    // unsigned char encrypted[128];
    // AES_KEY encryptKey;
    // AES_set_encrypt_key(aes_key, 128, &encryptKey);
    // AES_encrypt(reinterpret_cast<const unsigned char *>(toEncrypt.c_str()), encrypted, &encryptKey);
    // std::cout << "AES Encrypted: ";
    // for (unsigned char c : encrypted) std::cout << std::hex << (int)c;
    // std::cout << std::endl;

    return 0;
}
```
