# Paket Dinleyici (Packet Sniffer) – C / libpcap

Bu proje, **C dili ve libpcap kütüphanesi kullanılarak geliştirilmiş basit bir ağ paket dinleyicisidir (packet sniffer)**. Program, belirtilen bir ağ arayüzünden gelen paketleri yakalar, **BPF (Berkeley Packet Filter)** filtreleri uygular ve TCP paketlerinin içeriğini analiz eder.

Yakalanan paketlerden aşağıdaki bilgiler elde edilir:

* Kaynak IP adresi
* Hedef IP adresi
* TCP payload (veri içeriği)

Bu proje, **ağ paketlerinin nasıl yakalandığını ve analiz edildiğini öğrenmek amacıyla geliştirilmiştir.**

---

## Özellikler

* Belirtilen ağ arayüzünden paket yakalama
* **BPF filtreleri** ile trafik filtreleme
* **IP ve TCP header** ayrıştırma
* TCP payload verisini görüntüleme
* Kaynak ve hedef IP adreslerini gösterme
* Basit komut satırı kullanımı

---

## Gereksinimler

Programı derlemek için sisteminizde **libpcap** kütüphanesinin kurulu olması gerekir.

### Linux

```bash
sudo apt install libpcap-dev
```

### MacOS

```bash
brew install libpcap
```

---

## Derleme

Programı **gcc** ile aşağıdaki komut kullanılarak derleyebilirsiniz:

```bash
gcc sniffer.c -o sniffer -lpcap
```

---

## Kullanım

Program aşağıdaki şekilde çalıştırılır:

```bash
./sniffer -d <arayüz> -b <bpf_filtresi>
```

### Parametreler

| Parametre | Açıklama                           |
| --------- | ---------------------------------- |
| `-h`      | Yardım mesajını gösterir           |
| `-d`      | Paketlerin yakalanacağı ağ arayüzü |
| `-b`      | BPF filtre ifadesi                 |

---

## Kullanım Örneği

### HTTP trafiğini dinlemek

```bash
sudo ./sniffer -d eth0 -b "tcp port 80"
```

### Tüm TCP paketlerini dinlemek

```bash
sudo ./sniffer -d eth0 -b "tcp"
```

---

## Örnek Çıktı

```
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Captured packet:
Src IP: 192.168.1.10
Dst IP: 142.250.181.46
Payload (120 bytes):
Payload: GET / HTTP/1.1
Host: example.com
```

---

## Nasıl Çalışır?

1. Program kullanıcıdan bir **ağ arayüzü** alır.
2. Girilen **BPF filtresi** derlenir ve uygulanır.
3. `pcap_loop` fonksiyonu ile paketler yakalanır.
4. Paket işleyici fonksiyon:

   * Ethernet header
   * IP header
   * TCP header
     bölümlerini ayrıştırır.
5. TCP paketinin payload kısmı ekrana yazdırılır.

---


