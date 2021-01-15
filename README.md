# Intrussion Detection System (IDS)
Instalasi SNORT sebagai Intrussion Detection System
```
apt-get install snort
pico /etc/snort/snort.debian.conf
    # This file is used for options that are changed by Debian to leave
    # the original lib files untouched.
    # You have to use "dpkg-reconfigure snort" to change them.

    DEBIAN_SNORT_STARTUP="boot"
    DEBIAN_SNORT_HOME_NET="serverPublicIPAddress/32"
    DEBIAN_SNORT_OPTIONS=""
    DEBIAN_SNORT_INTERFACE="eth0"
    DEBIAN_SNORT_SEND_STATS="true"
    DEBIAN_SNORT_STATS_RCPT="root"
    DEBIAN_SNORT_STATS_THRESHOLD="1"
```
Pada contoh diatas, snort akan bekerja secara host-based dengan memantau ip tertentu pada interface eth0.
```
pico /etc/snort/rules/local.rules
    alert icmp any any -> $HOME_NET any (msg:"ICMP test"; sid:10000001; rev:001;)
```
Penjelasan rules diatas:
```
    kolom 1 = action untuk terhadap rule yang cocok (pass, log, alert), dalam hal ini adalah alert
    kolom 2 = protokol yang dipantau (TCP, UDP atau ICMP),dalam hal ini adalah icmp
    kolom 3 dan 4 = source ip address dan nomor port, dalam hal ini aalah segala alamat dan segala port
    kolom 5 dan 6 = destination ip address dan port, dalam hal ini $HOME_NET dan segala port
    kolom 7 adalah options
        msg adalah pesan pada log file /var/log/snort/alert (dalam hal ini adalah "ICMP test")
        sid adalah suatu id unique dengan nilai > 1000000, dalam hal ini 1000001
        rev adalah suatu identitas nomor versi dari rule menurut kita, dalam hal ini adalah 001.
```
Jadi rule diatas adalah alert terhadap semua ping ke alamat $HOME_NET, dan jika ada terjadi ping ke server, maka snort akan melakukan log ke /etc/snort/alert dan menghasilkan file tcpdump.log.xxxxxxxxx. Untuk membaca isi file tcpdump dapat menggunakan perintah:
```
snort -r tcpdump.log.xxxxxxxxxx
```
