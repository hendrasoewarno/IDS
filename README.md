# Intrussion Detection System (IDS)
Instalasi SNORT sebagai Intrussion Detection System
```
apt-get install snort
pico /etc/snort/snort.debian.conf
    # This file is used for options that are changed by Debian to leave
    # the original lib files untouched.
    # You have to use "dpkg-reconfigure snort" to change them.

    DEBIAN_SNORT_STARTUP="boot"
    DEBIAN_SNORT_HOME_NET="serverPublicIPAddress/32,serverPublicIPAddress/32"
    DEBIAN_SNORT_OPTIONS=""
    DEBIAN_SNORT_INTERFACE="eth0"
    DEBIAN_SNORT_SEND_STATS="true"
    DEBIAN_SNORT_STATS_RCPT="root"
    DEBIAN_SNORT_STATS_THRESHOLD="1"
```
Pada contoh diatas, snort akan bekerja secara host-based dengan memantau ip tertentu pada interface eth0. Kalau anda ingin menggunakan snort pada modus network-based, maka hal yang perlu dilakukan adalah memastikan bahwa network card yang akan digunakan untuk memantau jaringan adalah berada pada modus Promiscuous yang dapat diaktifkan dengan perintah:
```
ifconfig eth0 promisc
```
atau
```
ip link set eth0 promisc on
```
atau secara permanen dapat diset pada file /etc/network/interfaces
```
auto eth0
iface eth0 inet manual
        up ifconfig eth0 promisc up
        down ifconfig eth0 promisc down
```
Kemudian berikut ini adalah custom script untuk memantau host/jaringan.
```
pico /etc/snort/rules/local.rules
    alert icmp any any -> $HOME_NET any (msg:"ICMP test"; sid:10000001; rev:001;)
```
Penjelasan rules diatas:
```
    kolom 1 = action untuk terhadap rule yang cocok (pass, log, alert), dalam hal ini adalah alert
    kolom 2 = protokol yang dipantau (IP, TCP, UDP atau ICMP),dalam hal ini adalah icmp
    kolom 3 dan 4 = source ip address dan nomor port, dalam hal ini aalah segala alamat dan segala port
    kolom 5 = arah dari koneksi (source -> destination) atau (source <- destination)
    kolom 6 dan 7 = destination ip address dan port, dalam hal ini $HOME_NET dan segala port
    kolom 8 adalah options
        msg adalah pesan pada log file /var/log/snort/alert (dalam hal ini adalah "ICMP test")
        sid adalah suatu id unique dengan nilai > 1000000, dalam hal ini 1000001
        rev adalah suatu identitas nomor versi dari rule menurut kita, dalam hal ini adalah 001.
```
Jadi rule diatas adalah alert terhadap semua ping ke alamat $HOME_NET, dan jika ada terjadi ping ke server, maka snort akan melakukan log ke /etc/snort/alert dan menghasilkan file tcpdump.log.xxxxxxxxx. Untuk membaca isi file tcpdump dapat menggunakan perintah:
```
snort -r tcpdump.log.xxxxxxxxxx
```
Setelah perubahan rule, maka snort perlu direstart kembali
```
service snort restart
```
jika snort gagal distart, maka perlu diperiksa penyebab kegagalan, misalnya ada kesalahan dalam pengetikan rule, maka dapat dilihat pada syslog
```
tail /etc/log/syslog
```
# Mengatur Alert Log
Secara default, snort akan merekam alert pada file /var/log/snort/alert dalam format multiline, jika anda membutuhkan integrasi dengan fail2ban yang melakukan pemeriksaan pola serangan dalam bentuk perbaris dapat dilakukan perubahan setting pada file snort.conf:
```
output alert_csv: alert.csv default
```
Sehingga snort akan melakukan log pada file /var/log/snor/alert.csv secara default yang terdiri dari variabel sebagai berikut:
• timestamp
• sig_generator
• sig_id
• sig_rev
• msg
• proto
• src
• srcport
• dst
• dstport
• ethsrc
• ethdst
• ethlen
• tcpflags
• tcpseq
• tcpack
• tcplen
• tcpwindow
• ttl
• tos
• id
• dgmlen
• iplen
• icmptype
• icmpcode
• icmpid
• icmpseq<br>
Sehingga hasil log pada /var/log/snort/alert:
```
[**] [1:2515:13] WEB-MISC PCT Client_Hello overflow attempt [**]
[Classification: Attempted Administrator Privilege Gain] [Priority: 1]
08/26-09:08:01.141534 192.168.0.26:25680 -> 192.168.0.1:443
TCP TTL:122 TOS:0x0 ID:5833 IpLen:20 DgmLen:627 DF
***AP*** Seq: 0x185E6AF3  Ack: 0x360BDDE0  Win: 0x413A  TcpLen: 20
[Xref => http://www.microsoft.com/technet/security/bulletin/MS04-011.mspx][Xref => http://cve.mitre.org/cgi-bin/cvename.cgi?name=2003-0719][Xref => http://www.securityfocus.com/bid/10116]
```
menjadi pada /var/log/snort/alert.csv:
```
08/26-09:08:01.141534 ,1,2515,13,WEB-MISC PCT Client_Hello overflow attempt,TCP,192.168.0.26,25680,192.168.0.1,443,0:C:42:FF:CE:E3,5C:F3:FC:56:CB:FA,0x23B,***AP***,0x69637C84,0xB683568A,,0xFDB8,122,0,20991,557,20,,,,
```
Dapat dilakukan pembatasan log atas variabel yang menjadi perhatian kita saja dengan setting:
```
output alert_csv: alert.csv timestamp,msg,srcip,sport,dstip,dport,protoname,itype,icode
```
# Update rules
Untuk mengupdate rules dapat diperoleh di https://www.snort.org/downloads, buat user account, login dan download rule sesuai dengan versi snort yang terinstalasi, misalkan v2.9, dan timpa file-file yang bersesuaian ke masing-masing folder.

# Contoh IDS rule
```
alert tcp [1.0.0.0/8,!1.1.1.0/24] any -> any any (msg:"Example";sid:1000003;rev:001;)
alert tcp any 90 -> any [100:1000,9999:20000] (msg:"Example"; sid:1000004;rev:001;)
alert tcp any any -> $HOME_NET any (msg:"Nmap NULL Scan"; flags:0; sid:1000005; rev:001;)
alert tcp any any -> $HOME_NET any (msg:"Nmap FIN Scan"; flags:F; sid:1000006; rev:001;)
alert tcp any any -> 192.168.1.105 22 (msg:"Nmap XMAS Tree Scan"; flags:FPU; sid:1000007; rev:001;)
alert udp any any -> 192.168.1.105 any (msg:"DDOS attack"; count 1000, seconds 5; sid: 1000008; rev:001;)
```
Peringatan akan diberikan ketika ada 1000 paket UDP dalam waktu 5 detik dari segala alamat ke target 192.168.1.105.
```
alert tcp any any -> 192.168.1.105 any (msg:"Possible TCP SYN DDOS Flood Detection"; flags:S; count 100, seconds 10; sid: 1000009; rev:001;) 
```
Peringatan akan diberikan ketika ada 100 paket TCP dengan Flag S dalam waktu 10 detik dari segala alamat ke target 192.168.1.105.

# Contoh IPS rule
```
drop icmp any any -> $HOME_NET any (msg:"ICMP test detected"; GID:1; sid:10000001; rev:001; classtype:icmp-event;)
```

# Instalasi pada Kali Linux
```
apt-get install libpcap-dev bison flex
apt-get install snort
```
