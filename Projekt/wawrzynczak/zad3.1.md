# Security Onion
# Michał Wawrzyńczak

## Jako pierwsz do analizy wybrałem i zaimportowałem plik `zeus-sample-1`. 
```sudo so-import-pcap zeus-sample-1```
Analizę logów zacząłem od zapoznania się z infomacjami zwróconymi przez programy Squert i Kibana. 

Przy użyciu narzędzia Squert udało mi sie uzyskać takie informacja jak adresy ip z którymi łączył się zaatakowany host, numery portów na których odbywała się komunikacja, państwa z których pochodziły adresy IP. A przede wszystkim Squert wskazał już sygnatury do których pasują analizowane logi.

**Sygnatury - informacja, że mamy doczynienia z TROJAN Generic**
![Event](https://user-images.githubusercontent.com/56591106/72636542-8d171d00-395f-11ea-8a60-e9c2e2ab1c8f.PNG)
![event2](https://user-images.githubusercontent.com/56591106/72636543-8dafb380-395f-11ea-8500-a88863797a6c.PNG)

**Alerty NIDS**
![NIDSalert](https://user-images.githubusercontent.com/56591106/72664491-dff3e180-39fe-11ea-9b00-dcfbbb952b10.PNG)

**Adresy IP wraz z pochodzeniem oraz porty**
![summary](https://user-images.githubusercontent.com/56591106/72636556-8ee0e080-395f-11ea-9391-81755dbad69d.PNG)
![views](https://user-images.githubusercontent.com/56591106/72636557-8ee0e080-395f-11ea-9f11-84a8986d9e16.PNG)

**Posprawdzałem informacje o adresach IP celem określenia dokładniejszej lokalizacji, a także sprawdziłem je w bazie whoIs**
![whois](https://user-images.githubusercontent.com/56591106/72636558-8f797700-395f-11ea-9747-ea104c506ee4.PNG)
![ipLoc](https://user-images.githubusercontent.com/56591106/72636548-8e484a00-395f-11ea-99d5-0484aced0f7a.PNG)

**Porty na których odbywała się komunikacja sprawdziłem w bazie. Okazało się, że na portach z zakresu ~1033-1050 często komunikują się trojany i backdory**
![1033](https://user-images.githubusercontent.com/56591106/72636538-8c7e8680-395f-11ea-80e7-108fd19f0d5e.PNG)
![1034](https://user-images.githubusercontent.com/56591106/72636539-8d171d00-395f-11ea-883c-1616a8cc3e34.PNG)
![1040](https://user-images.githubusercontent.com/56591106/72636540-8d171d00-395f-11ea-8037-2c4a6c6086aa.PNG)

**Podobne czynności wykonałem przy użyciu Kibany, wyniki jak się spodziewałem były bardzo podobne, udało się jeszcze pozyskać informacjie o tym jakie pliki, z jakich i na jakie adresy były wysyłane.**
![Kibana1](https://user-images.githubusercontent.com/56591106/72636549-8e484a00-395f-11ea-9096-a08894f6579d.PNG)
![file](https://user-images.githubusercontent.com/56591106/72636544-8dafb380-395f-11ea-8a7e-4948ffb45a14.PNG)
![File2](https://user-images.githubusercontent.com/56591106/72636545-8dafb380-395f-11ea-8144-3d542b9b25ca.PNG)
![file3](https://user-images.githubusercontent.com/56591106/72636553-8e484a00-395f-11ea-83d0-6fc4dabfbc98.PNG)

**Znalazłem informacje o kolejnych portach na których odbywała się komunikacja, a także przesyłane były pliki i postanowiłem je sprawdzić**
![morePorts](https://user-images.githubusercontent.com/56591106/72636553-8e484a00-395f-11ea-83d0-6fc4dabfbc98.PNG)
![1073](https://user-images.githubusercontent.com/56591106/72636541-8d171d00-395f-11ea-899d-06483c90f4c4.PNG)
![1080](https://user-images.githubusercontent.com/56591106/72638307-783c8880-3963-11ea-9cec-c159212e7d7f.PNG)

**Uruchomiłem także program Sguily i przejżałem logi**
![squily](https://user-images.githubusercontent.com/56591106/72636555-8ee0e080-395f-11ea-87f6-e54ccd8d8b62.PNG)

**W NetworkMainer również znalazłem kilka dodatkowych informacji, a także udało mi się uzyskac pliki, które mogą zostać poddane dalszej analizie.
![miner](https://user-images.githubusercontent.com/56591106/72636551-8e484a00-395f-11ea-90a5-bdc7ac4e4b7f.PNG)
![cfg3](https://user-images.githubusercontent.com/56591106/72637979-b71e0e80-3962-11ea-84cc-45213a2e5f34.PNG)




## Jako drugi do analizy wybrałem i zaimportowałem plik `best-malwere-protection.pcap`. 
```sudo so-import-pcap best-malwere-protection.pcap```
Ponownie zacząłem od Kibany i Squerta.

**Widok zaimportowanego ruchu w Squert - dopasowane sygnatury**
![sygnatury](https://user-images.githubusercontent.com/56591106/72671099-ab574880-3a45-11ea-9d66-7c9a2b6e0024.PNG)

**Następnie w Squert sprawdziłem takie informacje jak: sygnatury dopasowane przez program, adresy IP z którymi najczęściej występowała komunikacja, oraz porty.**
![portsCountryIp](https://user-images.githubusercontent.com/56591106/72671097-ab574880-3a45-11ea-929c-062cf9c13f98.PNG
![diagram](https://user-images.githubusercontent.com/56591106/72671091-aa261b80-3a45-11ea-964a-ecf143ccd0ca.PNG)

**Alerty NIDS wraz z powiązanami adresami IP**
![NIDSalert](https://user-images.githubusercontent.com/56591106/72671096-ab574880-3a45-11ea-834e-0ffef1d71aba.PNG)

**Typy odbieranych/wysyłanych plików oraz adresy z którymi się to odbywało**
![files](https://user-images.githubusercontent.com/56591106/72671093-aabeb200-3a45-11ea-8e36-b0dc19efd8e2.PNG)

**Pliki wyodrębnione NetworkMinerem oraz ich analizy w VirusTotal**
![virusTotal](https://user-images.githubusercontent.com/56591106/72671100-abefdf00-3a45-11ea-879b-e5e2be11c62b.PNG)
![nextVirus](https://user-images.githubusercontent.com/56591106/72671095-aabeb200-3a45-11ea-92eb-f6e50fdb6718.PNG)

**Powiązanie analizowanych plików z adresem IP**
![koleracja](https://user-images.githubusercontent.com/56591106/72671098-ab574880-3a45-11ea-99e9-3ad9b6c2b5c2.PNG)

**Adres `174.127.83.149` widnieje w jadnej z baz danych jako zagrożenie**
![image](https://user-images.githubusercontent.com/56591106/72671346-1fdfb680-3a49-11ea-8236-b4b689cd1d35.png

**Podejrzany adres IP w whoIs, adres również z USA**
![LosAngeles](https://user-images.githubusercontent.com/56591106/72671224-616f6200-3a47-11ea-9139-79755db1c12a.PNG)

**Obrazy wyodrębnione przez NetworkMiner, moim zdaniem podejrzane
![gifffff](https://user-images.githubusercontent.com/56591106/72671272-f4a89780-3a47-11ea-8a9d-68c6287b2f5b.PNG)



