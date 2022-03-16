# Sprawozdanie_1 WCYB_Lab_4
## Marcin Dadura nr: 303_688
### Do realizacji zadania należy:

#### Zadanie 1
##### Do realizacji zadania należy:

a)  zaintalować wirtualny host Security Onion zgodnie z tym, co wykonawano podczas laboratorium.
b) zainstalować wirtualny host Windowsa 10 w wersji Education/Professional/Enterprise - licencja jest dostępna w Azure for Students (sekcja Education)
c) Skonfigurować generowanie logów systemowych systemu Windows - Sysmon. W tym kroku może być przeprowadzone to testowo - do pliku.
d) Skonfigurować wysyłanie logów sysmon do Security Onion.
e)  Zaobserowować działanie za pomocą UI dostępnego w Security Onion - Kibana.
f)  Przeanalizować zawartość informacyjną logów sysmon pod kątem wykrywania zagrożeń w cyberprzestrzeni.

##### a),b) Zaintalować wirtualny host Security Onion zgodnie z tym, co wykonawano podczas laboratorium,  zainstalować wirtualny host Windowsa 10 w wersji Education/Professional/Enterprise - licencja jest dostępna w Azure for Students (sekcja Education)
Po 3 próbach instalacji Security Onion i Win10 zaczęły działać. Korzytsam z licencji dostpęnej na [Azure](https://azure.microsoft.com/en-us/). Zainstalowana wersja systemu operacyjnego Windows to Education 64-bit.

![instalacjaOnion](https://user-images.githubusercontent.com/56841909/71767122-0dbe2e00-2f09-11ea-9451-05a43163538d.PNG)

![instalacjaWinEdu](https://user-images.githubusercontent.com/56841909/71767128-2890a280-2f09-11ea-9f42-0b01fd954fee.PNG)

##### c) Skonfigurować generowanie logów systemowych systemu Windows - Sysmon. W tym kroku może być przeprowadzone to testowo - do pliku.

Sysmon porałem ze strony [Microsot](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon).
Do konfiguracji użyłem pliku .xml z [Gita](https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml).

Do instalacji `Sysmon` użyłem

```
sysmon.exe -accepteula -i sysmonconfig-export.xml
```

gdzie `sysmonconfig-export.xml` to plik konfiguracyjny, który zamieszczam w repozytorium. Do update-owania Sysmon użyłem `sysmon.exe -c sysmonconfig-export.xml`.

Sysmon skonfigurowałem testow, aby odczytać logi należy wejść w:

* Podgląd zdarzeń
* Dziennik aplikacji i usług
* Microsoft
* Windows
* Sysmon

<img width="960" alt="sysmon do pliku" src="https://user-images.githubusercontent.com/56841909/71897566-3e93a280-3157-11ea-839d-5c6db35c2d74.PNG">

##### d) Skonfigurować wysyłanie logów sysmon do Security Onion.

Do wysyłania logów do SecurityOnion-a użyłem programu `winlogbeat`, ze strony https://www.elastic.co/downloads/beats/winlogbeat.
Do instalacji użyłem komendy wpisanej do PowerShella : ```PowerShell.exe -ExecutionPolicy UnRestricted -File .\install-service-winlogbeat.ps1 ```.

![image](https://user-images.githubusercontent.com/56841909/72023260-94a93880-3272-11ea-8985-57edf3c71962.png)

W pliku konfigruracjynym `winlogbeat.reference.yml` skonfiurowałem następujące rzeczy:
* Dla kibany
``` 
setup.kibana:
host: [https://192.168.56.108/app/kibana]
```
* Zakomentujemy część z elasticsearch
``` 
#output.elasticsearch:
#hosts: ["192.168.56.108:9200"]
```
* Dla logstash
```
output.logstash:
hosts: ["192.168.56.108:5044"]
```
Następnie sprawdzamy poprawność konfiguracji `winlogbeat`-a poprzez komendę(Config OK oznacza, że konfiguracja przeszłą pomyślnie):
```
 .\winlogbeat.exe test config -c .\winlogbeat.reference.yml -e
```

![image](https://user-images.githubusercontent.com/56841909/72023316-b5718e00-3272-11ea-9ab7-98f17af90330.png)


Następnie wyłączamy Firewall-a  w:
* windwos

![image](https://user-images.githubusercontent.com/56841909/72022285-59a60580-3270-11ea-8ad3-83a84847618d.png)

* Onion uzywamy komendy: ```sudo ufw disable```.

Kolejnym punktem jest uruchomienie usługi `winlogbeat` w Windows w PowerShell  poprzez komendę: ```Start-Service winlogbeat ```.

##### e) Zaobserowować działanie za pomocą UI dostępnego w Security Onion - Kibana.

Po odpaleniu `Kibana`-y i wejściu w zakłądkę `Discover` możemy zaobserować wysyłanei logów:

![image](https://user-images.githubusercontent.com/56841909/72022498-e05ae280-3270-11ea-9939-7f323b1f92a4.png)

##### f) Przeanalizować zawartość informacyjną logów sysmon pod kątem wykrywania zagrożeń w cyberprzestrzeni.




------------------------------------------------------------------

#### Zadanie 2

##### 1 ) W ramach możliwości konta Azure for Students ustanowić darmową maszynę wirtualną z systemem operacyjnym Linux.

Stworzyłęm vm na portalu Azzure.

<img width="960" alt="stworzenie vm" src="https://user-images.githubusercontent.com/56841909/71925401-407a5780-3191-11ea-89d0-5b7f86e226e2.PNG">

##### 2 ) Sonfigurować reguły firewalla:
a) dopuścić ruch na porcie 80 oraz 443 (HTTP) z dowolnej maszyny
b) dopuścić ruch dla usługi SSH tylko ze swojej maszyny (swój adres publiczny IP można znaleźć np. na stronie: https://www.myip.com)
c) zablokować wszystkie nieużywane porty
d) dopuścić ruch dla protokołu MQTT (sprawdzić, co jest potrzebne)

Do zalogowania się do maszyny virtualnej użyłem programu PuTTY. Logowanie przez PuTTY wygląda następująco. Wpisuję IP hosta virtualnej maszyny oraz podaje protokół SSH, port 22. Firewall wirtualnej maszyny ma zadefiniowaną podczas tworzenia możliwość logowania się przez SSH.

<img width="337" alt="logowanie PUTTY" src="https://user-images.githubusercontent.com/56841909/71925735-02c9fe80-3192-11ea-8bdc-862dedbed977.PNG">

<img width="493" alt="PUTTY logowanie" src="https://user-images.githubusercontent.com/56841909/71925890-648a6880-3192-11ea-9dc6-663771b2a0fb.PNG">

Po zalogowaniu się używając loginu oraz hasła mam dostpęp do terminala systemu.

<img width="493" alt="udane logowanie" src="https://user-images.githubusercontent.com/56841909/71925906-6eac6700-3192-11ea-97f5-366c4f8da7ed.PNG">

##### a )  Dopuścić ruch na porcie 80 oraz 443 (HTTP) z dowolnej maszyny.

Aby sprawdzić akrualne zasady firewalla należy wpisać komendę ```iptables -S```.

<img width="229" alt="firewall na samym poczatku" src="https://user-images.githubusercontent.com/56841909/71926112-d82c7580-3192-11ea-9811-7b71b88ac167.PNG">

Aby dopuścić ruch na należy użyć komend:
* na porcie 80: ```sudo iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT```
* na porcie 443: ```sudo iptables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT```

<img width="481" alt="nowe zasady firewall z 80 i 443" src="https://user-images.githubusercontent.com/56841909/71926552-e0d17b80-3193-11ea-9e8b-55b665a13995.PNG">

Aby sprawdzić, jakie protokoł są akrualnie akceptowane należy użyć komendy ```sudo iptables -L -n```. Załączonego poniżej screena wynika, że ruch na tych portach zzostal dozwolony.

<img width="481" alt="sudo iptables -L -n" src="https://user-images.githubusercontent.com/56841909/71926690-255d1700-3194-11ea-8a8d-fb1a23983094.PNG">

##### b ) Dopuścić ruch dla usługi SSH tylko ze swojej maszyny (swój adres publiczny IP można znaleźć np. na stronie: https://www.myip.com)

Adres publiczny maszyny, na której się znajduję to: `162.158.103.131`

Aby dopuścić ruch dla usługi SSH tylko ze swojej maszyny nalezy użyć komendy: ```sudo iptables -A INPUT -p tcp -s 162.158.103.131 -m tcp --dport 22 -j ACCEPT```.

<img width="480" alt="SSH" src="https://user-images.githubusercontent.com/56841909/71927116-0f038b00-3195-11ea-814e-b9bb0c35f7c8.PNG">

##### c) zablokować wszystkie nieużywane porty

Aby zablokować całą resztę ruchu sieciowego należy użyć komend: 
* ```sudo iptables -P INPUT DROP```
* ```sudo iptables -P OUTPUT DROP```

##### d) dopuścić ruch dla protokołu MQTT (sprawdzić, co jest potrzebne)

Aby dopuścić ruch dla protokołu MQTT należy zezwolić na ruch na porcie 1883 oraz 8883. Należy zrobić to komendami:
* ```sudo iptables -A INPUT -p tcp -m tcp --dport 1883 -j ACCEPT```
* ```sudo iptables -A INPUT -p tcp -m tcp --dport 8883 -j ACCEPT```
* ```sudo iptables -A OUTPUT -p tcp -m tcp --dport 1883 -j ACCEPT```
* ```sudo iptables -A OUTPUT -p tcp -m tcp --dport 8883 -j ACCEPT```

Po konfiguracji firewall-a należy zapisać konfigurację komendą: 
```sudo iptables-save | sudo tee /etc/sysconfig/iptables```

A następnie zrestartować komendą:
```sudo service iptables restart```


##### 3 ) Znaleźć best practices hardeningu serwera Linux. Następnie przeprowadzić procedurę hardeningu maszyny w Azure. Obowiązkowo uwzględnić:
* SSH certificates logins
* Fail2ban
* oraz wybrać 2 inne dowolne działania prowadzące go hardeningu systemu. Uzasadnić wybór.


##### Best practices hardeningu serwera linux:
* używać silnyc loginów oraz haseł (minimum 8 znaków, w tym duże znaki i znaki specjalne)
* dezaktywować logowanie na roota przez ssh
* zmniejszyć ilosć użytkownikó z możliwosćią zdalnego dostępu
* używanie niestandardowego portu dla SSH, zamiast standadowego 22
* limitowanie dostępu do ssh przez sprecezyowanie dokłądnego adresu IPz którego chcemy mieć zdalny dostęp (punkt b z poprzedniego zadania)
* ustawienie czasu, po którym sesja zakańcza się po braku aktywnośći (Idle Timeout Interval)
* używać klucza do autoryzacji ssh(SSH certificates logins)
* zablokować próby bruteforce-owania haseł do SSH poprzes `Fail2Ban`
* zablokować porty których nie używamy
* zablokować możliwosć wysyłąnai flag, w tym pingowania

##### Konfiguracja klucza SSH:
Należy wpisać komendę ```ssh-keygen```

<img width="465" alt="klucz ssh komenda 'ssh-keygen'" src="https://user-images.githubusercontent.com/56841909/71986977-a9171200-322d-11ea-811f-21aeec510a3d.PNG">

Dzięki tej komendzie stworzyliśmy publiczy oraz prywatny klucz dostępny w katalogu `.ssh`.

<img width="235" alt="klucze" src="https://user-images.githubusercontent.com/56841909/71987091-d499fc80-322d-11ea-8cf9-27b390f99526.PNG">

Aby wświetlicz te klucze można użyć komend ```cat id_rsa``` i ```cat id_rsa.pub```.

Aby móc się logować do SSH poprzez klucz publiczny należy mieć go u siebie w folderze .ssh oraz dezaktywować logowanie przez hasło.

Aby dezaktywować logowanie przez hasło należy użyć komendy: ```sudo nano/etc/ssh/sshd_config```

Należy w tym pliku zmienić `PasswordAuthentication yes` na `PasswordAuthentication no`.

![image](https://user-images.githubusercontent.com/56841909/72012054-6d933c80-325b-11ea-9bc3-c06ec6cc59ed.png)

Następnie należy zrestartować ssh poprzez komendę: `service ssh reload`

Aby zalogować się do servera Ubuntu poprzez PuTTY, należy w aplikacji PuTTYGEN dodać klucz prywatny. W zakłądce `Conversions` zaimportować klucz i zapisać go. Następnie w PuTTY w zakładce SSH, AUTH należy w polu "Pricate key file for a authentication" wyszukać wcześniej zapisany plik z PuTTYGEN. 

![image](https://user-images.githubusercontent.com/56841909/72011872-02496a80-325b-11ea-9068-95295dd8a76d.png)

Możemy cieszyć się logowanie poprzez klucz:
![image](https://user-images.githubusercontent.com/56841909/72011919-18572b00-325b-11ea-94e8-d1b4f1de9059.png)


##### Fail2ban

Należy najpierw zainstalować Fail2Ban poprzez komendę ```sudo apt-get Fail2Ban```.
![image](https://user-images.githubusercontent.com/56841909/72012185-c662d500-325b-11ea-915f-c59fe7f29f39.png)

Następnie należy uzyć komendy: ```cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local```.

Konfigurujemy linie:
* `igoneip` - ip które nie mogą się łaćzyć
* `bantime` - czas po krótej bezczynności odstajemy baana
* `maxretry` - mówi ile prób, po krótych dostajemy bana

![image](https://user-images.githubusercontent.com/56841909/72015714-9408a600-3262-11ea-8d1e-33ba8c19cc02.png)

(cześć dalsza konfiguracji)
* należy przejsć do cześći `JAILS`, w której zmieniamy standardowy port SSH na port 22222

![image](https://user-images.githubusercontent.com/56841909/72016324-db436680-3263-11ea-9816-159f625d51f1.png)

Nastęnie restartujemy używając komendy: ```sudo systemctl restart fail2ban```.

Po zmianie portu na 22222 należałoby teraz odblokować ten port w Firewall-u i zablokować port 22. `Fail2Ban` sam odblokowuje port, na który zmienimy jednakże sami musimy zablokować port 22 używając odpiwiedniej do tego komendy: ```sudo iptables -A INPUT -p tcp --dport 22 -j DROP```.

![image](https://user-images.githubusercontent.com/56841909/72016728-9cfa7700-3264-11ea-826e-a01017dcef29.png)

##### Zablokowanie wysyłania pustych pakietów z flagą NULL, pakietów SYN oraz pakietów z flagą XMAS.

Takie pakiety często używane są przez kaerów do badani sieci przez hakerów pod katem badani portów.
Do firewall-a należy dodac wykluczenie komendami:
* 
```sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP```.

* ```sudo iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP``` (flaga SYN, blokuje aby uchorniż przez wysyłaniem pakietów, które otwierają port i mogą przeciażyć serwer)
* ```sudo iptables -A INPUT -p tcp --tcp-flafs ALL ALL -j DROP``` (flaga XMAS)

![image](https://user-images.githubusercontent.com/56841909/72024173-11d5ad00-3275-11ea-9add-84ca0a1d7459.png)


##### Zablokowanie możliwości pingowania.

Pingowanie jest częśto wykorzytywane przez hakerów do odtworzenia topologii sieci, która powinna być tajemnicą każdej korporoacji, każdego cyber-bezpiecznika. Robimy to komendą:

```
sudo iptables -I INPUT -m state --state ESTABLISHED,RELATED -j DROP
```
