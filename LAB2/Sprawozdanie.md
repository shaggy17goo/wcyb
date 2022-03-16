# Michał Wawrzyńczak
# Sprawozdanie Lab2


## Zad 1
Uruchomiłem dwa skrypy `tcp_serv.py` i `tcp_client.py` na hoscie Kali Linux, następnie włączyłem nasłuchiwanie w programie WireShark. Podczas nałuchiwania eth0 w WireShark nie przechwycił żadnych pakietów, uruchomienie obu skryptów na jednym hoscie `Kali Linux` skutkje tym, że przekazywane pakiety nie wydostają się poza kartę sieciąwą. Uruchomiłem więc nasłuchiwanie loopback, w tym momencie WireShark przechwytywał wszystkie pakiety z możliwością odczytania przekazywanej informacji.

**Nasłuchiwanie eth0**
![ClientServer](https://user-images.githubusercontent.com/56591106/69888035-0db78680-12ea-11ea-8eef-17d535297fb1.PNG)

**Nasłuchiwanie loopback**
![ClientServerLB](https://user-images.githubusercontent.com/56591106/69888044-22941a00-12ea-11ea-8b5f-127b19bb2fab.PNG)

## Zad 2
Przy pomocy narzędzia `nmap` wykonałem skanowanie hosta `vulnix`. Uruchomienie nmapa bez podania rzadnej flagi to skanowanie domyślne z flagą SYN.

**Skanowanie TCP connect**
![sT](https://user-images.githubusercontent.com/56591106/69888196-e8774800-12ea-11ea-9925-20a5a78fe656.PNG)

**Skanowanie SYN**
![sS](https://user-images.githubusercontent.com/56591106/69888199-ee6d2900-12ea-11ea-8651-72e6ca670299.PNG)

## Zad 3
Wykonałem skanowanie SYN oraz XMAS hosta `vulnix` przy użyciu `nmapa`.

Podczas skanowania SYN dostajemy jedynie informacje które porty są otwarte, wynika to z tego że podczas tego skanowania nmap wysyła jedynie pakiety z flagą SYN w nagłówku, dla otwartych portów host vulnix odpowiada pakietem z flagami (SYN, ACK), a dla zamkniętych (RST, ACK)

Podczas skanowania XMAS otrzmujemy informacje o otwartych portach z dodatkową informacją że są one filtrowane, wynika to z tego że podczas skanowanie nmap wysyła pakiety z flagami (PSH, URG, FIN), w tym momencie firewall hosta vulnix uśmierca te pakiety na portach otwartych i do Kaliego nie wraca żadna odpowiedź, z tąd informacja że porty są filtrowane. Na portach zamkniętych sytuacja analogiczna jak podczas skanowania SYN, vulnix odpowiada Kaliemu pakietem z flagami (RST, ACK)

**Skanowanie SYN**
![sS](https://user-images.githubusercontent.com/56591106/69888820-317ccb80-12ee-11ea-8c85-d0bfd76358dd.PNG)

**Skanowanie XMAS**
![sXMAS](https://user-images.githubusercontent.com/56591106/69888838-49ece600-12ee-11ea-852b-98dc88654752.PNG)

## Zad 4
Wykonałem skanowani hosta vulnix pod kątem działających na nim usług oraz określenia systemu operacyjniego

**System i usługi Vulnix**
![systemVulnix](https://user-images.githubusercontent.com/56591106/69888896-99331680-12ee-11ea-8c86-826f8412502c.PNG)

## Zad 5
W pierwszej kolejności wykonałem skanowanie TCP oraz SYN hosta `metasploitable` bez uruchamiania na nim skryptów.
Następnie uruchomiłem skrypt `shrypt1.sh` oraz ponownie wykonałem skanowanie
Z zauważalnych zmian widzimy, że po uruchomieniu skryptu `nmap` wykrył że porty 21-ftp i 80-http są filtrowane.

**Skanowanie TCP oraz SYN bez uruchomionego skryptu**
![NoSkryptST](https://user-images.githubusercontent.com/56591106/69889252-2cb91700-12f0-11ea-8744-6f9f945215ea.PNG)
![NoSkryptSS](https://user-images.githubusercontent.com/56591106/69889253-2d51ad80-12f0-11ea-8332-64f17e44af2b.PNG)

**Skanowanie TCP oraz SYN po uruchomieniu skryptu `skypt1.sh`
![skrypt1sT](https://user-images.githubusercontent.com/56591106/69890016-51af8900-12f4-11ea-9582-f311e50ab7b3.PNG)
![skrypt1sS](https://user-images.githubusercontent.com/56591106/69890015-51af8900-12f4-11ea-8850-71a8676ba7a8.PNG)

## Zad 6
Uruchomiłem skrypt `skrypt2.sh` na hoscie `metasploitable` i wykonałem różne typy skanowania.
FireWall hosta jednoznacznie blokuje wszystkie pakiety z flagą ACK w nagłówku

**Skanowanie ACK**
![skrypt2sA](https://user-images.githubusercontent.com/56591106/69889448-49a21a00-12f1-11ea-9c13-9f94894e9775.PNG)

**Skanowanie usług i systemu**
![sktypt2sVO](https://user-images.githubusercontent.com/56591106/69889566-ecf32f00-12f1-11ea-915d-7d8456becfe3.PNG)

**Skanowanie SYN**
![skrypt2sS](https://user-images.githubusercontent.com/56591106/69889446-49a21a00-12f1-11ea-9480-7fce30b05632.PNG)

**Skanowanie TCP**
![skrypt2sT](https://user-images.githubusercontent.com/56591106/69890269-2b3e1d80-12f5-11ea-97ee-4c9d658ef1e8.PNG)

**Skanowanie XMAS**
![skrypt2sX](https://user-images.githubusercontent.com/56591106/69889447-49a21a00-12f1-11ea-947a-dc6222b7a583.PNG)

## Zad 7
W pierwszej kolejności sprawdziłem dostępne skrypty `Nmap NSE` dostępne w biblotece nmapa na Kalim, następnie wybrałem kilka z nich i wyonałem skanowanie hosta `vunix`. Np. próba złamania loginu i hasła do usługi ssh, pozyskanie ssh-hostkey

**Dostępne skrypty SSH**
![skryptSSH](https://user-images.githubusercontent.com/56591106/69889689-a3efaa80-12f2-11ea-91ab-e4101aed1f9d.PNG)

**Skanowania**

![Nmap_ssh1](https://user-images.githubusercontent.com/56591106/69889752-fc26ac80-12f2-11ea-8059-411a5af5fb2a.PNG)
![Nmap_ssh2](https://user-images.githubusercontent.com/56591106/69889753-fc26ac80-12f2-11ea-8619-f057b9234361.PNG)
![Nmap_ssh3](https://user-images.githubusercontent.com/56591106/69889754-fc26ac80-12f2-11ea-9af8-094e752f94dc.PNG)
![Nmap_ssh4](https://user-images.githubusercontent.com/56591106/69889755-fc26ac80-12f2-11ea-8231-24a46a10ef1f.PNG)
![Nmap_ssh5](https://user-images.githubusercontent.com/56591106/69889751-fb8e1600-12f2-11ea-8cbe-ea1434a19672.PNG)

## Zad 8
Skanowanie hosta `vulnix` przy użyciu narzędzia OpenVas
![OpenVAS](https://user-images.githubusercontent.com/56591106/69889937-e9f93e00-12f3-11ea-9334-a5808e25fd02.PNG)
![OpenVAS2](https://user-images.githubusercontent.com/56591106/69889936-e9f93e00-12f3-11ea-8245-84f51f68db67.PNG)

## Zad 9 
Skanowanie hosta `vulnix` przy użyciu narzędzia Nessus
![NessusVulnix3](https://user-images.githubusercontent.com/56591106/69889956-06957600-12f4-11ea-8ac4-134c84a4c813.PNG)
![NessusVulnix](https://user-images.githubusercontent.com/56591106/69889957-06957600-12f4-11ea-8d20-64450a2a26f8.PNG)
![NessusVulnix2](https://user-images.githubusercontent.com/56591106/69889958-06957600-12f4-11ea-88f4-fda99c8176b4.PNG)





