# Projekt_WCYB
## Marcin Dadura nr: 303_688
 
-------------------------------------------------------------
 
### Organizacja - `Politechnika Gdańska`
 
-------------------------------------------------------------
 
#### Zadanie 1 - OSINT (3p.)
##### Dla wytypowanej organizacji należy zebrać informacje dostępne w Internecie, w szczególności te udostępniane przez wyszukiwarkę Google oraz za pomocą narzędzi do rekonesansu Jakie informacje nas interesują?
 
a) infrastruktura posiadaną przez podmiot (serwery, ich adresy IP, prawdopodobna lokalizacja geograficzna),
b) ostatnie informacje o problemach bezpieczeństwa,
c) ostatni restart serwerów,
d) usługi oferowane przez serwery,
e) posiadane domeny i subdomeny,
f) informacje w cache’u wyszukiwarki Google,
g) numery telefonów, PESEL itp. oraz inne istotne informacje, które mogą zostać wykorzystane np. w socjotechnice oraz ogólnie w przeprowadzeniu udanych testów penetracyjnych.
 
---------------------------------------------------------
 
### a) infrastruktura posiadaną przez podmiot (serwery, ich adresy IP, prawdopodobna lokalizacja geograficzna),
#### Serwry:
<img width="246" alt="serwery pg edu pl 3 serwey" src="https://user-images.githubusercontent.com/56841909/72268069-6dab8780-3621-11ea-9242-fe7a58b05b45.PNG">
 
#### Adresy ip serwerów:
(skrypt:
```
#!/bin/bash
 
for x in $(host -t ns pg.edu.pl | cut -d  " " -f 4 | rev | cut -c2- | rev) ; do host $x | grep "has address"; done
```
 
![image](https://user-images.githubusercontent.com/56841909/72268234-bbc08b00-3621-11ea-8bb6-886a809bf1ff.png)
 
#### Prawdopodobna lokalizacja geograficzna
 
(strona https://www.iplocation.net/)
 
![image](https://user-images.githubusercontent.com/56841909/72270409-65554b80-3625-11ea-86bc-632e1ff36375.png)
 
(strona https://pg.edu.pl/uczelnia/kontakt)
 
![image](https://user-images.githubusercontent.com/56841909/72277408-2aa5e000-3632-11ea-8f01-bc8d2c95812b.png)
 
 
-------------------------------------------------------------------------
 
### b) Ostatnie informacje o problemach bezpieczeństwa.
 
* Wyciek danych studnetów z pewnej strony promotora. (1/10/2018 https://niebezpiecznik.pl/post/prywatne-serwisy-wykladowcow-z-danymi-osobowymi-czyli-uczelnianych-wpadek-czesc-v/) ![image](https://user-images.githubusercontent.com/56841909/72272683-57092e80-3629-11ea-98c8-8f382d0dd08d.png)
 
 
* Opublikowanie przez Anonymous baz danych wydziałów PG (Studenckiego Klubu Turystycznego Politechniki Gdańskiej, Wydziału Architektury Politechniki Gdańskiej, witrynie Katedry Chemii Nieorganicznej Politechniki Gdańskiej) (30.03.2012 https://niebezpiecznik.pl/post/anonymous-polska-bazy-sadow-i-prokuratur/)
 
-------------------------------------------------------------------------
 
 
### c) ostatni restart serwerów
 
 
 
# NAPISZ COS
 
 
-------------------------------------------------------------------------
 
### d) Usługi oferowane przez serwery.
 
https://cui.pg.edu.pl/
 
![image](https://user-images.githubusercontent.com/56841909/72278060-7b6a0880-3633-11ea-8072-3898add598a5.png)
 
-------------------------------------------------------------------------
 
### e) Posiadane domeny i subdomeny.
 
Użyłem komendy ```dnsrecon -d pg.edu.pl```
 
![image](https://user-images.githubusercontent.com/56841909/72276590-8e2f0e00-3630-11ea-902a-9cc5f1baaa22.png)
 
Do wylistowania subdomen użyłem narzędzia `sublist3r`. Użyłem komendy: ```python sublist3r.py -d pg.edu.pl -o subdomains.txt```
 
![image](https://user-images.githubusercontent.com/56841909/72279212-f03e4200-3635-11ea-95c2-ecd257d0ab80.png)
 
```
www.pg.edu.pl
akademiki.pg.edu.pl
ankieta.pg.edu.pl
ankiety.pg.edu.pl
arch.pg.edu.pl
arch.pg.edu.pl
rekrutacja.awf.pg.edu.pl
bg.pg.edu.pl
han.bg.pg.edu.pl
login.han.bg.pg.edu.pl
katalog.bg.pg.edu.pl
bilety.pg.edu.pl
biuletyn.pg.edu.pl
biuletyn.pg.edu.pl
budzetobywatelski.pg.edu.pl
campus.pg.edu.pl
cdn.pg.edu.pl
chat.pg.edu.pl
chem.pg.edu.pl
fmch.chem.pg.edu.pl
leki.chem.pg.edu.pl
chor.pg.edu.pl
cjo.pg.edu.pl
cjo.pg.edu.pl
mediateka.cjo.pg.edu.pl
clickmeeting.pg.edu.pl
cmtm.pg.edu.pl
cnm.pg.edu.pl
cnm-srv.pg.edu.pl
csa.pg.edu.pl
ctwit-crm.pg.edu.pl
ctwt.pg.edu.pl
cui.pg.edu.pl
domki.pg.edu.pl
drive.pg.edu.pl
dzp.pg.edu.pl
dzp.pg.edu.pl
ects.pg.edu.pl
eduroam.pg.edu.pl
eia.pg.edu.pl
chmura.eia.pg.edu.pl
eka.pg.edu.pl
eka.pg.edu.pl
enauczanie.pg.edu.pl
energia2015.pg.edu.pl
etee2015.pg.edu.pl
eti.pg.edu.pl
sis.eti.pg.edu.pl
ezd.pg.edu.pl
ezd-prod-app1.pg.edu.pl
ezd-prod-db1.pg.edu.pl
festiwal.pg.edu.pl
forum.pg.edu.pl
ftims.pg.edu.pl
git.pg.edu.pl
help.pg.edu.pl
imap.pg.edu.pl
kampus.pg.edu.pl
kp.pg.edu.pl
kube-prod-front1.pg.edu.pl
kube-prod-front2.pg.edu.pl
kube-prod-front3.pg.edu.pl
kube-prod-front4.pg.edu.pl
kube-prod-http.pg.edu.pl
logowanie.pg.edu.pl
smtprelay.mailing.pg.edu.pl
mba.pg.edu.pl
mech.pg.edu.pl
media.pg.edu.pl
meteo.pg.edu.pl
mif.pg.edu.pl
mobile.pg.edu.pl
moja.pg.edu.pl
pg.moja.pg.edu.pl
nextcloud.pg.edu.pl
oio.pg.edu.pl
piksel.oio.pg.edu.pl
pixel.oio.pg.edu.pl
synertech.oio.pg.edu.pl
okno.pg.edu.pl
pg.pg.edu.pl
phplist.pg.edu.pl
platnosci.pg.edu.pl
poczta.pg.edu.pl
pomoc.pg.edu.pl
position.pg.edu.pl
praca.pg.edu.pl
pub.pg.edu.pl
rekrutacja.pg.edu.pl
repos.pg.edu.pl
roundcube.pg.edu.pl
samorzad.pg.edu.pl
sk.pg.edu.pl
sklep.pg.edu.pl
smtp.pg.edu.pl
smtplist.pg.edu.pl
spotkania.pg.edu.pl
student.pg.edu.pl
imap.student.pg.edu.pl
smtp.student.pg.edu.pl
chat.szkol.pg.edu.pl
ezd-szkol-app1.szkol.pg.edu.pl
kube-szkol-http.szkol.pg.edu.pl
logowanie.szkol.pg.edu.pl
pg.moja.szkol.pg.edu.pl
techem9.pg.edu.pl
platnosci.test.pg.edu.pl
repos.test.pg.edu.pl
webmail.test.pg.edu.pl
vcenter.pg.edu.pl
voip.pg.edu.pl
vpn.pg.edu.pl
vpn1.pg.edu.pl
vpn2.pg.edu.pl
webapps.pg.edu.pl
webinar.pg.edu.pl
webmail.pg.edu.pl
ext.webmail.pg.edu.pl
wilis.pg.edu.pl
wilis.pg.edu.pl
wit.pg.edu.pl
wzie.pg.edu.pl
xn--wili-o5a.pg.edu.pl
zadania.pg.edu.pl
zapisy.pg.edu.pl
zgloszenia.pg.edu.pl
zie.pg.edu.pl
crk.zie.pg.edu.pl
ekonomia-kultura-wartosci.zie.pg.edu.pl
imap.zie.pg.edu.pl
kizo.zie.pg.edu.pl
mail.zie.pg.edu.pl
marketinfo.zie.pg.edu.pl
mx.zie.pg.edu.pl
pop3.zie.pg.edu.pl
smtp.zie.pg.edu.pl
zlecenia.pg.edu.pl
```
 
-------------------------------------------------------------------------
 
### f) Informacje w cache’u wyszukiwarki Google.
 
Aby dostać się do cashe wyszukwarki googla należu wpisać: ```cache:pg.edu.pl```
 
Pojawia się nastęujace informacje:
```
To jest kopia z pamięci podręcznej Google adresu https://pg.edu.pl/. Zdjęcie przedstawia stan strony z 10 Sty 2020 22:40:20 GMT
```
 
* ostatnia aktualizacja pamieci cashe to 10 styczani 2020, 22.40.20 GMT
* czas dostęu 13.01.2020, 18.06 GMT
 
![image](https://user-images.githubusercontent.com/56841909/72275941-3b088b80-362f-11ea-959d-fda7fee95bac.png)
 
Strona nie zapisuje cashe-u na dysku hosta któy korzysta ze strony (https://www.shodan.io/host/153.19.40.170):
 
![image](https://user-images.githubusercontent.com/56841909/72276352-01845000-3630-11ea-9b39-daa9c05cd37e.png)
 
-------------------------------------------------------------------------
 
### g) Numery telefonów, PESEL itp. oraz inne istotne informacje, które mogą zostać wykorzystane np. w socjotechnice oraz ogólnie w przeprowadzeniu udanych testów penetracyjnych.
 
##### Dane kontaktowe oraz adres organizacji wraz z NIP oraz REGON
![image](https://user-images.githubusercontent.com/56841909/72277275-f2060680-3631-11ea-9b2a-353d4471b532.png)
 
### nr albumu studentów
 
![image](https://user-images.githubusercontent.com/56841909/72280433-9db25500-3638-11ea-9efa-f71acbda2ffc.png)
 
![image](https://user-images.githubusercontent.com/56841909/72280369-7491c480-3638-11ea-8769-099de0938d20.png)
