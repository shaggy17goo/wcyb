# OSINT Politechnika Gdańska
# Michał Wawrzyńczak

Podczas zbierania informacji na temat Politechniki Gdańskiej wykorzystałem kilka podstawowych narzędi rekonesansu, głównym źródłem informacji była wyszukiwarka google, oraz strony publiczne dostępne w internecie:

- Infrastruktura posiadaną przez podmiot (serwery, ich adresy IP, prawdopodobna lokalizacja geograficzna):
Pierw sprawdziłem podstawowe informacja używając narzędzia whoIs, uzyskałem dzięki temu nazwy serwerów politechniki, informacje o utworzeniu i ostatniej modyfikacji serverów, oraz adres firmy która zajerejstrowała domenę politechniki gdańskiej (https://www.h88.pl/kontakt/).

![whoIs](https://user-images.githubusercontent.com/56591106/72541152-4acbde00-3882-11ea-847a-5877f1761b01.PNG)

Netcraft info: https://sitereport.netcraft.com/?url=https%3A%2F%2Fpg.gda.pl


Sprawdziłem lokalizację 3 serwerów, a także posiadny zakres adresów IP.
![location](https://user-images.githubusercontent.com/56591106/72543735-781a8b00-3886-11ea-8b9b-a4ada03a8cb4.png)
![ips](https://user-images.githubusercontent.com/56591106/72541162-4d2e3800-3882-11ea-93af-82d76cd2b2a7.PNG)

-Ostatnie informacje o problemach bezpieczeństwa
-Ostatni restart serwerów
Odnośnie tych aspektów nie udało mi się znaleźć zbyt wiele informacji, brak żadnych wzianek o jakichkolwiek problemach, jedyne co usyskałemto wpis o wpadce jednego z profesorów o publicznym udostępnieniu danych osobowych studentów. Informacji o ostatnim restarcie serwerów również nie uzyskałem, jedynie informacje o ostatnich modyfikacjach
![restartInfo](https://user-images.githubusercontent.com/56591106/72544605-f9265200-3887-11ea-95d9-59e855b3e915.PNG)

- Usługi oferowane przez serwery
- Posiadane domeny i subdomeny

Znalezione informacje o udostępnianych usługach:
![uslugiPG](https://user-images.githubusercontent.com/56591106/72545531-7605fb80-3889-11ea-9144-84f6d04d0e69.PNG)
![usługiOsiedleStudenckie](https://user-images.githubusercontent.com/56591106/72541148-4a334780-3882-11ea-8d87-5de5d0dbef6a.PNG)

Znalezione informacje o serverach, DNS i organizacji sieci
![Shodan](https://user-images.githubusercontent.com/56591106/72541151-4acbde00-3882-11ea-9754-655e4ad60cc8.PNG)
![DNS](https://user-images.githubusercontent.com/56591106/72541159-4c95a180-3882-11ea-8251-c79be3ebad7c.PNG)
![export](https://user-images.githubusercontent.com/56591106/72541161-4d2e3800-3882-11ea-8c34-82d6a688bc86.png)

Subdomeny:
```
mx.zie.pg.edu.pl,153.19.33.4
ezd-prod-app1.pg.edu.pl,153.19.40.133
ezd-prod-db1.pg.edu.pl,153.19.40.134
sklep.pg.edu.pl,153.19.40.137
ctwit-crm.pg.edu.pl,153.19.40.138
drive.pg.edu.pl,153.19.40.139
kube-prod-front1.pg.edu.pl,153.19.40.151
kube-prod-front2.pg.edu.pl,153.19.40.152
kube-prod-front3.pg.edu.pl,153.19.40.153
kube-prod-front4.pg.edu.pl,153.19.40.154
mobile.pg.edu.pl,153.19.40.155
position.pg.edu.pl,153.19.40.156
kube-prod-http.pg.edu.pl,153.19.40.158
enauczanie.pg.edu.pl,153.19.40.164
zadania.pg.edu.pl,153.19.40.175
vpn1.pg.edu.pl,153.19.40.186
vpn2.pg.edu.pl,153.19.40.187
vpn.pg.edu.pl,153.19.40.188
phplist.pg.edu.pl,153.19.40.198
smtplist.pg.edu.pl,153.19.40.199
smtp.student.pg.edu.pl,153.19.40.202
eka.pg.edu.pl,153.19.40.204
webmail.pg.edu.pl,153.19.40.207
imap.pg.edu.pl,153.19.40.220
smtprelay.mailing.pg.edu.pl,153.19.40.250
smtp.pg.edu.pl,153.19.40.251
dzp.pg.edu.pl,153.19.40.28
cnm-srv.pg.edu.pl,153.19.40.71
campus.pg.edu.pl,153.19.40.75
han.bg.pg.edu.pl,153.19.58.251
webmail.test.pg.edu.pl,153.19.62.130
repos.test.pg.edu.pl,153.19.62.68


ezd-prod-db1.pg.edu.pl,153.19.40.134
vpn1.pg.edu.pl,153.19.40.186
ezd-prod-app1.pg.edu.pl,153.19.40.133
vpn2.pg.edu.pl,153.19.40.187
mba.pg.edu.pl,153.19.33.16
eia.pg.edu.pl,153.19.40.170
zadania.pg.edu.pl,153.19.40.175
eka.pg.edu.pl,153.19.40.204
enauczanie.pg.edu.pl,153.19.40.164
zie.pg.edu.pl,153.19.40.170
mail.zie.pg.edu.pl,153.19.33.246
mx.zie.pg.edu.pl,153.19.33.4
drive.pg.edu.pl,153.19.40.139
han.bg.pg.edu.pl,153.19.58.251
smtprelay.mailing.pg.edu.pl,153.19.40.250
eti.pg.edu.pl,153.19.40.170
webmail.pg.edu.pl,153.19.40.207
ezd-szkol-app1.szkol.pg.edu.pl,10.15.230.50
kube-szkol-http.szkol.pg.edu.pl,10.15.230.20
ctwit-crm.pg.edu.pl,153.19.40.138
position.pg.edu.pl,153.19.40.156
vpn.pg.edu.pl,153.19.40.188
imap.pg.edu.pl,153.19.40.220
sklep.pg.edu.pl,153.19.40.137
smtp.pg.edu.pl,153.19.40.251
kube-prod-http.pg.edu.pl,153.19.40.158
dzp.pg.edu.pl,153.19.40.28
wilis.pg.edu.pl,153.19.40.170
campus.pg.edu.pl,153.19.40.75
student.pg.edu.pl,153.19.40.170
smtp.student.pg.edu.pl,153.19.40.202
webmail.test.pg.edu.pl,153.19.62.130
repos.test.pg.edu.pl,153.19.62.68
phplist.pg.edu.pl,153.19.40.198
smtplist.pg.edu.pl,153.19.40.199
cnm-srv.pg.edu.pl,153.19.40.71
```

- Informacje w cache’u wyszukiwarki Google
![cahce](https://user-images.githubusercontent.com/56591106/72541153-4b647480-3882-11ea-9865-48d750642385.PNG)

- Numery telefonów, PESEL itp. oraz inne istotne informacje:

Znalezione maile, baze ponad 3000 maili z możliwością filtrowania i weryfikacji źródła pochodzenia maila:
![maile2](https://user-images.githubusercontent.com/56591106/72554913-ea499a80-389b-11ea-964f-ea3736a62aa8.png)

Strona z numerami do wszystkich pokojów, akademików PG a także sprzątaczek, do biura, warsztatu:
![numery](https://user-images.githubusercontent.com/56591106/72546924-eca3f880-388b-11ea-9271-b8570ae3e323.PNG)

Kto, kiedy i gdzie ma konsultacje, w tym tego semestru:
![konsultacje](https://user-images.githubusercontent.com/56591106/72555106-43b1c980-389c-11ea-8de8-18171745f6f5.PNG)

Skoroszyt z imionami, nazwiskami i numerami albómów studentów:
![albumy](https://user-images.githubusercontent.com/56591106/72626924-e1b09d00-394b-11ea-992b-eb1bfe9f3138.PNG)

Oferta pracy w instytucie Informatyki i komunikacji
![praca](https://user-images.githubusercontent.com/56591106/72547765-89b36100-388d-11ea-85cf-1f9343bff7a6.PNG)

Skoroszyt z ocenami:
![oceny](https://user-images.githubusercontent.com/56591106/72547635-4953e300-388d-11ea-91d7-6cd9b25a245e.png)
