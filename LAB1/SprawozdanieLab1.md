#### Michał Wawrzyńczak Laboratorium 1

## Zad 1.
Pobierając plik index.html dla domeny `juniper.net` i filtrując go przy użyciu następującego polecania otrzymamy wyniki:

 **Subdomeny juniper.net**
 >grep "https://" index.html | cut -d "/" -f 3 | sort -u | grep "net"
 ![juniper.net](https://user-images.githubusercontent.com/56591106/68130070-02578200-ff1b-11e9-956e-830ff5fce220.PNG)

Następnie zapisując listę subdomen do pliku możemy przy użyciu polecenia host i pętli for znaleźć dla każdej adres IP serwera/serwerów obsługujących daną domenę.

**Adresy IP subdomen juniper.net**
>for url in $(cat list.txt); do host $url; done | grep "has address" | cut -d " " -f 4 | sort -u
![addressJuniper](https://user-images.githubusercontent.com/56591106/68130182-32068a00-ff1b-11e9-9ef3-99030e8f0ece.PNG)

## Zad 2.
Używając programu `Wireshark` przechwyciłem ruch sieciowy przy próbie logowania na uczelnianą skrzynkę pocztową medusa.elka.pw.edu.pl. Po analizie pakietów, ustaliłem gdzie nastąpiło nawiązanie sesji TCP, a gdzie jej zakończenie.

**Nawiązanie sesji TCP**
![nawiazywanieWireshark](https://user-images.githubusercontent.com/56591106/68130453-aa6d4b00-ff1b-11e9-965a-bd0dac09e13d.PNG)

**Zakończenie sesji TCP**
![zamykanieWireshark](https://user-images.githubusercontent.com/56591106/68130550-d688cc00-ff1b-11e9-9145-c4d51fb85c56.PNG)

## Zad 3.

#### Przechwycony ruch sieciowy przy próbie logowania na medusa.elka.pw.edu.pl

**Uzgodnienie sesji TCP**
![tcpdumpNawiazywanie](https://user-images.githubusercontent.com/56591106/68143781-781b1800-ff32-11e9-9f5c-3731929a05e7.PNG)

**Zakończenie sesji TCP**
![tcpdumpZakończenie](https://user-images.githubusercontent.com/56591106/68143782-781b1800-ff32-11e9-9084-cec77c7af66a.PNG)

**Sekwencja Logowania**
>tcpdump -vv -A -r tcp.pcap
![tcplogowanieA](https://user-images.githubusercontent.com/56591106/68535593-dc7c1400-0344-11ea-8284-c22df18ba664.PNG)

>Cały ruch sieciowy podczas logowania
![tcpdump](https://user-images.githubusercontent.com/56591106/68242802-770ce800-0011-11ea-95cc-6710b25d7244.PNG)

Niestety nie udało mi się odnaleźć sekwencji logowania w przechwyconym ruchu sieciowym, prawdopodobnie dlatego, że dane logowania są zaszyfrowane i wysyłane jak każdy inny pakiet.

**Filtrowanie ruchu na porcie 443**
![tcp443f](https://user-images.githubusercontent.com/56591106/68471300-2a4a2c80-021e-11ea-9562-e3b46ea541f8.PNG)

**Przechwytywanie ruchu na porcie 433**
![tcp443](https://user-images.githubusercontent.com/56591106/68133049-01751f00-ff20-11e9-8ad3-4111b9125921.PNG)

## Zad 4.

**Uniwersytet Łódzki**

**Dane kontaktowe:**
https://www.uni.lodz.pl/kontakt

**Adres**
Uniwersytet Łódzki
ul. Narutowicza 68, 90-136 Łódź
fax: (0 42)665 57 71, (0 42)635 40 43,
NIP: 724-000-32-43

**Informacje z serwisu whois**

![whoIsUL](https://user-images.githubusercontent.com/56591106/68242246-79bb0d80-0010-11ea-8a92-9b9fb5f7fdb9.PNG)

**Lista pracowników z możliwością pozyskania maili**
* https://www.linkedin.com/search/results/people/?facetCurrentCompany=%5B%2215097344%22%5D&facetSchool=%5B%2215999%22%5D&origin=FACETED_SEARCH

## Zad 5.
Przy pomocy wyszukiwarki google wykorzystując nastepujące zapytania udało mi się znaleźć kilka plików, które prawdopodobnie nie powinny być publicznie dostępne:

**Przykładowe zapytania**
>intitle:"index of" site:uni.lodz.pl
>intitle:"index of" inurl:uni.lodz.pl
>filetype:xls inurl:uni.lodz.pl intitle:"studen"

**Przykładowe pliki które udało się znaleźć**
![ulmatura](https://user-images.githubusercontent.com/56591106/68134567-9aa53500-ff22-11e9-9eda-c5a1f67d402c.PNG)
![ucenyul](https://user-images.githubusercontent.com/56591106/68134578-9e38bc00-ff22-11e9-9aaf-1e1e8cba70b6.PNG)
![ftpUniLodz](https://user-images.githubusercontent.com/56591106/68136263-48b1de80-ff25-11e9-80d1-91b723032787.png)

## Zad 6.
Próba wyszukania jakiś ciekawych informacji z domeny `pw.edu.pl` nie przyniosła zbyt wiele przydatnych informacji. Natomiast ilość odpowiedzi na zapytanie o serwery ftp, pliki xls i pdf w domenie `pw.edu.pl` jest dość spora. Więkasza ilość spędzonego czasu na żmudnym przeglądaniu wyników zapytań z pewnością dała by więcej interesujących rezultatów.

![googlePW](https://user-images.githubusercontent.com/56591106/68140228-c24ccb00-ff2b-11e9-9d15-26ee686079e3.PNG)\
![xlsPW](https://user-images.githubusercontent.com/56591106/68140664-78b0b000-ff2c-11e9-80b9-41006b03fea3.PNG)
![pdfElkaPW](https://user-images.githubusercontent.com/56591106/68140666-78b0b000-ff2c-11e9-9612-b6b1ff6bb2b5.PNG)


**Przykładowe pliki z Politechniki Warszawskiej które udało się znaleźć**
* http://wujek2.ia.pw.edu.pl/wm/archiwum/
* http://staff.elka.pw.edu.pl/
* http://home.elka.pw.edu.pl/~bgajewsk/
* http://home.elka.pw.edu.pl/~pnajgeba/

![GraPW](https://user-images.githubusercontent.com/56591106/68138829-6d0fba00-ff29-11e9-91cc-2d1fc0010df6.PNG)
![spieSobie](https://user-images.githubusercontent.com/56591106/68139021-ba8c2700-ff29-11e9-87eb-ff65374fc06d.jpg)

## Zad 7.
**Whois Politechnika Warszawska**
![whoisPW](https://user-images.githubusercontent.com/56591106/68144305-ad743580-ff33-11e9-8d73-48e8936cd01f.PNG)

## Zad 8.
**Serwery DNS megacorpone.com**

![dnsMegacorpone](https://user-images.githubusercontent.com/56591106/68145748-c29e9380-ff36-11e9-8362-8615b190376a.PNG)

## Zad 9.
**Skrypt w bashu przenoszący stefę**

```
#/bin/bash

if [ -z "$1" ]; then
echo "[*] Simple Zone transfer script"
echo "[*] Usage : $0 <domain name>"
exit 0
fi
for server in $(host -t ns $1 |cut -d" " -f4); do
host -l $1 $server |grep " has address"
done
```
![strefaBash](https://user-images.githubusercontent.com/56591106/68241074-542d0480-000e-11ea-99e3-dc6698f0b239.PNG)

## Zad 10.
**Transfer strefy przy użyciu dnsrecon**

![strefaMegacorpone](https://user-images.githubusercontent.com/56591106/68146235-d5fe2e80-ff37-11e9-8bc2-49e08f2b2ba5.PNG)



