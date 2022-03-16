# Wstęp do cyberbezpieczeństwa (WCYB)
## Moduł 1: Kali Linux | Wprowadzenie do testów penetracyjncych - rekonesans
##### Semestr: 19Z

## Plan laboratorium

Z tego laboratorium:
- zapoznasz się z systemem operacyjnym Kali Linux
- zapoznasz się z podstawowymi poleceniami systemu Linux
- dowiesz się w jaki sposób zarzadzać usługami na systemie Linux
- dowiesz się jak pisać skrytpy w Bash'u
- dowiesz się co to jest test penetracyjny
- zapoznasz się z podstawami wykonywania rekonesansu jako elementu przygotowania do testów penetracyjnych
- zapoznasz się z metodami pasywnego zbieranie informacji o celu
- zapoznasz się z metodami aktywnymi zbieranie informacji o celu


# 1. Korzystanie z Kali Linux

## 1.1. O Kali Linux

Kali Linux to darmowa dystrybucja systemu Operacyjnego Kali Linux przeznaczona dla adminstratorów IT i specjalistów ds. bezpieczeństwa do audytów bezpieczeńśtwa. Posiada ponad 300 narzędzi do przeprowadzania testów penetracyjnych i audyty bezpieczeństwa, a dzięki jego zgodności ze standardami rozwoju Debiana zapewnia bardziej znane środowisko dla aministratorów IT.
W rezultacie jest to bardziej niezawodne rozwiązanie, które można łatwiej zaktualizować. Użytkownicy mogą również dostosować system operacyjny do własnych potrzeb i preferencji.

Wszystkie programy dostarczone z systemem operacyjnym zostały ocenione pod kątem przydatności i skuteczności. Przykłady ważniejszych narzędzi:
* `Metasploit` zawierający bazę exploitów
* `nmap` do skanowania portów i podatności na zagrożenia
* `Wireshark` do monitorowania ruchu w sieci
* `aircrack-ng` do testowania bezpieczeństwa sieci bezprzewodowych

Kali Linux może działać na różnych urządzeniach, jest kompatybilny z wieloma urządzeniami bezprzewodowymi i USB, a także może pracować na urządzeniach z procesorami ARM. 

Zanim rozpoczniemy pracę z Kali Linux należy się uwierzytelnić. Domyślnymi poświadczeniami tego systemu dla instalacji z obrazu są:

**username**: **root**

**password**: **toor**

Przy pierwszym użyciu nalezy je zmianień za pomocą polecenia `passwd`. 
![passwd](https://user-images.githubusercontent.com/54263922/63650721-2db93600-c74e-11e9-8145-1a137310e242.png)

**Pamiętaj, aby zawsze zamienić wszelkie domyślne lub słabe hasła dla swoich urządzeń, usług, kont itp. na coś długiego i złożonego. Złożoność może być tu osiągana za pomocą:**
* **mieszanie liter, cyfr, znaków specjalnych, hasło o odpowiedniej długości**
* **hasła składające się z kilku słów, które np. łatwo zapamiętać**

**W szczególności warto chronić te konta, które dają wysoki poziom dostępu do działań na maszynie/w usłudze, np. SSH.**

## 1.2 Podstawowe komendy

### 1.2.1 find, locate and which
Istnieje wiele narzędzi systemu Linux, których można użyć do zlokalizowania plików w instalacji systemu Linux, przy czym trzy z nich to: `find`, `locate` i `which`. Wszystkie trzy z tych narzędzi mają podobne funkcje, ale działają i zwracają dane na różne sposoby. Przed użyciem narzędzia **locate** musimy najpierw użyć polecenia `updatedb`, aby zbudować lokalną bazę danych wszystkich plików w systemie plików. Po zbudowaniu bazy danych można użyć **locate** do łatwego przeszukiwania tej bazy danych podczas wyszukiwania plików lokalnych. Przed uruchomieniem **locate** należy zawsze aktualizować lokalną bazę danych za pomocą polecenia `updatedb`.

![locate](https://user-images.githubusercontent.com/54263922/63650530-c5695500-c74b-11e9-842d-7acee8767af7.png)

Komenda **which** przeszukuje katalogi zdefiniowane w zmiennej środowiskowej $PATH dla podanej nazwy pliku. Jeśli zostanie znalezione dopasowanie komenda zwróci pełną ścieżkę do pliku, jak pokazano poniżej.

![which](https://user-images.githubusercontent.com/54263922/63650535-d6b26180-c74b-11e9-87ef-c475a357725a.png)

Polecenie **find** jest bardziej agresywnym narzędziem wyszukiwania niż **locate** lub **which**. Find jest w stanie rekurencyjnie przeszukiwać dowolną ścieżkę w poszukiwaniu różnych plików.

![find](https://user-images.githubusercontent.com/54263922/63650543-e8940480-c74b-11e9-850d-f2a430e71343.png)

Teraz, gdy znamy podstawowe narzędzia do lokalizowania plików w systemie Kali Linux, przejdźmy do sprawdzenia, jak działają usługi Kali i co jest potrzebne do skutecznego zarządzania nimi.

#### Ćwiczenia do wykonania

1. Zapoznać się z listą dostępnych narzędzi systemu Kali Linux. 
2. Określ lokalizację pliku **plink.exe** w systemie Kali Linux.
3. Znajdź i zapoznaj się z dokumentacją narzędzia dnsenum.

## 1.3 Wybrane usługi

Kali Linux zawiera kilka niestandardowych funkcji. Domyślna instalacja Kali jest dostarczana z wstępnie zainstalowanymi kilkoma usługami np. SSH, HTTP, MySQL itp. Jeśli nie zostanie to odpowiednio skonfigurowane, to usługi te zostaną automatycznie załadowane podczas rozruchu systemy. Innymi słowy, Kali Linux domyślnie otworzy kilka portów popularnych usług sieciowych. Najczęściej chcemy unikać takich sytuacji - zarówno jako specjaliści cyberbezpieczeństwa, ale też zapewniając bezpieczeństwo np. Klientom. Kali pozwala skonfigurować, które usługi mają być uruchamiane przy starcie systemu. 

Ważnymi mechanizmi bezpieczeństwa stosowanym w wielu systemach operacyjnych lub w ogólności - *środowiskach wykonawczych aplikacji/systemów* są:
* mechanizm białej listy - *whitelisting* - domyślenie wykonanie każdej aplikacji czy otwarcie portu jest zabronione w systemie. Aby wykonać aplikację lub otworzyć port należy ją najpierw dodać do listy dopuszczalnych do wykonywania aplikacji/otwarcia portu.
* mechanizm  czarnej listy - *blacklisting* - domyślenie wykonanie każdej aplikacji czy otwarcie portu jest dozwolone w systemie. Aby zabronić wykonywania się aplikacji lub otworcia portu należy ją umieścić na liście zabronionych aplikacji/portów.

*Whitelisting/blacklisting* to jeden z podstawowych składników procesu *hardeningu* systemów i aplikacji. W ogólności stanowi jeden z podstawowych środków zabezpieczania systemów i aplikacji na etapie ich konfiguracji.

Poniżej omówiono niektóre z tych usług, a także sposób ich obsługi i zarządzania nimi.

### 1.3.1 Usługa SSH

Usługa Secure Shell (`SSH`) jest najczęściej używana do zdalnego dostępu do komputera przy użyciu bezpiecznego, szyfrowanego protokołu. `SSH` jest następcą protokołu `telnet` - w przeciwieństwie do swojego poprzednika, połączenia zestawiane przez `SSH` są szyfrowane. Jednak protokół SSH ma pewne zaskakujące i przydatne funkcje poza zapewnianiem dostępu do terminala (np. realizacja proxy lub enkapsulacja tunelu SSH w protokole HTTP). Usługa `SSH` jest oparta na protokole `TCP` i domyślnie nasłuchuje na porcie 22. Aby uruchomić usługę `SSH` w Kali, wpisz następujące polecenie w terminalu Kali.

![sshstart](https://user-images.githubusercontent.com/54263922/63651022-4a0aa200-c751-11e9-8b36-0e36f05932d5.png)

Możemy sprawdzić, czy usługa `SSH` działa i nasłuchuje na porcie `TCP` 22, używając polecenia `netstat`. Wykorzystamy do tego mechanizm powłoki Linux polegający na możliwości przekazania danych wynikowych z jednego polecenia jako dane wejściowe do następnego. Przekierowanie odbywa się poprzez stosowanie znaku `|` (*pipe*) między poleceniami, przy czym wynik pierwszego polecenia jest przekazywany do drugiego polecenia. Bardzo popularnym narzędziem systemie Linux jest `grep`, który służy do wyszukiwania w tekście i wyodrębniania linii zawierających ciąg znaków pasujący do podanego wyrażenia, będącego *wyrażeniem regularnym* (*wyrażenia regularne pojawią się w innych modułach przedmiotu*). Poniej zaprezentowano przykład przekierowania wyniku narzędzia `netstat` (tzw. *piping*) do polecenia `grep`, aby wyszukać dane wyjściowe w poszukiwaniu `sshd`. 

![netstat](https://user-images.githubusercontent.com/54263922/63651033-5a228180-c751-11e9-9594-bede22162192.png)

Jeśli, podobnie jak wielu użytkowników, chcesz, aby usługa SSH była uruchamiana automatycznie podczas uruchamiania, musisz ją włączyć za pomocą skryptu `update-rc.d` w następujący sposób. Skryptu `update-rc.d` można używać do włączania i wyłączania większości usług w systemie Kali Linux.

![rc](https://user-images.githubusercontent.com/54263922/63651044-72929c00-c751-11e9-8bc5-974318bca8a8.png)

### 1.3.2 Usługa HTTP

Usługa `HTTP` może się przydać podczas testu penetracyjnego w celu hostingu witryny lub zapewnienia platformy do pobierania plików na zaatakowany komputer. Usługa `HTTP` jest oparta na protokole `TCP `i domyślnie nasłuchuje na porcie 80. Aby uruchomić usługę `HTTP` w Kali, wpisz następujące polecenie w terminalu.

![apache2](https://user-images.githubusercontent.com/54263922/63651241-f6995380-c752-11e9-9912-d86fdaa16edc.png)

Podobnie jak w przypadku usługi `SSH`, możemy zweryfikować, czy usługa `HTTP` działa i nasłuchuje na porcie `TCP` 80, używając ponownie poleceń `netstat` i `grep`.

![netstatApache](https://user-images.githubusercontent.com/54263922/63651246-0a44ba00-c753-11e9-9a19-a182f8625147.png)

Aby usługa `HTTP` była uruchamiana w czasie rozruchu, podobnie jak w przypadku usługi `SSH`, musisz jawnie ją włączyć za pomocą **update-rc.d**.

![rcApache](https://user-images.githubusercontent.com/54263922/63651253-2183a780-c753-11e9-9ce2-74cceff8f7e4.png)

Większość usług w Kali Linux jest obsługiwana w podobny sposób jak demony SSH i HTTP, za pośrednictwem ich skryptów serwisowych lub inicjujących.
Aby uzyskać bardziej szczegółową kontrolę nad tymi usługami, możesz użyć narzędzi takich jak **rcconf** lub **sysv-rc-conf**, oba zaprojektowane w celu uproszczenia i zarządzania trwałością rozruchu tych usług

services.

#### Ćwiczenia do wykonania
1. Jeśli używasz obrazu Kali Linux zmień domyślne hasło na inne, bezpieczniejsze. .
2. Przećwicz uruchamianie i zatrzymywanie różnych usług Kali Linux.
3. Umożliwij uruchomienie usługi SSH w momencie rozruchu systemu.

## 1.4 Podstawy BASHa


Powłoka GNU **B**ourne-**A**gain **SH**ell (`Bash`) zapewnia środowisko do pracy oraz silnik skryptowy, z którego możemy korzystać do automatyzacji procedur przy użyciu istniejących narzędzi Linux. Możliwość szybkiego ulepszenia skryptu Bash w celu zautomatyzowania danego zadania jest niezbędnym wymogiem dla każdego specjalisty cyberbezpieczeństwa. W tej części laboratorium zapoznamy się ze elementami skryptów Bash.

### 1.4.1 Praktyczne wykorzystanie Bash'a - przykład 1

Wyobraź sobie, że Twoim zadaniem jest znalezienie wszystkich subdomen wymienionych na stronie `cisco.com`, a następnie znalezienie odpowiadających im adresów IP. Wykonanie tego ręcznie byłoby frustrujące i czasochłonne. Jednak za pomocą kilku prostych poleceń Bash możemy zamienić to w łatwe zadanie. Zaczynamy od pobrania strony indeksu `cisco.com` za pomocą polecenia `wget`.

![wget](https://user-images.githubusercontent.com/54263922/64079463-2236b380-cce8-11e9-9318-2bac897fb91c.png)

Szybko przeglądając ten plik, widzimy wpisy, które zawierają potrzebne informacje, takie jak ta pokazana poniżej:

![li](https://user-images.githubusercontent.com/54263922/64079497-5dd17d80-cce8-11e9-895e-eab6334a9a75.png)


Zaczynamy od użycia polecenia `grep`, aby wyodrębnić wszystkie wiersze w pliku zawierające ciąg „href =”, wskazując, że ten wiersz zawiera URL.

![grep](https://user-images.githubusercontent.com/54263922/64079516-aee17180-cce8-11e9-9b63-a67fc6445350.png)

Rezultatem jest nadal mnóstwo niepotrzebnego kodu HTML, ale zauważmy, że większość linii ma podobną strukturę i może być wygodnie podzielona za pomocą znaku „/” jako separatora. Aby odpowiednio wyodrębnić nazwy domen z pliku, możemy spróbować użyć polecenia `cut` z naszym separatorem w 3-cim polu.

![cut](https://user-images.githubusercontent.com/54263922/64079532-df291000-cce8-11e9-8fb4-9a74ddc52b78.png)

Wynik, który otrzymujemy, jest daleki od optymalnego i prawdopodobnie po drodze zostało pominięte sporo linków, ale kontynuujmy. Nasz tekst zawiera teraz następujące wpisy:

![lista](https://user-images.githubusercontent.com/54263922/63973143-72c0cd80-caaa-11e9-97d6-641bd5376807.png)

Następnie wyczyścimy naszą listę, aby uwzględnić tylko nazwy domen. Użyjmy **grep**, aby odfiltrować wszystkie wiersze zawierające kropkę, aby uzyskać przejrzystszy wynik.
![drugi grep](https://user-images.githubusercontent.com/54263922/63973191-8ec46f00-caaa-11e9-803e-60010f44e789.png)

Nasze wyniki są prawie przejrzyste, ale teraz mamy wpisy, które wyglądają następująco.

![lerning](https://user-images.githubusercontent.com/54263922/63973213-9f74e500-caaa-11e9-8c91-5bd886a2b8b3.png)

Możemy je wyczyścić, używając ponownie polecenia `cut` dla pierwszej kolumny.


![drugi cut](https://user-images.githubusercontent.com/54263922/63973264-b3b8e200-caaa-11e9-9f8b-4bbbbcd16774.png)

Teraz mamy wyczyszczoną listę, ale wiele duplikatów. Możemy je wyczyścić za pomocą polecenia `sort` z opcją _unique_(`-u`).

![druga lista](https://user-images.githubusercontent.com/54263922/63973321-d3e8a100-caaa-11e9-9c1b-245a6d8ceda6.png)

Jeszcze lepszym sposobem na to byłoby wykorzystanie wyrażeń regularnych do naszego polecenia, przekierowując dane wyjściowe do pliku tekstowego, jak pokazano poniżej:

![list](https://user-images.githubusercontent.com/54263922/63973446-14481f00-caab-11e9-8faa-8438739224bb.png)

Teraz mamy przejrzystszą listę nazw domen połączonych z główną domeną `cisco.com`. Naszym następnym krokiem będzie użycie polecenia `host` dla każdej nazwy domeny w utworzonym pliku tekstowym, aby znaleźć odpowiedni adres IP. Możemy użyć pętli `for` w formie jednoliniowej, aby zrealizować automatyzację tego zadania.

![for](https://user-images.githubusercontent.com/54263922/63973490-27f38580-caab-11e9-9393-029a60e5f10b.png)

Polecenie `host` daje nam różnego rodzaju dane wyjściowe, jednak nie wszystkie są istotne. Chcemy wyodrębnić jedynie adresy IP spośród wszystkich informacji, więc kierujemy dane wyjściowe do polecenia `grep`. Poszukiwanym wyrażeniem jest `"has address"`, a następnie wycinamy i sortujemy dane wyjściowe.

![lista final](https://user-images.githubusercontent.com/54263922/64079594-8dcd5080-cce9-11e9-9a65-ae34716e4e24.png)

### 1.4.2 Praktyczne wykorzystanie Bash'a - przykład 2

Otrzymujemy plik logów serwera `HTTP Apache`, który zawiera dowody przeprowadzenia cyberataku. Naszym zadaniem jest użycie prostych poleceń Bash do sprawdzenia pliku i odkrycia różnych informacji, takich jak:
* kim byli atakujący
* co dokładnie wydarzyło się na serwerze.

Najpierw używamy poleceń `head` i `wc`, aby szybko zapoznać się ze strukturą pliku dziennika.

![head2](https://user-images.githubusercontent.com/54263922/63977798-fd0e2f00-cab4-11e9-8cfb-eeb9f82c37de.png)

Zauważmy, że struktura pliku logów jest przyjazna dla polecenia `grep`. Różne pola, takie jak: adres IP, znacznik czasu, żądanie HTTP itp. są oddzielone spacjami. Zaczynamy od przeszukiwania żądań HTTP wysyłanych do serwera, aby znaleźć wszystkie adresy IP zapisane w tym pliku logów. Będziemy przesyłać dane wyjściowe `cat` do poleceń `cut` i `sort`. Może to dać nam wskazówkę co do liczby potencjalnych napastników, z którymi będziemy musieli sobie poradzić.

![cat2](https://user-images.githubusercontent.com/54263922/63977829-144d1c80-cab5-11e9-9453-4b942ec20d3e.png)

Widzimy, że w pliku logów zapisano mniej niż dziesięć adresów IP, choć to wciąż nie mówi nam nic o atakujących. Następnie używamy poleceń `uniq` i `sort` w celu dalszego udoskonalenia naszych wyników i sortowania danych według liczby przypadków, w których każdy adres IP uzyskał dostęp do serwera.

![cat21](https://user-images.githubusercontent.com/54263922/63977850-275fec80-cab5-11e9-9dfa-a8f2796730bb.png)

Kilka adresów IP wyróżnia się, ale najpierw skupimy się na adresie, który ma najwyższą częstotliwość dostępu. Aby wyświetlić i policzyć zasoby żądane przez adres IP, można użyć następującej sekwencji poleceń:

![cut2](https://user-images.githubusercontent.com/54263922/63977884-43638e00-cab5-11e9-9da8-fabbf506ce19.png)

Z tego wyniku wydaje się, że adres IP `208.68.234.99` miał dostęp wyłącznie do katalogu `/admin`. Przyjrzyjmy się temu bliżej:

![final2](https://user-images.githubusercontent.com/54263922/63977900-52e2d700-cab5-11e9-811a-280a8b2aa030.png)

Wygląda na to, że `208.68.234.99` było zaangażowanych w próbę ataku typu `HTTP Brute Force` przeciwko temu serwerowi WWW. Co więcej, wygląda na to, że po około 1070 próbach atak zakończył się powodzeniem, na co wskazuje komunikat `HTTP 200 OK`.


#### Ćwiczenia do wykonania
<!-- `Wykonaj przykład pierwszy dla domeny` **`juniper.net`**.-->
1. Przygotuj skrypt Bash, aby zrealizować zadanie sprawdzające dostępność (aktywność) hostów IP wewnątrz podsieci, w której znajduje się także Twój host. Podpowiedzi:
  * Adresacja/konfiguracja sieciowa Twojego urządzenia jest uzyskiwana za pomocą komeny `ifconfig`
  * Aktywność hosta pod danym adresem IP realizowana jest polecenim `ping <adres IP>` (podstawowa wersja, w wersji rozszerzonej mamy `ping <opcje> <adres IP>` , gdzie `<opcje>` służą do modyfikacji wysyłanych żądań)
  * Automatyzacja powtarzalnego zadania realizowana jest za pomocą pętli np. `for`
  * Kolejne wartości (sekwencja) można otrzymać z za pomoca polecenia `seq`

## 1.5 Podsłuchiwanie ruchu sieciowego

Jednym z zagrożeń w sieciach jest podsłuchiwanie ruchu sieciowego i wyciąganie z niego istotnych dla atakującego informacji takich jak: loginy, hasła, prywatne dane itp. Zdarza się też, że atakujący stara się utrudniać lub uniemożliwiać pracę atakowanego serwera np. poprzez blokadę ruchu, rozsyłanie szkodliwych pakietów, tworzenie nadmiernego ruchu sieciowego, wykorzystywanie błędów w zabezpieczeniach serwerów poprzez wstrzykiwanie złośliwych danych (np. SQL Injection) lub przeciążenia serwera - atak typu Denial of Service (DoS).

Podczas podsłuchiwania atakujący monitoruje ruch w sieci, który jest przesyłany przez jego interfejs sieciowy, odczytując w ten sposób nieswoje pakiety. Używa się do tego programów zwanych snifferami. W naszym przypadku skupimy się na dwóch najbardziej popularnych: `Wireshark` i `tcpdump` znajdujących się domyślnie w systemie operacyjnych Kali Linux.

Z punktu widzenia specjalistów cyberbezpieczeństwa podsłuch ruchu sieciowego służy do:
* odkrywania słabych punktów, niezapezpieczionych połączeń i danych, błędnych konfiguracji w ramach badań bezpieczeństwa systemów, aplikacji i infrastruktury (*security assessment*)
* weryfikacjia konfiguracji połączeń oraz ustawień urządzeń sieciowych, w tym urządzeń *security*, takie jak firewalle
* diagnozowanie problemów
* monitorowania pasywnego i wykorzystywania zebranych logów (zrzutów ruchu sieciowego) do odkrywania wykonywania się ataków czy anomalii sugerujących np. zaszycie się atakującego w naszej sieci. 

### 1.5.1 Wireshark

Korzystania z sieciowego snifera pakietów jest bardzo ważne w codziennych operacjach specjalistów cyberbezpieczeństwa - ofensywnych i defensywnych. Niezależnie od tego, czy próbujesz zrozumieć protokół, debugować klienta sieciowego, czy analizować ruch, zawsze będziesz potrzebować sniffera.

#### 1.5.1.1 Podstawy

Wireshark korzysta z bibliotek `libpcap` (w systemie Linux) lub `winpcap` (w systemie Windows) w celu przechwytywania pakietów z sieci. Jeśli użytkownik zastosuje filtry przechwytywania (*capture  filters*) dla sesji Wireshark, przefiltrowane pakiety zostaną odrzucone i tylko odpowiednie dane zostaną przekazane do silnika przechwytywania. Mechanizm przechwytywania analizuje przychodzące pakiety, a następnie stosuje dodatkowe filtry wyświetlania(*display  filters*) przed wyświetleniem danych wyjściowych użytkownikowi. Sekret używania snifferów sieciowych, takich jak `Wireshark`, polega na użyciu filtrów przechwytywania i wyświetlania w celu usunięcia wszystkich informacji, które Cię nie interesują. 

![wireshark1a](https://user-images.githubusercontent.com/54263922/64068360-67e77380-cc37-11e9-9466-6e1b9a455635.png)
![wireshark1b](https://user-images.githubusercontent.com/54263922/64068222-66b54700-cc35-11e9-9cf5-01463ba3cc0c.png)


#### 1.5.1.2 Analizowanie zrzutów ruchu sieciowego

Przeanalizujmy zrzut ruchu sieciowego w pliku w formacie `pcap` wykonanego podczas przeglądania strony `www.yahoo.com`.

![wireshark2](https://user-images.githubusercontent.com/54263922/64068382-b137c300-cc37-11e9-8345-85d299c4a37d.png)

| Numer pakietu   |      Objaśnienie      |
|----------|:-------------:|
| 1 | Brodcast `ARP` do domyślnej bramy |
| 2 | Odpowiedź unicast `ARP` zawierajaca adres MAC bramy |
| 3 | `DNS A` (`IPv4`) wyszukiwanie wprzód dla yahoo.com |
| 4 | `DNS AAAA` (`IPv`) zapytanie wyszukiwania wprzód |
| 5 | `DNS A` uzyskanie odpowiedzi |
| 6 | `DNS AAAA` uzyskanie odpowiedzi |
| 7-9 | Uzgadnianie sesji `TCP` z portem 80 `yahoo.com` |
| 10 | Początkowa negocjacja protokołu w `HTTP`. Wysłąnie zapytania `GET` |


#### 1.5.1.3 Filtry przechwytywania i wyświetlania

Zrzuty przechwytywania rzadko są tak wyraźne, jak w powyższym przykładzie, ponieważ w sieci zwykle występuje duży ruch tła. Różne transmisje, różne usługi sieciowe i inne działające aplikacje utrudniają analizę ruchu. W tym miejscu pomagają filtry przechwytywania (*capture  filters*), które mogą odfiltrować nieistotny ruch jeszcze przed wykonaniem zrzutu. Filtry te znacznie pomagają w określeniu pożądanego ruchu i zmniejszeniu niepożądanego do momentu, w którym możemy bez problemu rozumieć pojawiające się pakiety.

![wireshark3](https://user-images.githubusercontent.com/54263922/64068614-c5c98a80-cc3a-11e9-9b22-c7cbaf9314a6.png)

Po przechwyceniu ruchu możemy wybrać ruch, który `Wireshark` ma nam wyświetlać za pomocą filtrów wyświetlania (*display  filters*). Poniższy zrzut ekranu pokazuje filtr wyświetlania `arp` zastosowany do naszej sesji przeglądania `yahoo.com`.

![wireshark4](https://user-images.githubusercontent.com/54263922/64068556-04127a00-cc3a-11e9-8ed8-7207791f5bea.png)

#### 1.5.1.4 Śledzenie strumienia TCP

Często zdarza się, że pojedyncze pakiety z analizowanego ruchu sieciowego są trudne do zrozumienia, ponieważ zawierają tylko fragment informacji z całego strumienia do którego należą. Większość dostępnych snifferów, w tym Wireshark umie złożyć pojedyncze pakiety w konkrete sesje i wyświetlić ją w różnych formatach. Aby wyświetlić konkretny strumień `TCP`, kliknij PPM interesujący Cię pakiet, a następnie wybierz "Podążaj (Follow)" i "Strumień TCP" (Follow TCP Stream) z menu kontekstowego. Strumień TCP otworzy nowe okno, jak pokazano poniżej.

![wireshark5](https://user-images.githubusercontent.com/54263922/64068682-cdd5fa00-cc3b-11e9-9fe7-dafa2c6b581d.png)

#### Ćwiczenia do wykonania

1. Użyj Wireshark do przechwycenia aktywności sieci podczas próby logowania na swoją uczelnianą skrzynkę pocztową.<!--2. `Przeczytaj i zrozum wyniki. W którym momencie następuje uzgodnienie sesji TCP ? W którym momencie sesja jest zamykana (sekwencja flag TCP: FIN (klient), FIN+ACK (serwer), FIN (serwer), FIN+ACK(klient) w kolejnych segmentach)?`-->
2. W strumieniu TCP odnajdź sekwencję logowania.
3. Użyj filtra wyświetlania, aby zobaczyć tylko ruch na porcie 443
4. Uruchom ponownie przechwytywanie, tym razem za pomocą filtra przechwytywania, aby zebrać tylko port 443. 


### 1.5.2 Tcpdump

Czasami możemy nie mieć dostępu do graficznych interfejsów snifferów sieciowych, takich jak `Wireshark`. W takich przypadkach możemy użyć narzędzia `tcpdump` z wiersza poleceń. `tcpdump` jest jednym z najpopularniejszych analizatorów pakietów wiersza poleceń i można go znaleźć w większości systemów operacyjnych Linux. `tcpdump` może przechwytywać pliki z sieci lub czytać istniejące pliki przechwytywania. Spójrzmy na to, co się stało w pliku `pcap` **password_cracking_filtered** (https://www.offensive-security.com/pwk-online/password_cracking_filtered.pcap), który został pobrany na zaporze ogniowej (*firewall*).

![tcpdump1](https://user-images.githubusercontent.com/54263922/64076803-c2c9ab00-ccc9-11e9-956c-b003828aff1a.png)

#### 1.5.2.1 Filtrowanie ruchu

Dane wyjściowe są początkowo nieco przytłaczające, dlatego spróbujmy lepiej zrozumieć adresy IP i porty, używając poleceń `awk` i `sort`.

![tcpdump2](https://user-images.githubusercontent.com/54263922/64076842-500cff80-ccca-11e9-83bc-916857df1120.png)


Wygląda na to, że `208.68.234.99` wysłało wiele żądań do `172.16.40.10` na porcie 81. Możemy łatwo filtrować na podstawie adresu IP docelowego lub źródłowych i portów z wykorzystaniem składni podobnej do następującej:

![tcpdump3](https://user-images.githubusercontent.com/54263922/64076894-e9d4ac80-ccca-11e9-8754-e2af2e95ba34.png)


Zacznijmy od analizy ruchu przechwyconego w pliku zrzutu, w formacie szesnastkowym, aby sprawdzić, czy możemy uzyskać dodatkowe informacje z przesłanych danych:


![tcpdump4](https://user-images.githubusercontent.com/54263922/64077467-155a9580-ccd1-11e9-9b04-57433c9e8654.png)

Natychmiast możemy zauważyć, że ruch do `172.16.40.10` na porcie 81 wygląda jak `HTTP`. Co więcej, wygląda na to, że te żądania `HTTP` zawierają podstawowe dane uwierzytelniające z nagłówkiem `HTTP User-Agent: "Teh Forest Lobster"`.


#### 1.5.2.2 Zaawansowane filtrowanie nagłówków

`tcpdump` ma kilka zaawansowanych opcji filtrowania nagłówków, które mogą nam pomóc w naszej analizie pcap. Chcielibyśmy odfiltrować i wyświetlić tylko te zrzuty danych, które mają włączone flagi PSH i ACK. Jak widać na poniższym diagramie, flagi `TCP` są zdefiniowane w 14-stym bajcie nagłówka `TCP`.

![tcpdump5](https://user-images.githubusercontent.com/54263922/64077710-39b77180-ccd3-11e9-8fa9-e05de3abf89b.png)

Aby określić właściwy filtr do użycia, włączamy bity dla konkretnych flag, których potrzebujemy, w tym przykładzie flagi ACK i PSH:

![tcpdump6](https://user-images.githubusercontent.com/54263922/64077737-80a56700-ccd3-11e9-8ceb-f41d42d68993.png)


Nasze polecenie wyglądałoby podobnie do następującego - podając, że czternasty bajt w wyświetlanych pakietach powinien mieć ustawione flagi ACK lub PSH:

![tcpdump7](https://user-images.githubusercontent.com/54263922/64077942-77b59500-ccd5-11e9-8589-48ba32aaeef2.png)

Odtąd historia staje się jaśniejsza. Widzimy znaczną liczbę nieudanych prób uwierzytelnienia w katalogu `/admin`, na które wysłano odpowiedzami HTTP 401, podczas gdy ostatnia próba zalogowania się do katalogu `/admin` wydaje się być udana, ponieważ serwer odpowiedział odpowiedzią HTTP 301 .

#### Ćwiczenia do wykonania

<!--1. `Wykorzystaj narzędzie tcpdump, aby odtworzyć ćwiczenia wykonane dla Wireshark'a.`-->
1. Przećwicz działanie tcpdumpa zgodnie z punktem 1.5.2
2. Użyj flagi -X, aby wyświetlić zawartość pakietu. Jeśli dane są obcięte, sprawdź, w jaki sposób flaga --s może pomóc. 

# 2. Cyberbezpieczeństwo ofensywne - podstawy testów penetracyjnych

## 2.1 O testach penetracyjnych

Testy penetracyjne (*pentesty*) stanowią podstawę współcześnie określanego cyberbezpieczeństwa ofensywnego. Stanowią ciągły cykl sprawdzania podatności (*vulnerability assessments*), ataków na cel (*targeting*) i prób wykorzystania podatności (*exploiting*). Najczęściej proces taki trwa określony czas, więc należy utrzymywać dostęp do testowanych środowisk (*backdoors*). Odpowiada to także modelowi Cyber Kill Chain, w którym pojedyncza operacja testu penetracyjnego symuluje wykonanie każdego z etapów Cyber Kill Chain po kolei. Rezultatem testów penetracyjnych ma być ocena bieżącego stanu systemów, aplikacji i infrastruktury Zamawiającego (w określonym z nim zakresie i zgodnie z umową). Wiąże się to także często z szerszym pojęciem badań bezpieczeństwa (*security assessments*), dla których testy penetracyjne mogą stanowić jeden z etapów, który ma wyznaczyć dziury w systemach i pozwola oszacować ryzyko zagrożeń cyberbezpieczeństwa.

Ataki powinny być ustrukturyzowane i obliczone na cel, a jeśli to możliwe, zweryfikowany w laboratorium przed wdrożeniem go na żywym celu. Oto jak wizualizujemy proces testu penetracyjnego:

![Bez tytułu 1](https://user-images.githubusercontent.com/54263922/63640597-3a805000-c6a2-11e9-8879-d7c503e35e8c.png)

Jak sugeruje model, im więcej informacji zbierzemy, tym większe prawdopodobieństwo udanego ataku. Po przekroczeniu początkowej granicy celu zwykle rozpoczynamy cykl ponownie - na przykład zbierając informacje o sieci wewnętrznej w celu jej głębszej penetracji. 
To w jaki sposób przeprowadzać dane etapy zależy od przyjętej metodologii. Istnieje kilka metodologii przeprowadzania testów bezpieczeństwa (np. OWASP czy OSSTMM) jednak specjaliści ds. bezpieczeństwa opracowują często dedykowane metodologie - na własny użytek, na potrzeby Klienta, wykorzystując w nich istniejące standardy.

## 2.2 Rekonesans

Rekonesans jest pierwszym etapem testu penetracyjnego. Jego celem jest nieagresywne zbieranie informacji (czyli takie, które nie powoduje naruszeń polityki bezpieczeństwa) na temat badanej organizacji.

Zbieranie informacji można może być realizowane na dwa sposoby: aktywny i pasywny. Aktywne zbieranie informacji ma miejsce podczas wprowadzania ruchu sieciowego do sieci organizacji podlegającej badaniu. Innymi słowy oznacza to aktywne bezpośrednie oddziaływanie na sieć badanej organizacji, co już same w sobie może być uznane jako atak hakerski. W przypadku techniki pasywnej, informacje są gromadzone poprzez wykorzystanie usług firm trzecich, takich jak np. różne wyszukiwarki, m.in. Google. Podczas pasywnego rozpoznania nie są wysłane dane do systemów docelowych. Źródłem wiedzy potencjalnego napastnika są ogólnodostępne zasoby. Określa się to także mianiem *OSINT* - **o**pen-**s**ource **int**elligence.

## 2.3 Pasywne zbieranie informacji

Pasywne zbieranie informacji to proces gromadzenia informacji o celach za pomocą publicznie dostępnych informacji. Może to obejmować usługi takie jak wyniki wyszukiwania, informacje Whois, informacje pochodzące z usług, informacje o spółkach publicznych itp. Innymi słowy, czynność gromadzenia informacji o celu bez bezpośredniej komunikacji z nimi można uznać za "pasywny". Im więcej informacji uda nam się zebrać na temat naszego celu przed atakiem, tym większe prawdopodobieństwo, że odniesiemy sukces.

Dobrym przykładem pasywnego gromadzenia informacji jest przypadek podczas testu penetracyjnego w małej firmie kilka lat temu. Firma ta praktycznie nie była obecna w Internecie i miała mało zewnętrznych usług, które okazały się bezpieczne. Po wielu godzianch przeszukiwania Google w końcu udało się znaleźć post na forum kolekcjonerów znaczków napisany przez jednego z pracowników:

![pg1](https://user-images.githubusercontent.com/54263922/64077981-0b876100-ccd6-11e9-8b7e-27fa5224c8ad.png)

To były wszystkie informacje, które były potrzebne, aby przeprowadzić częściowo zaawansowany atak po stronie klienta. Szybko zarejestrowano domenę, taką jak `rare-stamps-trade.com`  i zaprojektowano stronę docelową, która wyświetlała różne rzadkie znaczki z lat 50. XX wieku, które można znaleźć za pomocą wyszukiwarki grafiki Google. Zarówno nazwa domeny, jak i projekt strony doprowadziły do zwiększenia postrzeganej wiarygodności strony internetowej z znaczkami. Następnie przystąpiono do osadzania złośliwego kodu HTML w kodzie witryny, zawierającego kod wykorzystujący najnowszą lukę w zabezpieczeniach programu Internet Explorer (w tym czasie MS05-001) i zadzwoniono do Davida na jego telefon komórkowy. Powiedziano mu, że dziadek atakującego dał mu ogromną kolekcję rzadkich znaczków, z której możliwa jest wymiana kilku znaczków. Zadbano o to, aby zadzwonić w ciągu dnia roboczego, aby zwiększyć szanse atakującego na dotarcie do Davida w biurze. David był bardzo szczęśliwy, że otrzymał takie wezwanie i bez wahania odwiedził złośliwą stronę internetową, aby zobaczyć „znaczki”, które atakujący miał do zaoferowania. Podczas przeglądania strony kod exploita na stronie internetowej pobrał i wykonał "ładunek podobny do Netcata" na swojej lokalnej maszynie, odsyłując atakującemyu powłokę zwrotną (*reverse shell*). 
Jest to dobry przykład tego, jak niektóre nieszkodliwe informacje, takie jak pracownik łączący swoje życie osobiste z firmową pocztą e-mail, mogą doprowadzić do udanego ataku. Ponadto przedstawiony przykład to praktyczne zastosowanie technik inżynierii społecznej - *spear phishing* - na etapie rekonesansu oraz dostarczenia narzędzi ataku do celu (*Delivery* - *Cyber Kill Chain*). Opisany sposób oszukiwania ludzi i w ten sposób dostarczanie złośliwych aplikacji do organizacji stanowi jeden z największych problemów współczesnych systemów teleinformatycznych i komputerowych.

Zbieranie iformacji jest najważniejszym etapem testu penetracyjnego. Znajomość celu przed atakiem to sprawdzony przepis na sukces. Nawet przyziemne posty na forum mogą dostarczyć przydatnych informacji.

### 2.3.1 Zbieranie informacji dostępnych w Internecie

Na początku pozyskiwania informacji najpierw poświęcić trochę czasu na przeglądanie sieci, szukając dodatkowych informacji o organizacji docelowej. Czym się zajmuje? Jak wygląda punkt styky ze swiatem? Czy mają dział sprzedaży? Czy sami zatrudniają? Przeglądaj witrynę organizacji i poszukaj ogólnych informacji, takich jak dane kontaktowe, numery telefonu i faksu, e-maile, struktura firmy i tak dalej. Pamiętaj też, aby poszukać witryn, które prowadzą do strony docelowej lub e-maili firmowych krążących się w Internecie. Czasami są to najdrobniejsze szczegóły, które dają najwięcej informacji: jak dobrze zaprojektowana jest docelowa witryna? Jak czysty jest ich kod HTML? Może to dać wskazówkę co do ich budżetu na tworzenie stron internetowych, co może wpłynąć na budżet bezpieczeństwa.

#### 2.3.1.1 Enumeracja z Google

Wyszukiwarka Google jest najlepszym przyjacielem audytora bezpieczeństwa, szczególnie jeśli chodzi o zbieranie informacji.

oogle obsługuje korzystanie z różnych operatorów wyszukiwania, które pozwalają użytkownikowi zawęzić i wskazać wyniki wyszukiwania. Na przykład operator **site** ograniczy wyniki wyszukiwania Google do jednej domeny. Prosty operator wyszukiwania taki jak ten dostarcza nam przydatnych informacji. Powiedzmy na przykład, że chcemy poznać przybliżoną obecność organizacji w sieci przed rozpoczęciem zaangażowania.

![google1](https://user-images.githubusercontent.com/54263922/64068722-391fcc00-cc3c-11e9-82e3-6a6552ebe159.png)

W powyższym przykładzie użyliśmy parametru **site**, aby ograniczyć wyniki wyświetlane przez Google tylko do domeny _microsoft.com_. Tego dnia Google zaindeksował około 67 milionów stron z domeny _microsoft.com_. Zauważ, że większość wyników, które do nas wracają, pochodzi z subdomeny www.microsoft.com. Odfiltrujmy je, aby zobaczyć, jakie inne subdomeny mogą istnieć na _microsoft.com_.

![google2](https://user-images.githubusercontent.com/54263922/64068737-8603a280-cc3c-11e9-9388-3a36bbcee47f.png)

Te dwa proste zapytania ujawniły sporo podstawowych informacji o domenie _microsoft.com_, takich jak daned na temat ich obecności w Internecie i lista ich poddomen dostępnych w Internecie.
Oczywiście to tylko jeden operator wyszukiwania, a jest ich znacznie więcej. Przykładami innych operatorów wyszukiwania są **filetype**,  **inurl** i **intitle** . Na przykład wspólny system wideo w serwerowni ma następującą stronę domyślną.

![google3](https://user-images.githubusercontent.com/54263922/64068755-d418a600-cc3c-11e9-86dc-5a3ad8781596.png)

Zwróć uwagę, w jaki sposób to urządzenie wideo zapewnia unikalny ozbaczenie tytułu - urządzenie Netbotz, a także numer modelu. Za pomocą kilku prostych wyszukiwań w Google możemy zawęzić wyniki wyszukiwania, tak aby obejmowały tylko te urządzenia.

![google4](https://user-images.githubusercontent.com/54263922/64068874-bba98b00-cc3e-11e9-9015-2e4d571f3118.png)

Przykłady specyficzne dla produktu, takie jak te, są z natury dynamiczne i mogą nie dać żadnych wyników dla tego konkretnego urządzenia w ciągu najbliższych kilku miesięcy. Jednak koncepcja tego typu wyszukiwań jest taka sama. Jeśli wiesz, jak efektywnie korzystać z operatorów wyszukiwania Google i wiesz dokładnie, czego szukasz, możesz znaleźć prawie wszystko.

#### 2.3.1.2 Google Hacking

Używanie Google do znajdowania ciekawych informacji, luk w zabezpieczeniach lub źle skonfigurowanych witryn zostało publicznie wprowadzone przez Johnny'ego Longa w 2001 roku. Od tego czasu opracowano bazę danych interesujących wyszukiwań, aby umożliwić audytorom bezpieczeństwa (i hakerom) szybkie wykrycie licznych nieprawidłowych konfiguracji w obrębie danej domeny. Kolejne zrzuty ekranu pokazują takie wyszukiwania.

##### 2.3.1.2.1 Sprzęt ze znanymi podatnściami
![google5](https://user-images.githubusercontent.com/54263922/64068889-48544900-cc3f-11e9-96d4-462fe3eb71bc.png)

##### 2.3.1.2.2 Dostępne z sieci routery Cisco
![google6](https://user-images.githubusercontent.com/54263922/64068942-10013a80-cc40-11e9-9935-a6e8c1fc4a15.png)

##### 2.3.1.2.3 Ujawnione pośwadczenia do logowania
![google7](https://user-images.githubusercontent.com/54263922/64068981-c2d19880-cc40-11e9-8def-b3ec6abd2795.png)

Istnieją setki ciekawych wyszukiwań, z których wiele można znaleźć w bazie Google Hacking (GHDB)

![google8](https://user-images.githubusercontent.com/54263922/64068994-0a582480-cc41-11e9-9495-b45b5b674f69.png)

<!--#### Ćwiczenia do wykonania
1. `Wybierz organizację i użyj Google, aby zebrać jak najwięcej informacji na jej temat`
2. `Skorzystaj z operatora` **`filetype`** `i poszukaj interesujących dokumentów pochodzenia wybranej organizacji w punkcie 1.`
3. `Ponownie wykonaj ćwiczenie w domenie Politechniki Warszawskiej. Czy możesz znaleźć wyciek danych, o którym nie wiedziałeś?`-->

#### 2.3.1.2 Pozyskiwanie e-mail

Zbieranie wiadomości e-mail to skuteczny sposób znajdowania wiadomości e-mail i ewentualnie nazw użytkowników należących do organizacji. Wiadomości e-mail są przydatne na wiele sposobów, na przykład dostarczając nam potencjalną listę ataków po stronie klienta, ujawniając konwencję nazewnictwa używaną w organizacji lub mapując użytkowników w organizacji. Jednym z narzędzi w Kali Linux, które może wykonać to zadanie, jest **theharvester**. Narzędzie to może wyszukiwać adresy e-mail w Google, Bing i innych witrynach, korzystając ze składni przedstawionej poniżej

![theharv](https://user-images.githubusercontent.com/54263922/64078212-04f9e900-ccd8-11e9-847e-0070cc67fe6a.png)


##### 2.3.1.2.1 Ćwiczenia do wykonania

1.Użyj **theharvester**, aby wylistować adresy e-mail należące do organizacji wybranej w poprzednich ćwiczeniach.
2. Eksperymentuj z różnymi źródłami danych (**-b**). Która jest dla Ciebie najlepsze?

#### 2.3.1.3 Enumeracja za pomocą Whois

Whois to nazwa usługi TCP, narzędzia i rodzaju bazy danych. Bazy danych Whois zawierają serwer nazw, rejestr oraz, w niektórych przypadkach, pełne dane kontaktowe dotyczące nazwy domeny. Każdy rejestr musi prowadzić bazę danych Whois zawierającą wszystkie dane kontaktowe dla domen, które prowadzą. Centralna baza danych Whois rejestru jest prowadzona przez InterNIC. Te bazy danych są zwykle publikowane przez serwer Whois za pośrednictwem portu TCP 43 i są dostępne za pomocą programu klienta **whois**.

![whois1](https://user-images.githubusercontent.com/54263922/64078169-94eb6300-ccd7-11e9-8a4f-91656a50d819.png)

Klient Whois może także wykonywać wyszukiwania odwrotne. Zamiast wpisywać nazwę domeny, możesz podać adres IP, jak pokazano poniżej:

![whois2](https://user-images.githubusercontent.com/54263922/64078248-6de16100-ccd8-11e9-9f2b-d04777758e0e.png)


Zwróć uwagę, w jaki sposób rejestr i dostawca hostingu są pokazani w wynikach zapytań Whois.

<!--#### Ćwiczenia do wykonania

1. `Za pomocą narzędzia` **`whois`** `systemu operacyjnego Kali Linux zidentyfikuj nazwy serwerów Politechniki Warszawskiej.`-->

#### 2.3.1.4 Recon-ng

`Recon-ng` to w pełni funkcjonalny program do rozpoznawania stron internetowych napisany w języku Python. W połączeniu z niezależnymi modułami, interakcją z bazą danych, interaktywną pomocą i uzupełnianiem poleceń, Recon-ng zapewnia potężne środowisko, w którym rozpoznanie oparte na sieci open source może być przeprowadzone szybko i dokładnie. Recon-ng wygląda podobnie do Metasploit Framework. Zaczniemy od użycia modułu `whois_poc`, aby wymyślić nazwiska pracowników i adresy e-mail w Cisco.

![rec](https://user-images.githubusercontent.com/54263922/64078322-9ddd3400-ccd9-11e9-970c-b01e51f0c31b.png)


Następnie możemy użyć `recon-ng` do wyszukiwania źródeł, takich jak `xssed`, w poszukiwaniu istniejących luk w zabezpieczeniach XSS, które zostały zgłoszone, ale jeszcze nie zostały naprawione, w domenie cisco.com.

![rec2](https://user-images.githubusercontent.com/54263922/64078365-04625200-ccda-11e9-9459-a669828df399.png)

Możemy również użyć modułu `google_site`, aby wyszukać dodatkowe subdomeny cisco.com za pośrednictwem wyszukiwarki Google.

![rec3](https://user-images.githubusercontent.com/54263922/64078403-6c189d00-ccda-11e9-8574-ee421f7bfda7.png)


Innym przydatnym przykładem jest moduł `ip_neighbour`, który próbuje wykryć sąsiednie adresy IP domeny docelowej, ewentualnie odkrywając inne domeny w tym procesie.

![rec4](https://user-images.githubusercontent.com/54263922/64078427-d3cee800-ccda-11e9-8ce3-d59ed9f39ef9.png)

#### Ćwiczenia do wykonania

1. Za pomocą narzędzia `recon-ng` systemu operacyjnego Kali Linux sprawdź czego możesz się dowiedzieć o domenie `www.pw.edu.pl` w kontekście omówionych modułów.

## 2.4 Aktywne zbieranie informacji

Po zebraniu wystarczającej ilości informacji o celu, z wykorzystaniem otwartych zasobów internetowych i innych pasywnych technik gromadzenia informacji, możesz dalej zbierać odpowiednie informacje z innych, bardziej szczegółowych źródeł.

### 2.4.1 Enumeracja DNS

System DNS (*Domain Name System*) jest jednym z częstych źródeł aktywnego gromadzenia informacji. DNS oferuje wiele informacji na temat publicznych (a czasem prywatnych!) serwerów organizacji, takich jak adresy IP, nazwy serwerów czy ich funkcje.

#### 2.4.1.1 Interakcja z serwerem DNS

Serwer DNS zwykle ujawnia informacje o DNS i serwerze poczty dla domeny, nad którą ma uprawnienia. Jest to konieczne, ponieważ publiczne żądania poczty i adresów serwerów DNS stanowią podstawową funkcjonalność Internetu. Na przykład przyjrzyjmy się domenie `megacorpone.com`, fałszywej domenie w Internecie, którą stworzyliśmy na potrzeby tego ćwiczenia. Użyjemy polecenia `host` wraz z parametrem `–t` (*typ*), aby wykryć zarówno DNS, jak i serwery poczty dla domeny `megacorpone.com`.

![dns1](https://user-images.githubusercontent.com/54263922/64078794-6ec9c100-ccdf-11e9-8377-85223a578139.png)

Domyślnie każda skonfigurowana domena powinna zapewniać przynajmniej DNS i serwery poczty odpowiedzialne za domenę.

#### 2.4.1.2 Automatyzacja wyszukiwania

Teraz, gdy mamy pewne wstępne dane z domeny `megacorpone.com`, możemy nadal korzystać z dodatkowych zapytań DNS, aby znaleźć więcej nazw hostów i adresów IP należących do megacorpone.com. Na przykład możemy założyć, że domena megacorpone.com ma serwer WWW, prawdopodobnie o nazwie hosta www. Możemy przetestować tę teorię za pomocą polecenia `host` jeszcze raz:

![dns2](https://user-images.githubusercontent.com/54263922/64078805-af293f00-ccdf-11e9-9b26-9dafe4399dde.png)

Teraz sprawdźmy, czy `megacorpone.com` ma również serwer z nazwą hosta _idontexist_. Zwróć uwagę na różnicę między wynikami zapytania.

![dns3](https://user-images.githubusercontent.com/54263922/64078818-ec8dcc80-ccdf-11e9-9914-b1ed18aab870.png)


#### 2.4.1.3 Brute force *wyszukiwania wprzód*

Kontynuując poprzednią koncepcję, możemy zautomatyzować wyszukiwanie wprzód DNS dla popularnych nazw hostów za pomocą polecenia `host` i skryptu Bash. Ideą tej techniki jest odgadnięcie prawidłowych nazw serwerów, próbując rozwiązać daną nazwę. Jeśli nazwa, którą odgadłeś, rozwiązuje się (pozytywne odpowiedzi z DNS), wyniki mogą wskazywać na obecność, a nawet funkcjonalność serwera. Możemy utworzyć krótką (lub długą) listę możliwych nazw hostów i zapętlić polecenie `host`, aby wypróbować każdą z nich.

![dns5](https://user-images.githubusercontent.com/54263922/64078862-8a819700-cce0-11e9-9696-006491076700.png)

W tym uproszczonym przykładzie zauważamy, że nazwy hostów `www`, `router` i `mail` zostały odkryte w wyniku tego ataku siłowego. Nazwy hostów `owa`, `ftp` i `proxy` nie zostały jednak znalezione.

#### 2.4.1.4 Brute force *wyszukiwania w tył*

Wyszukiwanie wwprzód DNS ujawniło zestaw rozproszonych adresów IP. Jeśli administrator DNS `megacorpone.com` skonfigurował rekordy PTR dla domeny, moglibyśmy znaleźć więcej nazw domen, które zostały pominięte podczas fazy *brute force* wyszukiwania do przodu, sprawdzając zakres tych znalezionych adresów w pętli.

![dns6](https://user-images.githubusercontent.com/54263922/64078903-e9dfa700-cce0-11e9-8577-daf9bc980586.png)

#### 2.4.1.5 Transfer stref DNS

Transfer strefy jest podobny do czynności replikacji bazy danych między powiązanymi serwerami DNS. Proces ten obejmuje kopiowanie pliku strefy z głównego serwera DNS na serwer podrzędny. Plik strefy zawiera listę wszystkich nazw DNS skonfigurowanych dla tej strefy. Transfery stref powinny zwykle ograniczać się do autoryzowanych podrzędnych serwerów DNS. Niestety wielu administratorów źle konfiguruje swoje serwery DNS, w wyniku czego każdy, kto poprosi o kopię strefy serwera DNS, otrzyma taki serwer. Jest to równoważne z przekazaniem bezpośrednio hakerowi układu sieci korporacyjnej. Wiele organizacji posiada serwery DNS które są źle skonfigurowane:
* nie podzielono wewnętrznej przestrzeni nazw DNS i zewnętrznej przestrzeni nazw DNS na osobne
* występują niepowiązane strefy

W wyniku tego powstaje kompletny obraz struktury sieciowej organzacji. Pomyślne przesłanie strefy nie powoduje bezpośrednio naruszenia sieci. Ułatwia to jednak proces. Składnia polecenia `host` służąca do wstępnego wykonania transferu strefy jest następująca. 

![dns7](https://user-images.githubusercontent.com/54263922/64078927-35925080-cce1-11e9-9f16-b1aadc12891e.png)


Z naszego poprzedniego polecenia `host` zauważyliśmy, że dwa serwery DNS obsługują domenę `megacorpone.com`: ns1 i ns2. Spróbujmy przenieść strefę na każdym z nich.

![dns8](https://user-images.githubusercontent.com/54263922/64079009-324b9480-cce2-11e9-833c-b8739e3f501b.png)


W tym przypadku _ns1_ odrzucił nam naszą prośbę o przeniesienie strefy, podczas gdy _ns2_ na to zezwolił. Rezultatem jest pełny zrzut pliku strefy dla domeny `megacorpone.com`, zapewniający nam wygodną listę adresów IP i nazw DNS dla domeny `megacorpone.com`. Domena `megacorpone.com` ma tylko dwa serwery DNS do sprawdzenia. Jednak niektóre większe organizacje mogą mieć wiele serwerów DNS lub możesz próbować przesłać żądania strefy dla danej domeny. Tutaj zaczyna się gra skryptów Bash. Aby wykonać transfer strefy za pomocą polecenia `host`, potrzebujemy dwóch parametrów: analizowanej nazwy domeny i adresu serwera nazw. Aby uzyskać serwery nazw dla danej domeny w czystym formacie, możemy wydać następujące polecenie.

![dns9](https://user-images.githubusercontent.com/54263922/64079025-8191c500-cce2-11e9-91c1-5d35223a2c10.png)

Idąc krok dalej, możemy napisać następujący prosty skrypt Bash, aby zautomatyzować procedurę wykrywania i próby transferu strefy na każdym znalezionym serwerze DNS.

![dns10](https://user-images.githubusercontent.com/54263922/64079097-86a34400-cce3-11e9-9dac-fa4e8d0bd36e.png)

Uruchomienie tego skryptu na megacorpone.com powinno automatycznie zidentyfikować oba serwery nazw i podjąć próbę przeniesienia strefy na każdym z nich.

![dns11](https://user-images.githubusercontent.com/54263922/64079130-1517c580-cce4-11e9-939c-81d002abf062.png)

#### 2.4.1.6 Odpowiednie narzedzia w Kali Linux

W Kali Linux istnieje kilka narzędzi, które pomagają nam w enumeracji DNS, a większość z nich wykonuje te same zadania, które już omówiliśmy wcześniej. Dwa znaczące narzędzia to DNSrecon i DNSenum. Każde z tych narzędzi ma przydatne opcje. Poniższe wyniki pokazują użycie tych narzędzi przy minimalnych parametrach.

##### 2.4.1.6.1 DNSrecon

DNSRecon to zaawansowany, nowoczesny skrypt enumeracji DNS napisany w języku Python. Uruchomienie skryptu **dnsrecon** w domenie megacorpone.com daje następujące wyniki:

![dns12](https://user-images.githubusercontent.com/54263922/64079206-2ca37e00-cce5-11e9-8615-9777a8fe50db.png)


##### 2.4.1.6.2 DNSenum

DNSEnum to kolejne popularne narzędzie do wyliczania DNS. Uruchomienie tego skryptu w domenie **zonetransfer.me**, która w szczególności zezwala na transfery stref, daje następujące wyniki:

![dns13](https://user-images.githubusercontent.com/54263922/64079346-ccadd700-cce6-11e9-9dc5-c7a21cc3b8a2.png)


<!--#### Ćwiczenia do wykonania

1. `Znajdź serwery DNS dla domeny megacorpone.com`
2. `Napisz mały skrypt Bash, aby spróbować przenieść strefę z megacorpone.com`
3. `Użyj` **`dnsrecon`**`, aby spróbować przenieść strefę z megacorpone.com`-->
