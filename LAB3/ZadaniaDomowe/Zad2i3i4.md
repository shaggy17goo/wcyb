

## Zad 2
**Skanowanie sieci składające się z 3 hostów - Kali, Vulnix, Metasploitable**

Pierw wykonałem skanowanie ping, aby sprawdzić jakie adresy ip są aktywne w sieci
![ScanIsUp](https://user-images.githubusercontent.com/56591106/71308643-72ed2c00-23ff-11ea-85bc-dd2d295c649b.PNG)
 
Następnie wykonałem podstawowe skanowanie : sn-NoPortScan, Syn, Tcp
![sn](https://user-images.githubusercontent.com/56591106/71308638-6e287800-23ff-11ea-82a4-25669736251a.PNG)
![sS](https://user-images.githubusercontent.com/56591106/71308639-6ec10e80-23ff-11ea-88ec-215c414c8faa.PNG)
![sT](https://user-images.githubusercontent.com/56591106/71308665-afb92300-23ff-11ea-9eea-83a1a99a8942.PNG)

Później także przy użyciu nmapa spróbowałem określić systemy operacyjne hostów znajdujących się w sieci
![vulnix](https://user-images.githubusercontent.com/56591106/71308700-04f53480-2400-11ea-826c-6435b95ce49b.PNG)
![metasploitable](https://user-images.githubusercontent.com/56591106/71308703-06266180-2400-11ea-92f7-14591c7821a0.PNG)

## Zad 3
**Skanowanie podatności hostów Vulnix i Metasploitable**

Vulnix
![VulnixNessus](https://user-images.githubusercontent.com/56591106/71308720-3b32b400-2400-11ea-8c0d-6cfed52e1f2d.PNG)
![VulnixOV](https://user-images.githubusercontent.com/56591106/71308721-3b32b400-2400-11ea-94e7-d6b7edc47bed.PNG)

Metasploitable
![MetasploitableNessus](https://user-images.githubusercontent.com/56591106/71308727-48e83980-2400-11ea-956d-e1795d83504b.PNG)
![MetasploitableOV](https://user-images.githubusercontent.com/56591106/71308728-4980d000-2400-11ea-9d05-26884cb9fc96.PNG)


## Zad 4
**Użycie narzędzia metasploit**

Wykorzystując podatność wykazaną podczas skanowanie hosta Metasploitable przy użyciu narzędzie OpenVas, wstrzyknąłem payoad z meterpreterem
![meterpreter1](https://user-images.githubusercontent.com/56591106/71308800-391d2500-2401-11ea-8b5b-5c76f5f05f66.PNG)
![meterpreter2](https://user-images.githubusercontent.com/56591106/71308801-391d2500-2401-11ea-9fe5-0bb46c26ff20.PNG)
![meterpreter3](https://user-images.githubusercontent.com/56591106/71308980-e5abd680-2402-11ea-88ab-c1a49673772b.PNG)

Wylistowanie użytkowników SMTP hosta vulnix
![SMTPusers](https://user-images.githubusercontent.com/56591106/71308995-29064500-2403-11ea-876b-6203f3bdf76d.PNG)

Hasło dla użytkownika user Vulnix
![vulnixPassword](https://user-images.githubusercontent.com/56591106/71309005-46d3aa00-2403-11ea-9536-d38eac67dc32.PNG)
