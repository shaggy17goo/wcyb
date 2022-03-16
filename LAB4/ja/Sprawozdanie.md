    
# Michał Wawrzyńczak
## Zadanie 1

**Pierw postawiłem wirtualne maszyny z systemami Windows i SecurityOnion.**

**Następnie pobrałem Sysmon'a i zainstalowałem na hoscie Windows.**
![SysmonInstal](https://user-images.githubusercontent.com/56591106/72205731-c1359e00-3486-11ea-9238-6a460190c476.PNG)


**Następnie pobrałem z internetu przykładowy config i skonfigurowałem Sysmona.**
```
sysmon.exe -accepteula -c config.xml
```
![SysmonConfig](https://user-images.githubusercontent.com/56591106/72205727-c1359e00-3486-11ea-941e-9dca87023794.PNG)


**Po uruchomieniu usługi mogłem już podejrzeć logi w programie EventViwer, a także zapisac je do pliku**
![EventViwer](https://user-images.githubusercontent.com/56591106/72205732-c1ce3480-3486-11ea-8722-f45ffd6bddf2.PNG)


**Następnie pobrałem program winlogbeat, aby skonfigurować automatyczne wysyłanie logów do hosta SecurityOnion i odebranie ich w Kibanie**
```
PowerShell.exe -ExecutionPolicy UnRestricted -File .\install-service-winlogbeat.ps1
```
![InstalWinLogBeat](https://user-images.githubusercontent.com/56591106/72205726-c09d0780-3486-11ea-9ce7-5b693e15d644.PNG)


**Ustawiłem potrzebne dane w pliku konfiguracyjnym winlogbeat'a po czym uruchomiem usługę.**

-Kibana
```
setup.kibana:
host: [https://192.168.12.10/app/kibana]
```
-Elasticsearch
```
#output.elasticsearch:
#hosts: ["192.168.12.10:9200"]
```
-Logstash
```
output.logstash:
hosts: ["192.168.12.10:5044"]
```

-Sprawdzenie poprawności configu
```
.\winlogbeat.exe test config -c .\winlogbeat.reference.yml -e
```
![ConfigPoprawStart](https://user-images.githubusercontent.com/56591106/72205733-c1ce3480-3486-11ea-80dd-324d0e5aa506.PNG)


**Teraz mogłem przejść już do SecurityOniona i sprawdzić czy logi z Windowsa są dostarczane. Uruchomiłem Kibane i w zakładce Discovery po wybraniu danych z logstasha, zaobserwowałem, że logi z Windowsa nie są odbierane. Postanowiłem więc wyłączyć firewalle na obu maszynach, pocz ym mogłem już zaobserwować odebrane logi.**
![KibanaDane](https://user-images.githubusercontent.com/56591106/72205728-c1359e00-3486-11ea-95be-23327f9db31e.PNG)


**Teraz, można już przeglądać i analizować logi systemowe z Windowsa.**
![DashBoardKibana](https://user-images.githubusercontent.com/56591106/72205729-c1359e00-3486-11ea-89b3-8c626b9ee120.PNG)

## Zadanie 2

**Utworzyłem maszynę wirtualną z systemem operacyjnym Linux w chmurze Azure**
![Arzurze](https://user-images.githubusercontent.com/56591106/72208899-dcb1a080-34a8-11ea-8762-8805c604a804.png)

**Przy pomocy programu PuTTY używając protokołu ssh zalogowałem się, uzyskując dostęp do terminala maszyny**
![puttyLog](https://user-images.githubusercontent.com/56591106/72208872-82184480-34a8-11ea-84bb-620d8818a6dc.PNG)

**Następnie używając następujących poleceń **
```
sudo iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
sudo iptables -A OUTPUT -p tcp -m tcp --dport 80 -j ACCEPT
sudo iptables -A OUTPUT -p tcp -m tcp --dport 443 -j ACCEPT

```
![80i443](https://user-images.githubusercontent.com/56591106/72208987-e12a8900-34a9-11ea-82cf-641259b92599.PNG)

**Używając kolejnego polecenia dopuściłem ruch  polecenia**
```
sudo iptables -A INPUT -p tcp -s 185.49.203.47 -m tcp --dport 22 -j ACCEPT
sudo iptables -A OUTPUT -p tcp -s 185.49.203.47 -m tcp --dport 22 -j ACCEPT
```
![myIP](https://user-images.githubusercontent.com/56591106/72209073-f9e76e80-34aa-11ea-89ca-bc407a55d881.PNG)

**Wykorzystując kolejne 2 polecenia zablokowałem komunikacje na nieużywanych pportach**
```
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
```

**Sprawdziłem jakie porty są konieczne do komunikacji wprotokole MQTT a następnie użyłem poleceń i odblokowałem ruch na tych portach**
```
sudo iptables -A INPUT -p tcp -m tcp --dport 1883 -j ACCEPT
sudo iptables -A INPUT -p tcp -m tcp --dport 8883 -j ACCEPT
sudo iptables -A OUTPUT -p tcp -m tcp --dport 1883 -j ACCEPT
sudo iptables -A OUTPUT -p tcp -m tcp --dport 8883 -j ACCEPT
```
![MQTT](https://user-images.githubusercontent.com/56591106/72209226-441d1f80-34ac-11ea-895b-2dc5b5e4d859.PNG)


