
/**

## Jako trzeci do analizy wybrałem i zaimportowałem plik `example.com-1.pcap`. 
```sudo so-import-pcap example.com-1.pcap```
Ponownie zacząłem od Kibany i Squerta.

**Widok zaimportowanego ruchu w Kibanie**
![discover](https://user-images.githubusercontent.com/56591106/72654708-ff542580-3990-11ea-9552-af6b1c9ffc78.PNG)

**Podsumowania alertów NIDS oraz ich podział na poszczególne kategorie**
![NIDS](https://user-images.githubusercontent.com/56591106/72654711-ffecbc00-3990-11ea-8aa5-9b6881640d19.PNG)
![NIDSalert](https://user-images.githubusercontent.com/56591106/72654712-ffecbc00-3990-11ea-85c8-b0741663a11f.PNG)

**Usługi działające podczas ataku oraz wykorzystywane protokoły**
![ProtocolServices](https://user-images.githubusercontent.com/56591106/72654716-00855280-3991-11ea-8cd9-1f8263ee6d79.PNG)

**Porty na których odbywała się komunikacja, oraz dodatkowe informacje na ich temat**
![Port](https://user-images.githubusercontent.com/56591106/72654714-00855280-3991-11ea-99c4-561f7283d6e4.PNG)
![161](https://user-images.githubusercontent.com/56591106/72654705-ff542580-3990-11ea-9587-97bb598b112a.PNG)
![445](https://user-images.githubusercontent.com/56591106/72654706-ff542580-3990-11ea-8163-87c7e959edff.PNG)

![sygnatury](https://user-images.githubusercontent.com/56591106/72654718-011de900-3991-11ea-9686-ffc416e75bd8.PNG)
![topIP](https://user-images.githubusercontent.com/56591106/72654719-011de900-3991-11ea-9cfc-231b924fc9dc.PNG)
![topPort](https://user-images.githubusercontent.com/56591106/72654720-011de900-3991-11ea-976f-c92df222a2da.PNG)

**Z tego diagramu wynika że nasz host komunikował się z innymi urządzeniami w sieci wewnętrznej a także zewnętrzynym adresem IP pochodzącym z UK**
![ipsDiag](https://user-images.githubusercontent.com/56591106/72654710-ffecbc00-3990-11ea-992b-ff4a1b24fcdd.PNG)

**W Programie Network Miner uzyskałem informację o hostach, a wyodrębnione pliki z ruchu sieciowego**
![hosty](https://user-images.githubusercontent.com/56591106/72654709-ffecbc00-3990-11ea-9e66-d19ec71af644.PNG)
![pliki](https://user-images.githubusercontent.com/56591106/72654713-00855280-3991-11ea-8ff7-5d7e1fa24ad4.PNG)

**Sprawdziłem także widok logów w programi Sguily**
![sguil](https://user-images.githubusercontent.com/56591106/72654717-00855280-3991-11ea-8514-817836141c7c.PNG)

*/
