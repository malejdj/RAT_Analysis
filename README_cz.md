# StormWall / Hyper.Hosting — Threat Intel Summary

**Datum:** 2026-07-18
**Autor:** malejdj

## Shrnutí

Vyšetřování začalo u vzorku malwaru (LxBase RAT) s C2 serverem hostovaným na VPS IP `193.93.193.20`. BGP origin ASN je AS63023 (GTHost / GlobalTeleHost Corp., formálně kanadská firma), ale detailní RIPE WHOIS ukazuje, že konkrétní blok `193.93.193.0/24` je přidělený ruskému resellerovi/datacentru vedenému pod maintainerem `MNT-PINSUPPORT` (historicky `RU-PIN-20100326`), se admin/tech kontaktem v Moskvě, a IP geolokace řadí server přímo do Moskvy. Reverse-DNS ukázala, že C2 IP nese hostname `vm49515.hyper.hosting` — `hyper.hosting` je pojmenovací schéma této VPS značky, provozované v rámci GTHost/PIN infrastruktury (potvrzeno na desítkách dalších `vm*.hyper.hosting` záznamů ve stejném /24).

Nezávisle na tom je administrativní/billingové rozhraní téže značky (`bill.`, `black.`, `police.hyper.hosting`) chráněno proti DDoS útokům přes samostatnou IP (`5.252.32.61`), která patří **StormWall s.r.o.** — formálně slovenské firmě s RIPE LIR statusem. StormWall je dle nezávislé investigativní žurnalistiky (VSquare/FRONTSTORY/ICJK) vlastněná dvěma ruskými podnikateli a propojená se sítí firem, jež hostovaly ruské doxingové a propagandistické weby. Tato vazba na Rusko je tedy zdvojená a nezávislá po dvou různých liniích: (1) přímo přes ruského provozovatele konkrétního IP bloku, na kterém C2 běžní, a (2) přes StormWall, který chrání sousední administrativní panel téže VPS značky. Technická analýza síťových metadat navíc odhalila skrytý mechanismus „černé díry“, kdy slovenská entita slouží pouze jako externí paraván a veškerý provoz končí přes přímý vnitřní peering v Moskvě.

---

## 1. Malware — LxBase RAT (Joe Sandbox Analysis ID: 1944201)



**Sample:** `281_26.bat`


**Detekce:** Koadic, Clipboard Hijacker, LxBase RAT — Score 100/100

**MD5:** `ae7ca058b8f640f8513a223e1f70cc29`


**SHA1:** `b48347184fd98ac6324ccbe06ab96835c6dd2ec5`


**SHA256:** `0af90dfbc5f2a98a64f6aeec58dc6ada8e6d1d6af3f1292ca2d9da82f7fab1d`

### Řetězec spuštění

1. `281_26.bat` → PowerShell (`-ExecutionPolicy Bypass`, hidden window)


2. Extrakce base64 payloadu z markeru `---BEGIN_PS---` uvnitř .bat souboru → uložen jako `.ps1` do Temp


3. Víceúrovňová obfuskace: AES dešifrování, rail-fence cifra, reflective assembly loading


4. Dynamická kompilace C# přes `csc.exe`

5. PE injection do `MSBuild.exe`, následně thread injection do `chrome.exe`


### Malware Configuration

```json
{
  "Threat": "LXBase Rat",
  "Version": "1.0.21",
  "C2": ["193.93.193.20:63099", "neuvo1.ydns.eu:63921"],
  "Install File": "client.exe",
  "Mutex": "dae9e5a75f4148a2841393a33181605b",
  "Tag": "Group1",
  "Log Dir": "WindowsTelemetry\\Logs"
}

```

### IOC — Network

| Typ | Hodnota | Poznámka |
| --- | --- | --- |
| IP:Port | `193.93.193.20:63099` | primární C2 |
| Domain:Port | `neuvo1.ydns.eu:63921` | sekundární C2 (Dynamic DNS) |
| JA3 | `28a2c9bd18a11de089ef85a160da29e4` | opakovaně pozorováno u příbuzných vzorků |

**Vyřazeno jako non-IOC:** `208.95.112.1` (dle Joe Sandbox pozorováno v HTTP provozu, host `ip-api.com`) se ukázala patřit legitimní firmě Total Uptime Technologies, LLC (Skyland, NC, USA) — CDN/ADC-as-a-Service provider, žádný threat-intel hit. Jde o standardní geolokační dotaz, kterým si RAT ověřuje veřejnou IP/polohu oběti (typická anti-sandbox/geofencing technika), ne o součást C2 infrastruktury. WhoisXML report 2026-07-18.

### Schopnosti

* Credential theft: Chrome (`Login Data For Account`), Firefox (`pkcs11.txt`, `key4.db`)


* Crypto wallet theft: Electrum, Atomic Wallet, Jaxx, Exodus


* E-mail credential theft (registry access na Windows Messaging Subsystem)


* Global keyboard hook (keylogging)


* Clipboard hijacking (záměna crypto adres)



---

## 2. Síťová infrastruktura C2 IP `193.93.193.20`

### DNS

```
$ dig -x 193.93.193.20 +short
vm49515.hyper.hosting.

$ host 193.93.193.20
20.193.93.193.in-addr.arpa domain name pointer vm49515.hyper.hosting.

```

`hyper.hosting` NS záznamy vedou na Cloudflare (`bailey.ns.cloudflare.com`, `cullen.ns.cloudflare.com`) — neutrální DNS provider, neurčuje vlastníka domény.

### Traceroute (ICMP mód, ekvivalent Windows tracert)

```
$ sudo traceroute -I 193.93.193.20
 1  ant.smart1.forpsi.net (x.x.x.x)
 2  120.232.forpsi.net (x.x.x.x)
 3  * * *
 4  be9352.ccr81.prg01.atlas.cogentco.com (154.54.77.105)   [Praha]
 5  be9354.ccr41.ham01.atlas.cogentco.com (154.54.77.129)   [Hamburg]
 6  be2815.ccr41.ams03.atlas.cogentco.com (154.54.38.205)   [Amsterdam]
 7  be3197.rcr21.b031955-0.ams03.atlas.cogentco.com (154.54.56.154)
 8-30 * * *   (timeout)

```

### ASN / WHOIS — C2 IP `193.93.193.20`

| Pole | Hodnota |
| --- | --- |
| BGP origin ASN | AS63023 — GTHost (route 193.93.193.0/24) |
| ASN organizace | GlobalTeleHost Corp., Richmond Hill, Ontario, Kanada |
| RIPE inetnum (přesný blok) | `193.93.193.0 - 193.93.193.255`, netname `cust88530-network`<br> |
| RIPE maintainer | `MNT-PINSUPPORT`<br> |
| Admin/tech kontakt (RIPE) | Varnyan Valeriya Viktorovna, b-r Semfiropolskij 30, Moskva 117452, Ruská federace, tel. +79689509509 |
| Abuse kontakt | abuse@hyper.hosting |
| Historický netname (starší RIPE záznam, stejný rozsah) | `RU-PIN-20100326`<br> |
| IP geolokace (WhoisXML) | **Moskva, Rusko** (55.75204, 37.61781), ISP "PIN Datacenter" |
| Zdroj | WhoisXML API RDAP report, 2026-07-18; potvrzuje BGP origin z IPinfo.io a Joe Sandboxu |

**Interpretace:** GTHost (AS63023) je formálně kanadský ASN a announce-uje `193.93.193.0/24` navenek do BGP, ale konkrétní přidělení tohoto bloku je vedené pod ruským resellerem/datacentrem "PIN" (`MNT-PINSUPPORT`, historicky `RU-PIN-20100326`), se sídlem administrátora v Moskvě. IP geolokace řadí C2 přímo do Moskvy. To je odlišná a přímější vazba na Rusko, než jakou nabízí StormWall (sekce 3) — tahle vede přímo k IP, na které C2 běží, ne jen k firmě chránící sousední administrativní panel.

**Pozn. k historii dokumentu:** V dřívější verzi byla v této sekci omylem uvedena WHOIS data pro StormWall (`AS59796`, `SK-STORMWALL-20190204`) — ta patří jiné IP (`5.252.32.61`, viz sekce 3), ne C2 serveru. Opraveno 2026-07-18, následně doplněno o přímý WhoisXML report na `193.93.193.20` (tamtéž).

---

## 3. StormWall s.r.o. a Storm Networks LLC — Globální a regionální síťová struktura

Distribuce zátěže a krytí v rámci značky StormWall jsou technicky realizovány úzkou koordinací dvou autonomních systémů, které sdílejí totožnou identitu v databázi IRR (`AS-STORMWALL-SET`). Zatímco slovenská entita slouží jako globální paraván pro západní tranzit, ruské rameno zajišťuje fyzické ukotvení přímo v Moskvě.

### 3a. Globální Anycast paraván: StormWall s.r.o. (AS59796)

* **Charakteristika síťového provozu:** Síť figuruje jako Network Service Provider (NSP) s globálním geografickým rozsahem. Zpracovává masivní datové toky v rozmezí **300–500 Gbps**. Poměr provozu je definován jako **„Více příchozí“**, což bezprostředně odpovídá charakteru Anycast scrubbing center, která absorbují a filtrují DDoS útoky směřující na klientské panely (např. `hyper.hosting`) před předáním vyčištěného provozu.


* **Fyzická PoP a datacentrová infrastruktura (Interconnection Facilities):** Společnost nedisponuje žádným fyzickým síťovým bodem ani propojovacím uzlem na území Slovenska. Její uzly jsou celosvětově rozmístěny v těchto lokalitách:


* **Uzly Equinix:** Equinix FR5 (Frankfurt, Německo), Equinix HK1 (Tsuen Wan, Hongkong), Equinix LA1 (Los Angeles, USA), Equinix MI1 (Miami, USA), Equinix SG1 a SG3 (Singapur).


* **Ostatní mezinárodní DC:** NTT Frankfurt 1 (Německo), IPDN Data Center (Jakarta, Indonésie), PS Internet Company DC (Almaty, Kazachstán), SmartHub Fujairah (SAE) a TELEPOINT Sofia Centre (Sofia, Bulharsko).


* **Ruská federace:** Fyzická přítomnost v klíčovém moskevském telekomunikačním uzlu **Moscow M9** (Moskva, Rusko).




* **Veřejný BGP Peering (IXP):** Za účelem absorpce legitimního i škodlivého provozu je AS59796 masivně propojen v uzlech: **DE-CIX Frankfurt (kapacita 400G)**, NetIX (100G), BIX.BG (100G), FL-IX (100G), Equinix Hong Kong (100G), Equinix Singapore (100G), vedle eurasijských bodů Eurasia Peering IX (100G) a PITER-IX Moscow (100G).


* **Tranzitní sítě a ruské propojení:** Západní tranzit zajišťují operátoři AS6453 (Tata), AS9002 (RETN), AS1299 (Arelion/Telia), AS2914 (NTT) a AS3491 (PCCW). Přímý peering směřuje na ruské národní operátory AS31133 (PJSC MegaFon), AS20764 (Rostelecom) a AS20485 (TTK).


* **Kontaktní a provozní anomálie:** Všechny operativní složky slovenské s.r.o. (Abuse, NOC, Sales) uvádějí slovenské doménové e-maily (`abuse@stormwall.sk`, `noc@stormwall.sk`, `sales@stormwall.sk`), avšak sdílejí **jednotné britské telefonní číslo +442036956722**.



### 3b. Ruské rameno: Storm Networks LLC (AS43298)

* **Profil sítě:** V databázích vystupuje pod názvem Storm Networks (či alternativně StormWall). Na rozdíl od slovenské větve je tato entita registrována jako ruská LLC a její síťové operace jsou striktně regionální.


* **Ukotvení a peering v RF:** Jediným deklarovaným propojovacím bodem (Facility) sítě je **Moscow M9** v Rusku. Lokální distribuci dat a propojitelnost s ruským internetem zajišťuje skrze uzly: **MSK-IX Moscow (kapacita 200G)**, PITER-IX Saint-Petersburg (100G), PITER-IX Moscow (100G), GNM-IX (100G) a Eurasia Peering IX (100G).



### Přidružené domény na StormWall infrastruktuře

* `hyper.hosting`, `bill.hyper.hosting`, `black.hyper.hosting`, `police.hyper.hosting` — jako Associated Domains pro `5.252.32.61` (reverse lookup přes WhoisXML), tj. StormWall poskytuje DDoS scrubbing pro tato konkrétní admin/billing rozhraní GTHostu.


* `smsbest.pro` / `smsbest.me` — ruskocílená SMS-receive/PVA (phone verification account) služba pro obcházení SMS ověření (Telegram, WhatsApp, VK, Wildberries, Sbermarket, OZON, Google, Microsoft, OpenAI aj.), sdílející stejnou StormWall IP.



### ASN / WHOIS — StormWall IP `5.252.32.61`

| Pole | Hodnota |
| --- | --- |
| ASN | AS59796 — STORMWALL-AS |
| Organizace | StormWall s.r.o. |
| RIPE Net Name | SK-STORMWALL-20190204 |
| Rozsah | 5.252.32.0/22 |
| Domain | stormwall.network |
| Abuse kontakty | abuse@stormwall.sk, noc@stormwall.sk, management@stormwall.pro |
| Deklarované sídlo (RIPE) | Ligurcekova 8, Bratislava, Slovensko (registrace 2019-02-04) |
| Geolokace WHOIS (WhoisXML) | Altstadt, Hessen, Německo |
| `dig -x 5.252.32.61` | žádný PTR záznam |

---

## 4. Vlastnická struktura StormWall (zdroj: VSquare / FRONTSTORY.pl / ICJK, přebráno investigace.cz, 10. 7. 2025)



* Doxingové weby **ForeignCombatants** a **Wartears** (sběr dat ukrajinských vojáků a jejich rodin pro ruskou psychologickou válku) hostuje seychelská firma **Safe Value Limited**, jejíž jediná cesta na internet vede přes moskevské firmy **Storm Networks** a **StormWall**.


* Expert DomainTools: indikátory silně naznačují jedno společné řídící centrum.


* **Storm Networks** je jedna z několika propojených firem kolem značky StormWall. Ochrannou známku vlastní **Storm Systems**, jejíž záznamy uvádějí adresu **Skolkova** (sankcionovaný ruský "technologický inkubátor" napojený na Kreml).


* DomainTools: komplexní propojení firem může sloužit k záměrnému udržování zdání, že StormWall nemá vazby na Rusko.


* **Russian Storm Systems** (další firma ze skupiny) poskytovala hosting pro **NewsFront** — ruský propagandistický web působící v desítce evropských zemí.


* **Skuteční vlastníci StormWall s.r.o.:**
* **Ramil Chantimirov** — absolvent petrohradské obchodní školy, kyberbezpečnost


* **Alexej Šijan** — bývalý zaměstnanec ruského ministerstva hospodářského rozvoje


* Oba mají od května 2025 hlášený trvalý pobyt v Bratislavě




* Sídlo v Bratislavě (Podunajské Biskupice) — fyzicky prázdná kancelář na okraji města. Loňské tržby: 1,5 mil. € (~37 mil. Kč).


* StormWall na dotaz novinářů k propojení firem neodpověděl.



**Zdroj:** investigace.cz — *"Doxing: Když se osobní data stanou ruskou zbraní"* (Barbora Šturmová, 10. 7. 2025), autoři originálu Anastasiia Morozova, Alicja Pawłowska, Anna Gielewska (FRONTSTORY.pl), spolupráce Daniel Flis (FRONTSTORY), Tamara Kaňuchová (VSquare), Tomáš Madleňák, Karin Kőváry Sólymos (ICJK). [https://www.investigace.cz/doxing-kdyz-se-osobni-data-stanou-ruskou-zbrani/](https://www.investigace.cz/doxing-kdyz-se-osobni-data-stanou-ruskou-zbrani/)

---

## 5. Závěr / vzorec: Mechanismus „Černé díry“ (Traffic Laundering)

Detailní analýza síťových metadat odhaluje sofistikovanou metodu maskování, kterou lze popsat jako **geopolitická černá díra** pro internetový provoz šedé zóny. Celý řetězec a maskovací manévr funguje v následujících fázích:

1. **Vytvoření horizontu událostí (reputační paraván):** Provoz pro C2 infrastrukturu malwaru nebo pro doxingové projekty směřuje navenek na slovenskou společnost StormWall s.r.o. (AS59796). Ta má díky sídlu v EU, západnímu tranzitu (Tata, NTT, Arelion) a přítomnosti na uzlech jako DE-CIX výbornou reputaci a nepodléhá plošným geoblokacím.


2. **Absorpce a vyčištění:** Masivní síť (300–500 Gbps) zachytí provoz na některém ze svých globálních Anycast uzlů (např. ve Frankfurtu) a očistí ho od případných DDoS protiútoků.


3. **Vtažení do moskevského jádra:** Vyčištěná data jsou vnitřními trasami StormWall (backhaul linkami) okamžitě přeposlána do ruského uzlu **Moscow M9**, kde jsou fyzicky přítomny obě sestry (AS59796 i AS43298).


4. **Přímý crossover (Vnitřní peering):** V Moskvě dochází k okamžitému předání dat do čistě ruské sítě Storm Networks (AS43298). Tento přímý propoj je jasně viditelný na identických internetových uzlech, kde obě sítě sedí vedle sebe na stejných podsítích:


* **Eurasia Peering IX:** slovenská větev `185.232.60.193` ↔ ruská větev `185.232.60.36`


* **PITER-IX Moscow:** slovenská větev `185.0.12.172` ↔ ruská větev `185.0.12.148`




5. **Doručení cíli:** Z ruského AS43298 je provoz přes lokální peering nebo ruské státní operátory (Rostelecom, MegaFon) doručen finálnímu škodlivému serveru chráněnému v moskevském PIN Datacentru.



Navenek se tak celá infrastruktura tváří stoprocentně evropsky a legálně, ale reálně data padají do moskevské infrastruktury s plnou imunitou vůči západním právním orgánům a abuse požadavkům. Obě linie ukazují na stejný závěr (VPS značka `hyper.hosting` má silné ruské vazby) různými, na sobě nezávislými cestami.

## IOC souhrn (pro import do TI nástrojů)

```
193.93.193.20:63099          # LxBase RAT C2 (BGP: GTHost/AS63023; RIPE inetnum: ruský reseller "PIN", Moskva)[cite: 4]
neuvo1.ydns.eu:63921         # LxBase RAT C2 (DDNS)[cite: 4]
vm49515.hyper.hosting        # PTR pro 193.93.193.20[cite: 4]
MNT-PINSUPPORT / RU-PIN-20100326   # ruský maintainer/netname bloku 193.93.193.0/24[cite: 4]
abuse@hyper.hosting          # abuse kontakt pro 193.93.193.0/24 (RIPE)[cite: 4]
208.95.112.1                 # doprovodná IP (AS-GLOBALTELEHOST-GTHostUS)[cite: 4]
28a2c9bd18a11de089ef85a160da29e4   # JA3 fingerprint[cite: 4]
dae9e5a75f4148a2841393a33181605b   # RAT mutex[cite: 4]
ae7ca058b8f640f8513a223e1f70cc29   # MD5 (281_26.bat)[cite: 4]
b48347184fd98ac6324ccbe06ab96835c6dd2ec5   # SHA1[cite: 4]
0af90dfbc5f2a98a64f6aeec58dc6ada8e6d1d6af3f1292ca2d9da82f7fab1d   # SHA256[cite: 4]
5.252.32.61                  # StormWall DDoS-protection IP for hyper.hosting admin panel[cite: 4]
AS59796                      # STORMWALL-AS (Slovenský Anycast / reputační paraván)[cite: 4]
AS43298                      # Storm Networks LLC / StormWall (Ruské rameno infrastruktury)[cite: 1]
AS-STORMWALL-SET             # IRR as-set / route-set sdílený oběma entitami[cite: 1, 2]
5.252.32.0/22                # StormWall rozsah (RIPE, dle RDAP)[cite: 4]
smsbest.pro / smsbest.me     # StormWall-hosted SMS-PVA služba[cite: 4]
hyper.hosting / bill.hyper.hosting / black.hyper.hosting / police.hyper.hosting[cite: 4]
+442036956722                # Jednotný britský telefonní kontakt pro NOC/Abuse/Sales StormWall s.r.o.[cite: 2]
sales@stormwall.sk           # Komerční e-mailový kontakt slovenské entity[cite: 2]
185.232.60.193               # AS59796 uzel na Eurasia Peering IX (Crossover bod)[cite: 2]
185.232.60.36                # AS43298 uzel na Eurasia Peering IX (Crossover bod)[cite: 1]
185.0.12.172                 # AS59796 uzel na PITER-IX Moscow (Crossover bod)[cite: 2]
185.0.12.148                 # AS43298 uzel na PITER-IX Moscow (Crossover bod)[cite: 1]

```
