# StormWall / Hyper.Hosting — Threat Intel Summary

**Date:** 2026-07-18
**Author:** malejdj

## Summary

The investigation began with a malware sample (LxBase RAT) with a C2 server hosted on a VPS IP `193.93.193.20`. The BGP origin ASN is AS63023 (GTHost / GlobalTeleHost Corp., formally a Canadian company), but detailed RIPE WHOIS shows that the specific block `193.93.193.0/24` is allocated to a Russian reseller/datacenter registered under maintainer `MNT-PINSUPPORT` (historically `RU-PIN-20100326`), with an admin/tech contact in Moscow, and IP geolocation places the server directly in Moscow. Reverse-DNS revealed that the C2 IP carries the hostname `vm49515.hyper.hosting` — `hyper.hosting` is the naming scheme of this VPS brand, operated within the GTHost/PIN infrastructure (confirmed across dozens of other `vm*.hyper.hosting` records in the same /24).

Independently, the administrative/billing interface of the same brand (`bill.`, `black.`, `police.hyper.hosting`) is protected against DDoS attacks via a separate IP (`5.252.32.61`), which belongs to **StormWall s.r.o.** — formally a Slovak company with RIPE LIR status. According to independent investigative journalism (VSquare/FRONTSTORY/ICJK), StormWall is owned by two Russian businessmen and is connected to a network of companies that hosted Russian doxing and propaganda websites. This Russia connection is therefore doubled and independent along two different lines: (1) directly via the Russian operator of the specific IP block on which the C2 runs, and (2) via StormWall, which protects the neighboring administrative panel of the same VPS brand. Technical analysis of network metadata further revealed a hidden "black hole" mechanism, where the Slovak entity serves merely as an external front and all traffic ends up via direct internal peering in Moscow.

---

## 1. Malware — LxBase RAT (Joe Sandbox Analysis ID: 1944201)

**Sample:** `281_26.bat`

**Detection:** Koadic, Clipboard Hijacker, LxBase RAT — Score 100/100

**MD5:** `ae7ca058b8f640f8513a223e1f70cc29`

**SHA1:** `b48347184fd98ac6324ccbe06ab96835c6dd2ec5`

**SHA256:** `0af90dfbc5f2a98a64f6aeec58dc6ada8e6d1d6af3f1292ca2d9da82f7fab1d`

### Execution Chain

1. `281_26.bat` → PowerShell (`-ExecutionPolicy Bypass`, hidden window)
2. Extraction of base64 payload from the `---BEGIN_PS---` marker inside the .bat file → saved as `.ps1` to Temp
3. Multi-level obfuscation: AES decryption, rail-fence cipher, reflective assembly loading
4. Dynamic C# compilation via `csc.exe`
5. PE injection into `MSBuild.exe`, followed by thread injection into `chrome.exe`

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

| Type | Value | Note |
| --- | --- | --- |
| IP:Port | `193.93.193.20:63099` | primary C2 |
| Domain:Port | `neuvo1.ydns.eu:63921` | secondary C2 (Dynamic DNS) |
| JA3 | `28a2c9bd18a11de089ef85a160da29e4` | repeatedly observed in related samples |

**Excluded as non-IOC:** `208.95.112.1` (observed in HTTP traffic per Joe Sandbox, host `ip-api.com`) turned out to belong to the legitimate company Total Uptime Technologies, LLC (Skyland, NC, USA) — a CDN/ADC-as-a-Service provider, no threat-intel hit. This is a standard geolocation query by which the RAT verifies the victim's public IP/location (a typical anti-sandbox/geofencing technique), not part of the C2 infrastructure. WhoisXML report 2026-07-18.

### Capabilities

* Credential theft: Chrome (`Login Data For Account`), Firefox (`pkcs11.txt`, `key4.db`)
* Crypto wallet theft: Electrum, Atomic Wallet, Jaxx, Exodus
* E-mail credential theft (registry access to Windows Messaging Subsystem)
* Global keyboard hook (keylogging)
* Clipboard hijacking (swapping crypto addresses)

---

## 2. Network Infrastructure of C2 IP `193.93.193.20`

### DNS

```
$ dig -x 193.93.193.20 +short
vm49515.hyper.hosting.

$ host 193.93.193.20
20.193.93.193.in-addr.arpa domain name pointer vm49515.hyper.hosting.
```

`hyper.hosting` NS records point to Cloudflare (`bailey.ns.cloudflare.com`, `cullen.ns.cloudflare.com`) — a neutral DNS provider, does not determine the domain owner.

### Traceroute (ICMP mode, equivalent to Windows tracert)

```
$ sudo traceroute -I 193.93.193.20
 1  ant.smart1.forpsi.net (x.x.x.x)
 2  120.232.forpsi.net (x.x.x.x)
 3  * * *
 4  be9352.ccr81.prg01.atlas.cogentco.com (154.54.77.105)   [Prague]
 5  be9354.ccr41.ham01.atlas.cogentco.com (154.54.77.129)   [Hamburg]
 6  be2815.ccr41.ams03.atlas.cogentco.com (154.54.38.205)   [Amsterdam]
 7  be3197.rcr21.b031955-0.ams03.atlas.cogentco.com (154.54.56.154)
 8-30 * * *   (timeout)
```

### ASN / WHOIS — C2 IP `193.93.193.20`

| Field | Value |
| --- | --- |
| BGP origin ASN | AS63023 — GTHost (route 193.93.193.0/24) |
| ASN organization | GlobalTeleHost Corp., Richmond Hill, Ontario, Canada |
| RIPE inetnum (exact block) | `193.93.193.0 - 193.93.193.255`, netname `cust88530-network` |
| RIPE maintainer | `MNT-PINSUPPORT` |
| Admin/tech contact (RIPE) | Varnyan Valeriya Viktorovna, b-r Semfiropolskij 30, Moscow 117452, Russian Federation, tel. +79689509509 |
| Abuse contact | abuse@hyper.hosting |
| Historical netname (older RIPE record, same range) | `RU-PIN-20100326` |
| IP geolocation (WhoisXML) | **Moscow, Russia** (55.75204, 37.61781), ISP "PIN Datacenter" |
| Source | WhoisXML API RDAP report, 2026-07-18; confirms BGP origin from IPinfo.io and Joe Sandbox |

**Interpretation:** GTHost (AS63023) is formally a Canadian ASN and announces `193.93.193.0/24` externally into BGP, but the specific allocation of this block is registered under the Russian reseller/datacenter "PIN" (`MNT-PINSUPPORT`, historically `RU-PIN-20100326`), with the administrator's seat in Moscow. IP geolocation places the C2 directly in Moscow. This is a different and more direct Russia connection than that offered by StormWall (section 3) — this one leads directly to the IP on which the C2 runs, not just to the company protecting the neighboring administrative panel.

**Note on document history:** In an earlier version, the WHOIS data for StormWall (`AS59796`, `SK-STORMWALL-20190204`) was mistakenly listed in this section — those belong to a different IP (`5.252.32.61`, see section 3), not the C2 server. Corrected 2026-07-18, subsequently supplemented with a direct WhoisXML report on `193.93.193.20` (same date).

---

## 3. StormWall s.r.o. and Storm Networks LLC — Global and Regional Network Structure

The distribution of load and coverage under the StormWall brand are technically realized through close coordination of two autonomous systems that share an identical identity in the IRR database (`AS-STORMWALL-SET`). While the Slovak entity serves as a global front for Western transit, the Russian arm ensures physical anchoring directly in Moscow.

### 3a. Global Anycast Front: StormWall s.r.o. (AS59796)

* **Network traffic characteristics:** The network operates as a Network Service Provider (NSP) with a global geographic scope. It processes massive data flows ranging from **300–500 Gbps**. The traffic ratio is defined as **"Inbound-heavy"**, which directly corresponds to the nature of an Anycast scrubbing center that absorbs and filters DDoS attacks targeting client panels (e.g., `hyper.hosting`) before handing over the cleaned traffic.

* **Physical PoP and datacenter infrastructure (Interconnection Facilities):** The company has no physical network point or interconnection node on the territory of Slovakia. Its nodes are distributed worldwide in the following locations:

  * **Equinix nodes:** Equinix FR5 (Frankfurt, Germany), Equinix HK1 (Tsuen Wan, Hong Kong), Equinix LA1 (Los Angeles, USA), Equinix MI1 (Miami, USA), Equinix SG1 and SG3 (Singapore).
  * **Other international DCs:** NTT Frankfurt 1 (Germany), IPDN Data Center (Jakarta, Indonesia), PS Internet Company DC (Almaty, Kazakhstan), SmartHub Fujairah (UAE) and TELEPOINT Sofia Centre (Sofia, Bulgaria).
  * **Russian Federation:** Physical presence in the key Moscow telecom node **Moscow M9** (Moscow, Russia).

* **Public BGP Peering (IXP):** To absorb both legitimate and malicious traffic, AS59796 is massively interconnected at nodes: **DE-CIX Frankfurt (capacity 400G)**, NetIX (100G), BIX.BG (100G), FL-IX (100G), Equinix Hong Kong (100G), Equinix Singapore (100G), alongside Eurasian points Eurasia Peering IX (100G) and PITER-IX Moscow (100G).

* **Transit networks and Russian interconnection:** Western transit is provided by operators AS6453 (Tata), AS9002 (RETN), AS1299 (Arelion/Telia), AS2914 (NTT) and AS3491 (PCCW). Direct peering targets Russian national operators AS31133 (PJSC MegaFon), AS20764 (Rostelecom) and AS20485 (TTK).

* **Contact and operational anomalies:** All operational units of the Slovak s.r.o. (Abuse, NOC, Sales) list Slovak domain emails (`abuse@stormwall.sk`, `noc@stormwall.sk`, `sales@stormwall.sk`), yet share a **single UK phone number +442036956722**.

### 3b. Russian Arm: Storm Networks LLC (AS43298)

* **Network profile:** In databases it appears under the name Storm Networks (or alternatively StormWall). Unlike the Slovak branch, this entity is registered as a Russian LLC and its network operations are strictly regional.

* **Anchoring and peering in RF:** The only declared interconnection point (Facility) of the network is **Moscow M9** in Russia. Local data distribution and connectivity to the Russian internet are ensured via nodes: **MSK-IX Moscow (capacity 200G)**, PITER-IX Saint-Petersburg (100G), PITER-IX Moscow (100G), GNM-IX (100G) and Eurasia Peering IX (100G).

### Associated Domains on StormWall Infrastructure

* `hyper.hosting`, `bill.hyper.hosting`, `black.hyper.hosting`, `police.hyper.hosting` — as Associated Domains for `5.252.32.61` (reverse lookup via WhoisXML), i.e., StormWall provides DDoS scrubbing for these specific GTHost admin/billing interfaces.
* `smsbest.pro` / `smsbest.me` — a Russia-targeted SMS-receive/PVA (phone verification account) service for bypassing SMS verification (Telegram, WhatsApp, VK, Wildberries, Sbermarket, OZON, Google, Microsoft, OpenAI, etc.), sharing the same StormWall IP.

### ASN / WHOIS — StormWall IP `5.252.32.61`

| Field | Value |
| --- | --- |
| ASN | AS59796 — STORMWALL-AS |
| Organization | StormWall s.r.o. |
| RIPE Net Name | SK-STORMWALL-20190204 |
| Range | 5.252.32.0/22 |
| Domain | stormwall.network |
| Abuse contacts | abuse@stormwall.sk, noc@stormwall.sk, management@stormwall.pro |
| Declared seat (RIPE) | Ligurcekova 8, Bratislava, Slovakia (registration 2019-02-04) |
| WHOIS geolocation (WhoisXML) | Altstadt, Hesse, Germany |
| `dig -x 5.252.32.61` | no PTR record |

---

## 4. StormWall Ownership Structure (source: VSquare / FRONTSTORY.pl / ICJK, taken from investigace.cz, 10. 7. 2025)

* Doxing websites **ForeignCombatants** and **Wartears** (collecting data on Ukrainian soldiers and their families for Russian psychological warfare) are hosted by the Seychelles company **Safe Value Limited**, whose only path to the internet runs through Moscow companies **Storm Networks** and **StormWall**.
* DomainTools expert: indicators strongly suggest a single shared command center.
* **Storm Networks** is one of several interconnected companies around the StormWall brand. The trademark is owned by **Storm Systems**, whose records list the address **Skolkova** (a sanctioned Russian "technology incubator" linked to the Kremlin).
* DomainTools: the complex interconnection of companies may serve to deliberately maintain the appearance that StormWall has no ties to Russia.
* **Russian Storm Systems** (another company in the group) provided hosting for **NewsFront** — a Russian propaganda website operating in a dozen European countries.
* **Actual owners of StormWall s.r.o.:**
  * **Ramil Chantimirov** — graduate of a St. Petersburg business school, cybersecurity
  * **Alexey Shiyan** — former employee of the Russian Ministry of Economic Development
  * Both have reported permanent residence in Bratislava since May 2025
* Seat in Bratislava (Podunajské Biskupice) — a physically empty office on the outskirts of the city. Last year's revenue: €1.5 million (~37 million CZK).
* StormWall did not respond to journalists' questions regarding the interconnection of companies.

**Source:** investigace.cz — *"Doxing: When Personal Data Becomes a Russian Weapon"* (Barbora Šturmová, 10. 7. 2025), original authors Anastasiia Morozova, Alicja Pawłowska, Anna Gielewska (FRONTSTORY.pl), in cooperation with Daniel Flis (FRONTSTORY), Tamara Kaňuchová (VSquare), Tomáš Madleňák, Karin Kőváry Sólymos (ICJK). [https://www.investigace.cz/doxing-kdyz-se-osobni-data-stanou-ruskou-zbrani/](https://www.investigace.cz/doxing-kdyz-se-osobni-data-stanou-ruskou-zbrani/)

---

## 5. Conclusion / Pattern: The "Black Hole" Mechanism (Traffic Laundering)

Detailed analysis of network metadata reveals a sophisticated masking method that can be described as a **geopolitical black hole** for gray-zone internet traffic. The entire chain and masking maneuver works in the following phases:

1. **Creation of the event horizon (reputation front):** Traffic for the malware C2 infrastructure or for doxing projects is directed externally to the Slovak company StormWall s.r.o. (AS59796). Thanks to its EU seat, Western transit (Tata, NTT, Arelion) and presence at nodes like DE-CIX, it has an excellent reputation and is not subject to blanket geoblocks.
2. **Absorption and cleaning:** The massive network (300–500 Gbps) captures traffic at one of its global Anycast nodes (e.g., in Frankfurt) and cleans it of any DDoS counterattacks.
3. **Drawing into the Moscow core:** The cleaned data is immediately forwarded via StormWall's internal routes (backhaul links) to the Russian node **Moscow M9**, where both sisters (AS59796 and AS43298) are physically present.
4. **Direct crossover (internal peering):** In Moscow, data is immediately handed over to the purely Russian network Storm Networks (AS43298). This direct interconnection is clearly visible at identical internet nodes where both networks sit next to each other on the same subnets:
   * **Eurasia Peering IX:** Slovak branch `185.232.60.193` ↔ Russian branch `185.232.60.36`
   * **PITER-IX Moscow:** Slovak branch `185.0.12.172` ↔ Russian branch `185.0.12.148`
5. **Delivery to target:** From the Russian AS43298, traffic is delivered via local peering or Russian state operators (Rostelecom, MegaFon) to the final malicious server hosted in the Moscow PIN Datacenter.

Externally, the entire infrastructure thus appears 100% European and legal, but in reality the data falls into Moscow infrastructure with full immunity against Western legal authorities and abuse requests. Both lines lead to the same conclusion (the `hyper.hosting` VPS brand has strong Russian ties) via different, mutually independent paths.

## IOC Summary (for import into TI tools)

```
193.93.193.20:63099          # LxBase RAT C2 (BGP: GTHost/AS63023; RIPE inetnum: Russian reseller "PIN", Moscow)[cite: 4]
neuvo1.ydns.eu:63921         # LxBase RAT C2 (DDNS)[cite: 4]
vm49515.hyper.hosting        # PTR for 193.93.193.20[cite: 4]
MNT-PINSUPPORT / RU-PIN-20100326   # Russian maintainer/netname of block 193.93.193.0/24[cite: 4]
abuse@hyper.hosting          # abuse contact for 193.93.193.0/24 (RIPE)[cite: 4]
208.95.112.1                 # accompanying IP (AS-GLOBALTELEHOST-GTHostUS)[cite: 4]
28a2c9bd18a11de089ef85a160da29e4   # JA3 fingerprint[cite: 4]
dae9e5a75f4148a2841393a33181605b   # RAT mutex[cite: 4]
ae7ca058b8f640f8513a223e1f70cc29   # MD5 (281_26.bat)[cite: 4]
b48347184fd98ac6324ccbe06ab96835c6dd2ec5   # SHA1[cite: 4]
0af90dfbc5f2a98a64f6aeec58dc6ada8e6d1d6af3f1292ca2d9da82f7fab1d   # SHA256[cite: 4]
5.252.32.61                  # StormWall DDoS-protection IP for hyper.hosting admin panel[cite: 4]
AS59796                      # STORMWALL-AS (Slovak Anycast / reputation front)[cite: 4]
AS43298                      # Storm Networks LLC / StormWall (Russian arm of infrastructure)[cite: 1]
AS-STORMWALL-SET             # IRR as-set / route-set shared by both entities[cite: 1, 2]
5.252.32.0/22                # StormWall range (RIPE, per RDAP)[cite: 4]
smsbest.pro / smsbest.me     # StormWall-hosted SMS-PVA service[cite: 4]
hyper.hosting / bill.hyper.hosting / black.hyper.hosting / police.hyper.hosting[cite: 4]
+442036956722                # Single UK phone contact for NOC/Abuse/Sales of StormWall s.r.o.[cite: 2]
sales@stormwall.sk           # Commercial email contact of Slovak entity[cite: 2]
185.232.60.193               # AS59796 node at Eurasia Peering IX (Crossover point)[cite: 2]
185.232.60.36                # AS43298 node at Eurasia Peering IX (Crossover point)[cite: 1]
185.0.12.172                 # AS59796 node at PITER-IX Moscow (Crossover point)[cite: 2]
185.0.12.148                 # AS43298 node at PITER-IX Moscow (Crossover point)[cite: 1]
```
