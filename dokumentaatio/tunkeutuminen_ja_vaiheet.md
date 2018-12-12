# Tunkeutumistestaus käytännössä
## Testiympäristö
Tunkeutumiseen käytimme Kali Linux käyttöjärjestelmää, joka sisältää paljon hyödyllisiä tunkeutumistestaukseen käytettäviä työkaluja.  

VulnHubista löytyy useita erilaisia tarkoituksella haavoittuvaksi luotuja virtuaalisia koneita, joita voidaan käyttää tunkeutumistestauksen harjoitteluun.  
Jotta voisimme demonstroida tunkeutumistestausta, niin valitsimme suhteellisen helpon harjoituskoneen nimeltään Basic pentesting: 1. Kyseinen harjoittelukone VulnHubista osoitteesta: https://www.vulnhub.com/entry/basic-pentesting-1,216/
  
Testi ympäristön asennus on erittäin helppoa. VulnHubista saa ladattua harjoituskoneen .Ova tiedoston, jonka voi importata VirtualBoxiin niin, että se on heti käytettävissä.
  
Virtuaalisen koneen importtaaminen onnistuu yksinkertaisuudessaa VirtualBoxin vasemmasta yläkulmasta "File" valikon alta "Import appliance..." napista. Valitset tiedosto selaimella vain ladatun .Ova tiedoston, jonka jälkeen VirtualBox purkaa paketin käytettävään muotoon.  
Basic Pentesting koneessa, jota käytämme oli kuitenkin pieni virhe käynyt paketoidessa ja virtuaalisen koneen asetuksista piti ottaa USB tuki pois päältä, jotta se käynnistyisi oikein. Asetuksen muutoksen jälkeen kone kuitenkin aukesi nätisti.


## Tunkeutumisen vaiheet

### Scopen tunnistaminen

Scopella tarkoitetaan testauksen aluetta. Yleensä scope on rajattu tiettyyn IP-osoitteeseen/osoitteisiin.

**Huomio!** Ennen kuin kohdetta aletaan testaamaan on tärkeää varmistua kohteen IP-osoitteesta, sillä väärään osoitteeseen kohdistuvat pelkät porttiskannaukset saattavat täyttää rikoksen merkit ja johtaa syytteisiin.
  
Valitussa Basic Pentesting harjoituskoneessa oli huonosti esitetty mikä IP-osoite on käytössä, mutta tämän sai selville helposti sillä koneeseen oli onneksi tehty Guest user, jolla pääsin käyttämään komennon Ifconfig, jolla näkee koneen IP-osoitteen.
(kuva kohdekone IP)

Tarkistin vielä, että kyseessä on varmasti oikea IP-osoite tekemällä Tracerouten, joka näytti että kone on samassa verkossa ja käymällä nettiselaimella kyseisessä osoitteessa, jossa tervehtikin "It works!" viesti, joka oli myös koneen esikatselu kuvissa.  

(It works kuva)

### Hyökkäyspinta-alan tunnistaminen

Kun scope on tiedossa voidaan siirtyä hyökkäyspinta-alan etsimiseen.  
Hyökkäyspinta-alan tunnistaminen aloitetaan yleensä Nmap skannauksella, jolla etsitään avonaisia portteja kohteesta, joita voitaisiin käyttää palvelimelle tunkeutumiseen.
  
Itse suosin metasploitin db_nmappia, koska se tallentaa saadut tulokset suoraan tietokantaan, josta tietoja voidaan hyödyntää esimerkiksi Armitagella. Armitage osaa automaattisesti hakea skannauksen tiedot ja esittää ne visuaalisesti.  
Aluksi metasploitin tietokanta pitää kuitenkin käynnistää. Tämä onnistuu terminaalista komennolla: "Msfdb init".

(kuva msfdb tietokannan luonti)

  
Kun tietokanta on luotu voidaan käynnistää Metasploit, jonka kautta db_nmappia voidaan ajaa. Metasploitin käynnistäminen onnistuu komennolla: "msfconsole".
  
(kuva metasploit käynnistys)

  
Kun Metasploit on käynnistynyt, voidaan aloittaa db_nmapin ajo.  
Itse suosin parametrejä: db_nmap --top-ports 100 -sV -Pn 80.221.60.3
  
Selityksenä vielä parametrit, joita tässä käytetään:
  
--top-ports 100 # Kertoo, että skannataan nmapin määrittämät 100 eniten käytettyä porttia.  
-sV # Selvittää mitä palveluja portin takana on ja mikä versio kyseisestä palvelusta.  
-Pn # Ei pingaa porttia vaan tutkii sen väkisin. Toimii hyvin, jos kohde on estänyt pingiin vastaamiset.  
Lopussa on IP-osoite, jota skannataan.

Tässä tapauksessa kokeilen aluksi ilman -Pn parametriä, koska se hidastaa hakua ja kohteessa ei välttämättä ole estetty pingiin vastaamista.  
Käytän kohteen skannaamiseen siis komentoa: db_nmap --top-ports 100 -sV 80.221.60.3  
**Huom!** Muista tarkastaa kohde IP-osoite, ettet vahingossa syyllisty rikokseen.  
  
Yleensä haku kestää jonkin aikaa ja haettavien porttien määrää pitää kasvattaa, jotta hyökkäyspinta-ala löytyy.  
Tässä tapauksessa, koska kohde pyöri virtuaalisena samalla koneella, tulokset tulivat erittäin nopeasti kahdeksassa sekunnissa.

(kuva db_nmap skannaus)


Kuten kuvasta näkeekin, niin löysi Nmap kolme avointa porttia ja tunnisti niiden takana olevat palvelut.  
Portti 21 takana on FTP palvelu. Tämän takaa voidaan mahdollisesti myöhemmin löytää joitakin tiedostoja, joita ei ole suojattu tarpeeksi hyvin.
  
Portti 22 takaa paljastuu perinteinen OpenSSH palvelu. Palvelun versio näyttäisi olevan ajantasalla, eikä siihen ole tällä hetkellä kunnollisia exploitteja, joita voitaisiin hyödyntää.
  
Portti 80 takaa löytyy perinteinen Apache2 palvelu. Tämän jo tiesimmekin, kun vierailimme IP-osoitteessa selaimella ja saimme "It works!" viestin.
  
### Haavoittuvuuksien etsiminen

Aloitan tutkimisen tuon portin 80 kautta, eli ihan vain nettiselaimella vaan tuon osoitteen. Portti 80 tarkoittaa aivan perinteistä HTTP verkkosivua.
  
Normaalisti, jos sivulla olisi muutakin kuin vain oletus sivu, tarkistaisin Firefoxin inspector toolilla sivun sisältöä ja saattaisin mahdollisesti löytää haavoittuvuuksia kirjautumisen vahvennuksessa tai cookie tiedostoja, joita voisi väärentää tai muunnella. Tässä tapauksessa tälläisiä ei kuitenkaan löytynyt.  
  
Koska sivusto ei itsessään anna tietoa mitä sen takana on, niin päätimme käyttää Nikto haavoittuvuusskanneria haavoittuvuuden löytämiseksi.
  
Nikton käyttö on melko yksinkertaista. Niktolle annetaan kohteen IP-osoite ja portti, jota halutaan tutkia. Tämä onnistuu terminaalista komennolla: "nikto -host http://80.221.60.3/ -p 80"  
Nikto paljastikin, että sivulla on piilotettu osio /secret/, sekä Apachen vakio tiedosto README on näkyvissä.

(kuva nikto skannaus)


Jos Nikto ei olisi löytänyt mitään, niin olisi meidän pitänyt kokeilla toista haavoittuvuus skanneria tai turvautua bruteforce tekniikoihin eli väkisin yrittämiseen. Tälläiseen olisi soveltunut esimerkiksi DirBuster, joka etsii väkisin piilotettuja osioita ja tiedostoja palvelimista.  
Nyt Nikto kuitenkin löysi meille mystiseltä kuullostavan /secret/ osion, jota lähdimme tutkimaan.  
  
  
Löytyneestä salaisesta osiosta osoitteessa: 80.221.60.3/secret/ löytyikin rikkinäinen blogi sivusto nimeltä "My secret blog".  
Rikkinäisyyden löytyikin nopeasti. Kun katsoi sivuston linkkejä, niin ne osoittivat domain nimeen vtcsec, kuten eräs linkki näytti tältä: "vtcsec/secret/index.php".  
Sivusto ei siis toiminut, koska se ei löytänyt kyseistä domainia. Korjasin tämän lisäämällä palvelimen etsimän domainin Kalin Hosts tiedostoon, jolloin se ohjautuisi oikein palvelimen IP-osoitteeseen.  
Hosts tiedostoa pääsin muokkaamaan komennolla: "sudo nano /etc/hosts".  
Hosts tiedostoon lisäsin harjoituskoneen IP-osoitteen ja sen perään tuon vtcsec domain nimen, jotta domain nimi ohjautuisi oikeaan osoitteeseen.  

(kuva hosts muokkaus)

  
Kun Hosts tiedosto oli kunnossa päivitin sivun ja se näkyi vihdoin kunnolla.

(kuva secret kunnossa)
  
Sivusto on selvästi Wordpressillä tehty. Jos ulkonäkö ei sitä paljastanut, niin viimeistään alapalkissa oleva "Powered by WordPress" teksti paljastaa sen samantien.  
Itse sivun kautta tuskin saan paljoa aikaan, mutta kirjautumissivun kautta voisin kokeilla päästä sisään.  
Sivulla olikin WordPressin oletus kirjautumis sivu oletus osoitteessa: http://vtcsec/secret/wp-admin  
Ei tarvinnut siis tälläkään kertaa turvautua DirBusteriin kirjautumisen löytämiseksi.  
Kokeilin kirjautumiseen oletus käyttäjätunnusta "Admin" ja salasanaksi annoin "password".  
Salasana oli väärin, eikä sivusto antanut kirjautua sisään. WordPressillä on kuitenkin pieni tietoturvallinen heikkous ja se kertoo, jos käyttäjätunnus on kuitenkin oikein. Tässäkin tapauksessa WordPress ilmoitti, että salasana käyttäjätunnukselle "Admin" on väärin, mutta samalla vahvisti käyttäjätunnuksen "Admin" olevan olemassa.  
  
(kuva admin paljastus)

Päätin käyttää Armitagella moduulia "wordpress_login_enum", jota käytetään WordPressin bruteforcettamiseen.  
Annoin moduulille Metasploitin mukana tulevan unix_passwords.txt salasana tiedostoksi, koska se sisältää useita vakio salasanoja, jotka toimivat useimmissa palveluissa.  
Käyttäjätunnukseksi määritin Admin, koska se oli jo tiedossa käsin tutkimisen avulla. Olisin myös voinut asettaa, että moduuli kokeilee tiedostosta yleisimpiä Unix käyttäjätunnuksia, jos tunnus ei olisi ollut jo tiedossa.  
  
(kuva wordpress login enum)
  
Bruteforce löysikin oikean salasanan heti. Salasana oli myös Admin. Tämän olisi voinut myös testata manuaalisti käsin, niin olisi säästytty pieneltä vaivalta. Päätin kuitenkin käyttää bruteforcea demo tarkoituksessa. Jos metasploitin vakio salasana listat eivät toimi, niin on suositeltavaa ladata ja käyttää rockyou.txt salasana listaa, sillä se sisältää erittäin monta paljon käytettyä salasanaa, jotka toimivat erittäin usein.  

(kuva wordpress brute complete)
  

Nyt pääsemme kirjautumaan WordPressin hallintaan käyttäjätunnuksella "Admin" ja salasanalla "admin".  

Sisälle päästyämme meillä on melko vapaat kädet sotkea WordPress sivusto. Haluamme kuitenkin hallinan ihan palvelimelle asti.  
Tarkistin Armitagen hyödyllisellä haulla mitä exploitteja olisi käytettävissä. Kirjoitin hakuun wp ja armitage listasin melkoisen monta eri moduulia. Lisäsin vielä wp_admin, koska meillä oli jo admin tilaan pääsy ja emme tarvitse muita moduuleja. Jäljelle jäikin yksi moduuli nimeltään "wp_admin_shell_upload".  

(kuva armitage haku)

Moduulin nimen perusteella tällä moduulilla pystyy lähettämään tiedoston WordPressin admin paneelin kautta, jolla saamme etäyhteyden itse palvelimen puolelle.  
Avasin moduulin ja katsoin mitä tietoja se tarvitsee.

(kuva wordpress shell upload)

Kuten kuvasta näkyy annoin moduulille käyttäjänimen, salasanan ja osoitteen WordPressiin. Laitoin vielä ruksin kohtaan "Use reverse connection", jolloin shell ottaakin yhteyden hyökkäävään koneeseen, eikä toisinpäin.  
Shellin syöttäminen onnistuikin mutkittomasti ja Armitagessa kohdekoneen kuvake muuttui punaiseksi ja salamoilla koristelluksi, joka kertoo siitä että koneeseen on nyt shell yhteys.  

(kuva shell yhteys saavutettu)


Nyt voimme kirjautua palvelimelle luodun meterpreter shellin kautta. Tämä onnistuu Armitagella klikkaamalla oikealla punaisena olevaa kohde konetta ja navigoimalla valikossa meterpreter1>Interact>Meterpreter Shell.  
Näin tehtyämme Armitagee aukeaa uusi "Meterpreter 1" niminen välilehti, jolla pystymme syöttämään komentoja kohde koneelle.  






