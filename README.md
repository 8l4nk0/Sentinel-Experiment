# Sentinel-Experiment
tl, dr: Mappare i tentativi di autenticazione fallita di tutto il mondo con Azure Sentinel<br>

L'obiettivo di questo esperimento era di riuscire a mappare i tentativi di autenticazione fallita su una macchina virtuale windows vulnerabile grazie a Azure Sentinerl.<br>
Svolgimento:<br>

1)
Creazione della macchina virtuale Windows 10 tramite il servizio Azure (io ho fatto la registrazione gratuita).<br>
Ho aperto la macchina virtuale con la funzionalità Windows Desktop Remoto tramite l'IP pubblico della VM.<br>
Dalle impostazioni della VM su Azure ho modificato la regola delle connessioni in entrata così che la VM fosse soggetta a qualsiasi scan che fossero SYN o ICMP o ...<br>
Aperta la VM ho poi disattivato il firewall a livello di dominio, di privato e pubblico.<br>

2)
Creazione dell'ambiente di lavoro dei log su Azure. <br>
Ho collegato questo ambiente di lavoro alla VM in modo tale che potesse leggerne i file di sistema. Ci servirà per la fase 4).<br>

3)
Sulla VM poi ho aperto il visualizzatore eventi per vedere quali fossero gli eventi in corso. <br>
Tra questi, l'evento con EventID = 4625 è quello che descrive i tentativi di autenticazione fallita da remoto.<br>
Tramite lo script powershell di Josh Madakor (a questo indirizzo: https://github.com/joshmadakor1/Sentinel-Lab/blob/main/Custom_Security_Log_Exporter.ps1)
che ho copiato e incollato sulla VM in un file .ps1.
Ho aperto lo script con Powershell_ISE.<br>
Questo script permette di raccogliere gli eventi con EventID 4625 dal visualizzatore eventi di Windows.<br>
In questi eventi, nei dettagli si trova l'indirizzo IP di chi ha provato ad effettuare l'accesso non autorizzato.<br>
Sfruttando questa informazione e grazie all'API key del servizio geoiplocation.io praticamente incolliamo l'ip dell'"attaccante" per ricavarne
vari valori quali latitudine, longitudine, ip sorgente, ip destinazione, stato, paese, città, orario e giorno che lo script salva in un file al
percorso C:\ProgramData\failed_rdp.log della VM.<br>

4)
Grazie al collegamento effettuato prima, ora possiamo creare un log personalizzato chiamato FAILED_RDP_WITH_GEO_CL in cui carichiamo il contenuto del file generato dallo script Powershell.
Un esempio del file che lo script ha generato a me:<br>
![esempio log](https://github.com/user-attachments/assets/a4308a33-8994-4daf-baf6-4941d9a5c153)<br>



Siccome i log registrati nel file appaiono come stringa unica, ho utilizzato una query in KQL per filtrare i singoli valori tramite espressioni regolari:<br>

FAILED_RDP_WITH_GEO_CL<br>
| extend Latitude = extract(@"latitude:([+-]?\d+\.\d+)", 1, RawData)<br>
| extend Longitude = extract(@"longitude:([+-]?\d+\.\d+)", 1, RawData)<br>
| extend DestinationHost = extract(@"destinationhost:([^,]+)", 1, RawData)<br>
| extend SourceHost = extract(@"sourcehost:([^,]+)", 1, RawData)<br>
| extend State = extract(@"state:([^,]+)", 1, RawData)<br>
| extend Country = extract(@"country:([^,]+?)(?:,|$)", 1, RawData)<br>
| extend Label = extract(@"label:([^,]+)", 1, RawData)<br>
| extend Timestamp = extract(@"timestamp:([^,]+)", 1, RawData)<br>
| project Latitude, Longitude, DestinationHost, SourceHost, State, Country, Label, Timestamp<br>


In questo modo riusciamo a vedere i singoli valori dei campi che ci servono per la mappatura.<br>


5)
Dopo aver creato un'istanza di Azure Sentinel e averla collegata al nostro ambiente di lavoro dei log ho scritto questa query per ottere i valori dei vari campi più
il campo event_count() per tenere traccia del numero di tentativi effettuati dalle singole differenti sorgenti. <br>
Ho usato sempre una query KQL con uso di espressioni regolari per ordinare e filtrare i valori. Ho inoltre escluso tutti i valori con:<br>
- sorgente ignota<br>
- destinazione = samplehost (sono i log generati in automatico dallo script per verificare il funzionamento del tutto)<br>
- stato ignoto<br>
Questa è la query che ho usato io:<br>

FAILED_RDP_WITH_GEO_CL<br>
| extend Latitude = extract(@"latitude:([+-]?\d+\.\d+)", 1, RawData)<br>
| extend Longitude = extract(@"longitude:([+-]?\d+\.\d+)", 1, RawData)<br>
| extend DestinationHost = extract(@"destinationhost:([^,]+)", 1, RawData)<br>
| extend SourceHost = extract(@"sourcehost:([^,]+)", 1, RawData)<br>
| extend State = extract(@"state:([^,]+)", 1, RawData)<br>
| extend Country = extract(@"country:([^,]+?)(?:,|$)", 1, RawData)<br>
| extend Label = extract(@"label:([^,]+)", 1, RawData)<br>
| extend Timestamp = extract(@"timestamp:([^,]+)", 1, RawData)<br>
| where SourceHost != "" and State != "null" and DestinationHost != "samplehost"<br>
| project Latitude, Longitude, DestinationHost, SourceHost, State, Country, Label, Timestamp<br>
| summarize event_count= count() by SourceHost, DestinationHost, Latitude, Longitude, Country, Label<br>


6)
Impostando la visualizzazione dei log su Mappa, ho filtrato i log per latitudine e longitudine differenziandone il colore e la grandezza in base al numero di tentativi effettuati.<br>
Questo è il risultato finale:<br>

![mappa finale](https://github.com/user-attachments/assets/1ba65e0d-f5d5-443b-8a7f-1ed70a6aabd8)<br>


