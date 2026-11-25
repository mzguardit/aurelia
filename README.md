# Aurelia VPN · Tor Network Client for Windows

Aurelia è un client VPN Tor per Windows sviluppato in C11 nativo, che instrada il traffico di rete a livello di sistema attraverso la rete Tor tramite driver Wintun ad alte prestazioni e filtraggio WFP (Windows Filtering Platform).

---

## Caratteristiche Principali

- **Wintun Tun Device**: Tunneling L3 ad alte prestazioni con stack TCP nativo.
- **Fail-Closed Kill Switch**: Regole firewall WFP per bloccare qualsiasi fuga accidentale di traffico non instradato.
- **Protezione Anti-Leak DNS**: Tutte le query DNS passano tramite MapDNS interno (198.18.0.2) verso Tor, evitando leak su server locali.
- **Isolamento e Circuit Display**: Visualizzazione in tempo reale di Guard, Middle ed Exit relay con calcolo della latenza e verifica anti-MITM.
- **Interfaccia Vettoriale Anti-Aliased**: GUI GDI+ fluida, priva di dipendenze esterne o framework pesanti.
- **Bundle Portabile Standalone**: Include il core Tor, database GeoIP e librerie di tunneling pronte all'avvio su qualsiasi macchina Windows 10/11 x64.

---

## Requisiti

- Windows 10 / Windows 11 (64-bit)
- Privilegi di Amministratore (necessari per la creazione dell'interfaccia Wintun e le regole WFP)

---

## Compilazione da Sorgente

Per compilare con CMake e MSVC (Visual Studio Build Tools):

```powershell
cmake -B build -S .
cmake --build build --config Release
```

I binari generati saranno disponibili nella cartella `build/Release/`.

---

## Licenza

Questo progetto è distribuito sotto la licenza **Aurelia Non-Commercial Public License 1.0**.
L'uso per scopi personali, di ricerca, di studio e di audit di sicurezza è libero e gratuito. È espressamente vietata la rivendita, la commercializzazione o l'inclusione in servizi a pagamento. Consultare il file `LICENSE` per i dettagli completi.
