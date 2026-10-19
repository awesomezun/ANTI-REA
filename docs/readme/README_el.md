[English](../../README.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](README_ko.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md) · **Ελληνικά** · [മലയാളം](README_ml.md)

# ANTI-REA

### Ένα ενιαίο MCP για την προστασία δυαδικών αρχείων, εφαρμογών και βασικής λογικής από την ανάλυση του REA.

**Έχετε μια κρίσιμη λειτουργία που θέλετε να προστατεύσετε; Αποτρέψτε την ανάλυση και την αντιγραφή της μέχρι το δυαδικό επίπεδο.**

[![Defense vs REA](https://img.shields.io/badge/Defense_vs_REA-25%25-4bbd9c?style=flat-square)](#roadmap)
[![MCP + CLI](https://img.shields.io/badge/MCP-stdio_%2B_CLI-5c4ee5?style=flat-square)](#quick-start)
[![Python requirements](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)](#quick-start)
[![Engines](https://img.shields.io/badge/Engines-ANTI--REA_Engine_%7C_VMP_%7C_Themida_%7C_CV-cb3837?style=flat-square)](#engines)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)

Εργαλεία αντίστροφης μηχανικής όπως το [REA](https://github.com/morluto/rea) επιτρέπουν σε έναν πράκτορα (agent) να αναλύσει ένα εκτελέσιμο αρχείο και να ανακατασκευάσει την ακριβή λογική του όταν του ζητήσετε: *«Κατανόησε πώς λειτουργεί αυτό το χαρακτηριστικό σε εκείνη την εφαρμογή και φτιάξε το ίδιο στο έργο μου»*.

**Επίθεση με πράκτορες AI; Τότε η απάντησή μας είναι άμυνα με πράκτορες AI — μια άμυνα που γίνεται ολοένα και πιο ισχυρή με την πάροδο του χρόνου.** Ο τελικός στόχος του **ANTI-REA** είναι **να μπλοκάρει καθετί που μπορεί να αναλύσει το REA**. Απλώς ζητήστε από τον πράκτορά σας σε φυσική γλώσσα: **«Προστάτευσε τη βασική λογική του προγράμματός μου ώστε να μην μπορεί το REA να την αναλύσει ή να την κλωνοποιήσει»**, και ο πράκτορας θα εντοπίσει τον κρίσιμο κώδικα και τα γύρω στοιχεία, θα εφαρμόσει συσκότιση (obfuscation) και εικονικοποίηση (VM), θα ελέγξει ότι η αρχική λειτουργία παραμένει ανέπαφη και θα μετρήσει σε τι ποσοστό της αρχικής ταχύτητας εκτελείται.

Δεν χρειάζεται να στήσετε μόνοι σας ένα πολύπλοκο εργαστήριο επίθεσης και άμυνας. **Κάθε μέρα φέρνουμε τον υπολογιστή άμυνάς μας αντιμέτωπο με έναν ξεχωριστό υπολογιστή επίθεσης REA, βλέπουμε πώς παραβιάζεται η VM στο TestApp, κλείνουμε τα κενά και ενισχύουμε την άμυνα.** Εσείς απλώς συνδέετε το ANTI-REA στον πράκτορά σας.

---

## Τρέχουσα Ισχύς Άμυνας & Οδικός Χάρτης (TestApp VM εναντίον πραγματικών επιθέσεων REA)

![TestApp VM Defense vs. REA 25%](../../docs/assets/defense-roadmap.svg)

Το παραπάνω ποσοστό δεν είναι ένα θεωρητικό χρονοδιάγραμμα, αλλά δείχνει **πόσο αντέχει το προστατευμένο με VM TestApp μας απέναντι σε απευθείας επιθέσεις του REA από άλλο μηχάνημα**.

### Στάδια Ενίσχυσης Άμυνας (Τελικός Στόχος: Φραγή όλων όσων αναλύει το REA)

- **25% (Τώρα) · Αποτροπή στατικής ανακατασκευής 1ου σταδίου:** Η διαφοροποίηση των handlers και η σύνδεση συμφραζομένων των τελεστών εμπόδισαν τη στατική ανάλυση του REA να ανακτήσει τον τύπο.
- **50% · Φραγή στατικής ανάλυσης & συμπερασμού συμφραζομένων:** Απόκρυψη βοηθητικών συναρτήσεων εντός του dispatcher και ενδείξεων στο γράφημα κλήσεων.
- **75% · Άμυνα απέναντι σε δυναμική ανίχνευση & αποσφαλμάτωση:** Προστασία της λογικής και των σταθερών από debuggers, Frida, ίχνη εκτέλεσης και memory dumps.
- **100% · Πλήρης άμυνα σε όλους τους στόχους και τις διαδρομές του REA:** Επέκταση από εγγενή δυαδικά (C/C++, Rust, Go) σε .NET, Java/Kotlin, JavaScript/Electron, Python και macOS (Mach-O/ARM64).

---

## Γρήγορη εκκίνηση

### 1. Εγκατάσταση & Σύνδεση στον Πράκτορα (`Set up your agent`)

Χωρίς χειροκίνητες εντολές τερματικού ή επεξεργασία αρχείων JSON· απλώς ζητήστε από τον πράκτορά σας (Claude Code, Cursor, Codex, Gemini CLI κ.λπ.):

```text
Εγκατάστησε το ANTI-REA σε ένα τοπικό εικονικό περιβάλλον Python (.venv) και σύνδεσε τον διακομιστή antirea.defense_mcp στις ρυθμίσεις MCP ώστε να μπορείς να τον χρησιμοποιήσεις αμέσως.
```

### 2. Ζητήστε το σε φυσική γλώσσα (`Ask your agent`)

```text
Προστάτευσε τη βασική υπολογιστική λογική και τα γύρω στοιχεία στο έργο μου ώστε να μην μπορεί το REA να τα αναλύσει ή να τα κλωνοποιήσει, και πες μου αν η αρχική λειτουργία παραμένει άθικτη και σε τι ποσοστό της αρχικής ταχύτητας τρέχει.
```

```text
Δημιούργησε πρώτα ένα πλάνο προστασίας με το VMProtect για το app.exe, δείξε μου το και εκτέλεσέ το μόλις το εγκρίνω.
```

### 3. Απευθείας χρήση από το τερματικό (`Use the terminal`)

```powershell
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json providers
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json doctor
```

---

## Πώς λειτουργεί & πώς δυναμώνει καθημερινά

![ANTI-REA Overview](../../docs/assets/antirea-overview.svg)

| Iteration | Protection | REA Outcome |
|---|---|---|

---

## Υποστηριζόμενες Μηχανές

Ενώ η ενσωματωμένη μηχανή ανοιχτού κώδικα (`ANTI-REA Engine`) δυναμώνει καθημερινά, **αν χρειάζεστε ακόμη ισχυρότερη προστασία άμεσα, μπορείτε να αγοράσετε το Themida, το VMProtect ή το Code Virtualizer, να το συνδέσετε στο ANTI-REA και απλώς να γράψετε σε φυσική γλώσσα στον πράκτορά σας τι απόδοση εκτέλεσης και τι επίπεδο άμυνας επιθυμείτε.**

```text
Χρησιμοποίησε το VMProtect (ή Themida / Code Virtualizer) διατηρώντας την ταχύτητα εκτέλεσης πάνω από το 80% της αρχικής, ενώ προστατεύεις τη βασική λογική όσο το δυνατόν πιο ισχυρά.
```

| Engine | Connection | Status |
|---|---|---|
| **ANTI-REA Engine** | C++/LLVM defense pipeline | Active VM protection, automated verification & daily hardening (Windows x86-64) |
| **Themida** | Defense MCP/CLI (`.tmd`/`.tm`) | Windows native x86/x64 PE adapter implemented |
| **VMProtect** | Defense MCP/CLI (`.vmp`) | Windows native x86/x64 PE adapter implemented |
| **Code Virtualizer** | Defense MCP/CLI (`.cv`) | Windows native x86/x64 PE adapter implemented |

---

## Ανάπτυξη & Δοκιμές

```powershell
python -m unittest discover -s tests -v
```

Αυτό το έργο διανέμεται υπό την άδεια [MIT License](../../LICENSE) (οι συνδεδεμένες μηχανές προστασίας διέπονται από τις δικές τους άδειες).
