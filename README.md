#  Password Security Analyzer

Password Security Analyzer is a lightweight, browser-based tool that evaluates how strong a password really is. It scores the password against length and character-variety rules, flags weak patterns such as repeated characters, keyboard or numeric sequences and repeated chunks, checks whether the password appears in the **RockYou** wordlist or in the **Have I Been Pwned** breach corpus, estimates theoretical crack times, and generates strong random passwords with the Web Crypto API. Everything runs locally in the browser. The only network request is the Have I Been Pwned check, and it follows the k-Anonymity model, so the password itself never leaves your device.

> Built as a cybersecurity learning project. Version 1.

---

##  Features

- **Strength score** (0–100%) based on length and character variety, displayed as a color-coded ring.
- **Requirement checklist**: length ≥ 8, uppercase, lowercase, number, special character.
- **Weak pattern detection**:
  - repeated characters (`aaa`, `111`)
  - sequences (`abc`, `123`, `qwerty`, `asdf`…)
  - repeated patterns (`abab`, `123123`)
- **RockYou check**: local lookup of the password in a wordlist (`Wordlists/rockyou.txt`).
- **Have I Been Pwned check** using **k-Anonymity**: only the first 5 characters of the password's SHA-1 hash are sent to the API.
- **Crack time estimation** (average and worst case) based on a theoretical model of 255,000 guesses per second.
- **Secure password generator** built on the **Web Crypto API** (`crypto.getRandomValues`), with lengths from 4 to 64 and selectable character types.

---

##  Project structure

```
password-security-analyzer/
├── index.html
├── style.css
├── script.js
├── README.md
└── Wordlists/
    └── rockyou.txt   ← sample of ~1,000 common passwords
```

---

##  Getting started

1. Clone the repository:

   ```bash
   git clone https://github.com/S4M1X-1/password-security-analyzer.git
   cd password-security-analyzer
   ```

2. Start a local web server. This is required so the browser can load `rockyou.txt`. Opening `index.html` directly from the file system (`file://`) blocks the wordlist from loading.

   ```bash
   python3 -m http.server 8000
   ```

   You can also use the **Live Server** extension in VS Code.

3. Open [http://localhost:8000](http://localhost:8000) in your browser.

---

##  About `rockyou.txt`

 **The `Wordlists/rockyou.txt` file in this repository is NOT the full list.**
It is only a **sample of about 1,000 of the most common passwords**, so you can try the tool right away.

### Why the full list is not included

- The original RockYou list contains **more than 14 million passwords** (~133 MB), which exceeds GitHub's 100 MB file size limit.
- It comes from a **real data breach (2009)**. Rather than redistributing it, this project asks users to get it from a well-known source.

### Using the full list

For a more complete check, download `rockyou.txt` from a recognized source: 

- **Kali Linux**: the wordlist ships with the system at `/usr/share/wordlists/rockyou.txt.gz`
  ```bash
  gunzip /usr/share/wordlists/rockyou.txt.gz
  ```
- **SecLists** (a widely used security reference repository): [github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Leaked-Databases)

Then replace `Wordlists/rockyou.txt` with the full version, keeping the same name and location.

>  With the full list, the initial load can take a few seconds depending on your machine and browser.

---

##  Privacy

- All analysis happens **locally in your browser**.
- No data is stored or sent anywhere, **except** during the Have I Been Pwned check, where only a 5-character prefix of the SHA-1 hash is transmitted ([learn more about k-Anonymity](https://haveibeenpwned.com/API/v3#PwnedPasswords)).

---

## 🛠️ Tech stack

- HTML5
- CSS3
- Vanilla JavaScript
- Web Crypto API
- [Have I Been Pwned – Pwned Passwords API](https://haveibeenpwned.com/Passwords)

---

##  Disclaimer

This tool is intended for **learning and responsible use**.
Crack time estimates are **theoretical** and depend on the hashing algorithm, hardware and attack strategy used.
Do not use the RockYou wordlist for malicious purposes.

---

##  License

This project is released under the MIT License. You are free to use, modify and share it.
