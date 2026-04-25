Scope:

1. tcp kommunikáció
    - kliens csatlakozik
    - szerver listenel tcp 5150-es porton
2. MTP
    - message struktúra (hdr + payload + mac)
    - AES-GCM enc
    - seq num
    - replay protection
    Header:
        - ver (2B)
        - typ (2B)
        - len
        - sqn
        - rnd
        - rsv
3. Login protocol
    - auth + session key establishment
    - kliens: generál tk (temp AES kulcs) + client_random + RSA titkosítás
    - szerver: RSA privát kulcs + tk visszafejtés
    - mindkettő: HKDF -> final session key
    - RSA + ARS + KDF
4. Commands protocol
    - pwd
    - lst
    - chd
    - mkd
    - del
    - upl
    - dnl
4. Upload / download
    - 1024 byte-os fragmentek
    - SHA-256
5. Kriptográfia
    - AES-GCM
    - RSA-OAEP (2048 bit)
    - SHA-256
    - HKDF
    - jelszó hashelés

Lépések:

kommunikáció (TCP kliens + szerver) -> 
MTP skeleton (msg struct/parse, header kezelés, seq num tracking) -> 
AES-GCM implementáció (encrypt payload, decrypt+verify, nonce = sqn + rnd) -> 
Login protocol (RSA kulcspár, login_req, login_res, HKDF kulcs deriv) -> 
parancsok (string parsing, fájl műveletek, request_hash validáció) -> 
Upload/download (chunkolás, SHA-256 ellenőrzés) -> 
edge-cases (hibakezelés, connection close szabályok, replay attack védekezés)
