# Bad Memory

__author__: John Hammond

__synopsis__: A user came to us and said they forgot their password. Can you recover it? The flag is the MD5 hash of the recovered password wrapped in the proper flag format.
Download the file(s) below and press the Start button on the top-right to begin this challenge.

__Attachements__: image.zip

---

Mémoire, Forensics, premier réflexe, on lance volatility sur le fichier dézipé

```bash
vol -f image.bin windows.info
```

L'image est bien sous windows, comme on recherche un mot de passe, on va directement utiliser le module windows.hashdump

```bash
vol -f image.bin windows.hashdump
```

ce que nous retourne les informations suivantes:

```bash
User	rid	lmhash	nthash
Administrator	500	aad3b435b51404eeaad3b435b51404ee	31d6cfe0d16ae931b73c59d7e0c089c0
Guest	501	aad3b435b51404eeaad3b435b51404ee	31d6cfe0d16ae931b73c59d7e0c089c0
DefaultAccount	503	aad3b435b51404eeaad3b435b51404ee	31d6cfe0d16ae931b73c59d7e0c089c0
WDAGUtilityAccount	504	aad3b435b51404eeaad3b435b51404ee	4cff1380be22a7b2e12d22ac19e2cdc0
congo	1001	aad3b435b51404eeaad3b435b51404ee	ab395607d3779239b83eed9906b4fb92
```


Un peu de regex-fu pour mettre le fichier en forme pour hashcat, au final il devra ressembler à cela:

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:4cff1380be22a7b2e12d22ac19e2cdc0:::
congo:1001:aad3b435b51404eeaad3b435b51404ee:ab395607d3779239b83eed9906b4fb92:::
```

Une fois mis en forme, on lance hashcat

```bash
hashcat -a 0 -m 1000 hashdump /opt/SecLists/Passwords/rockyou.txt --username
```

Et le travail ce fait extrêmement rapidement.

```
Administrator:31d6cfe0d16ae931b73c59d7e0c089c0:
Guest:31d6cfe0d16ae931b73c59d7e0c089c0:
DefaultAccount:31d6cfe0d16ae931b73c59d7e0c089c0:
congo:ab395607d3779239b83eed9906b4fb92:goldfish#
```

Congo nous donnes donc son mot de passe, il nous reste plus qu'à le hasher en MD5

```bash
echo -n "goldfish" | md5sum
```

Ce qui donne le résultat suivant:

2eb53da441962150ae7d3840444dfdde

Le flag était donc:

flag{2eb53da441962150ae7d3840444dfdde}
