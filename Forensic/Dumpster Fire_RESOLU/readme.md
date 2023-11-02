# Dumpster Fire

__author__: John Hammond

__synopsis__: We found all this data in the dumpster! Can you find anything interesting in here, like any cool passwords or anything? Check it out quick before the foxes get to it!

__Attachements__: dumpster_fire.tar.xz

---

Bon, pas beaucoup d'indices dans le titre ou l'explication, à part peut être un petit tour sur firefox et ses profils (**check it out before the foxes get to it**)

On commence par lister ce qu'il y a dans l'archive

```bash
tar --list -f dumpster_fire.tar.xz
```

Ce qui nous donne le résultat suivant:

```bash
bin/
bin/bash
bin/bzip2
bin/bzcat
bin/bunzip2
bin/bzcmp
bin/bzdiff
bin/bzegrep
bin/bzexe
bin/bzfgrep
bin/bzgrep
bin/bzip2recover
bin/bzless
bin/bzmore
bin/cat
bin/chgrp
bin/chmod
bin/chown
bin/cp
[…]
var/lib/dpkg/triggers/
var/lib/dpkg/triggers/Lock
var/lib/dpkg/triggers/Unincorp
var/lib/dpkg/triggers/ldconfig
var/lib/dpkg/updates/
var/lib/dpkg/diversions
var/lib/dpkg/diversions-old
```

Bon nous avons un joli filesystem unix, avec l'indice sur firefox, nous allons chercher dans le dossier utilisateur

```bash
ls -alh /home
total 4,0K
drwxr-xr-x 1 tiphergane tiphergane    0  7 nov.   2020 .
drwxr-xr-x 1 tiphergane tiphergane 4,0K  2 nov.  17:30 ..
drwxr-xr-x 1 tiphergane tiphergane    0  7 nov.   2020 challenge
```

Challenge semble être notre cible

```bash
ls -alh /home/challenge
total 12K
drwxr-xr-x 1 tiphergane tiphergane    0  7 nov.   2020 .
drwxr-xr-x 1 tiphergane tiphergane    0  7 nov.   2020 ..
-rw-r--r-- 1 tiphergane tiphergane  220  7 nov.   2020 .bash_logout
-rw-r--r-- 1 tiphergane tiphergane 3,7K  7 nov.   2020 .bashrc
drwxr-xr-x 1 tiphergane tiphergane    0  7 nov.   2020 .mozilla
-rw-r--r-- 1 tiphergane tiphergane  807  7 nov.   2020 .profile
```

Bingo, nous avons un repertoire de configuration **mozzilla**.

Il est de notoriété publique que nous pouvons extraire les mots de passe depuis un profil, comme nous sommes dans un CTF, nous allons tester cela de suite.

Nous allons utiliser [Firefox Decrypt](https://github.com/unode/firefox_decrypt) de **unode**  pour cela.

Une fois le clone fait, il ne vous reste plus qu'a lui demander de scanner la base sqlite du profil et d'extraire nos informantions:

```bash
python /opt/firefox_decrypt/firefox_decrypt.py home/Challenge/.mozilla/firefox/bc1m1zlr.default-release
2023-11-02 17:49:38,959 - WARNING - profile.ini not found in home/challenge/.mozilla/firefox/bc1m1zlr.default-release/
2023-11-02 17:49:38,959 - WARNING - Continuing and assuming 'home/challenge/.mozilla/firefox/bc1m1zlr.default-release/' is a profile location

Website:   http://localhost:31337
Username: 'flag'
Password: 'flag{35446041dc161cf5c9c325a3d28af3e3}'
```


