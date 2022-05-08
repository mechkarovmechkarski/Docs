@echo off
SET Domain=set
SET Name=account
SET Server=IP

SET text=Enter Domain name: 
ECHO %text%
ECHO %Domain%

SET text=*******
ECHO %text%

SET text=Enter username for domain %Domain%: 
ECHO %text%
ECHO %Name%

SET text=*******
ECHO %text%

SET text=Domain controllers in scania.local:
ECHO %text%
SET text=server (IP)
ECHO %text%
SET text=Enter domain controller IP:
ECHO %text%

ECHO %Server%
SET text=*******
ECHO %text%

runas /netonly /user:%Domain%\%Name% "mmc %SystemRoot%\system32\dsa.msc /server=%Server%"