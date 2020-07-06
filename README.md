# RfaAgentRepair
Tools for fixing various known issues with RMM agents

## Load the module into your session
```
Invoke-Expression (( new-object Net.WebClient ).DownloadString( 'https://raw.githubusercontent.com/RFAInc/RfaAgentRepair/master/RfaAgentRepair.psm1' ));
```

## Just run the uninstaller
```
Invoke-Expression (( new-object Net.WebClient ).DownloadString( 'https://raw.githubusercontent.com/RFAInc/RfaAgentRepair/master/RfaAgentRepair.psm1' )); Start-RfaLtUninstaller;
```
