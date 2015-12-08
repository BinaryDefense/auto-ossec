#REQUIRES -Version 2.0
<#
.SYNOPSIS
    Uses the WiX Toolset to create an msi.
.NOTES
    File Name      : Create-MsiForAutoOSSEC.ps1
    Author         : Binary Defense Systems
    Prerequisite   : WiX Toolset v3.10
    Copyright 2015 - Binary Defense Systems
.LINK
    WiX Toolset Can be found at:
    http://wixtoolset.org/
#>

$addr = Read-Host 'What is the IP Address where you will be running auto_server.py?'

Write-Host 'Compiling...'
& 'C:\Program Files (x86)\WiX Toolset v3.10\bin\candle.exe' -dServerAddress="$addr" .\auto_ossec.wxs

Write-Host 'Linking...'
& 'C:\Program Files (x86)\WiX Toolset v3.10\bin\light.exe' -spdb -out auto_ossec.msi auto_ossec.wixobj

Write-Host 'Cleaning up...'
Remove-Item auto_ossec.wixobj
