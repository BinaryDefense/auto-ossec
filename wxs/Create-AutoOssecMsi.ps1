#REQUIRES -Version 2.0
<#
.SYNOPSIS
    Uses the WiX Toolset to create an msi.
.NOTES
    File Name      : Create-MsiForAutoOSSEC.ps1
    Author         : Binary Defense Systems
    Prerequisite   : WiX Toolset v3.10
    Copyright 2015 through 2016 to Binary Defense Systems, LLC
.LINK
    WiX Toolset Can be found at:
    http://wixtoolset.org/
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$False, Position=1)]
    [string]$Address = $(Read-Host "What is the IP Address where you will be running auto_server.py?")
)

Write-Host "MSI will be built for Address: ${Address}`n"

Write-Host -NoNewLine "Compiling...              "
& 'C:\Program Files (x86)\WiX Toolset v3.10\bin\candle.exe' -dServerAddress="$Address" .\auto_ossec.wxs | Out-Null
Write-Host "compiled."

Write-Host -NoNewLine "Linking...                "
& 'C:\Program Files (x86)\WiX Toolset v3.10\bin\light.exe' -spdb -out auto_ossec.msi auto_ossec.wixobj | Out-Null
Write-Host "linked."

Write-Host -NoNewLine "Cleaning up...            "
Remove-Item auto_ossec.wixobj | Out-Null
Write-Host "cleaned up."
