<#
  _________                                   __    
 /   _____/__________     ____   ____   ____ |  | __
 \_____  \\____ \__  \   / ___\_/ __ \_/ __ \|  |/ /
 /        \  |_> > __ \_/ /_/  >  ___/\  ___/|    < 
/_______  /   __(____  /\___  / \___  >\___  >__|_ \
        \/|__|       \//_____/      \/     \/     \/	

	Presents:	Binary Patching Tool
	Version:	0.1d
	Released:	14/06/10
  Rel.Name: Patch-Bin.ps1
	Language:	PS1
	Author:		@jr_lambea
	Sites:		www.spageek.net

#>

<#
.SYNOPSIS
Apply patches as binary.

.DESCRIPTION
This is a template.

.PARAMETER File 
File to patch.

.PARAMETER Offset
The byte address to start write data, the format of this Offset could be decimal (3735928559d), hexadecimal (0xdeadbeef) or binary (11011110101011011011111011101111b).

.PARAMETER Bytes_to_Write
The data to write, the format could be as array of bytes value in decimal (235d), hexadecimal (0xEB) or binary (11101011b).

.EXAMPLE
Write a JMP (Hex) in a example.exe file at address 0x452EF3.

Patch-Bin.ps1 -File example.exe -Offset 0x452EF3 -Bytes_to_Write 0xEB

.EXAMPLE 
Write a "A" char in a example.txt file at address byte number 10.

Patch-Bin.ps1 -File example.txt -Offset 10d -Bytes_to_Write 65d

.NOTES

#>

Param(
    [parameter(Mandatory=$true)]
    [alias("f")]
    [string]
    $File,
    [parameter(Mandatory=$true)]
    [alias("o")]
    [string]
    $Offset,
    [parameter(Mandatory=$true)]
    [alias("b")]
    [string]
    $Bytes_to_Write)

Function parse( [String]$value )
{

    $result_value = 0

    switch -regex ($value)
    {
        "^0x[0-9,A-F]*$" { $result_value = [Convert]::ToInt64( ($value).Split("x")[1], 16 ) }
        "^[0,1]*b$" { $result_value = [Convert]::ToInt64( ($value).replace("b",""), 2 ) }
        "^[0-9]*[0-9,d]$" { $result_value = [Convert]::ToInt64( ($value).replace("d",""), 10 ) }
        default { Return $false }
    }

    Return $result_value
}

if ( !( $Offset = parse($Offset) ) -Or !( $Bytes_to_Write = parse($Bytes_to_Write) ) )
{
    "Error value format mismatch."
    Exit 3
}
