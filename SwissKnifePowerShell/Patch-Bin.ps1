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

.EXAMPLE
Patch all files from pipe writing two NOPs.

Get-ChildItem *.exe | Patch-Bin.ps1 -Offset 0x45EA67 -Bytes_to_Write 0x9090

.NOTES

#>

[CmdletBinding()]

Param(
    [parameter( Mandatory = $true, Position = 0, valueFromPipeline = $true )]
    [alias( "f" )]
    [string]$File,

    [parameter( Mandatory = $true )]
    [alias( "o" )]
    [string]$Offset,

    [parameter( Mandatory = $true )]
    [alias( "b" )]
    [string[]]$Bytes_to_Write
)

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

Function parseArray( [String[]]$value )
{

    $result_value = @()
    $result = $true

    $value | % {
        
        if ( !( parse($_) ) -Or ( (parse($_)) -gt 255 ) )
        {
            $result = $false

        } else {
            $result_value += parse($_)

        }

    }

    if ( !($result) ) { Return $false } else { Return $result_value }

}

if ( !( parse($Offset) ) -Or !( parseArray($Bytes_to_Write) ) )
{
    "[e] Error value format mismatch."; Exit 3
}

$Offset = parse($Offset)
$Bytes_to_Write = parseArray($Bytes_to_Write)

If ( !( Test-Path "$File" ) )
{
    "[e] Error file doesn't exist."; Exit 4

} else {
    $File = ( Get-ChildItem $File ).FullName

}

$Min_len = [Int]$Offset + $Bytes_to_Write.Length

If ( ( Get-ChildItem $File ).Length -lt $Min_len )
{
    "[e] Error Params: Out of Range"; Exit 5
}

"[i] Opening $File for edit."
[System.IO.BinaryWriter]$br = [System.IO.File]::Open( $File, 3 )

"[i] Seeking offset " + $Offset
if ( $br.BaseStream.seek( $Offset,0 ) )
{
    $Bytes_to_Write | % {
        "[i] Writing byte " + $_
        $br.BaseStream.WriteByte( $_ )
    }

}

"[i] Patch success. Closing file."
$br.Close()

Exit 0
