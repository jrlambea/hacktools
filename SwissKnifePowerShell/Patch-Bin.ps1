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
Patch-Bin.ps1 -File example.exe -Offset 0x452EF3 -Bytes_to_Write 0xEB

Write a JMP (Hex) in a example.exe file at address 0x452EF3.

.EXAMPLE
Patch-Bin.ps1 -File example.txt -Offset 10d -Bytes_to_Write 65d

Write a "A" char in a example.txt file at address byte number 10.

.EXAMPLE
Get-ChildItem *.exe | Patch-Bin.ps1 -Offset 0x45EA67 -Bytes_to_Write 0x9090

Patch all files from pipe writing two NOPs.

.EXAMPLE
.\Patch-Bin.ps1 -File .\example.txt -Offset 0x1 -Bytes_to_Write 0x69 -ForPipeLine:$True | .\Patch-Bin.ps1 -Offset 0x9 -Bytes_to_Write 0x70

Using "ForPipeLine" to use multiple pipelines to patch the same file.

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
    [string[]]$Bytes_to_Write,

    [parameter( Mandatory = $false)]
    [alias( "p" )]
    [boolean]$ForPipeLine = $false
)

# Function to parse and convert a value to integer.
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

# Function to use the parse with an array of values.
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

# If any of the input values is not parseable then exit with code 3
if ( !( parse($Offset) ) -Or !( parseArray($Bytes_to_Write) ) )
{
    "[e] Error value format mismatch."; Exit 3
}

# Assign integer parsed values to Offset and Bytes_to_Write
$Offset = parse($Offset)
$Bytes_to_Write = parseArray($Bytes_to_Write)

# Test if the input file exists, if not exits with code 4
If ( !( Test-Path "$File" ) )
{
    "[e] Error file doesn't exist."; Exit 4

} else {
    $File = ( Get-ChildItem $File ).FullName

}

<#
 Test if the inputed values does not exceed from the file length,
 if exceeds then exits with code 5.
#>
$Min_len = [Int]$Offset + $Bytes_to_Write.Length

If ( ( Get-ChildItem $File ).Length -lt $Min_len )
{
    "[e] Error Params: Out of Range"; Exit 5
}

# Apply patch
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

# If ForPipeLine then returns file name, if not returns $true
If ( $ForPipeLine ) { Return $File } else { Return $true }
