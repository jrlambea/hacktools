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
