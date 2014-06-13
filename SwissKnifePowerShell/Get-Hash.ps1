<#
  _________                                   __    
 /   _____/__________     ____   ____   ____ |  | __
 \_____  \\____ \__  \   / ___\_/ __ \_/ __ \|  |/ /
 /        \  |_> > __ \_/ /_/  >  ___/\  ___/|    < 
/_______  /   __(____  /\___  / \___  >\___  >__|_ \
        \/|__|       \//_____/      \/     \/     \/	

Original credits:
# Hash Identifier v1.1
# By Zion3R
# www.Blackploit.com
# Root@Blackploit.com

Translation credits:
Presents:   Hash Identifier
Version:    1.1
Released:   13/06/10
Rel.Name:   Get-Hash.ps1
Language:   PS1
Author:     Translation by @jr_lambea
Sites:      www.spageek.net

#>

<#
.SYNOPSIS
Get the type of a hash.

.DESCRIPTION

.PARAMETER Hash
Hash to identify.

.EXAMPLE
Get-Hash.ps1 -Hash 2b903105b59299c12d6c1e2ac8016941

Gets the type of the hash 2b903105b59299c12d6c1e2ac8016941 (md5 in this case).

.NOTES

#>

[CmdletBinding()]

Param(
    [parameter( Mandatory = $true, Position = 0, valueFromPipeline = $true )]
    [alias( "h" )]
    [string]$Hash,
    [parameter( Mandatory = $false, Position = 0 )]
    [alias( "nb" )]
    [boolean]$NoBanner = $false
)

if ( !($NoBanner) )
{
    "`
    #########################################################################`
    #     __  __                     __           ______    _____           #`
    #    /\ \/\ \                   /\ \         /\__  _\  /\  _ ``\         #`
    #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #`
    #     \ \  _  \  /'__``\   / ,__\ \ \  _ ``\      \ \ \   \ \ \ \ \       #`
    #      \ \ \ \ \/\ \_\ \_/\__, ``\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #`
    #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #`
    #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.1 #`
    #                                                             By Zion3R #`
    #                                                    www.Blackploit.com #`
    #                                                   Root@Blackploit.com #`
    #                                                 PS port by @jr_lambea #`
    #                                                       www.spageek.net #`
    #########################################################################`
    "
}

function CRC16(){
    hs='4607'
    if ( ( $hash.Length -eq $hs.Length ) -And ( $Hash.isalpha() -eq $False ) -And ( hash.isalnum() -eq $True ) { jerar.append("101020") }
}
    
