<#
  _________                                   __    
 /   _____/__________     ____   ____   ____ |  | __
 \_____  \\____ \__  \   / ___\_/ __ \_/ __ \|  |/ /
 /        \  |_> > __ \_/ /_/  >  ___/\  ___/|    < 
/_______  /   __(____  /\___  / \___  >\___  >__|_ \
        \/|__|       \//_____/      \/     \/     \/	

	Presents:	IP Geo Location
	Version:	0.9.0
	Released:	18/06/10
    Rel.Name:   Get-IPGeoLocation.ps1
	Language:	PS1
	Author:		@jr_lambea
	Sites:		www.spageek.net

#>

<#
.SYNOPSIS
Query the RESTful service of http://db-ip.com for resolve the IP Geo Location.

.DESCRIPTION
Query the RESTful service of http://db-ip.com for resolve the IP Geo Location.
You Will need BEFORE use this script to set into the script YOUR OWN API key, their service is free with a reasonable accuracy.

.PARAMETER IPv4
IPv4 Address to geolocate.

.EXAMPLE
.\Get-IPGeoLocation.ps1 193.146.141.234

Address                       Country                       StateProv                     City
-------                       -------                       ---------                     ----
193.146.141.234               ES                            Madrid                        Madrid

Query the service. It will returns an custom object as you can see.

.NOTES

#>


[CmdletBinding()]

Param(
    [parameter( Mandatory = $true, Position = 0, valueFromPipeline = $true )]
    [alias( "i" )]
    [string]$IPv4
)

$key = "--->> YOUR_KEY_HERE!! <<---"

if ( ( [System.Net.IPAddress]::Parse($IPv4) ) )
{
    $r = [System.Net.WebRequest]::Create("http://api.db-ip.com/addrinfo?addr=$IPv4&api_key=$key")
    $r.Method ="GET"
    $r.ContentLength = 0
    $res = $r.GetResponse()
    $reader = new-object System.IO.StreamReader($res.GetResponseStream())
    $resp = $reader.ReadToEnd()
    
    $loc = New-Object -TypeName Object
    $loc | Add-Member -Type NoteProperty -Name Address -value $resp.Split("""")[3]
    $loc | Add-Member -Type NoteProperty -Name Country -value $resp.Split("""")[7]
    $loc | Add-Member -Type NoteProperty -Name StateProv -value $resp.Split("""")[11]
    $loc | Add-Member -Type NoteProperty -Name City -value $resp.Split("""")[15]
    
    Return $loc
    
} else {
    "The ip $ipv4 not seems a valid IPv4 address."
    Return $False
}
