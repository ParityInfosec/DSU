#  Copyright (c) 2024 Justin Cornwell justin.cornwell@trojans.dsu.edu
#  Created Date: Friday, May 17th 2024, 14:31:00 HST
#  Author: Justin Cornwell
#  ----------------
#  Course: CSC842
#  Project/Lab: Cycle1 - Expander-Check
#  ----------	---	----------------------------------------------------------

<#

.SYNOPSIS
This is a PowerShell script which redirects known url shortners to localhost, resolves full link, determines if domain is a threat (via virustotal API), provides popup to approve or block, and redirects appropriately.

.DESCRIPTION
This script will allow users to gain awareness on URL shortner redirects prior to following in case of malicious redirects.
* Note: This script is only created to handle known sites and immediate redirects. Cannot handle custom vanity URLs 

.EXAMPLE
Import-Module .\expander-check.ps1

.EXAMPLE
Expander-Check -apiKey "68FC955B5E9D194D320906D8FF43E16E8FA0A64F"

.EXAMPLE
Expander-Check -shortURLs "custom.ly"

.NOTES
This script is under active development.

.LINK
https://github.com/ParityInfosec/DSU/CSC842/

#>

param (
    [string]$apiKey = "ABCDE",  # VirusTotal API Key required for receiving threat data, do not hardcode
    [string[]]$shortURLs = @(
                            "3.ly", "bit.ly", "bitly.kr", "bl.ink", "buff.ly", "clicky.me", "cutt.ly", "Dub.co", "fox.ly", "gg.gg", "han.gl", "hoy.kr", "is.gd",
                            "KurzeLinks.de", "kutt.it", "LinkHuddle.com", "LinkSplit.io", "lstu.fr", "name.com", "oe.cd", "Ow.ly", "rebrandly.com", "rip.to", 
                            "san.aq", "short.io", "shorturl.at", "smallseotools.com", "spoo.me", "switchy.io", "t.co", "T2M.co", "tinu.be", "TinyURL.com", "T.LY", 
                            "urlr.me", "v.gd", "vo.la"
                            ), # short list of shortners
    [string]$hostsFile = "C:\Windows\System32\drivers\etc\hosts"    # For forcing redirect
)

# For HTTP/HTTPS listeners
Add-Type @"
using System;
using System.Net;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using System.Security.Authentication;
"@

function ExpandURL([string]$URL) {      # Credit: @mdxkln / xkln.net
    (Invoke-WebRequest -MaximumRedirection 0 -Uri $URL -ErrorAction SilentlyContinue).Headers.Location
}

# Redirect local to local requests on 80/443 to new ports 8080/8081
function StartProxy {
    Start-Process -FilePath "netsh" -ArgumentList "interface portproxy add v4tov4 listenport=80 listenaddress=127.0.0.1 connectport=8080 connectaddress=127.0.0.1"
    #Start-Process -FilePath "netsh" -ArgumentList "interface portproxy add v4tov4 listenport=443 listenaddress=127.0.0.1 connectport=8081 connectaddress=127.0.0.1"
    
}

# Remove redirection / Clean Up
function StopProxy {
    Start-Process -FilePath "netsh" -ArgumentList "interface portproxy delete v4tov4 listenport=80 listenaddress=127.0.0.1"
    #Start-Process -FilePath "netsh" -ArgumentList "interface portproxy delete v4tov4 listenport=443 listenaddress=127.0.0.1"
}

# VirusTotal uses base64 encoded domains for URL Identifiers in API calls
function Convert-ToBase64Url {
    param (
        [string]$url
    )
    # Encode the URL to bytes
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($url)
    
    # Convert bytes to base64 string
    $base64Url = [Convert]::ToBase64String($bytes)
    
    # Replace URL-unsafe characters according to Base64URL encoding
    $base64Url = $base64Url.Replace('+', '-').Replace('/', '_').TrimEnd('=')
    
    return $base64Url
}

# VirusTotal API checker to find threat "rating" of website
function CheckSite ([string]$URL){ 
    $domain = [System.Uri]::new($url)
    $base64dom = Convert-ToBase64Url ($domain)
    $headers=@{}
    $headers.Add("accept", "application/json")
    $response = Invoke-WebRequest -Uri 'https://www.virustotal.com/api/v3/domains/$base64dom' -Method GET -Headers $headers
}

# Function to display the options box with UAC prompt
# WORKS, but no UAC prompt
function Show-OptionsBox {
    param([string]$message)
    [void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Redirect Link Alert"
    $form.Size = New-Object System.Drawing.Size(300,200)
    $form.StartPosition = "CenterScreen"

    $label = New-Object System.Windows.Forms.Label
    $label.Text = "$message.\n\n Do you want to continue?"
    $label.Size = New-Object System.Drawing.Size(280,40)
    $label.Location = New-Object System.Drawing.Point(10,20)
    $form.Controls.Add($label)

    $yesButton = New-Object System.Windows.Forms.Button
    $yesButton.Text = "Continue"
    $yesButton.Location = New-Object System.Drawing.Point(50,80)
    $yesButton.Add_Click({
        $form.DialogResult = [System.Windows.Forms.DialogResult]::Yes
        $form.Close()
    })
    $form.Controls.Add($yesButton)

    $noButton = New-Object System.Windows.Forms.Button
    $noButton.Text = "Quit"
    $noButton.Location = New-Object System.Drawing.Point(150,80)
    $noButton.Add_Click({
        $form.DialogResult = [System.Windows.Forms.DialogResult]::No
        $form.Close()
    })
    $form.Controls.Add($noButton)

    $result = $form.ShowDialog()
    return $result
}

function Listeners {
    param (
        [string]$HttpPort = "8080",
        [string]$HttpsPort = "8081"
    )

    # Get cert if already exists, build if none present 
    if (Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -eq 'CN=localhost' }) {
        $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -eq 'CN=localhost' }
    } else {
        $cert = New-SelfSignedCertificate -DnsName "localhost" -CertStoreLocation "cert:\LocalMachine\My"
    }

    # Define HTTP and HTTPS prefixes
    $httpPrefix = "http://*:$HttpPort/"
    # $httpsPrefix = "https://*:$HttpsPort/"

    # Create HTTP listener
    $httpListener = New-Object System.Net.HttpListener
    $httpListener.Prefixes.Add($httpPrefix)

    # Create HTTPS listener
    #$httpsListener = New-Object System.Net.HttpListener
    #$httpsListener.Prefixes.Add($httpsPrefix)

    # Bind the certificate to the HTTPS listener
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cert.RawData)
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

    # Start the listeners
    $httpListener.Start()
    #$httpsListener.Start()

    Write-Host "Listening for incoming HTTP requests on port $HttpPort..."
    # Write-Host "Listening for incoming HTTPS requests on port $HttpsPort..."

    function Handle-Request {
        param (
            [System.Net.HttpListenerContext]$context
        )
        Write-Host "Packet Received for processing"
        $request = $context.Request
        $response = $context.Response
        Write-Host $context
        Write-Host $request
        
        # Extract the original requested link
        $originalUrl = $request.Url.AbsoluteUri
        $expandedUrl = ExpandURL($originalUrl)
        Write-Host $originalUrl
        Write-Host $expandedUrl
        
        # Get VirusTotal Data
        $output = CheckSite(convert-ToBase64Url($expandedUrl))

        # Ask User Go or Stop
        $optionsChoice = Show-OptionsBox($output)

        # Yes = Continue, No = End
        if ($optionsChoice -eq "Yes") {
            AllowHosts($originalUrl)
            $response.StatusCode = 302
            $response.RedirectLocation = $expandedUrl
            $responseString = "You are being redirected to <a href='$expandedURL'>$expandedUrl</a>."
        } else {
            $response.StatusCode = 403
            $responseString = "Access denied: The requested URL ($expandedUrl) is considered malicious."
        }

        # Prepare the response
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($responseString)

        # Set the response content type and length
        $response.ContentLength64 = $buffer.Length
        $response.ContentType = "text/plain"

        # Write the response
        $response.OutputStream.Write($buffer, 0, $buffer.Length)
        $response.OutputStream.Close()
    }

    # Create a ThreadStart delegate for the HTTP listener
    #$httpThreadStart = [System.Threading.ThreadStart]{
        try {
            $httpContext = $httpListener.GetContext()
            Handle-Request -context $httpContext
        } catch {
            Write-Host "HTTP Listener encountered an error: $_"
        }
    #}

    # Create a ThreadStart delegate for the HTTPS listener
    #$httpsThreadStart = [System.Threading.ThreadStart]{
    #while ($httpsListener.IsListening) {
    #    try {
    #        write-host "Really listening to the try loop"
    #        $httpsContext = $httpsListener.GetContext()
    #        Write-Host "Got Context...handling"
    #        Handle-Request -context $httpsContext
    #    } catch {
    #        Write-Host "HTTPS Listener encountered an error: $_"
    #    }
    #}
    

    # Handle requests in separate threads
    #$httpThread = [System.Threading.Thread]::new($httpThreadStart)
    #$httpsThread = [System.Threading.Thread]::new($httpsThreadStart)

    # Start the threads
    #$httpThread.Start()
    #$httpsThread.Start()
    #Write-Host "Threads started"

    # Wait for the threads to finish (they won't unless the listeners stop)
    #$httpThread.Join()
    #$httpsThread.Join()
    #Write-Host "Threads joined"

    # Stop the listeners
    $httpListener.Stop()
    #$httpsListener.Stop()
    #Write-Host "Threads stopped"
}

# Force known URL shortners through local proxy/checks
function LoadHosts {
    foreach ($shortURL in $shortURLs) {
        $entry = "127.0.0.1 $shortURL"
        if (gc -Path $hostsFile | sls -pattern $entry) {
            Write-Host "host found: $entry"
            
        } else {
            $queue += "$entry`n"
            Write-Host "host written: $entry"
        }
    }
    Add-Content -Path $hostsFile -value $queue
}

# Stop redirectors for URL shortners
function CleanHosts {
    $filteredcontent = gc -Path $hostsFile
    foreach ($shortURL in $shortURLs) {
        $entry = "127.0.0.1 $shortURL"
        $filteredcontent = $filteredcontent | where-Object { $_ -notmatch $entry}
        Write-Host "host deleted: $entry"
    }
    Set-Content -Path $hostsFile -value $filteredcontent
}

#GoTime
LoadHosts
StartProxy
Clear-DnsClientCache


try {
    Write-Host "Press Ctrl+C to stop the script..."
    while ($true) {
        # Start & Run Listeners
        Listeners
        Start-Sleep -Seconds 1
    }
}
catch {
    Write-Host "Stopping the script..."
    CleanHosts
    StopProxy
} finally {
    CleanHosts
    StopProxy
}