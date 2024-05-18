#  Copyright (c) 2024 Justin Cornwell justin.cornwell@trojans.dsu.edu
#  Created Date: Friday, May 17th 2024, 14:31:00 HST
#  Author: Justin Cornwell
#  ----------------
#  Course: CSC842
#  Project/Lab: Cycle1 - PauseRansom
#  ----------	---	----------------------------------------------------------

<#

.SYNOPSIS
This is a PowerShell script which detects IOCs from ransomware to pause processes so that incident handlers have the ability to advise and address before further damage is created.

.DESCRIPTION
This script will allow users to monitor key defined folders and "honeypot" files to find potential bulk/rapid encryption processes. Using the Pause-Process tool, the automated Pause-Ransom tool sends the appropriate pause and unpause running commands. 

.EXAMPLE
Import-Module .\pause-ransom.ps1

.EXAMPLE
Pause-Ransom -keyUserFolders [folder1,folder2,folder3]

.EXAMPLE
Pause-Ransom -logFilePath [logfile location]

.NOTES
This script is under active development.

.LINK
https://github.com/ParityInfosec/DSU

#>

param (
    [string]$logFilePath = "C:\RansomwareLogs\activity_log.txt", # Maintain a log file 
    [string[]]$keyUserFolders = @("Documents", "Desktop", "Downloads", "Pictures", "Music", "Videos", "OneDrive"), # Monitor important user folders for encryption actions
    [string[]]$honeyFiles = @("0000", "zzzzz"), # Place trigger files at start of alphabetic/reverse alphabetic order 
    [string[]]$honeyExts = @("", ".txt", ".docx", ".jpg"), # Look for popular extension types targeted by ransomware
    [string[]]$ransomwareExts = @(".encrypted", ".locked", ".crypto", ".crypt", ".locky"), # known ransomware extensions
    [int]$changeThreshold = 100,  # Number of changes within the interval to consider suspicious
    [int]$checkInterval = 10  # Interval in seconds to check the change count
)

# Dot source to import script content
. "$PSScriptRoot\pause-process.ps1"

# Initialize 
$watchers = @() # an array to hold FileSystemWatcher objects
$changeCounter = 0 # counter for threshold checks

# Function to log events
function Log-Event {
    param ([string]$message)
    $timestamp = Get-Date
    Add-Content -Path $logFilePath -Value "$timestamp - $message"
}

# Function to display the options box with UAC prompt
# WORKS, but no UAC prompt
function Show-OptionsBox {
    [void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Ransomware Alert"
    $form.Size = New-Object System.Drawing.Size(300,200)
    $form.StartPosition = "CenterScreen"

    $label = New-Object System.Windows.Forms.Label
    $label.Text = "Potential ransomware activity detected. Do you want to quit or continue monitoring?"
    $label.Size = New-Object System.Drawing.Size(280,40)
    $label.Location = New-Object System.Drawing.Point(10,20)
    $form.Controls.Add($label)

    $yesButton = New-Object System.Windows.Forms.Button
    $yesButton.Text = "Quit"
    $yesButton.Location = New-Object System.Drawing.Point(50,80)
    $yesButton.Add_Click({
        $form.DialogResult = [System.Windows.Forms.DialogResult]::Yes
        $form.Close()
    })
    $form.Controls.Add($yesButton)

    $noButton = New-Object System.Windows.Forms.Button
    $noButton.Text = "Continue"
    $noButton.Location = New-Object System.Drawing.Point(150,80)
    $noButton.Add_Click({
        $form.DialogResult = [System.Windows.Forms.DialogResult]::No
        $form.Close()
    })
    $form.Controls.Add($noButton)

    $result = $form.ShowDialog()
    return $result
}

# Function to backtrace the process accessing activated watcher file
function Backtrace-Process {
    param ([string]$filePath)
    $changeCounter++
    $filePath = [System.IO.Path]::GetFullPath($filePath)
    $query = "SELECT * FROM CIM_DataFile WHERE Name = '$filePath'"
    $file = Get-WmiObject -Query $query
    if ($file) {
        $fileHandles = Get-Process | Where-Object { $_.Modules.FileName -eq $filePath }
        foreach ($handle in $fileHandles) {
            process-pause -Id $handle.Id
            $processInfo = "Process ID: $($hxxxandle.Id), Process Name: $($handle.Name)"
            Write-Host $processInfo
            Log-Event -message $processInfo
            $result = Show-OptionsBox
            if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
                Stop-Process -Id $handle.Id -Force
                exit
            } else {
                process-unpause -Id $handle.Id
            }
        }
    } else {
        Write-Host "No process found accessing the file."
    }
}

# Get all user profile directories
$userProfiles = Get-ChildItem -Path "C:\Users" -Directory

# Start LogFile
Log-Event -message "Starting Log"

# Create a FileSystemWatcher for each user's key folders
foreach ($profile in $userProfiles) {
    foreach ($folder in $keyUserFolders) {
        
        $keyPath = Join-Path -Path $profile.FullName -ChildPath $folder
        foreach ($file in $honeyFiles) {
            foreach ($ext in $honeyExts) {
                $honey = "$keyPath\$file$ext"
                if (-not (Test-Path -Path $honey)) {
                    Set-Content -Path $honey -Value "test"
                    Write-Host "File Created: $honey"
                }
            }
        }
        
        if (Test-Path -Path $keyPath) {
            # Create a new FileSystemWatcher
            $watcher = New-Object System.IO.FileSystemWatcher
            $watcher.Path = $keyPath
            $watcher.Filter = "*.*"
            $watcher.IncludeSubdirectories = $true
            $watcher.EnableRaisingEvents = $true
    
            # Define the action to take when a file is changed
            $action = {
                $path = $Event.SourceEventArgs.FullPath
                $changeType = $Event.SourceEventArgs.ChangeType
                $timestamp = Get-Date
    
                # Log the event
                Log-Event -message "$timestamp - $path was $changeType"
    
                # Detect ransomware activity (e.g., rapid file modifications)
                if ($changeType -eq [System.IO.WatcherChangeTypes]::Changed) {
                    Backtrace-Process -filePath $path
                    $message = "Potential ransomware activity detected at $timestamp. File: $path"
                    Log-Event -message $message
                }
            }
        
            # Register the event handler
            Register-ObjectEvent -InputObject $watcher -EventName "Changed" -Action $action
            Register-ObjectEvent -InputObject $watcher -EventName "Created" -Action $action
            Register-ObjectEvent -InputObject $watcher -EventName "Deleted" -Action $action
            Register-ObjectEvent -InputObject $watcher -EventName "Renamed" -Action $action
            
            # Enable the FileSystemWatcher
            $watcher.EnableRaisingEvents = $true
            
            # Add the watcher to the array
            $watchers += $watcher
    
            Write-Host "Monitoring $keyPath"
        } else {
            Write-Host "Key folder not found for user profile: $($profile.Name)"
        }
    }
}

# Keep the script running
while ($true) { Start-Sleep -Seconds .01 }
