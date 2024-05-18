#  Copyright (c) 2024 Justin Cornwell justin.cornwell@trojans.dsu.edu
#  Created Date: Friday, May 17th 2024, 14:31:00 HST
#  Author: Justin Cornwell
#  ----------------
#  Course: CSC842
#  Project/Lab: Cycle1 - PauseRansom
#  ----------	---	----------------------------------------------------------

# Dot source Script1.ps1 to import its content
. "$PSScriptRoot\pause-process.ps1"

# Log dump location
# TODO: Provide switch to override the default?
$logFilePath = "C:\RansomwareLogs\activity_log.txt"
# Initialize an array to hold FileSystemWatcher objects
$watchers = @()
# List key User subdirectories to monitor
$keyUserFolders = @("Documents", "Desktop", "Downloads", "Pictures", "Music", "Videos", "OneDrive")

# Function to log events
function Log-Event {
    param ([string]$message)
    $timestamp = Get-Date
    Add-Content -Path $logFilePath -Value "$timestamp - $message"
}

# Function to display the options box with UAC prompt
# WORKS
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

# Get all user profile directories
$userProfiles = Get-ChildItem -Path "C:\User" -Directory

# Create a FileSystemWatcher for each user's key folders
foreach ($profile in $userProfiles) {
    foreach ($folder in $keyUserFolders) {
        
        $keyPath = Join-Path -Path $profile.FullName -ChildPath $folder
        
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
                    $message = "Potential ransomware activity detected at $timestamp. File: $path"
                    Log-Event -message $message
                }
            }
        
            # Register the event handler
            Register-ObjectEvent -InputObject $watcher -EventName "Changed" -Action $action
    
            # Add the watcher to the array
            $watchers += $watcher
    
            Write-Host "Monitoring $keyPath"
        } else {
            Write-Host "Key folder not found for user profile: $($profile.Name)"
        }
    }
    # Register the event handler
    Register-ObjectEvent -InputObject $watcher -EventName "Changed" -Action $action
}

# Function to backtrace the process accessing activated watcher file
function Backtrace-Process {
    param ([string]$filePath)
    $filePath = [System.IO.Path]::GetFullPath($filePath)
    $query = "SELECT * FROM CIM_DataFile WHERE Name = '$filePath'"
    $file = Get-WmiObject -Query $query
    if ($file) {
        $fileHandles = Get-Process | Where-Object { $_.Modules.FileName -eq $filePath }
        foreach ($handle in $fileHandles) {
            # FIX THIS:
            process-pause $($handle.Id)
            $processInfo = "Process ID: $($handle.Id), Process Name: $($handle.Name)"
            Write-Host $processInfo
            Log-Event -message $processInfo
            Show-OptionsBox
        }
    } else {
        Write-Host "No process found accessing the file."
    }
}

# Keep the script running
while ($true) { Start-Sleep -Seconds 10 }