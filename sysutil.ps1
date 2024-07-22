# Get list of running processes using PsList
param ($mode=1, $excludeProcesses, $outputFile='out.txt', $hashInputFile, $sortType='WS', $numProcesses=5)

$currTime = Get-Date

if ($excludeProcesses) {$excluded = Get-Content $excludeProcesses}
$processList = & pslist.exe -m
$uniqueProcesses = @()
$pathList = @()
$pathToPid = @()
$processCount = 0


$processList | Select-Object -Skip 8 | Sort-Object | ForEach-Object{
         $processCount += 1
         $procInfo = $_ -split "\s+"
         $procName = $procInfo[0..($procInfo.Count -9)] -Join " "
         if (($excluded -notcontains $procName) -eq $true) {
            $uniqueProcesses += [pscustomobject]@{
                Name = $procName
                Pid = $procInfo[-8]
                VM = [long]$procInfo[-7]
                WS = [long]$procInfo[-6]
                path = (Get-Process -Id $procInfo[-8] -ErrorAction SilentlyContinue).path
            }
         }
     }

#Performance Helper
if ($mode -eq 1){

    "`r`n--------------------`r`nRunning Performance Check - $currTime`r`n" | Out-File -FilePath $outputFile -Append

    $uniqueProcesses | Sort-Object $sortType -Descending | Select-Object -First $numProcesses | ForEach-Object {
        $parentProcess = (Get-CimInstance CIM_Process | Where-Object processid -eq $_.'pid').parentProcessId
        $p_Name = $_.'Name'
        $p_ID = $_.'Pid'
        $p_VM = $_.'VM' / 1024
        $p_WS = $_.'WS'
        if ($sortType -eq 'WS'){
            "Process $p_ID ($p_Name) with parent process ID $parentProcess is using $p_WS KB memory" | Out-File -FilePath $outputFile -Append
            $ans = Read-Host "Process $p_ID ($p_Name) with parent process ID $parentProcess is using $p_WS KB memory. Do you want to kill it? (y/n)"
        } 
        if ($sortType -eq 'VM'){
            "Process $p_ID ($p_Name) with parent process ID $parentProcess is using $p_VM MB memory" | Out-File -FilePath $outputFile -Append
            $ans = Read-Host "Process $p_ID ($p_Name) with parent process ID $parentProcess is using $p_VM MB memory. Do you want to kill it? (y/n)"
        }
    
        if ($ans -eq "Y" -or $ans -eq "y"){
            pskill.exe $p_ID > $null
            "Killed $p_Name with ID $p_ID" | Out-File -FilePath $outputFile -Append
            "Killed $p_Name with ID $p_ID"
        }
    }
}

# Security Scan
if ($mode -eq 2){

    "`r`n--------------------`r`nRunning Virus Check - $currTime`r`n" | Out-File -FilePath $outputFile -Append

    $uniqueProcesses | Select-Object -Unique -Property pid | Sort-Object pid | ForEach-Object{
        $id = $_
        $procPath = (Get-Process -Id $id."pid" -ErrorAction SilentlyContinue).path
        $pathList += $procPath
        $pathToPid += [pscustomobject]@{
            path = $procPath
            id = $id."pid"
        }
    }

    $pathList = $pathList | Select-Object -Unique

    $pathList | ForEach-Object{
        $path = $_
        $result = sigcheck.exe -h -vt $path | Select-Object -Skip 5
        $props = $result -split '\n'
        $exeName = $props[0].Substring(0,$props[0].Length-1)
        $verified = ($props[1] -split '\s+')[2]
        # $fileVersion = ($props[8] -split '\s+')[3]
        # $sha256 = ($props[14] -split '\s+')[2]
        $vtDetection = ($props[16] -split '\s+')[3]
        $vtLink = ($props[17] -split '\s+')[3]

        "Scanning $exeName..."

        if (-Not($verified -eq 'Signed')){
            "$exeName does not have a valid signature" | Out-File -FilePath $outputFile -Append
        }
        
        if (($vtDetection -split '/')[0] -gt 0) {

            "File Location: $exeName" | Out-File -FilePath $outputFile -Append
            "VT Detection: $vtDetection" | Out-File -FilePath $outputFile -Append
            "VT Scan Results: $vtLink`r`n" | Out-File -FilePath $outputFile -Append

            $killAns = Read-Host "$exeName is potentially malicious. Do you want to kill it? (y/n)"

            if (($killAns -eq 'y') -or ($killAns -eq 'Y')){
                $pathToPid | ForEach-Object{
                    if ($_.'path' -eq $exeName){
                        $killPid = $_.'id'
                        pskill.exe $killPid > $null
                        "Killed $exeName with ID $killPid" | Out-File -FilePath $outputFile -Append
                    }
                }
            }
        }
    }
}

# HASH Compare
if ($mode -eq 3){

    "`r`n--------------------`r`nRunning Hash Check - $currTime`r`n" | Out-File -FilePath $outputFile -Append

    $uniqueProcesses | Select-Object -Unique -Property pid | Sort-Object pid | ForEach-Object{
        $id = $_
        $procPath = (Get-Process -Id $id."pid" -ErrorAction SilentlyContinue).path
        $pathList += $procPath
        $pathToPid += [pscustomobject]@{
            path = $procPath
            id = $id."pid"
        }
    }

    $pathList = $pathList | Select-Object -Unique

    if (-Not $hashInputFile){
        "Generating Hash file..."
    }

    $pathList | ForEach-Object{
        $path = $_
        $result = sigcheck.exe -h $path | Select-Object -Skip 5
        $props = $result -split '\n'
        $exeName = $props[0].Substring(0,$props[0].Length-1)
        # $verified = ($props[1] -split '\s+')[2]
        $fileVersion = ($props[8] -split '\s+')[3]
        $sha256 = ($props[14] -split '\s+')[2]
        # $vtDetection = ($props[16] -split '\s+')[3]
        # $vtLink = ($props[17] -split '\s+')[3]


        if (-Not $hashInputFile){
            "$path::$sha256::$fileVersion" | Out-File -FilePath "hashes.txt" -Append
        }

        if ($hashInputFile){
            $storedHashes = Get-Content $hashInputFile
            $storedHashes | ForEach-Object{
                $line = $_ -split '::'
                $linePath = $line[0]
                $lineHash = $line[1]
                $lineVersion = $line[2]

                if ($linePath -eq $exeName){
                    if ($lineHash -eq $sha256){
                        "Matching Hash for $linePath"
                    }
                    else {
                        if ($lineVersion -eq $fileVersion){
                            "Different HASH, same file version. Possible malicious data manipulation for $exeName"
                        }
                        else {
                            "File version of $exeName changed from $fileVersion to $lineVersion"
                        }
                    }
                }
            }
        }
    } | Out-File -FilePath $outputFile -Append
    if (-Not $hashInputFile){
        "Generated Hash file..." | Out-File -FilePath $outputFile -Append
    }
}



