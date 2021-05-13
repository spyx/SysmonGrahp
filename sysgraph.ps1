# ID's
# 1 - create process
# 3 - network connection
# 22 -dns
# 11 - file creation
# 15 - file stream creation
# 13 - registry changed 
# 12 - registry added
# 7 - image loaded
# 5 - process terminated

$filter =@{
    Logname='Microsoft-Windows-Sysmon/Operational'
    ID=1,3,11,15,22
    StartTime = [datetime]::Today
    EndTime = [datetime]::Today.addDays(1)
    }

$a = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
if ($a.count -eq 0) {
    Write-Host "There is no events to match you filter"
    exit
}


$pids = @()
$files = $a | Sort-Object -Property Id
$results = ""
$processes = $files | ? {$_.Id -eq 1}


Write ("CREATE ")
foreach ($event in $files) {
   if ($event.id -eq 1) {
       #write ("process")
       $ev = $event.Message -split "`r`n"
   $jsons="{ "
   foreach ($line in $ev) {
       $line=$line -replace "\\","\\" `
               -replace "\{"," " `
               -replace "\}"," " `
               -replace '"','\"' `
               -replace "`n"," " 
       $line=$line -replace '(\s*[\w\s]+):\s*(.*)', '"$1":"$2",'
       $jsons = $jsons + $line }
       $jsons =$jsons + '"blah" : "blah" }'  

       $convert = ConvertFrom-Json -InputObject $jsons
    # get values from processes
        $UtcTime = $convert.UtcTime
        $date =  $UtcTime.Split(" ")[0]
        $procesID = $convert.ProcessId 
        $Image = $convert.Image.Replace("\","\\")
        $FileVersion = $convert.FileVersion
        $Description = $convert.Description
        $Product = $convert.Product
        $Company = $convert.Company
        $OriginalFileName = if ($convert.OriginalFileName -eq '-') {"Unknown"} else {$convert.OriginalFileName}
        $CommandLine = $convert.CommandLine
        $Bytes = [System.Text.Encoding]::Unicode.GetBytes($CommandLine)
        $EncodedCommand = [Convert]::ToBase64String($Bytes)

        $CurrentDirectory = $convert.CurrentDirectory.Replace("\","\\")
        $User = $convert.User.Replace("\","\\")
        $Hashes = $convert.Hashes

        $ParentImage = $convert.ParentImage
        $ParentProcessId = $convert.ParentProcessId
        $ParentCommandLine = $convert.ParentCommandLine.Replace("\","\\")
        
       
        
        

       if($pids -notcontains $procesID) {
           Write "(id$procesID :Process{id:$procesID,name:'$OriginalFileName',user:'$User',date:'$date', CurrentDirectory:'$CurrentDirectory',FileVersion:'$FileVersion',hashes:'$Hashes',UtcTime:'$UtcTime',Image:'$Image',Description:'$Description',Product:'$Product',Company:'$Company', CommandLine:'$EncodedCommand'}),"
               $pids += $procesID
       }
       if ($pids -notcontains $ParentProcessId){

           foreach ($process in $processes) {
            if($process.properties[3].value -eq $ParentProcessId){
                $UtcTime = $process.properties[1].value
                $date = $UtcTime.Split(" ")[0]
                $processID = $process.properties[3].value
                $Image = $process.properties[4].value.Replace("\","\\")
                $FileVersion = $process.properties[5].value
                $Description = $process.properties[6].value
                $Product = $process.properties[7].value
                $Company = $process.properties[8].value
                $OriginalFileName = $process.properties[9].value
                $CommandLine = $process.properties[10].value
                $Bytes = [System.Text.Encoding]::Unicode.GetBytes($CommandLine)
                $EncodedCommand = [Convert]::ToBase64String($Bytes)
                $CurrentDirectory = $process.properties[11].value.Replace("\","\\")
                $User = $process.properties[12].value.Replace("\","\\")
                $Hashes = $process.properties[17].value

                Write "(id$ParentProcessId :Process{id:$procesID,name:'$OriginalFileName',user:'$User',date:'$date', CurrentDirectory:'$CurrentDirectory',FileVersion:'$FileVersion',hashes:'$Hashes',UtcTime:'$UtcTime',Image:'$Image',Description:'$Description',Product:'$Product',Company:'$Company', CommandLine:'$EncodedCommand'}),"
                $pids += $ParentProcessId
                $results += "(id$ParentProcessId)-[:CreateProcess]->(id$procesID),"
                break
            }
           
           }
           if ($pids -notcontains $ParentProcessId) {
                $name = $ParentImage.split("\")[-1]
               $results +=  "(id$ParentProcessId :Process{id:$ParentProcessId,name:'$name',ParentCommandLine:'$ParentCommandLine'}),"
               $pids += $ParentProcessId

           }
           
           
           
       }
       $results += "(id$ParentProcessId)-[:CreateProcess]->(id$procesID),"
   }
   elseif ($event.id -eq 3) {
       #write("network")
       $ev = $event.Message -split "`r`n"
               $jsons="{ "
               foreach ($line in $ev) {
                   $line=$line -replace "\\","\\" `
                          -replace "\{"," " `
                          -replace "\}"," " `
                          -replace '"','\"' `
                          -replace "`n"," " 
                   $line=$line -replace '(\s*[\w\s]+):\s*(.*)', '"$1":"$2",'
                   $jsons = $jsons + $line } 
                   $jsons =$jsons + '"blah" : "blah" }' 
                   #ConvertFrom-Json -InputObject $jsons
                   $UtcTime = $convert.UtcTime
                   $convert = ConvertFrom-Json -InputObject $jsons
                   $ProcessId = $convert.ProcessId
                   $Image = $convert.Image.Replace("\","\\")
                   $User = $convert.User
                   $Protocol = $convert.Protocol
                   $SourceIp = $convert.SourceIp
                   $SourceHostname = $convert.SourceHostname
                   $SourcePort = $convert.SourcePort
                   $SourcePortName = $convert.SourcePortName
                   $DestinationIp = $convert.DestinationIp
                   $DestinationHostname = $convert.DestinationHostname
                   $DestinationPort = $convert.DestinationPort
                   $DestinationPortName = $convert.DestinationPortName
                   $results += "(id$ProcessId)-[:NetworkConnection{utctime:'$UtcTime'}]->(nc$counter :Network{DestinationPortName:'$DestinationPortName', DestinationPort:'$DestinationPort', SourcePortName:'$SourcePortName', SourcePort:'$SourcePort', SourceHostname:'$SourceHostname', SourceIp:'$SourceIp', Protocol:'$Protocol', User:'$User', Image:'$Image', name:'$DestinationIp', DestinationIp:'$DestinationIp',DestinationHostname:'$DestinationHostname' }),"     
                   $counter += 1
   }
   elseif($event.id -eq 22) {
       #write("DNS")
       $ev = $event.Message -split "`r`n"
       $jsons="{ "
       foreach ($line in $ev) {
           $line=$line -replace "\\","\\" `
                  -replace "\{"," " `
                  -replace "\}"," " `
                  -replace '"','\"' `
                  -replace "`n"," " 
           $line=$line -replace '(\s*[\w\s]+):\s*(.*)', '"$1":"$2",'
           $jsons = $jsons + $line } 
           $jsons =$jsons + '"blah" : "blah" }' 
           #ConvertFrom-Json -InputObject $jsons
           $convert = ConvertFrom-Json -InputObject $jsons
           $UtcTime = $convert.UtcTime
           $ProcessId = $convert.ProcessId
           $QueryName = $convert.QueryName
           $QueryStatus = $convert.QueryStatus
           $QueryResults = $convert.QueryResults
           $Image = $convert.Image.Replace("\","\\")
           
           $results += "(id$ProcessId)-[:DNS_Request{UtcTime:'UtcTime'}]->(dns$counter :DNS{name:'$QueryName',QueryStatus:'$QueryStatus', QueryResults:'$QueryResults',Image:'$Image'}),"
           $counter+=1
   }
   elseif($event.id -eq 11){
       
       $ev = $event.Message -split "`r`n"
       $jsons="{ "
       foreach ($line in $ev) {
           $line=$line -replace "\\","\\" `
                   -replace "\{"," " `
                   -replace "\}"," " `
                   -replace '"','\"' `
                   -replace "`n"," " 
           $line=$line -replace '(\s*[\w\s]+):\s*(.*)', '"$1":"$2",'
           $jsons = $jsons + $line } 
           $jsons =$jsons + '"blah" : "blah" }' 
               #ConvertFrom-Json -InputObject $jsons
           $convert = ConvertFrom-Json -InputObject $jsons
           
           $UtcTime = $convert.UtcTime
           $ProcessId = $convert.ProcessId
           $Image = $convert.Image.Split("\")[-1]
           $TargetFilename = $convert.TargetFilename.Replace("\","\\")
           $name = $convert.TargetFilename.Split("\")[-1]
           if ($pids -notcontains $ProcessId) {
            $results += "(id$ProcessId :Process{id:'$ProcessId',name:'$Image'})-[:FileCreated{UtcTime:'$UtcTime'}]->(file$counter :File{name:'$name', TargetFilename:'$TargetFilename',image:'$Image'}),"
            $pids += $ProcessId
            }
           else {
            $results += "(id$ProcessId)-[:FileCreated{UtcTime:'$UtcTime'}]->(file$counter :File{name:'$name', TargetFilename:'$TargetFilename',image:'$Image'}),"
           }
              
           $counter += 1     
           
   }
   elseif($event.id -eq 23){
       
       $ev = $event.Message -split "`r`n"
       $jsons="{ "
       foreach ($line in $ev) {
           $line=$line -replace "\\","\\" `
                   -replace "\{"," " `
                   -replace "\}"," " `
                   -replace '"','\"' `
                   -replace "`n"," " 
           $line=$line -replace '(\s*[\w\s]+):\s*(.*)', '"$1":"$2",'
           $jsons = $jsons + $line } 
           $jsons =$jsons + '"blah" : "blah" }' 
               #ConvertFrom-Json -InputObject $jsons
           $convert = ConvertFrom-Json -InputObject $jsons
             
           $ProcessId = $convert.ProcessId
           $Image = $convert.Image.Split("\")[-1]
           $TargetFilename = $convert.TargetFilename.Split("\")[-1]
           
           if ($pids -notcontains $ProcessId) {
            $results += "(id$ProcessId :Process{id:'$ProcessId',name:'$Image'})-[:FileDeleted]->(file$counter :FileDel{name:'$TargetFilename'}),"
            $pids += $ProcessId
        }
           else {
            $results += "(id$ProcessId)-[:FileDeleted]->(file$counter :FileDel{name:'$TargetFilename'}),"
           }
           
           
              
           $counter += 1     
           
   }
   elseif($event.id -eq 15){
       
       $ev = $event.Message -split "`r`n"
       $jsons="{ "
       foreach ($line in $ev) {
           $line=$line -replace "\\","\\" `
                   -replace "\{"," " `
                   -replace "\}"," " `
                   -replace '"','\"' `
                   -replace "`n"," " 
           $line=$line -replace '(\s*[\w\s]+):\s*(.*)', '"$1":"$2",'
           $jsons = $jsons + $line } 
           $jsons =$jsons + '"blah" : "blah" }' 
               #ConvertFrom-Json -InputObject $jsons
           $convert = ConvertFrom-Json -InputObject $jsons
           $UtcTime = $convert.UtcTime
           $ProcessId = $convert.ProcessId
           $Image = $convert.Image.Split("\")[-1]
           $Name = $convert.TargetFilename.Split("\")[-1]
           $TargetFilename = $convert.TargetFilename.Replace("\","\\")
           $Hash = $convert.Hash
           if ($pids -notcontains $ProcessId) {
            $results += "(id$ProcessId :Process{id:'$ProcessId',name:'$Image'})-[:FileStreamCreated{UtcTime:'$UtcTime'}]->(file$counter :FileStream{name:'$Name',TargetFilename:'$TargetFilename',Hash:'$Hash'}),"
            $pids += $ProcessId
        }
           else {
            $results += "(id$ProcessId)-[:FileStreamCreated{UtcTime:'$UtcTime'}]->(file$counter :FileStream{name:'$Name',TargetFilename:'$TargetFilename',Hash:'$Hash'}),"
           }
           $counter += 1     
   }
   elseif($event.id -eq 12){
       
    $ev = $event.Message -split "`r`n"
    $jsons="{ "
    foreach ($line in $ev) {
        $line=$line -replace "\\","\\" `
                -replace "\{"," " `
                -replace "\}"," " `
                -replace '"','\"' `
                -replace "`n"," " 
        $line=$line -replace '(\s*[\w\s]+):\s*(.*)', '"$1":"$2",'
        $jsons = $jsons + $line } 
        $jsons =$jsons + '"blah" : "blah" }' 
            #ConvertFrom-Json -InputObject $jsons
        $convert = ConvertFrom-Json -InputObject $jsons
        $Image = $convert.Image.Split("\")[-1]
        $TargetObject = $convert.TargetObject.Replace("\","\\")
        $ProcessId = $convert.ProcessId
        if ($pids -contains $ProcessId) {
            $results += "(id$ProcessId)-[:RegistryAddedDeleted]->(registry$couter :Registry{name:'$Image',TargetObject:'$TargetObject'}), "
        }

        $counter += 1     
    }
    elseif($event.id -eq 13){
       
        $ev = $event.Message -split "`r`n"
        $jsons="{ "
        foreach ($line in $ev) {
            $line=$line -replace "\\","\\" `
                    -replace "\{"," " `
                    -replace "\}"," " `
                    -replace '"','\"' `
                    -replace "`n"," " 
            $line=$line -replace '(\s*[\w\s]+):\s*(.*)', '"$1":"$2",'
            $jsons = $jsons + $line } 
            $jsons =$jsons + '"blah" : "blah" }' 
                #ConvertFrom-Json -InputObject $jsons
            $convert = ConvertFrom-Json -InputObject $jsons
            $Image = $convert.Image.Split("\")[-1]
            $TargetObject = $convert.TargetObject.Replace("\","\\")
            $Details = $convert.Details.Replace("\","\\")
            $ProcessId = $convert.ProcessId
            if ($pids -contains $ProcessId) {
                $results += "(id$ProcessId)-[:RegistryChange]->(registry$couter :RegistryEdit{name:'$Image',TargetObject:'$TargetObject',details:'$Details'}), "
            }
    
            $counter += 1     
        }

        elseif($event.id -eq 7){
       
            $ev = $event.Message -split "`r`n"
            $jsons="{ "
            foreach ($line in $ev) {
                $line=$line -replace "\\","\\" `
                        -replace "\{"," " `
                        -replace "\}"," " `
                        -replace '"','\"' `
                        -replace "`n"," " 
                $line=$line -replace '(\s*[\w\s]+):\s*(.*)', '"$1":"$2",'
                $jsons = $jsons + $line } 
                $jsons =$jsons + '"blah" : "blah" }' 
                    #ConvertFrom-Json -InputObject $jsons
                $convert = ConvertFrom-Json -InputObject $jsons
                $Image = $convert.Image.Split("\")[-1]
                $ImageLoaded = $convert.ImageLoaded.Replace("\","\\")
                $FileVersion = $convert.FileVersion
                $Description = $convert.Description
                $OriginalFileName = $convert.OriginalFileName
                $Signature = $convert.Signature
                $SignatureStatus = $convert.SignatureStatus
                $Signed = $convert.Signed
                $ProcessId = $convert.ProcessId
                if ($pids -contains $ProcessId) {
                    $results += "(id$ProcessId)-[:ImageLoaded]->(imaege$couter :Image{name:'$Image',ImageLoaded:'$ImageLoaded',FileVersion:'$FileVersion',Description:'$Description',OriginalFileName:'$OriginalFileName',Signature:'$Signature',SignatureStatus:'$SignatureStatus',Signed:'$Signed'}), "
                }
        
                $counter += 1     
            }
            elseif($event.id -eq 5){
       
                $ev = $event.Message -split "`r`n"
                $jsons="{ "
                foreach ($line in $ev) {
                    $line=$line -replace "\\","\\" `
                            -replace "\{"," " `
                            -replace "\}"," " `
                            -replace '"','\"' `
                            -replace "`n"," " 
                    $line=$line -replace '(\s*[\w\s]+):\s*(.*)', '"$1":"$2",'
                    $jsons = $jsons + $line } 
                    $jsons =$jsons + '"blah" : "blah" }' 
                        #ConvertFrom-Json -InputObject $jsons
                    $convert = ConvertFrom-Json -InputObject $jsons
                    $ProcessId = $convert.ProcessId
                    if ($pids -contains $ProcessId) {
                        $results += "(id$ProcessId)-[:Terminated]->(temp$counter :Term), "
                    }
            
                    $counter += 1     
                }

   else {
       write ("No idea")
   }
}

$results = $results.TrimEnd(",")
$results += "return *"

$results