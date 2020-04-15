# לבצע בדיקה על $ExpDomain שזה באמת עובד
# לבדוק אם אפשר להגדיר את $DeferredDomains כהאשטייבל 


#mail Function
$login = "statusky@yazamco-it.com"
$password = "218220" | Convertto-SecureString -AsPlainText -Force
$MailCred = New-Object System.Management.Automation.Pscredential -Argumentlist $login,$password

Function Send-mail {

    param(

    $From = 'MonitorSpam@yazamco.co.il',
    $To = 'matanya@yazamco.co.il',
    $Subject = 'SpamTitan Alert',
    $Body = 'some body',
    $SMTPServer = 'mailscan.yazamco-it.com',
    $Port = 25,
    $Credential = $MailCred


    )
Send-MailMessage -From $From -To $To -Subject $Subject -Body $Body -SmtpServer $SMTPServer -Port $Port -Credential $Credential
}

######################

# Create Status File, to Prevent resending for a known issue
if (!(Test-Path .\StatusFile.csv)){New-Item -ItemType File -Name StatusFile.csv}
$status = Import-Csv .\StatusFile.csv
Remove-Item .\StatusFile.csv

# Item You Can Change
[array]$ExpDomain = 'domainA.co.il','domainB.com' # List of Domain Excluded
[int]$ResendTime = '30' # Time to wait before resend mail about know issue
[int]$MailCount = '5' # The treshold nember of Deferred mail to send alert


$DeferredDomains = @()
$Domains = @{}


$token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp0aSI6ImMyMGU0YjQ0Yjk1NWU5MzgxNmEyMGM4MGZiZThiZTA2Mjc4ZDUyYzhhOTE3YzM0NDcxM2JhOGY2N2NjMzI3MGZlYTQ2NDgzN2FmYzkwYjUxIn0.eyJhdWQiOiIzIiwianRpIjoiYzIwZTRiNDRiOTU1ZTkzODE2YTIwYzgwZmJlOGJlMDYyNzhkNTJjOGE5MTdjMzQ0NzEzYmE4ZjY3Y2MzMjcwZmVhNDY0ODM3YWZjOTBiNTEiLCJpYXQiOjE1ODU2NjgwNTgsIm5iZiI6MTU4NTY2ODA1OCwiZXhwIjoxNjE3MjA0MDU4LCJzdWIiOiIyOCIsInNjb3BlcyI6W119.qkmkULGw65U5clf9qZocHhMvVEm5Y_h_g82cHEQVOtMVUhtnoUJ7maHSsTG5JMtJOS7o7X4S3nuJT20KCdBNLkZksUzb44WP1UqSd4iNF361iyipF-78vPoq4KcYZ9DqFmHOijD6Su3txhpZClhMLbvXVrbPgFx5i-m8GDw3So8o0iPiIeO45nGfAOGRj2p16lu5zFvHRA_KlPzjkekIcdNOkmbiJneXCwtOwjkAg-9H3rOIWb_4YA36U0vmLqwjZulAfITm3XB0WPEiqJOSS86C1t709ea26lub_OZS5eZhGeUdos0Sbrz7juJJO-HvwiMcLjrbCvakx7xNEgdfJ4yBH7o-psXqVcWSxNRUMSUxaechaDbfYYQT4gqI0zUpSn2RKbHoZU1gL6ZzFcbgh7EN1VmCEjrg_T1NZ7YwZA48uqrt11E09l4Xkv0AZBn8qWu7rqInFuPDuxm0HNDiKnIwvGFN2bhjiZrDM63aS4scPa-BSP1UDIyPSV4CEisxrk2IBxWIQ48ce_JClHJOeH6vXkTD5feprH-E3_JA1l7yNjJ4gRRAdLtfkN_fSkvXVP9C67yMyUObD1bB4FAHyBdycfmwAIBUZ3yFROeWyM1KJH0XvCZ2Rz3m62MSL96HxtlU7tCPOhsxYYlgniOGZwCVALkbjo22UDDuoCa1wxI'

#Get List of Authorized domain From SpamTitan
$AuthDomains = Invoke-WebRequest -Uri "https://mx01.yazamcocloud.co.il/restapi/domains/auth" -Headers @{"Authorization" = "Bearer $Token"} 
$AuthDomains = $AuthDomains.content
$StartData = $AuthDomains.IndexOf("[{") ; $EndData = $AuthDomains.IndexOf("}]")
$AuthDomains = $AuthDomains.Substring($StartData, $EndData-$startdata+2) |ConvertFrom-Json
$AuthDomains = $AuthDomains.domain

#Get List of Deferred Mails From SpamTitan
$Deferred = Invoke-WebRequest -Uri "https://mx01.yazamcocloud.co.il/restapi/mail-queue/deferred" -Headers @{"Authorization" = "Bearer $Token"} 
$Deferred = $Deferred.Content
$StartData = $Deferred.IndexOf("[{") ; $EndData = $Deferred.IndexOf("]}")
$Deferred = $Deferred.Substring($StartData, $EndData-$startdata+1) |ConvertFrom-Json

# Convert List of mails to List of Domains and Filter Unauthorized Domain
 foreach ($msg in $Deferred){
    $domain = $msg.recipients -split '@' |select -last 1
    if ($domain -in $ExpDomain) {continue} #temp for testing
    #if ($domain -notin $AuthDomains -or $domain -in $ExpDomain) {continue}
    else{
        $DeferredDomains = $DeferredDomains + $domain

    }
}

# Convert $DeferredDomains String to $Domains HashTable 
foreach ($DeferredDomain in $DeferredDomains){$Domains[$DeferredDomain] +=1}
foreach ($Line in $domains.GetEnumerator()){
    if ($Line.value -ge $MailCount){
        if ($status -ne $null){
        foreach ($StatusItem in $status){ 
            $StatusItemTime  = [datetime]::parseexact($StatusItem.time , "dd/MM/yyyy HH:mm:ss", $null)
                
                if ($Line.Name -like $StatusItem.domain){ 
                    $props = @{
                            'Domain'=$Line.name;
                            'Count'=$Line.value;
                            'Time'= $StatusItem.Time

                    }
                    $NewStatus = New-Object -TypeName psobject -Property $props
                    $NewStatus |export-csv .\StatusFile.csv -Append -NoTypeInformation
                }
                if (!($status.domain).contains($line.Name)){
                    $props = @{
                            'Domain'=$Line.name;
                            'Count'=$Line.value;
                            'Time'= Get-Date  -Format "dd/MM/yyyy HH:mm:ss"
                    }
                    $NewStatus = New-Object -TypeName psobject -Property $props
                    $NewStatus |export-csv .\StatusFile.csv -Append -NoTypeInformation
                    $WarningMSG ="Problem with Domain $($Line.name), $($line.Value) massages is Deferred"
                    Send-mail -Body $WarningMSG
                }

                if ($Line.Name -like $StatusItem.domain -and (Get-Date) -ge ($StatusItemTime).AddMinutes(+$ResendTime)){
                    #Write-Warning "Mail Deferred: $($Line.name)"
                    $WarningMSG ="Problem with Domain $($Line.name), $($line.Value) massages is Deferred"
                    Send-mail -Body $WarningMSG
                }
        }
        }
        else{
                Write-Warning "Mail Deferred: $($Line.name)"
                $WarningMSG ="Problem with Domain $($Line.name), $($line.Value) massages is Deferred"
                Send-mail -Body $WarningMSG
                $props = @{
                            'Domain'=$Line.name;
                            'Count'=$Line.value;
                            'Time'= Get-Date  -Format "dd/MM/yyyy HH:mm:ss"
                    }
                    $NewStatus = New-Object -TypeName psobject -Property $props
                    $NewStatus |export-csv .\StatusFile.csv -Append -NoTypeInformation
         }
      }
}

 

    

    
   
