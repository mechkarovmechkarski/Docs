.DESCRIPTION
You can add multiplmachines to domain using this script.
.PARAMETER ComputerName
The name of the computer to add to Domain.
.PARAMETER DomainName
The name of domain to be joined.
.EXAMPLE
.\Add-Domain -DomainName Vinit.com -ComputerName localhost 
#>
Function Add-Domain {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true,HelpMessage=’Provide a domain name.')]
    $DomainName,
    [Parameter(Mandatory=$true,HelpMessage=’Press Enter once all computernames are entered.')]
    [String[]]$ComputerName,
    $UserName= (Get-Credential -message "Enter Domain administrator username and password"),
    $LocalCred
    )
    [System.Windows.Forms.MessageBox]:: Show("Joining Computer to Domain, Click OK to continue")

        Foreach($Computer in $ComputerName)
              { 
              $LocalCred = Get-Credential -Message "Enter $Computer local Username and password"  
                Invoke-Command -computerName $Computer -credential $LocalCred -scriptBlock {Param ($x,$y)Add-Computer -DomainName $x -Credential $y $ErrorActionPreference = 'Continue'} -argumentlist $DomainName,$UserName
                Write-Verbose "Adding $Computer to $DomainName"
              }
} 
