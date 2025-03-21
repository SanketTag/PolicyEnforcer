<#
.SYNOPSIS
    This script determines the default branch of a specified repository in Azure DevOps and enforces specific policies and permissions.

.DESCRIPTION
    The script uses the AzureDevOpsPolicyEnforcer module to interact with Azure DevOps services.
    It requires the organization name, repository ID, and project name as mandatory parameters.
    The script will output the default branch of the specified repository and enforce specific policies and permissions.

.PARAMETER organization
    The name of the Azure DevOps organization.

.PARAMETER repoId
    The ID of the repository.

.PARAMETER projectName
    The name of the project.

.NOTES
    Author: Sanket Tagalpallewar

.EXAMPLE
    .\EnforceAzureDevOpsPolicies.ps1 -organization "myOrg" -repoId "myRepoId" -projectName "myProject"
#>

using module "./modules/AzureDevOpsPolicyEnforcer.psm1"

param (
    [Parameter(Mandatory = $true)]
    [string] $organization,

    [Parameter(Mandatory = $true)]
    [string] $projectName,   

    [Parameter(Mandatory = $true)]
    [string] $repoName,

    [Parameter(Mandatory = $true)]
    [string] $groupDescriptor,

    [Parameter(Mandatory = $true)]
    [string] $policyName,

    [Parameter(Mandatory = $true)]
    [int] $minContributors
)

# Stop script on error
$ErrorActionPreference = "Stop"

# Define permissions hashtable
$permissions = @{
    "ForcePush"                       = 8
    "EditPolicies"                    = 2048
    "BypassPoliciesWhenCompletingPRs" = 32768
    "BypassPoliciesWhenPushing"       = 128
}

Function EnforceBranchPolicy {
    param (
        [Parameter(Mandatory = $true)]
        [object] $enforcer,

        [Parameter(Mandatory = $true)]
        [string] $policyName,

        [Parameter(Mandatory = $true)]
        [int] $minContributors
    )


    $policyId = $enforcer.GetPolicyIdByName($policyName)
    $policy = $enforcer.GetBranchPolicy($enforcer.repositoryId, $enforcer.defaultBranchName)
    Write-Host "Policy from script: $($policy)"
    if ($policy -eq $null -or $policy.settings.minimumApproverCount -ne $minContributors -or $policy.settings.resetOnSourcePush -ne $true) {
             
        # Set branch policy
        Write-Host "Setting branch policy on $($enforcer.defaultBranchName)"
        $policyBody = @{
            isEnabled  = $true
            isBlocking = $false
            type       = @{ id = $policyId }  # Correct policy type ID
            settings   = @{
                minimumApproverCount = $minContributors
                creatorVoteCounts    = $false
                resetOnSourcePush    = $true
                scope                = @(@{
                        repositoryId = $enforcer.repositoryId
                        refName      = "refs/heads/$($enforcer.defaultBranchName)"
                        matchKind    = "exact"
                    })
            }
        }
        $enforcer.SetBranchPolicy($policyBody)
        Write-Host "Branch policy set successfully."
    }
    else {
        Write-Host "Branch policy is already set with the correct values."
    }
}

function EnsureBranchPermissions {
    param (
        [Parameter(Mandatory = $true)]
        [object] $enforcer,

        [Parameter(Mandatory = $true)]
        [string] $securityToken,

        [Parameter(Mandatory = $true)]
        [string] $securityNamespaceId,

        [Parameter(Mandatory = $true)]
        [string] $groupDescriptor,

        [Parameter(Mandatory = $true)]
        [hashtable] $permissions
    )

    foreach ($permission in $permissions.Keys) {
        $hasPermission = $enforcer.HasPermissionSetForGroup($securityToken, $permissions[$permission], $securityNamespaceId, $groupDescriptor)
        
        if (-not $hasPermission) {
            Write-Host "Setting $permission to deny for a group on branch $($enforcer.defaultBranchName)"
            $enforcer.SetBranchPermissions($securityToken, $groupDescriptor, $permissions[$permission], $securityNamespaceId)  
        }
    }
}


try {
    # Create an instance of the AzureDevOpsPolicyEnforcer class
    Write-Host "Creating AzureDevOpsPolicyEnforcer instance for organization: $organization, $projectName, $repoName"
    $enforcer = [AzureDevOpsPolicyEnforcer]::new($organization, $projectName, $repoName)
    

    # Check and enforce permissions
    $utf16Bytes = [System.Text.Encoding]::Unicode.GetBytes($enforcer.defaultBranchName)
    $hexString = ($utf16Bytes | ForEach-Object { $_.ToString("x2") }) -join ""
    $securityToken = "repoV2/$($enforcer.projectId)/$($enforcer.repositoryId)/refs/heads/$hexString"
    Write-Host "Security token: $securityToken"

    # Get the security namespace ID for the repository
    $securityNamespaceId = $enforcer.GetSecurityNamespaceId()
    Write-Host "Security namespace ID: $securityNamespaceId"

    # Split the comma-separated list into an array
    $groupList = $groupDescriptor -split ','

    # Loop through each group in the list and execute the function
    foreach ($group in $groupList) {        
        EnsureBranchPermissions -enforcer $enforcer -securityToken $securityToken -securityNamespaceId $securityNamespaceId `
            -groupDescriptor $group.Trim() -permissions $permissions        
    }

    # Check and enforce policies
        EnforceBranchPolicy -enforcer $enforcer -policyName $policyName -minContributors $minContributors 
    

}
catch {
    Write-Error "An error occurred: $_"
}
