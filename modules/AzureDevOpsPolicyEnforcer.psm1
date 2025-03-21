class AzureDevOpsPolicyEnforcer {
    [string] $org
    [string] $projectName
    [hashtable] $headers
    [string] $orgUrl
    [string] $repositoryName
    [string] $defaultBranchName
    [string] $projectId
    [string] $repositoryId

    AzureDevOpsPolicyEnforcer([string]$organization, [string]$projectName, [string]$repoName) {
        $this.org = $organization
        $this.projectName = $projectName
        $this.orgUrl = "https://dev.azure.com/$organization"
        $this.repositoryName = $repoName
        $token = $env:PAT_TOKEN
        $this.headers = @{Authorization = ("Bearer $token") }
        $this.defaultBranchName = $this.GetDefaultBranch()
        $this.repositoryId = $this.GetRepositoryId()
        $this.projectId = $this.GetProjectId()
    }

    [string] GetDefaultBranch() {
        Write-Host "GetDefaultBranch called with repoId: $($this.repositoryName)"
        $url = "$($this.orgUrl)/$($this.projectName)/_apis/git/repositories/$($this.repositoryName)?api-version=6.0"
        Write-Host "URL: $url"
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $this.headers
        $defaultBranch = $response.defaultBranch -replace '^refs/heads/', ''
        Write-Host "Default branch: $($defaultBranch)"
        return $defaultBranch
    }

    [string] GetProjectId() {
        Write-Host "GetProjectID called for project: $($this.projectName)"
        $url = "$($this.orgUrl)/_apis/projects/$($this.projectName)?api-version=6.0"
        Write-Host "URL: $url"
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $this.headers
        $projId = $response.id
        Write-Host "Project ID: $projId"
        return $projId
    }

    [string] GetRepositoryId() {
        Write-Host "GetRepositoryId called for repository: $($this.repositoryName) in project: $($this.projectName)"
        $url = "$($this.orgUrl)/$($this.projectName)/_apis/git/repositories/$($this.repositoryName)?api-version=7.1"
        Write-Host "URL: $url"
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $this.headers
        $repoId = $response.id
        Write-Host "Repository ID: $repoId"
        return $repoId
    }

    [string] GetSecurityNamespaceId() {
        $securityNamespaceId = $null
        $url = "$($this.orgUrl)/_apis/securitynamespaces?api-version=7.1"
        Write-Host "Fetching security namespaces from: $url"
        try {
            $response = Invoke-RestMethod -Uri $url -Method Get -Headers $this.headers
            Write-Host "Security namespaces fetched successfully."

            # Find the Git repository permissions namespace
            $gitNamespace = $response.value | Where-Object { $_.name -eq "Git Repositories" }

            if ($gitNamespace) {
                $securityNamespaceId = $gitNamespace.namespaceId
                Write-Host "Git Repositories security namespace found with ID: $securityNamespaceId"
            }
            else {
                Write-Error "Error: Git Repositories security namespace not found!"
            }
        }
        catch {
            Write-Error "Error occurred while fetching security namespaces: $_"
        }
        Return $securityNamespaceId
    }

    [boolean] HasPermissionSetForGroup([string]$securityToken, [int]$permissionBitmask, [string]$securityNamespaceId, [string]$groupDescriptor) {
        $hasPermission = $false

        # Permissions API URL
        $permissionsUrl = "$($this.orgUrl)/_apis/accesscontrollists/$($securityNamespaceId)?token=$($securityToken)&api-version=7.1"
        Write-Host "Checking and Enforcing permission: $permissionBitmask"
        Write-Host "Permissions URL: $permissionsUrl"

        try {
            # Fetch current permissions
            $response = Invoke-RestMethod -Uri $permissionsUrl -Method Get -Headers $this.headers
            Write-Host "Response: $($response | ConvertTo-Json -Depth 10)"
            $acesDictionary = $response.value[0].acesDictionary
            $groupEntry = $acesDictionary.PSObject.Properties | Where-Object { $_.Name -eq $groupDescriptor } | Select-Object -ExpandProperty Value

            # Output the result
            Write-Host "Matching Entry: $($groupEntry | ConvertTo-Json -Depth 10)"

            # Check if "group" already has "Deny" set
            if ($groupEntry -and ($groupEntry.deny -band [int]$permissionBitmask) -ne 0) {
                Write-Host "Permission is already denied for $groupDescriptor."
                $hasPermission = $true
            }
        }
        catch {
            Write-Host "An error occurred: $_"
        }
        Return $hasPermission
    }

    [Object] GetBranchPolicy ([string]$repoId, [string]$defaultBranch) {
        $policyUrl = "$($this.orgUrl)/$($this.projectName)/_apis/policy/configurations?repositoryId=$repoId&refName=$defaultBranch&api-version=7.10"
        $response = Invoke-RestMethod -Uri $policyUrl -Method Get -Headers $this.headers
        Write-Host "Fetched branch policy: $($response | ConvertTo-Json -Depth 10)"
        $policy = $response.value | Where-Object { 
            $_.type.id -eq "fa4e907d-c16b-4a4c-9dfa-4906e5d171dd"  # Ensuring it's the "Minimum Number of Reviewers" policy
        }
        Write-Host "Policy: $($policy | ConvertTo-Json -Depth 10)"
        if ($policy -eq $null) {
            Return $null
        }
        else {
            return $policy
        }
    }

    [void] SetBranchPermissions ([string]$securityToken, [string]$groupDescriptor, [int]$permissionBitmask, [string]$securityNamespaceId) {   
        $body = @{
            token                = $securityToken
            merge                = $true
            accessControlEntries = @(
                @{
                    descriptor   = $groupDescriptor
                    allow        = 0
                    deny         = $permissionBitmask
                    extendedinfo = @{}
                }
            )
        } | ConvertTo-Json -Depth 10

        $updateUrl = "$($this.orgUrl)/_apis/accesscontrolentries/$($securityNamespaceId)?api-version=7.1"

        # Log the URL and body
        Write-Host "Update URL: $updateUrl"
        Write-Host "Request Body: $body"

        $response = Invoke-RestMethod -Uri $updateUrl -Method Post -Headers $this.headers -Body $body -ContentType "application/json"
        Write-Host "Denied permission successfully for given group. $($response | ConvertTo-Json -Depth 10)"
    }

    [void] RemoveBranchPermissions ([string]$securityToken, [string]$groupDescriptor, [int]$permissionBitmask, [string]$securityNamespaceId) {   
        $body = @{
            token                = $securityToken
            merge                = $true
            accessControlEntries = @(
                @{
                    descriptor   = $groupDescriptor
                    allow        = $permissionBitmask
                    deny         = 0 # Removing denied permissions
                    extendedinfo = @{ }
                }
            )
        } | ConvertTo-Json -Depth 10

        $updateUrl = "$($this.orgUrl)/_apis/accesscontrolentries/$($securityNamespaceId)?api-version=7.1"

        # Log the URL and body
        Write-Host "Update URL: $updateUrl"
        Write-Host "Request Body: $body"

        try {
            $response = Invoke-RestMethod -Uri $updateUrl -Method Post -Headers $this.headers -Body $body -ContentType "application/json"
            Write-Host "Successfully removed denied permissions for the given group. $($response | ConvertTo-Json -Depth 10)"
        }
        catch {
            Write-Host "Error removing denied permissions: $_"
        }
    }


    [void] SetBranchPolicy([Hashtable]$policyBody) {
        $policyUrl = "$($this.orgUrl)/$($this.projectName)/_apis/policy/configurations?api-version=7.1"
        $policyBodyJson = $policyBody | ConvertTo-Json -Depth 10
        Write-Host "Enforcing branch policies with body: $policyBodyJson"
        Invoke-RestMethod -Uri $policyUrl -Method POST -Headers $this.headers -Body $policyBodyJson -ContentType "application/json"
        Write-Host "Successfully enforced branch policies."
    }

    [string] GetPolicyIdByName([string]$policyName) {
        $policyTypesUrl = "$($this.orgUrl)/$($this.projectName)/_apis/policy/types?api-version=7.1"
        $response = Invoke-RestMethod -Uri $policyTypesUrl -Method Get -Headers $this.headers

        $policy = $response.value | Where-Object { $_.displayName -eq $policyName }

        if ($policy) {
            return $policy.id
        }
        else {
            Write-Host "Policy '$policyName' not found."
            return $null
        }
    }

    [bool] HasPermissionForBranch([string]$securityToken, [string]$securityNamespaceId, [int]$managePermissionsBit) {
        # Construct the permissions API URL with necessary query parameters
        $permissionsUrl = "$($this.orgUrl)/_apis/permissions/$($securityNamespaceId)/$($managePermissionsBit)?tokens=$($securityToken)&api-version=7.1"

        # Fetch permission details
        try {
            $permissionsResponse = Invoke-RestMethod -Uri $permissionsUrl -Method Get -Headers $this.headers
        }
        catch {
            Write-Host "Error fetching permissions: $_"
            return $false
        }

        # Check if the caller has the specified permission
        $hasPermission = $permissionsResponse.value | Where-Object { $_.permissions -band $managePermissionsBit }

        if ($hasPermission) {
            Write-Host "Caller has permission for ManagePermissionsBit: $managePermissionsBit."
            return $true
        }
        else {
            Write-Host "Caller does NOT have permission for ManagePermissionsBit: $managePermissionsBit."
            return $false
        }
    }
}

