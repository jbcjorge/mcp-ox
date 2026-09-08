package client

// Queries contains all GraphQL queries used by the MCP tools.

const QueryGetSingleIssueInfo = `
query GetSingleIssueInfo($getSingleIssueInput: SingleIssueInput) {
  getSingleIssueInfo(getSingleIssueInput: $getSingleIssueInput) {
    issueId
    mainTitle
    secondTitle
    severity
    originalSeverity
    description
    impact
    recommendation
    category { name categoryId subCategoryName }
    app { name businessPriority repoName organization owners { name email } branch }
    owners
    ownerEmails
    occurrences
    createdAt
    issueUpdatedAt
    scanDate
    sourceTools
    ruleId
    cwe
    fixLink
    publicExploitLink
    isFixAvailable
    isFixApplied
    isFalsePositive
    falsePositiveComment
    severityChange
    originalToolSeverity
    severityChangedReason { shortName reason changeCategory }
    policy { name detailedDescription }
    resource { id type }
    sla { daysPastSLA status }
    aggregations {
      type
      items {
        filePath fileUri startLine endLine snippet branch language match realMatch
      }
    }
    tags { name displayName tagCategory }
    issueLink
    appName
    learnMore
    extraInfo { key value link }
    compliance { standard control category description }
  }
}
`

const QueryGetIssueGraph = `
query GetIssueGraph($issueId: String!) {
  getIssueGraph(issueId: $issueId) {
    nodes { id type metaData }
    edges { id type metaData target source }
  }
}
`

const QuerySearchIssues = `
query GetIssues($getIssuesInput: IssuesInput) {
  getIssues(getIssuesInput: $getIssuesInput) {
    issues {
      issueId
      mainTitle
      severity
      originalSeverity
      category { name categoryId }
      app { name businessPriority }
      owners
      occurrences
      createdAt
      description
      recommendation
      severityChangedReason { shortName }
      aggregations {
        items { filePath fileUri startLine endLine snippet branch language }
      }
      isFixAvailable
      isFalsePositive
      sla { daysPastSLA status }
    }
    totalIssues
    totalFilteredIssues
    offset
  }
}
`

const QueryGetResolvedIssue = `
query GetResolvedIssue($getSingleIssueInput: SingleIssueInput) {
  getResolvedIssue(getSingleIssueInput: $getSingleIssueInput) {
    issueId
    mainTitle
    severity
    description
    recommendation
    resolvedIssueDate
    resolvedReason
    resolvedReasonDetails { description }
    category { name categoryId }
    app { name businessPriority }
    owners
    aggregations {
      items { filePath fileUri startLine endLine snippet branch language }
    }
  }
}
`

const QueryGetRemovedIssue = `
query GetRemovedIssue($getSingleDisappearedIssueInput: SingleDisappearedIssueInput) {
  getRemovedIssue(getSingleDisappearedIssueInput: $getSingleDisappearedIssueInput) {
    issueId
    mainTitle
    severity
    description
    disappearedReason
    disappearedReasonDetails { description }
    disappearedDate
    category { name categoryId }
    app { name businessPriority }
    owners
  }
}
`

const QueryGetIssuePrioritization = `
query GetIssuePrioritization($issueId: String!) {
  getIssuePrioritization(issueId: $issueId)
}
`

const QueryGetApplications = `
query GetApplications($getApplicationsInput: GetApplicationsInput) {
  getApplications(getApplicationsInput: $getApplicationsInput) {
    applications {
      appId
      appName
      repoName
      branch
      organization
      businessPriority
      securityPosture
      risk
      issues
      issuesBySeverity { critical high medium low info }
      appOwners { name email }
      languages { language languagePercentage }
      lastCodeChange
      relevant
      link
      tags { name displayName tagCategory }
      oxInPipeline
      appClassification
    }
    total
    totalFilteredApps
    offset
  }
}
`

const QueryGetIssueFilters = `
query GetIssueFilters($getIssuesInput: IssuesInput) {
  getIssuesConditionalFiltersLazy(getIssuesInput: $getIssuesInput) {
    filters {
      type
      items { label count }
    }
  }
}
`

const QueryGetSbom = `
query GetSbom($getSbomInput: GetApplicationsSbom) {
  getSbom(getSbomInput: $getSbomInput) {
    sbomLibs {
      id
      libraryName
      libraryVersion
      license
      appName
      appId
      language
      dependencyType
      source
      packageManager
      purl
      latestVersion
      vulnerabilityCounts { critical high medium low info }
      malicious
      notMaintained
      isDeprecated
      runtimeStatus
      firstSeenDate
    }
    total
    offset
  }
}
`

const QueryGetVulnerableLibraries = `
query GetSbomVulnerableLibraries($getSbomInput: GetApplicationsSbom) {
  getSbomVulnerableLibraries(getSbomInput: $getSbomInput) {
    sbomLibs {
      id
      libraryName
      libraryVersion
      license
      appName
      language
      dependencyType
      packageManager
      purl
      latestVersion
      vulnerabilityCounts { critical high medium low info }
      vulnerabilities {
        cve
        cveLink
        oxSeverity
        epss
        percentile
        libName
        libVersion
        description
        minorVerWithFix
        majorVerWithFix
        exploitInTheWild
        exploitInTheWildLink
        runtimeStatus
      }
      malicious
      runtimeStatus
      firstSeenDate
    }
    total
    offset
  }
}
`

const QueryGetPipelineIssues = `
query GetCICDIssues($getCICDIssuesInput: CICDIssuesInput) {
  getCICDIssues(getCICDIssuesInput: $getCICDIssuesInput) {
    issues {
      issueId
      mainTitle
      severity
      category { name categoryId }
      app { name businessPriority }
      owners
      description
      recommendation
      aggregations {
        items { filePath fileUri startLine endLine snippet branch language }
      }
      cicdFields {
        issueStatus
        sourceBranch
        targetBranch
        jobId
        jobTriggeredAt
        jobTriggeredBy
        jobUrl
        pullRequestId
        pullRequestUrl
        enforcement
        cicdEventType
      }
    }
    totalIssues
    totalFilteredIssues
    offset
  }
}
`

// QueryGetSingleSbomLibrary fetches full details (including CVEs) for one SBOM library.
const QueryGetSingleSbomLibrary = `
query GetSingleSbomLibrary($getSingleSbomLibraryInput: GetSingleSbomLibraryInput) {
  getSingleSbomLibrary(getSingleSbomLibraryInput: $getSingleSbomLibraryInput) {
    id
    language
    libraryName
    libraryVersion
    license
    appName
    appId
    location
    locationLink
    appLink
    dependencyType
    dependencyLevel
    source
    pkgName
    purl
    libLink
    packageManager
    packageManagerLink
    latestVersion
    latestVersionDate
    usedVersionReleaseDate
    firstSeenDate
    stars
    forks
    openIssues
    maintainers
    contributors
    downloads
    sourceLink
    notPopular
    licenseIssue
    licenseLink
    malicious
    malwareType
    notMaintained
    isDeprecated
    notUpdated
    projectDescription
    pinState
    declaredConstraint
    lockfilePresent
    referenceCount
    triggerPackage
    vulnerabilityCounts { appox critical high medium low info }
    vulnerabilities {
      issueId
      cve
      cveLink
      oxSeverity
      severityFromTool
      cvssVersion
      epss
      percentile
      libName
      libVersion
      dependencyChain
      chainDepth
      exploitInTheWild
      exploitInTheWildLink
      description
      dateDiscovered
      minorVerWithFix
      majorVerWithFix
      runtimeStatus
      originalSeverity
      cwe { name shortName description url }
    }
    references {
      triggerPackage
      location
      locationLink
      dependencyType
      dependencyLevel
      fileName
      declaredConstraint
      commit { commitedAt committerName committerEmail }
    }
    maintainersList { name email }
    artifactInSbomLibs {
      image imageLink imageCreatedAt sha os osVersion baseImage baseImageVersion tag layer registryName source
    }
  }
}
`

// MutationAddCommentToIssue adds a comment to an issue. Returns Boolean.
const MutationAddCommentToIssue = `
mutation AddCommentToIssue($input: addCommentToIssueInput!) {
  addCommentToIssue(input: $input)
}
`

// MutationUpdateIssueSeverity overrides the severity of an issue. Returns Boolean.
const MutationUpdateIssueSeverity = `
mutation UpdateIssueSeverity($input: UpdateIssueSeverityInput!) {
  updateIssueSeverity(input: $input)
}
`

// MutationReportFalsePositive reports a regular (scan) issue as a false positive.
const MutationReportFalsePositive = `
mutation ReportAlertAsFalsePositive($input: ReportFalsePositiveInput!) {
  reportAlertAsFalsePositive(input: $input) {
    aggregationsStatus
    exclusionInfo {
      totalExclusions
      totalFilteredExclusions
      exclusions {
        exclusionId
        exclusionType
        exclusionTypeLabel
        oxIssueId
        issueName
        appName
        comment
        createdAt
        expiredAt
        isActive
        fp
      }
    }
  }
}
`

// MutationReportFalsePositiveForPipelineIssues reports a pipeline (CI/CD) issue as a false positive.
const MutationReportFalsePositiveForPipelineIssues = `
mutation ReportAlertAsFalsePositiveForPipelineIssues($input: ReportFalsePositiveInput!) {
  reportAlertAsFalsePositiveForPipelineIssues(input: $input) {
    aggregationsStatus
    exclusionInfo {
      totalExclusions
      totalFilteredExclusions
      exclusions {
        exclusionId
        exclusionType
        exclusionTypeLabel
        oxIssueId
        issueName
        appName
        comment
        createdAt
        expiredAt
        isActive
        fp
      }
    }
  }
}
`

// MutationExcludeIssues creates exclusions for one or more issues in bulk.
const MutationExcludeIssues = `
mutation ExcludeIssues($input: ExcludeIssuesInput!) {
  excludeIssues(input: $input) {
    totalExclusions
    totalFilteredExclusions
    exclusions {
      exclusionId
      exclusionType
      exclusionTypeLabel
      oxIssueId
      issueName
      appName
      comment
      createdAt
      expiredAt
      isActive
      status
    }
  }
}
`
