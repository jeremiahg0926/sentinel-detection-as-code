// Core layer: long-lived resources for the detection-as-code project.
// Deployed once into rg-dac-core and kept between lab sessions.

@description('Azure region. Defaults to the resource group\'s region.')
param location string = resourceGroup().location

@description('Name of the Log Analytics workspace.')
param workspaceName string

@description('Days to keep log data.')
@minValue(30)
@maxValue(730)
param retentionInDays int = 30

@description('Daily ingestion cap in GB. Protects the student credit.')
@minValue(1)
param dailyCapGb int = 1

@description('Tags applied to every resource.')
param tags object


@description('Turns Microsoft Sentinel on for the workspace. Keep false until attack testing (starts the 31-day trial).')
param enableSentinel bool = false

// ---------- Log Analytics workspace: where logs are stored ----------
resource law 'Microsoft.OperationalInsights/workspaces@2025-07-01' = {
  name: workspaceName
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: retentionInDays
    workspaceCapping: {
      dailyQuotaGb: dailyCapGb
    }
    features: {
      disableLocalAuth: true
    }
  }
}

// ---------- Data collection rule: decides which events to keep ----------
resource dcr 'Microsoft.Insights/dataCollectionRules@2024-03-11' = {
  name: 'dcr-dac-windows'
  location: location
  tags: tags
  kind: 'Windows'
  properties: {
    dataSources: {
      windowsEventLogs: [
        {
          name: 'detectionEvents'
          streams: [
            'Microsoft-Event'
          ]
          xPathQueries: [
            // Every Sysmon event (process, network, registry, LSASS access, ...)
            'Microsoft-Windows-Sysmon/Operational!*'
            // Security log: only the event IDs the backlog needs
            'Security!*[System[(EventID=4688 or EventID=4720 or EventID=4732 or EventID=4698 or EventID=1102)]]'
            // RDP logons only (logon type 10), not every 4624
            'Security!*[System[(EventID=4624)]] and *[EventData[Data[@Name=\'LogonType\']=\'10\']]'
            // New service installed
            'System!*[System[(EventID=7045)]]'
          ]
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          name: 'coreWorkspace'
          workspaceResourceId: law.id
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          'Microsoft-Event'
        ]
        destinations: [
          'coreWorkspace'
        ]
      }
    ]
  }
}


// ---------- Microsoft Sentinel: only deployed when enableSentinel is true ----------
resource sentinel 'Microsoft.SecurityInsights/onboardingStates@2025-09-01' = if (enableSentinel) {
  name: 'default'
  scope: law
  properties: {
    customerManagedKey: false
  }
}

output workspaceName string = law.name
output workspaceId string = law.id
output dcrId string = dcr.id
output sentinelEnabled bool = enableSentinel
