// Lab layer: disposable attack-test environment for the detection-as-code project.
// Network (NSG, VNet/subnet, public IP, NIC), a Windows Server VM, the Azure Monitor
// Agent with an association to the core layer's DCR, and a nightly auto-shutdown.

@description('Azure region. Defaults to the resource group\'s region.')
param location string = resourceGroup().location

@description('The single public IPv4 address allowed to RDP to the lab VM, without a CIDR suffix. Supplied at deploy time, never committed.')
@minLength(7)
@maxLength(15)
param allowedSourceIp string

@description('Tags applied to every resource.')
param tags object = {
  project: 'dac'
  layer: 'lab'
  managedBy: 'bicep'
}

@description('Local administrator username for the lab VM.')
param adminUsername string = 'dacadmin'

@description('Local administrator password for the lab VM. Supplied at deploy time, never committed.')
@secure()
@minLength(12)
param adminPassword string

@description('VM size for the lab VM.')
param vmSize string = 'Standard_B2as_v2'

@description('Resource group that holds the core layer (workspace and DCR).')
param coreResourceGroupName string = 'rg-dac-core'

@description('Name of the existing data collection rule in the core resource group.')
param dataCollectionRuleName string = 'dcr-dac-windows'

@description('Daily auto-shutdown time in 24-hour HHmm format.')
param autoShutdownTime string = '2330'

@description('Windows time zone ID used for the auto-shutdown time.')
param autoShutdownTimeZone string = 'Eastern Standard Time'

var nsgName = 'nsg-dac-lab'
var vnetName = 'vnet-dac-lab'
var subnetName = 'snet-dac-lab'
var pipName = 'pip-dac-lab'
var nicName = 'nic-dac-lab'
var vmName = 'vm-dac-lab'
var osDiskName = 'osdisk-dac-lab'
var dcrAssociationName = 'dcra-dac-lab'
// Azure requires exactly this name format for VM auto-shutdown schedules.
var shutdownScheduleName = 'shutdown-computevm-${vmName}'

// ---------- Network security group: only RDP from one IP gets in ----------
resource nsg 'Microsoft.Network/networkSecurityGroups@2025-05-01' = {
  name: nsgName
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'AllowRdpFromAllowedIp'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '${allowedSourceIp}/32'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '3389'
        }
      }
    ]
  }
}

// ---------- Virtual network with one subnet, protected by the NSG ----------
resource vnet 'Microsoft.Network/virtualNetworks@2025-05-01' = {
  name: vnetName
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.20.0.0/16'
      ]
    }
    subnets: [
      {
        name: subnetName
        properties: {
          addressPrefix: '10.20.1.0/24'
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
    ]
  }

  // Handle to the inline subnet so the NIC can reference it symbolically.
  resource subnet 'subnets' existing = {
    name: subnetName
  }
}

// ---------- Public IP: fixed address used to RDP in ----------
resource pip 'Microsoft.Network/publicIPAddresses@2025-05-01' = {
  name: pipName
  location: location
  tags: tags
  sku: {
    name: 'Standard'
    tier: 'Regional'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
  }
}

// ---------- Network interface: joins the subnet and carries the public IP ----------
resource nic 'Microsoft.Network/networkInterfaces@2025-05-01' = {
  name: nicName
  location: location
  tags: tags
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: vnet::subnet.id
          }
          publicIPAddress: {
            id: pip.id
          }
        }
      }
    ]
  }
}

// ---------- Windows Server VM: the attack-test target ----------
resource vm 'Microsoft.Compute/virtualMachines@2025-04-01' = {
  name: vmName
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    osProfile: {
      computerName: vmName
      adminUsername: adminUsername
      adminPassword: adminPassword
      windowsConfiguration: {
        provisionVMAgent: true
        enableAutomaticUpdates: true
        patchSettings: {
          patchMode: 'AutomaticByOS'
        }
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftWindowsServer'
        offer: 'WindowsServer'
        sku: '2022-datacenter-g2'
        version: 'latest'
      }
      osDisk: {
        name: osDiskName
        createOption: 'FromImage'
        caching: 'ReadWrite'
        managedDisk: {
          storageAccountType: 'StandardSSD_LRS'
        }
        deleteOption: 'Delete'
      }
    }
    securityProfile: {
      securityType: 'TrustedLaunch'
      uefiSettings: {
        secureBootEnabled: true
        vTpmEnabled: true
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: true
      }
    }
  }
}

// ---------- Existing DCR from the core layer: referenced, never modified ----------
resource dcr 'Microsoft.Insights/dataCollectionRules@2024-03-11' existing = {
  name: dataCollectionRuleName
  scope: resourceGroup(coreResourceGroupName)
}

// ---------- Azure Monitor Agent: ships VM events to the workspace ----------
resource ama 'Microsoft.Compute/virtualMachines/extensions@2025-04-01' = {
  parent: vm
  name: 'AzureMonitorWindowsAgent'
  location: location
  tags: tags
  properties: {
    publisher: 'Microsoft.Azure.Monitor'
    type: 'AzureMonitorWindowsAgent'
    typeHandlerVersion: '1.0'
    autoUpgradeMinorVersion: true
    enableAutomaticUpgrade: true
  }
}

// ---------- DCR association: tells the agent which events to collect ----------
resource dcrAssociation 'Microsoft.Insights/dataCollectionRuleAssociations@2024-03-11' = {
  name: dcrAssociationName
  scope: vm
  properties: {
    description: 'Links the lab VM to the core Windows DCR.'
    dataCollectionRuleId: dcr.id
  }
}

// ---------- Auto-shutdown: stops the VM nightly to save credit ----------
resource autoShutdown 'Microsoft.DevTestLab/schedules@2018-09-15' = {
  name: shutdownScheduleName
  location: location
  tags: tags
  properties: {
    status: 'Enabled'
    taskType: 'ComputeVmShutdownTask'
    dailyRecurrence: {
      time: autoShutdownTime
    }
    timeZoneId: autoShutdownTimeZone
    targetResourceId: vm.id
    notificationSettings: {
      status: 'Disabled'
    }
  }
}

output publicIpAddress string = pip.properties.ipAddress
