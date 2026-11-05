using './main.bicep'

param workspaceName = 'law-dac-core'
param retentionInDays = 30
param dailyCapGb = 1
param enableSentinel = false
param tags = {
  project: 'dac'
  layer: 'core'
  managedBy: 'bicep'
}
