using './main.bicep'

param allowedSourceIp = readEnvironmentVariable('DAC_ALLOWED_IP')
param adminPassword = readEnvironmentVariable('DAC_ADMIN_PASSWORD')
