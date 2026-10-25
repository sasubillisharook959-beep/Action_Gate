# Build, test and package ActionGate (Windows PowerShell)
$ErrorActionPreference = "Stop"
java -version
mvn -version
mvn clean verify
Write-Host "Main jar : target\actiongate-1.0.0.jar (dependencies in target\lib)"
Write-Host "Hook jar : target\actiongate-1.0.0-hook.jar"
