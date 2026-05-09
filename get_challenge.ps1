$headers = @{
    "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Gecko/20100101 Firefox/150.0"
    "Accept" = "*/*"
    "Content-Type" = "application/json"
    "Cookie" = "sl-session=pnNNMqYeAGqEesOakii4Dw==; monkeycode_ai_session=6f5f03a0-3e4b-4d92-9c24-6d4f99dce312"
}

try {
    $response = Invoke-RestMethod -Uri "https://monkeycode-ai.com/api/v1/public/captcha/challenge" -Method Post -Headers $headers -Verbose
    Write-Host "=== 返回结果 ===" -ForegroundColor Green
    $response | ConvertTo-Json -Depth 5
    Write-Host "================" -ForegroundColor Green
} catch {
    Write-Host "请求失败: $_" -ForegroundColor Red
    $_.Exception.Response
}
