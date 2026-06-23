<#
  Get-DockerAccessLog.ps1
  EC2 の docker compose ログを SSH 取得し、プライベートIP除外・IPマスキング後に整形・集計して出力する。
  出力① ログファイル：整形済みログ本文。
  出力② xlsx：日別×ステータス別集計（件数・Total・ユニークIP）。
  出力③ additional-exclude-ip.txt：スキャンと判定したIPを抽出（exclude-ip.txt にも追記し、判定別(A〜C)の累計件数と合計を集計コメントとして付加。0件なら生成しない）。
  ※ 接続情報は env.ps1、xlsx 出力ヘルパーは Write-XlsxSummary.ps1、スキャン検知・除外リストヘルパーは ScanExclude.ps1（いずれも同フォルダ）。
#>

# 異常終了時の挙動。エラー内容を表示し、Enter 入力までウィンドウ（コンソール）を残す。
# 終了コードはメッセージの「exit code: N」から取得（無ければ 99）。
trap {
    $msg = $_.Exception.Message
    if ($msg -match 'exit code:\s*(\d+)') {
        $ec = [int]$matches[1]
    } else {
        $ec  = 99
        $msg = "想定外のエラーが発生しました (exit code: 99)`n$msg"
    }
    Write-Host $msg
    Read-Host "Enterキーを押すと閉じます"
    exit $ec
}

# 外部ファイル参照の基準フォルダ（実行ファイル自身の場所）。
$baseDir = Split-Path -Parent ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)

# env.ps1 から設定を読み込む（不在なら分かりやすく停止）
$envFile = "$baseDir\env.ps1"
if (-not (Test-Path -LiteralPath $envFile)) {
    throw "env.ps1が見つかりません (exit code: 10)`nスクリプトと同じフォルダに配置してください`n$envFile"
}
. $envFile

# 必須設定の存在チェック（未定義・空なら停止）
$required = 'ServerIp', 'Ec2Host', 'MyIp', 'KeyPath', 'Ec2User', 'ProjectDir', 'LocalLog', 'ComposeService'
$missing  = $required | Where-Object { [string]::IsNullOrWhiteSpace((Get-Variable $_ -ValueOnly -ErrorAction SilentlyContinue)) }
if ($missing) {
    throw "env.ps1で未設定または空の変数があります (exit code: 11)`n$($missing -join "`n")"
}

# xlsx 出力ヘルパー（関数 Write-XlsxSummary）を読み込む（不在なら停止）。集計xlsx生成時に使用。
$xlsxHelperFile = "$baseDir\Write-XlsxSummary.ps1"
if (-not (Test-Path -LiteralPath $xlsxHelperFile)) {
    throw "Write-XlsxSummary.ps1が見つかりません (exit code: 12)`nスクリプトと同じフォルダに配置してください`n$xlsxHelperFile"
}
. $xlsxHelperFile

# スキャン検知・除外リストヘルパー（Resolve-ScanConfig / Get-ScanCategoryMap / Build-ScanExcludeContent などを提供）を読み込む（不在なら停止）。追加除外IPの抽出時に使用。
$scanHelperFile = "$baseDir\ScanExclude.ps1"
if (-not (Test-Path -LiteralPath $scanHelperFile)) {
    throw "ScanExclude.ps1が見つかりません (exit code: 13)`nスクリプトと同じフォルダに配置してください`n$scanHelperFile"
}
. $scanHelperFile

# フォルダ内の同種ファイルを「最新1件のみ」に保つヘルパー。
# 今回名($CurrentName)を除く該当ファイル($Filter)の最新1件を、今回の出力先($Destination)へリネーム（この後の上書き出力で実質1ファイルに更新）。
function Move-LatestExisting {
    param(
        [Parameter(Mandatory)] [string] $Dir,
        [Parameter(Mandatory)] [string] $Filter,
        [Parameter(Mandatory)] [string] $CurrentName,
        [Parameter(Mandatory)] [string] $Destination
    )
    $existing = Get-ChildItem -LiteralPath $Dir -Filter $Filter -File |
                Where-Object { $_.Name -ne $CurrentName } |
                Sort-Object LastWriteTime | Select-Object -Last 1
    if ($existing) {
        Move-Item -LiteralPath $existing.FullName -Destination $Destination -Force
    }
}

# ファイル書き出し・標準出力デコードで共用する UTF-8(BOMなし) エンコーディング（WriteAllLines は CRLF 出力）。
$utf8NoBom = New-Object System.Text.UTF8Encoding $false

# プライベートIP（127/8・10/8・192.168/16・172.16〜31/12）の除外用パターン
$oct       = '[0-9]{1,3}'
$privateIp = "127\.$oct\.$oct\.$oct" +
             "|10\.$oct\.$oct\.$oct" +
             "|192\.168\.$oct\.$oct" +
             "|172\.(1[6-9]|2[0-9]|3[01])\.$oct\.$oct"

# 除外IPリストを読み込む（1行1IP、空行と'#'行は無視）。
$excludeIpFile = if (-not [string]::IsNullOrWhiteSpace($ExcludeIpFile)) { $ExcludeIpFile }
                 else { Join-Path $baseDir 'exclude-ip.txt' }

$excludeIps = @()
if (Test-Path -LiteralPath $excludeIpFile) {
    $excludeIps = Get-Content -LiteralPath $excludeIpFile -Encoding UTF8 |
                  ForEach-Object { $_.Trim() } |
                  Where-Object { $_ -ne '' -and -not $_.StartsWith('#') } |
                  ForEach-Object { [regex]::Escape($_) }
}

# プライベートIP＋除外IPリストを1つの除外パターンに結合
$excludePattern = $privateIp
if ($excludeIps.Count -gt 0) {
    $excludePattern += '|' + ($excludeIps -join '|')
}

# IP のドットを正規表現用にエスケープ
$serverRe = [regex]::Escape($ServerIp)
$myRe     = [regex]::Escape($MyIp)

# signal process 通知除外・プライベートIP/除外IP除外＋IPマスキングのフィルタ
# 2つ目の grep で nginx の「[notice] N#N: signal process started」行（定期 reload/reopen のノイズ）を落とす。
$filter = "grep -vE '^($excludePattern) - '" +
          " | grep -vE '\[notice\] [0-9]+#[0-9]+: signal process started'" +
          " | sed 's/$serverRe/[Elastic IP]/g'" +
          " | sed 's/$myRe/[My IP]/g'"

# リモート実行コマンド。docker 出力を raw=$(...) で受けて && に終了コードを反映し docker/cd 失敗を検知。
# フィルタは最後の文なので grep 無一致でも誤検知しない（printf '%s\n' は % を誤展開しない安全形）。
$remoteCmd = "cd $ProjectDir" +
             " && raw=`$(docker compose logs --no-log-prefix $ComposeService 2>&1)" +
             " && printf '%s\n' `"`$raw`"" +
             " | $filter"

# SSH 実行。標準出力を .NET Process で生のまま受け取り改行分割する（stderr はコンソールへ）。
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName               = 'ssh'
$psi.Arguments              = '-i "' + $KeyPath + '" ' + $Ec2User + '@' + $Ec2Host + ' "' + ($remoteCmd -replace '"', '\"') + '"'
$psi.UseShellExecute        = $false
$psi.RedirectStandardOutput = $true
$psi.StandardOutputEncoding = $utf8NoBom

$proc   = [System.Diagnostics.Process]::Start($psi)
$stdout = $proc.StandardOutput.ReadToEnd()
$proc.WaitForExit()
$log    = ($stdout -replace "(`r?`n)+$", "") -split "`r?`n"
$code   = $proc.ExitCode

# SSH／リモートコマンドの失敗を検知し、状況別に見出しを分けて停止（中断=130 / 接続系=255 / それ以外=リモートコマンド失敗）。
if ($code -ne 0) {
    switch ($code) {
        130 { throw "Ctrl+Cにより処理が中断されました (exit code: 130)" }
        255 { throw "SSH接続に失敗した可能性があります (exit code: 255)`nホスト・ユーザー・認証鍵・ネットワーク・ホスト鍵の設定を確認" }
        default {
            $detail = switch ($code) {
                1       { "一般エラー（ProjectDirへのcd・docker composeの実行・dockerデーモンの起動を確認）" }
                2       { "シェル構文エラー（生成されたremoteCmd・ProjectDirの値を確認）" }
                126     { "コマンドを実行できません（dockerの実行権限を確認）" }
                127     { "コマンドが見つかりません（docker / docker composeのPATHを確認）" }
                default { "不明なエラー" }
            }
            throw "リモートコマンドの実行に失敗しました (exit code: $code)`n$detail"
        }
    }
}

# 集計用：$counts=コード→件数 / $statusIps=コード→ユニークIP集合
#         $dailyCounts=日付→件数 / $dailyIps=日付→ユニークIP集合 / $dailyStatus=日付→(コード→件数)
$counts      = @{}
$statusIps   = @{}
$dailyCounts = @{}
$dailyIps    = @{}
$dailyStatus = @{}

# 集計対象のステータス（コード→ラベル、列挙順＝表示順）。ここに無いコードは本文には残すが集計しない。
$statusDefs = [ordered]@{
    '200' = '200 OK'
    '301' = '301 Moved Permanently'
    '400' = '400 Bad Request'
    '404' = '404 Not Found'
    '405' = '405 Method Not Allowed'
}

# 日時の英語月名(MMM)を解釈するための InvariantCulture（解析・整形の両ループで使用）。
$ci = [System.Globalization.CultureInfo]::InvariantCulture

# 各行を正規表現で解析（IP=1 / 時刻=3 / ステータス=4）。数字IP行のみ対象。
# statusDefs 外のステータスは集計対象外（continue でスキップ。本文には残る）。
foreach ($line in $log) {
    if ($line -match '^(\d{1,3}(\.\d{1,3}){3})\s+-\s+\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})[^\]]*\]\s+"[^"]*"\s+(\d{3})') {
        $ip   = $matches[1]
        $code = $matches[4]
        if (-not $statusDefs.Contains($code)) { continue }

        $dt  = [datetime]::ParseExact($matches[3], 'dd/MMM/yyyy:HH:mm:ss', $ci)
        $day = $dt.ToString('yyyy/MM/dd')

        # 件数を加算し、IP を集合へ登録。
        if ($counts.ContainsKey($code)) { $counts[$code]++ } else { $counts[$code] = 1 }
        if (-not $statusIps.ContainsKey($code)) { $statusIps[$code] = @{} }
        $statusIps[$code][$ip] = $true

        # 日別の件数とユニークIPを加算
        if ($dailyCounts.ContainsKey($day)) { $dailyCounts[$day]++ } else { $dailyCounts[$day] = 1 }
        if (-not $dailyIps.ContainsKey($day)) { $dailyIps[$day] = @{} }
        $dailyIps[$day][$ip] = $true

        # 日別×ステータス別の件数を加算
        if (-not $dailyStatus.ContainsKey($day)) { $dailyStatus[$day] = @{} }
        if ($dailyStatus[$day].ContainsKey($code)) { $dailyStatus[$day][$code]++ } else { $dailyStatus[$day][$code] = 1 }
    }
}

# 総数（件数合計）とユニークIP数（集計対象コード横断）
$total  = [int](($counts.Values | Measure-Object -Sum).Sum)
$unique = @($statusIps.Values | ForEach-Object { $_.Keys } | Sort-Object -Unique).Count

# 日別×ステータス別の集計。集計は解析ループで実施済み。別ファイル(Excel/xlsx)に出力。
# 列: Date,<各ステータスラベル>,Total,Unique IP。日付昇順（古い順）→ 末尾に Total 行（全期間の集計）。
$codes       = @($statusDefs.Keys)                                            # データ参照用キー: 200,301,400,404,405（表示順）
$headerCells = @('Date') + @($statusDefs.Values) + @('Total', 'Unique IP')    # 見出しはラベル（例: 200 OK）

# Total 行：各コードは全期間件数 $counts、Total は総数 $total、Unique IP は全期間 $unique（日別値の合計ではない）。
$totalCells = @('Total')
foreach ($c in $codes) { $totalCells += "$([int]$counts[$c])" }
$totalCells += "$total"
$totalCells += "$unique"

# 各日（日付昇順）：各コードは $dailyStatus[$day]（不在は 0）、Total は $dailyCounts、Unique IP は $dailyIps の数。
$dayRows = @(foreach ($day in ($dailyCounts.Keys | Sort-Object)) {
    $cells = @($day)
    foreach ($c in $codes) { $cells += "$([int]$dailyStatus[$day][$c])" }
    $cells += "$($dailyCounts[$day])"
    $cells += "$($dailyIps[$day].Count)"
    ,$cells
})

# xlsx 出力用に全行をまとめる（1行目=ヘッダ, 以降=日付昇順, 末尾=Total）。
$xlsxRows = @(,$headerCells) + $dayRows + @(,$totalCells)

# ログ本文を「日時 | IP(15桁左寄せ) | リクエスト」に整形（アクセス行以外はそのまま出力）
$logFormatted = @($log | ForEach-Object {
    if ($_ -match '^(\[[^\]]*\]|[0-9.]+) - \[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})[^\]]*\] (.*)$') {
        $dt = [datetime]::ParseExact($matches[2], 'dd/MMM/yyyy:HH:mm:ss', $ci)
        '{0:yyyy/MM/dd HH:mm:ss} | {1,-15} | {2}' -f $dt, $matches[1], $matches[3]
    } else {
        $_
    }
})

# 最新のログを上にするため逆順にする（docker compose logs は古い順で出力される）
[array]::Reverse($logFormatted)

# 出力先フォルダ・ファイル名を準備（フォルダが無ければ作成）
$logDir   = Split-Path -Parent $LocalLog
$current  = Split-Path -Leaf $LocalLog
New-Item -ItemType Directory -Path $logDir -Force | Out-Null

# 既存ログを最新1件のみに保つ（今回名へリネーム→この後上書き）
Move-LatestExisting -Dir $logDir -Filter '*_datecalc_access.log' -CurrentName $current -Destination $LocalLog

# 取得した最新ログでファイル内容を上書き（日別×ステータス集計は xlsx へ別出力）。
$logLines = [string[]]$logFormatted
[System.IO.File]::WriteAllLines($LocalLog, $logLines, $utf8NoBom)

# 日別×ステータス集計を Excel(xlsx) 出力。ファイル名はログと同じ yyyyMMddHHmm を流用し「..._datecalc_access_summary.xlsx」。
$summaryName = [System.IO.Path]::GetFileNameWithoutExtension($current) + '_summary.xlsx'
$summaryXlsx = Join-Path $logDir $summaryName

# 既存の集計xlsxを最新1件のみに保つ（ログと同様）
Move-LatestExisting -Dir $logDir -Filter '*_datecalc_access_summary.xlsx' -CurrentName $summaryName -Destination $summaryXlsx

# Excel(OOXML) の構築・書き出しはヘルパー（Write-XlsxSummary.ps1 の Write-XlsxSummary）に集約。本体は集計行データを渡すだけ。
# Write-XlsxSummary 実行時エラーを書式・独自コード(14)に統一して投げ直す。
try {
    Write-XlsxSummary -Path $summaryXlsx -Rows $xlsxRows
} catch {
    throw "xlsx出力に失敗しました (exit code: 14)`n$($_.Exception.Message)"
}

# 追加除外IPの抽出。ログ本文をIP別に集計し、「スキャン」と判定した送信元IPを抽出する。
# 集計・判定（A〜Cの3種・しきい値・パス正規化など）の詳細は ScanExclude.ps1 に集約。しきい値は env.ps1 で上書き可。
# 抽出結果は additional-exclude-ip.txt（IP昇順）へ書き出し、exclude-ip.txt にも追記する（判定別(A〜C)の累計件数と合計を集計コメントとして付加）。
# 0件のときは exclude-ip.txt は変更せず、additional-exclude-ip.txt も生成しない（前回分が残っていれば削除）。

# しきい値設定を組み立てる（env.ps1 の上書き値を渡し、未設定は ScanExclude.ps1 側の既定値で補完）。
$scanConfig = Resolve-ScanConfig -MinTotal $ScanMinTotal -MinPath $ScanMinPath `
    -Count404 $Scan404Count -Ratio200 $Scan200Ratio -ErrCount $ScanErrCount `
    -ErrRatio $ScanErrRatio -BrutePath $BruteOnePath -BruteAuthErr $BruteAuthErr `
    -AuthRegex $AuthPathRegex -RatePerMin $ScanRatePerMin `
    -Err5xxWeight $Scan5xxWeight -RateWindowMin $ScanRateWindowMin

# ログを集計・判定し、該当IP→分類(A/B/C) のマップを取得（Get-ScanCategoryMap）。抽出IPの昇順リストはそのキーから得る。
$categoryMap   = Get-ScanCategoryMap -Log $log -Config $scanConfig
$additionalIps = Sort-ScanIp -Ip @($categoryMap.Keys)

# additional-exclude-ip.txt の出力先はログ・xlsx と同じフォルダ。
$additionalFile = Join-Path $logDir 'additional-exclude-ip.txt'

if ($additionalIps.Count -gt 0) {
    # additional-exclude-ip.txt：コメントなし・抽出IPのみ（IP昇順）。
    [System.IO.File]::WriteAllLines($additionalFile, [string[]]$additionalIps, $utf8NoBom)

    # exclude-ip.txt を更新：既存内容に抽出IP・分類を反映した新しい内容を組み立てて上書き（無ければ新規作成）。
    # 既存行の解析・累計集計・マージ整列・コメント整形は ScanExclude.ps1 の Build-ScanExcludeContent に集約。
    $existingLines = if (Test-Path -LiteralPath $excludeIpFile) { Get-Content -LiteralPath $excludeIpFile -Encoding UTF8 } else { @() }
    $excludeLines  = Build-ScanExcludeContent -ExistingLines $existingLines -AdditionalIps $additionalIps -CategoryMap $categoryMap
    [System.IO.File]::WriteAllLines($excludeIpFile, [string[]]$excludeLines, $utf8NoBom)
} else {
    # 0件：残存している additional-exclude-ip.txt があれば削除。
    if (Test-Path -LiteralPath $additionalFile) {
        Remove-Item -LiteralPath $additionalFile -Force
    }
}

# 全処理が正常に完了。完了メッセージを出力し、3秒待機後にフォルダを開いてからウィンドウ（コンソール）を閉じる。
Write-Host "処理が正常に完了しました (exit code: 0)"
Start-Sleep -Seconds 3

# 出力先フォルダをエクスプローラーで新規ウィンドウで開く
Start-Process -FilePath 'explorer.exe' -ArgumentList "`"$logDir`""

exit 0
