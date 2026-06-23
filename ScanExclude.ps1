<#
  ScanExclude.ps1
  スキャンIPの検知と除外リスト整形をまとめたヘルパー。
  本体 Get-DockerAccessLog.ps1 からドットソースで読み込んで使う。
  SSH・実ファイルに依存しない純関数のみ（入力は取得済みログ配列／集計結果／既存の除外リスト行）なので、Pester 等で単体テスト可能。

  公開関数:
    Measure-ScanIp           : 取得済みログ配列 -> IP別集計（Paths/Status/Total/PeakRate）
    Resolve-ScanConfig       : しきい値（env.ps1 の上書き値）-> 既定補完済みの設定オブジェクト
    Get-ScanIpReason         : 1 IP の集計が判定(A〜C)に該当するか評価
    Get-ScanCategoryMap      : ログ配列＋設定 -> 該当IPを「IP -> 該当分類(A/B/C)の配列」で返す（集計→判定の本体）
    Sort-ScanIp              : IP文字列配列を IP昇順（オクテットの数値順）に整列（任意で重複排除）
    Build-ScanExcludeContent : 既存除外リスト行＋抽出IP＋分類マップ -> 新しい exclude-ip.txt の行配列（説明/集計コメント＋IP昇順）
#>

# 指定したタイムスタンプ列について、最も混雑した窓（既定1分）の「1分あたり要求数（ピークレート）」を返す。
# 全期間平均では長時間に分散したアクセスでバーストが薄まるため、要求レートはピークで評価する。
# 窓を広げると瞬間的なマイクロバーストが均され、件/分の意味を保つため窓内の最大件数を窓幅で正規化する。
# 引数:
#   $Times         : [datetime] の配列（順不同可。空なら0）
#   $WindowMinutes : ピーク算出の窓幅（分）。既定1。0以下は1に丸める。
# 戻り値:
#   最も混雑した窓における1分あたりの件数（=ピーク時の件/分。窓1分なら窓内件数そのもの）。
function Get-PeakRatePerMin {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [AllowNull()] $Times,
        [double] $WindowMinutes = 1
    )

    if ($WindowMinutes -le 0) { $WindowMinutes = 1 }
    $arr = @($Times | Sort-Object)
    if ($arr.Count -eq 0) { return 0 }

    # 昇順に並べ、左右ポインタで「右端から窓幅未満に収まる範囲」を保ちながら最大件数を求める（半開区間 [t, t+窓)）。
    $window = [TimeSpan]::FromMinutes($WindowMinutes)
    $left   = 0
    $peak   = 0
    for ($right = 0; $right -lt $arr.Count; $right++) {
        while (($arr[$right] - $arr[$left]) -ge $window) { $left++ }
        $n = $right - $left + 1
        if ($n -gt $peak) { $peak = $n }
    }
    # 窓内の最大件数を窓幅（分）で割り、1分あたりの件数（件/分）に正規化して返す。
    $peak / $WindowMinutes
}

# 取得済みログ配列を解析し、送信元IPごとに「パス別件数・総応答数・ステータス別件数・ピークレート」を集計する。
# 数字IP行のみ対象（マスキング済みの [Elastic IP]/[My IP] 行は対象外）。URLパスはクエリ文字列(?以降)を除外し、表記揺れを正規化する。
# 引数:
#   $Log           : 取得済みログ（文字列の配列。1要素1行）
#   $RateWindowMin : ピークレート算出の窓幅（分）。既定1。
# 戻り値:
#   Paths/Status/Total/PeakRate を持つオブジェクト。
#     Paths    : IP -> (パス -> 件数)
#     Status   : IP -> (ステータス -> 件数)
#     Total    : IP -> 総応答数
#     PeakRate : IP -> 最も混雑した窓（既定1分）の1分あたり要求数（時刻が解析できた行から算出。レートガード用）
function Measure-ScanIp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [AllowNull()] $Log,
        [double] $RateWindowMin = 1
    )

    $paths   = @{}
    $status  = @{}
    $total   = @{}
    $tstamps = @{}

    # 英語月名(MMM)を解釈するための InvariantCulture（時刻解析に使用）。
    $ci = [System.Globalization.CultureInfo]::InvariantCulture

    foreach ($line in $Log) {
        # IP=1 / リクエスト=3 / ステータス=4 を取得（数字IP行のみ対象）。
        if ($line -match '^(\d{1,3}(\.\d{1,3}){3})\s+-\s+\[[^\]]*\]\s+"([^"]*)"\s+(\d{3})') {
            $sIp  = $matches[1]
            $sReq = $matches[3]
            $sSt  = $matches[4]

            # リクエスト行（"METHOD PATH PROTOCOL"）から URL パスを取り出し、クエリ文字列(?以降)は除外。
            $sPath = $sReq
            if ($sReq -match '^\S+\s+(\S+)') { $sPath = $matches[1] }
            $qi = $sPath.IndexOf('?')
            if ($qi -ge 0) { $sPath = $sPath.Substring(0, $qi) }

            # パスの表記揺れ（パーセントエンコード・大文字小文字・末尾スラッシュ）を吸収してから集計する。
            # 同一パスの変種が別キーに割れるのを防ぎ、パス多様性と単一パス集中の評価を安定させる。
            $sPath = [System.Uri]::UnescapeDataString($sPath)
            $sPath = $sPath.ToLowerInvariant()
            if ($sPath.Length -gt 1) { $sPath = $sPath.TrimEnd('/') }
            if ($sPath -eq '') { $sPath = '/' }

            # IP別にパス別アクセス件数・総応答数・ステータス別件数を集計。
            if (-not $paths.ContainsKey($sIp)) { $paths[$sIp] = @{} }
            if ($paths[$sIp].ContainsKey($sPath)) { $paths[$sIp][$sPath]++ } else { $paths[$sIp][$sPath] = 1 }

            if ($total.ContainsKey($sIp)) { $total[$sIp]++ } else { $total[$sIp] = 1 }

            if (-not $status.ContainsKey($sIp)) { $status[$sIp] = @{} }
            if ($status[$sIp].ContainsKey($sSt)) { $status[$sIp][$sSt]++ } else { $status[$sIp][$sSt] = 1 }

            # タイムスタンプを記録（要求レート算出用）。解析できた行だけ反映し、件数集計には影響しない。
            $dt = [datetime]::MinValue
            if ($line -match '\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})' -and
                [datetime]::TryParseExact($matches[1], 'dd/MMM/yyyy:HH:mm:ss', $ci, [System.Globalization.DateTimeStyles]::None, [ref]$dt)) {
                if (-not $tstamps.ContainsKey($sIp)) { $tstamps[$sIp] = [System.Collections.Generic.List[datetime]]::new() }
                $tstamps[$sIp].Add($dt)
            }
        }
    }

    # 各IPの最も混雑した窓のピークレート（件/分）を求める。レートガードに用いる。
    $peakRate = @{}
    foreach ($kv in $tstamps.GetEnumerator()) {
        $peakRate[$kv.Key] = Get-PeakRatePerMin -Times $kv.Value -WindowMinutes $RateWindowMin
    }

    [pscustomobject]@{
        Paths    = $paths
        Status   = $status
        Total    = $total
        PeakRate = $peakRate
    }
}

# スキャン判定しきい値の設定オブジェクトを組み立てる。
# 各引数は env.ps1 の上書き値（未設定なら $null）を渡す想定。$null の項目は既定値で補完する。
# 戻り値:
#   Get-ScanIpReason の -Config に渡せる設定オブジェクト。
function Resolve-ScanConfig {
    [CmdletBinding()]
    param(
        $MinTotal,
        $MinPath,
        $Count404,
        $Ratio200,
        $ErrCount,
        $ErrRatio,
        $BrutePath,
        $BruteAuthErr,
        $AuthRegex,
        $RatePerMin,
        $Err5xxWeight,
        $RateWindowMin
    )

    # 未設定（$null）のときの既定値。
    if ($null -eq $MinTotal)      { $MinTotal      = 30 }
    if ($null -eq $RateWindowMin) { $RateWindowMin = 1 }
    if ($null -eq $RatePerMin)    { $RatePerMin    = 10 }
    if ($null -eq $MinPath)       { $MinPath       = 20 }
    if ($null -eq $Count404)      { $Count404      = 20 }
    if ($null -eq $Ratio200)      { $Ratio200      = 0.1 }
    if ($null -eq $ErrCount)      { $ErrCount      = 30 }
    if ($null -eq $ErrRatio)      { $ErrRatio      = 0.5 }
    if ($null -eq $Err5xxWeight)  { $Err5xxWeight  = 0.5 }
    if ($null -eq $BrutePath)     { $BrutePath     = 50 }
    if ($null -eq $BruteAuthErr)  { $BruteAuthErr  = 20 }
    if ([string]::IsNullOrWhiteSpace($AuthRegex)) {
        $AuthRegex = '(?i)(wp-login|xmlrpc|/wp-json|/admin|/login|/signin|/user/login|/api/(login|auth|token|session|oauth)|/\.env|/actuator|/graphql)'
    }

    [pscustomobject]@{
        MinTotal      = [int]$MinTotal
        MinPath       = [int]$MinPath
        Count404      = [int]$Count404
        Ratio200      = [double]$Ratio200
        ErrCount      = [int]$ErrCount
        ErrRatio      = [double]$ErrRatio
        BrutePath     = [int]$BrutePath
        BruteAuthErr  = [int]$BruteAuthErr
        AuthRegex     = [string]$AuthRegex
        RatePerMin    = [double]$RatePerMin
        Err5xxWeight  = [double]$Err5xxWeight
        RateWindowMin = [double]$RateWindowMin
    }
}

# 1つのIPの集計結果がスキャン判定(A〜C)に該当するか評価する。
# 引数:
#   $Paths          : URLパス -> アクセス件数 のハッシュテーブル
#   $Status         : ステータスコード -> 件数 のハッシュテーブル
#   $Total          : 総応答数
#   $Config         : しきい値（MinTotal/MinPath/Count404/Ratio200/ErrCount/ErrRatio/BrutePath/BruteAuthErr/AuthRegex/RatePerMin/Err5xxWeight/RateWindowMin）
#   $PeakRatePerMin : そのIPの最も混雑した窓（既定1分）の1分あたり要求数（ピークレート）。0以下ならレートガードを適用しない（時刻不明・後方互換）。
# 戻り値:
#   非該当（または対象外）なら $null。該当時は Reasons（enum/error/brute の配列）を持つオブジェクト。
function Get-ScanIpReason {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Paths,
        [Parameter(Mandatory)] [hashtable] $Status,
        [Parameter(Mandatory)] [int]       $Total,
        [Parameter(Mandatory)]             $Config,
        [double] $PeakRatePerMin = 0
    )

    # 共通：最低リクエスト数に満たないIPは対象外（小サンプルでの誤検知防止）。
    if ($Total -lt $Config.MinTotal) { return $null }

    # 共通：ピークレート（最も混雑した窓内の1分あたり要求数）が下限未満のIPは対象外。
    # 全期間平均ではなくピーク（任意の窓＝既定1分の最大件数を窓幅で正規化）で見ることで、長時間に分散していても
    # 短時間に集中したバーストを取りこぼさず、薄く分散する低速アクセス（正規利用者寄り）は救済する。
    # ピークが取れない（0）または下限が0以下のときは適用しない。
    if ($Config.RatePerMin -gt 0 -and $PeakRatePerMin -gt 0) {
        if ($PeakRatePerMin -lt $Config.RatePerMin) { return $null }
    }

    # ステータス別件数（不在は0。5xx は 500〜599 を合算）。
    $cnt = { param($h, $k) if ($h.ContainsKey($k)) { $h[$k] } else { 0 } }
    $c200 = & $cnt $Status '200'
    $c401 = & $cnt $Status '401'
    $c403 = & $cnt $Status '403'
    $c404 = & $cnt $Status '404'
    $c429 = & $cnt $Status '429'
    $c5xx = 0
    foreach ($k in $Status.Keys) { if ($k -like '5??') { $c5xx += $Status[$k] } }

    # エラー量の評価値。クライアント起因の 4xx は満額で数え、サーバ起因にもなりうる 5xx は重みを下げて補助的に加味する。
    # 重みは Config.Err5xxWeight（既定0.5）。障害時に 5xx を量産しただけの正規クライアントを高エラー型として誤検知しにくくする。
    $errClient = $c401 + $c403 + $c404 + $c429
    $errScore  = $errClient + ($c5xx * $Config.Err5xxWeight)

    # 単一パスへの最大集中件数と、閾値超パスに認証系パスが含まれるか。
    # 認証パス一致は「最大集中パス1つ」ではなく「BrutePath 以上のいずれか」で見る
    # （同数並びでのハッシュ列挙順依存＝非決定性を排除し、認証URLへの総当たり取りこぼしも防ぐ）。
    $maxHits     = 0
    $authPathHit = $false
    foreach ($p in $Paths.Keys) {
        if ($Paths[$p] -gt $maxHits) { $maxHits = $Paths[$p] }
        if ($Paths[$p] -ge $Config.BrutePath -and $p -match $Config.AuthRegex) { $authPathHit = $true }
    }

    # (A) 列挙スキャン：パス多様性＋失敗応答の多さ。
    $isEnum = ($Paths.Count -ge $Config.MinPath) -and
              (($c404 -ge $Config.Count404) -or ($c200 -lt ($Total * $Config.Ratio200)))

    # (B) 高エラー型：4xx 主体のエラー量と比率（5xx は重み付きで加味）。
    # 404単独に依存せず、未知パスに200を返す soft-404 サイトでの取りこぼしを抑えつつ、
    # 401/403/429 を量産するスキャナも捕捉する。
    $isHighErr = ($errScore -ge $Config.ErrCount) -and
                 ($errScore -ge ($Total * $Config.ErrRatio))

    # (C) クレデンシャル総当たり：単一パスへの集中＋認証エラー/認証パス。
    # 認証エラーの合算に 429（レート制限の応酬）も含める。
    $isBrute = ($maxHits -ge $Config.BrutePath) -and
               ((($c401 + $c403 + $c429) -ge $Config.BruteAuthErr) -or $authPathHit)

    $reasons = @()
    if ($isEnum)    { $reasons += 'enum' }
    if ($isHighErr) { $reasons += 'error' }
    if ($isBrute)   { $reasons += 'brute' }

    if ($reasons.Count -gt 0) { [pscustomobject]@{ Reasons = $reasons } } else { $null }
}

# IP文字列の配列を IP昇順（オクテットの数値順）に整列して返す。並び順ルール（[version]比較）を一元化する。
# 引数:
#   $Ip     : IP文字列の配列（順不同可。空/Null可）
#   $Unique : 指定時は重複排除も行う
# 戻り値:
#   IP昇順に整列した配列（0件なら空配列）。
function Sort-ScanIp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [AllowNull()] $Ip,
        [switch] $Unique
    )
    if ($Unique) { @($Ip | Sort-Object { [version]$_ } -Unique) }
    else         { @($Ip | Sort-Object { [version]$_ }) }
}

# 取得済みログ配列を集計・判定し、該当した各IPが満たす判定を (A)/(B)/(C) のラベル配列で表した
# 「IP -> 分類ラベル配列(@('A','B',...))」のハッシュテーブルを返す。
# 1つのIPが複数の判定に該当する場合は、該当する分類をすべて配列に含める（A/B/C は重複して計上されうる）。
# 引数:
#   $Log    : 取得済みログ（文字列の配列）
#   $Config : Resolve-ScanConfig が返す設定オブジェクト
# 戻り値:
#   該当IP -> 分類ラベル配列('A'/'B'/'C') のハッシュテーブル（該当0件なら空）。キーは判定(A〜C)に該当したIP。
function Get-ScanCategoryMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [AllowNull()] $Log,
        [Parameter(Mandatory)]                                        $Config
    )

    $stats = Measure-ScanIp -Log $Log -RateWindowMin $Config.RateWindowMin

    $map = @{}
    foreach ($ip in $stats.Paths.Keys) {
        # 最も混雑した窓（既定1分）の1分あたり要求数（ピークレート）。取得できないIPは0としレートガードを適用しない（Get-ScanIpReason側でスキップ）。
        $peakRate = 0
        if ($stats.PeakRate.ContainsKey($ip)) { $peakRate = $stats.PeakRate[$ip] }

        $reason = Get-ScanIpReason -Paths $stats.Paths[$ip] -Status $stats.Status[$ip] -Total $stats.Total[$ip] -Config $Config -PeakRatePerMin $peakRate
        if ($reason) {
            # 該当する判定をすべてラベル配列に含める（複数該当は各分類で計上）。
            $cats = @()
            if ($reason.Reasons -contains 'enum')  { $cats += 'A' }
            if ($reason.Reasons -contains 'error') { $cats += 'B' }
            if ($reason.Reasons -contains 'brute') { $cats += 'C' }
            $map[$ip] = $cats
        }
    }

    $map
}

# 既存の exclude-ip.txt 行・今回の抽出IP・分類マップから、新しい exclude-ip.txt の行配列を組み立てる純関数。
# 実ファイルI/Oは行わず、行配列を受け取り行配列を返す（読み書きは呼び出し側が担う）。
# 既存の説明コメントは保持し、集計コメント(# Count/# (A)/(B)/(C)/# Total)は既存累計＋今回新規分で再計算する。
# 引数:
#   $ExistingLines : 既存 exclude-ip.txt の行配列（無ければ空/Null）
#   $AdditionalIps : 今回スキャンと判定した抽出IP（順不同可）
#   $CategoryMap   : IP -> 該当分類配列('A'/'B'/'C')（Get-ScanCategoryMap の戻り）
# 戻り値:
#   新しい exclude-ip.txt の行配列（説明コメント → 集計コメント → IP昇順）。
function Build-ScanExcludeContent {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()] [AllowNull()]                        $ExistingLines,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [AllowNull()] $AdditionalIps,
        [Parameter(Mandatory)] [hashtable]                            $CategoryMap
    )

    $descComments = [System.Collections.Generic.List[string]]::new()
    $existingIps  = [System.Collections.Generic.List[string]]::new()
    $cumA = 0; $cumB = 0; $cumC = 0

    foreach ($l in @($ExistingLines)) {
        $t = "$l".Trim()
        if ($t -eq '') { continue }
        if ($t.StartsWith('#')) {
            # 集計コメント（ラベル＋数字のみの行）は累計値を読み取って破棄し、後で作り直す。
            # 説明コメントの「# (A) 列挙スキャン…」等は数字のみ行に一致しないため、そのまま保持される。
            if     ($t -match '^#\s*Count\s*$')         { }
            elseif ($t -match '^#\s*\(A\)\s*(\d+)\s*$') { $cumA = [int]$matches[1] }
            elseif ($t -match '^#\s*\(B\)\s*(\d+)\s*$') { $cumB = [int]$matches[1] }
            elseif ($t -match '^#\s*\(C\)\s*(\d+)\s*$') { $cumC = [int]$matches[1] }
            elseif ($t -match '^#\s*Total\s*(\d+)\s*$') { }
            else                                        { $descComments.Add($l) }
        } else {
            $existingIps.Add($t)
        }
    }

    # 今回新たに加わるIP（既存リストに無いもの）の該当分類を加算して累計を更新。
    # 複数判定に該当するIPは該当する分類をすべて加算するため、A/B/C は重複して計上されうる。
    $existingSet = @{}
    foreach ($ip in $existingIps) { $existingSet[$ip] = $true }
    foreach ($ip in @($AdditionalIps)) {
        if (-not $existingSet.ContainsKey($ip)) {
            foreach ($cat in @($CategoryMap[$ip])) {
                switch ($cat) {
                    'A' { $cumA++ }
                    'B' { $cumB++ }
                    'C' { $cumC++ }
                }
            }
        }
    }

    # 既存IP＋抽出IPを重複排除し IP昇順（オクテットの数値順）に整列。
    $mergedIps = Sort-ScanIp -Ip (@($existingIps) + @($AdditionalIps)) -Unique

    # Total は累計の実IP数（=exclude-ip.txt 内のIP数、重複なし）。A+B+C とは一致しないことがある。
    $cumTotal = $mergedIps.Count

    $countComments = @(
        '# Count'
        '# (A)'.PadRight(8)   + $cumA
        '# (B)'.PadRight(8)   + $cumB
        '# (C)'.PadRight(8)   + $cumC
        '# Total'.PadRight(8) + $cumTotal
    )

    # 出力順：説明コメント → 集計コメント → IP（昇順）。
    [string[]](@($descComments) + @($countComments) + @($mergedIps))
}
