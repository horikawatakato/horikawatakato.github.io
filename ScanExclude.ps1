<#
  ScanExclude.ps1
  スキャンIPの検知と除外リスト整形をまとめたヘルパー。Get-DockerAccessLog.ps1 からドットソースで読み込む。
  SSH・実ファイルに依存しない純関数のみ（入力は取得済みログ配列／集計結果／既存の除外リスト行）。

  公開関数:
    Measure-ScanIp           : 取得済みログ配列＋設定 -> IP別の集計（パス/ステータス/総数/ピークレート/POST/認証エラー/認証パス成功/内容指標シグナル）
    Resolve-ScanConfig       : しきい値の上書き値 -> 既定補完済みの設定オブジェクト
    Get-ScanIpReason         : 1 IP の集計が判定に該当するか評価（enum/error/brute/sig/login）
    Get-ScanCategoryMap      : ログ配列＋設定 -> 該当IP -> 分類ラベル配列(A/B/C/S/L)
    Sort-ScanIp              : IP文字列配列を IP昇順（オクテット数値順）に整列（任意で重複排除）
    Build-ScanExcludeContent : 既存除外リスト行＋抽出IP＋分類マップ -> 新しい exclude-ip.txt の行配列
#>

# 指定タイムスタンプ列の、最も混雑した窓（既定1分）における1分あたり要求数（ピークレート）を返す。
# 引数: $Times=[datetime]配列（順不同可・空可）, $WindowMinutes=窓幅（分・0以下は1に丸め）
function Get-PeakRatePerMin {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [AllowNull()] $Times,
        [double] $WindowMinutes = 1
    )

    if ($WindowMinutes -le 0) { $WindowMinutes = 1 }
    $arr = @($Times | Sort-Object)
    if ($arr.Count -eq 0) { return 0 }

    # 昇順に並べ、左右ポインタで半開区間 [t, t+窓) に収まる範囲を保ちながら最大件数を求める。
    $window = [TimeSpan]::FromMinutes($WindowMinutes)
    $left   = 0
    $peak   = 0
    for ($right = 0; $right -lt $arr.Count; $right++) {
        while (($arr[$right] - $arr[$left]) -ge $window) { $left++ }
        $n = $right - $left + 1
        if ($n -gt $peak) { $peak = $n }
    }
    # 窓内最大件数を窓幅で割り、1分あたり件数に正規化して返す。
    $peak / $WindowMinutes
}

# 取得済みログ配列を解析し、送信元IPごとに集計する。数字IP行のみ対象（マスキング済み行は対象外）。
# 戻り値の各フィールドは IP をキーに持つ。
#   Paths        : IP -> (パス -> 件数)        パスはクエリ除去・デコード・小文字化・末尾スラッシュ除去で正規化
#   Status       : IP -> (ステータス -> 件数)
#   Total        : IP -> 総応答数
#   PeakRate     : IP -> 最も混雑した窓の1分あたり要求数
#   Posts        : IP -> (パス -> POST件数)
#   PathAuthErr  : IP -> (パス -> 401/403/429件数)
#   AuthPath200  : IP -> 認証パス（AuthRegex一致かつApiAuthRegex非該当）上の200件数
#   AuthPathTotal: IP -> 同上パスへの総アクセス件数
#   SigHits      : IP -> 攻撃ファイルパス（SigRegex）該当件数（パスで評価）
#   ExploitHits  : IP -> 攻撃トークン（ExploitRegex）該当件数（クエリ込みリクエスト原文をデコードして評価）
#   ProxyHit     : IP -> 絶対URI（ProxyRegex）該当フラグ
#   BadMethodHit : IP -> 異常メソッド（BadMethodRegex）該当フラグ
#   ProtoHit     : IP -> 確定プロトコルシグネチャ該当、または整形不正バイナリが3件以上かつ全要求の過半、のフラグ
function Measure-ScanIp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [AllowNull()] $Log,
        [Parameter(Mandatory)] $Config
    )

    $paths        = @{}
    $status       = @{}
    $total        = @{}
    $tstamps      = @{}
    $posts        = @{}
    $pathAuthErr  = @{}
    $authPath200  = @{}
    $authPathTot  = @{}
    $sigHits      = @{}
    $exploitHits  = @{}
    $proxyHit     = @{}
    $badMethodHit = @{}
    $protoSig     = @{}
    $malformed    = @{}

    $ci = [System.Globalization.CultureInfo]::InvariantCulture
    # 正常なリクエスト行（METHOD SP target SP HTTP/x[.y]）。これに合致せずバイナリ混入する行を整形不正とみなす。
    $wellFormed = '^[A-Z]+\s+\S+\s+HTTP/\d(\.\d)?$'

    foreach ($line in $Log) {
        # IP=1 / リクエスト=3 / ステータス=4。
        if ($line -match '^(\d{1,3}(\.\d{1,3}){3})\s+-\s+\[[^\]]*\]\s+"([^"]*)"\s+(\d{3})') {
            $sIp  = $matches[1]
            $sReq = $matches[3]
            $sSt  = $matches[4]

            # メソッド（リクエスト行の先頭トークン）。
            $sMethod = ''
            if ($sReq -match '^(\S+)\s') { $sMethod = $matches[1].ToUpperInvariant() }

            # URLパス（リクエストの2番目のトークン）。クエリ除去 → デコード → 小文字化 → 末尾スラッシュ除去。
            $sPath = $sReq
            if ($sReq -match '^\S+\s+(\S+)') { $sPath = $matches[1] }
            $qi = $sPath.IndexOf('?')
            if ($qi -ge 0) { $sPath = $sPath.Substring(0, $qi) }
            $sPath = [System.Uri]::UnescapeDataString($sPath)
            $sPath = $sPath.ToLowerInvariant()
            if ($sPath.Length -gt 1) { $sPath = $sPath.TrimEnd('/') }
            if ($sPath -eq '') { $sPath = '/' }

            # パス別件数・総応答数・ステータス別件数。
            if (-not $paths.ContainsKey($sIp)) { $paths[$sIp] = @{} }
            if ($paths[$sIp].ContainsKey($sPath)) { $paths[$sIp][$sPath]++ } else { $paths[$sIp][$sPath] = 1 }
            if ($total.ContainsKey($sIp)) { $total[$sIp]++ } else { $total[$sIp] = 1 }
            if (-not $status.ContainsKey($sIp)) { $status[$sIp] = @{} }
            if ($status[$sIp].ContainsKey($sSt)) { $status[$sIp][$sSt]++ } else { $status[$sIp][$sSt] = 1 }

            # POST件数（パス別）。
            if ($sMethod -eq 'POST') {
                if (-not $posts.ContainsKey($sIp)) { $posts[$sIp] = @{} }
                if ($posts[$sIp].ContainsKey($sPath)) { $posts[$sIp][$sPath]++ } else { $posts[$sIp][$sPath] = 1 }
            }

            # 認証エラー（401/403/429）件数（パス別）。404は含めない。
            if ($sSt -eq '401' -or $sSt -eq '403' -or $sSt -eq '429') {
                if (-not $pathAuthErr.ContainsKey($sIp)) { $pathAuthErr[$sIp] = @{} }
                if ($pathAuthErr[$sIp].ContainsKey($sPath)) { $pathAuthErr[$sIp][$sPath]++ } else { $pathAuthErr[$sIp][$sPath] = 1 }
            }

            # 認証パス（AuthRegex一致かつApiAuthRegex非該当）への総アクセスと200成功。
            if ($sPath -match $Config.AuthRegex -and $sPath -notmatch $Config.ApiAuthRegex) {
                if ($authPathTot.ContainsKey($sIp)) { $authPathTot[$sIp]++ } else { $authPathTot[$sIp] = 1 }
                if ($sSt -eq '200') {
                    if ($authPath200.ContainsKey($sIp)) { $authPath200[$sIp]++ } else { $authPath200[$sIp] = 1 }
                }
            }

            # 攻撃ファイルパス（正規化パスで評価）。
            if ($sPath -match $Config.SigRegex) {
                if ($sigHits.ContainsKey($sIp)) { $sigHits[$sIp]++ } else { $sigHits[$sIp] = 1 }
            }

            # 攻撃トークン（クエリを含むリクエスト原文を1回デコードして評価）。
            $reqDecoded = [System.Uri]::UnescapeDataString($sReq)
            if ($reqDecoded -match $Config.ExploitRegex) {
                if ($exploitHits.ContainsKey($sIp)) { $exploitHits[$sIp]++ } else { $exploitHits[$sIp] = 1 }
            }

            # 絶対URI（プロキシ探索）・異常メソッド・確定プロトコルシグネチャ（リクエスト原文で評価）。
            if ($sReq -match $Config.ProxyRegex)     { $proxyHit[$sIp]     = $true }
            if ($sReq -match $Config.BadMethodRegex) { $badMethodHit[$sIp] = $true }
            if ($sReq -match $Config.ProtoRegex)     { $protoSig[$sIp]     = $true }

            # 整形不正かつバイナリ混入（プロトコル探索の支配率判定に使用）。
            if ($sReq.Trim() -ne '' -and $sReq -notmatch $wellFormed -and $sReq.Contains('\x')) {
                if ($malformed.ContainsKey($sIp)) { $malformed[$sIp]++ } else { $malformed[$sIp] = 1 }
            }

            # タイムスタンプ（ピークレート用。解析できた行のみ。件数集計には影響しない）。
            $dt = [datetime]::MinValue
            if ($line -match '\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})' -and
                [datetime]::TryParseExact($matches[1], 'dd/MMM/yyyy:HH:mm:ss', $ci, [System.Globalization.DateTimeStyles]::None, [ref]$dt)) {
                if (-not $tstamps.ContainsKey($sIp)) { $tstamps[$sIp] = [System.Collections.Generic.List[datetime]]::new() }
                $tstamps[$sIp].Add($dt)
            }
        }
    }

    # 各IPのピークレート。
    $peakRate = @{}
    foreach ($kv in $tstamps.GetEnumerator()) {
        $peakRate[$kv.Key] = Get-PeakRatePerMin -Times $kv.Value -WindowMinutes $Config.RateWindowMin
    }

    # プロトコル探索フラグの確定（確定シグネチャ該当、または整形不正バイナリが3件以上かつ全要求の過半）。
    $protoHit = @{}
    foreach ($ip in $total.Keys) {
        $mal = if ($malformed.ContainsKey($ip)) { $malformed[$ip] } else { 0 }
        $tot = $total[$ip]
        if ($protoSig.ContainsKey($ip) -or ($mal -ge 3 -and $mal -ge ($tot * 0.5))) { $protoHit[$ip] = $true }
    }

    [pscustomobject]@{
        Paths         = $paths
        Status        = $status
        Total         = $total
        PeakRate      = $peakRate
        Posts         = $posts
        PathAuthErr   = $pathAuthErr
        AuthPath200   = $authPath200
        AuthPathTotal = $authPathTot
        SigHits       = $sigHits
        ExploitHits   = $exploitHits
        ProxyHit      = $proxyHit
        BadMethodHit  = $badMethodHit
        ProtoHit      = $protoHit
    }
}

# スキャン判定しきい値の設定オブジェクトを組み立てる。各引数は env.ps1 の上書き値（未設定なら $null）を渡す想定。
# $null（文字列は空白）の項目は既定値で補完する。
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
        $RateWindowMin,
        $BrutePost,
        $LoginFormRegex,
        $BruteAuthVariety,
        $AuthSuccessRatioMax,
        $ApiAuthRegex,
        $SigRegex,
        $ExploitRegex,
        $ProxyRegex,
        $BadMethodRegex,
        $ProtoRegex
    )

    if ($null -eq $MinTotal)            { $MinTotal            = 30 }
    if ($null -eq $RateWindowMin)       { $RateWindowMin       = 1 }
    if ($null -eq $RatePerMin)          { $RatePerMin          = 10 }
    if ($null -eq $MinPath)             { $MinPath             = 20 }
    if ($null -eq $Count404)            { $Count404            = 20 }
    if ($null -eq $Ratio200)            { $Ratio200            = 0.1 }
    if ($null -eq $ErrCount)            { $ErrCount            = 30 }
    if ($null -eq $ErrRatio)            { $ErrRatio            = 0.5 }
    if ($null -eq $Err5xxWeight)        { $Err5xxWeight        = 0.5 }
    if ($null -eq $BrutePath)           { $BrutePath           = 50 }
    if ($null -eq $BruteAuthErr)        { $BruteAuthErr        = 20 }
    if ($null -eq $BrutePost)           { $BrutePost           = 20 }
    if ($null -eq $BruteAuthVariety)    { $BruteAuthVariety    = 3 }
    if ($null -eq $AuthSuccessRatioMax) { $AuthSuccessRatioMax = 0.5 }

    # 正規ログインURL（ログイン探索の種類数集計に使用）。
    if ([string]::IsNullOrWhiteSpace($AuthRegex)) {
        $AuthRegex = '(?i)(/admin|/login|/signin|/user/login|/api/(login|auth|token|session|oauth)|/graphql)'
    }
    # 総当たりの集中パス判定に使うログインフォーム。プログラム的・管理操作で多数POSTされ得るパスは含めない。
    if ([string]::IsNullOrWhiteSpace($LoginFormRegex)) {
        $LoginFormRegex = '(?i)(/login|/signin|/user/login|/admin/login|wp-login|/administrator/index)'
    }
    # ログイン探索の種類数集計から除外する API 認証エンドポイント。
    if ([string]::IsNullOrWhiteSpace($ApiAuthRegex)) {
        $ApiAuthRegex = '(?i)/api/(login|auth|token|session|oauth)'
    }
    # 攻撃ファイルパス。
    if ([string]::IsNullOrWhiteSpace($SigRegex)) {
        $SigRegex = '(?i)(/\.env|/\.git|/\.aws|/\.ssh|/\.svn|/\.htpasswd|/\.vscode|wp-login\.php|xmlrpc\.php|wp-config\.php|/wp-content/plugins/|/wp-includes/|/wp-admin/|/vendor/phpunit|eval-stdin\.php|/cgi-bin/.*(\.\./|%2e%2e|/bin/sh|php-cgi)|/boaform|/solr/|/manager/html|/hudson|/_ignition|/credentials\.json|/phpmyadmin|/adminer|/druid|/jolokia|/struts|/actuator|/wp-json)'
    }
    # 攻撃トークン。
    if ([string]::IsNullOrWhiteSpace($ExploitRegex)) {
        $ExploitRegex = '(?i)(\$\{jndi:|\.\./\.\.|%2e%2e|union\s+select|\bor\s+1=1\b|<script|/etc/passwd|/bin/sh|cmd=|base64_|/win\.ini)'
    }
    # 絶対URI（プロキシ探索）。
    if ([string]::IsNullOrWhiteSpace($ProxyRegex)) {
        $ProxyRegex = '(?i)^[A-Z]+\s+[a-z][a-z0-9+.\-]*://'
    }
    # 異常メソッド。
    if ([string]::IsNullOrWhiteSpace($BadMethodRegex)) {
        $BadMethodRegex = '(?i)^(CONNECT|PROPFIND|DEBUG|TRACE|TRACK|SEARCH|MKCOL|MOVE)\s'
    }
    # 確定プロトコルシグネチャ（SMB/RAT/マイニング）。
    if ([string]::IsNullOrWhiteSpace($ProtoRegex)) {
        $ProtoRegex = '(?i)(SMBr|\\xFESMB|\\xFFSMB|Gh0st|mining\.subscribe|mining\.authorize)'
    }

    [pscustomobject]@{
        MinTotal            = [int]$MinTotal
        MinPath             = [int]$MinPath
        Count404            = [int]$Count404
        Ratio200            = [double]$Ratio200
        ErrCount            = [int]$ErrCount
        ErrRatio            = [double]$ErrRatio
        BrutePath           = [int]$BrutePath
        BruteAuthErr        = [int]$BruteAuthErr
        AuthRegex           = [string]$AuthRegex
        RatePerMin          = [double]$RatePerMin
        Err5xxWeight        = [double]$Err5xxWeight
        RateWindowMin       = [double]$RateWindowMin
        BrutePost           = [int]$BrutePost
        LoginFormRegex      = [string]$LoginFormRegex
        BruteAuthVariety    = [int]$BruteAuthVariety
        AuthSuccessRatioMax = [double]$AuthSuccessRatioMax
        ApiAuthRegex        = [string]$ApiAuthRegex
        SigRegex            = [string]$SigRegex
        ExploitRegex        = [string]$ExploitRegex
        ProxyRegex          = [string]$ProxyRegex
        BadMethodRegex      = [string]$BadMethodRegex
        ProtoRegex          = [string]$ProtoRegex
    }
}

# 1 IP の集計結果が判定に該当するか評価する。
# 内容指標（sig）とログイン探索（login）は共通ゲートを通さず、低量でも評価する。
# 列挙（enum）・高エラー（error）・総当たり（brute）は共通ゲート（最低リクエスト数・ピークレート）を満たす場合のみ評価する。
# 戻り値: 非該当なら $null。該当時は Reasons（enum/error/brute/sig/login の配列）を持つオブジェクト。
function Get-ScanIpReason {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Paths,
        [Parameter(Mandatory)] [hashtable] $Status,
        [Parameter(Mandatory)] [int]       $Total,
        [Parameter(Mandatory)]             $Config,
        [double]    $PeakRatePerMin = 0,
        [hashtable] $Posts          = @{},
        [hashtable] $PathAuthErr    = @{},
        [int]       $AuthPath200    = 0,
        [int]       $AuthPathTotal  = 0,
        [int]       $SigHits        = 0,
        [int]       $ExploitHits    = 0,
        [bool]      $ProxyHit       = $false,
        [bool]      $BadMethodHit   = $false,
        [bool]      $ProtoHit       = $false
    )

    $reasons = @()

    # (S) 内容指標：攻撃ファイルパス／攻撃トークン／プロキシ探索／異常メソッド／プロトコル探索のいずれか。共通ゲート免除。
    if (($SigHits -ge 1) -or ($ExploitHits -ge 1) -or $ProxyHit -or $BadMethodHit -or $ProtoHit) {
        $reasons += 'sig'
    }

    # (L) ログイン探索：AuthRegex一致かつApiAuthRegex非該当パスの種類数が下限以上、かつ認証パス上の200成功率が上限未満。共通ゲート免除。
    $authVariety = 0
    foreach ($p in $Paths.Keys) {
        if ($p -match $Config.AuthRegex -and $p -notmatch $Config.ApiAuthRegex) { $authVariety++ }
    }
    $lowSuccess = ($AuthPathTotal -eq 0) -or (($AuthPath200 / $AuthPathTotal) -lt $Config.AuthSuccessRatioMax)
    if ($authVariety -ge $Config.BruteAuthVariety -and $lowSuccess) { $reasons += 'login' }

    # 共通ゲート：A・B・C にのみ適用。最低リクエスト数未満、またはピークレート下限未満（算出可かつ下限>0のとき）は対象外。
    $gated = $true
    if ($Total -lt $Config.MinTotal) { $gated = $false }
    if ($Config.RatePerMin -gt 0 -and $PeakRatePerMin -gt 0 -and $PeakRatePerMin -lt $Config.RatePerMin) { $gated = $false }

    if ($gated) {
        # ステータス別件数（不在は0。5xx は 500〜599 を合算）。
        $cnt = { param($h, $k) if ($h.ContainsKey($k)) { $h[$k] } else { 0 } }
        $c200 = & $cnt $Status '200'
        $c401 = & $cnt $Status '401'
        $c403 = & $cnt $Status '403'
        $c404 = & $cnt $Status '404'
        $c429 = & $cnt $Status '429'
        $c5xx = 0
        foreach ($k in $Status.Keys) { if ($k -like '5??') { $c5xx += $Status[$k] } }

        # クライアント起因の 4xx は満額、サーバ起因にもなりうる 5xx は重み付きで加味。
        $errClient = $c401 + $c403 + $c404 + $c429
        $errScore  = $errClient + ($c5xx * $Config.Err5xxWeight)

        # (A) 列挙：パス多様性＋失敗応答の多さ。
        $isEnum = ($Paths.Count -ge $Config.MinPath) -and
                  (($c404 -ge $Config.Count404) -or ($c200 -lt ($Total * $Config.Ratio200)))
        if ($isEnum) { $reasons += 'enum' }

        # (B) 高エラー型：エラー量と比率（5xx は重み付き）。
        $isHighErr = ($errScore -ge $Config.ErrCount) -and ($errScore -ge ($Total * $Config.ErrRatio))
        if ($isHighErr) { $reasons += 'error' }

        # (C) 総当たり：経路1=単一ログインフォームへのPOST集中、経路2=単一パス集中＋同一パスの認証兆候。
        # 経路1・経路2 の集中パス判定はログインフォーム（LoginFormRegex）に限定。認証エラー分岐はパス内容に依存しない。
        $maxLoginPost = 0
        foreach ($p in $Posts.Keys) {
            if ($p -match $Config.LoginFormRegex -and $Posts[$p] -gt $maxLoginPost) { $maxLoginPost = $Posts[$p] }
        }
        $bruteByPost = ($maxLoginPost -ge $Config.BrutePost)

        $bruteByConc = $false
        foreach ($p in $Paths.Keys) {
            if ($Paths[$p] -ge $Config.BrutePath) {
                $aerr = 0
                if ($PathAuthErr.ContainsKey($p)) { $aerr = $PathAuthErr[$p] }
                if (($p -match $Config.LoginFormRegex) -or ($aerr -ge $Config.BruteAuthErr)) { $bruteByConc = $true; break }
            }
        }
        if ($bruteByPost -or $bruteByConc) { $reasons += 'brute' }
    }

    if ($reasons.Count -gt 0) { [pscustomobject]@{ Reasons = $reasons } } else { $null }
}

# IP文字列配列を IP昇順（[version]比較＝オクテット数値順）に整列。-Unique 指定で重複排除。
function Sort-ScanIp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [AllowNull()] $Ip,
        [switch] $Unique
    )
    if ($Unique) { @($Ip | Sort-Object { [version]$_ } -Unique) }
    else         { @($Ip | Sort-Object { [version]$_ }) }
}

# 取得済みログ配列を集計・判定し、該当IP -> 分類ラベル配列(A/B/C/S/L) のハッシュテーブルを返す。
# 1つのIPが複数判定に該当する場合は該当分類をすべて含める。該当0件なら空ハッシュ。
function Get-ScanCategoryMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [AllowNull()] $Log,
        [Parameter(Mandatory)]                                        $Config
    )

    $stats = Measure-ScanIp -Log $Log -Config $Config

    $map = @{}
    foreach ($ip in $stats.Paths.Keys) {
        $peakRate = 0
        if ($stats.PeakRate.ContainsKey($ip)) { $peakRate = $stats.PeakRate[$ip] }
        $posts = if ($stats.Posts.ContainsKey($ip))         { $stats.Posts[$ip] }         else { @{} }
        $pErr  = if ($stats.PathAuthErr.ContainsKey($ip))   { $stats.PathAuthErr[$ip] }   else { @{} }
        $ap200 = if ($stats.AuthPath200.ContainsKey($ip))   { $stats.AuthPath200[$ip] }   else { 0 }
        $apTot = if ($stats.AuthPathTotal.ContainsKey($ip)) { $stats.AuthPathTotal[$ip] } else { 0 }
        $sigH  = if ($stats.SigHits.ContainsKey($ip))       { $stats.SigHits[$ip] }       else { 0 }
        $expH  = if ($stats.ExploitHits.ContainsKey($ip))   { $stats.ExploitHits[$ip] }   else { 0 }
        $prox  = $stats.ProxyHit.ContainsKey($ip)
        $bmth  = $stats.BadMethodHit.ContainsKey($ip)
        $prot  = $stats.ProtoHit.ContainsKey($ip)

        $reason = Get-ScanIpReason -Paths $stats.Paths[$ip] -Status $stats.Status[$ip] -Total $stats.Total[$ip] `
            -Config $Config -PeakRatePerMin $peakRate -Posts $posts -PathAuthErr $pErr `
            -AuthPath200 $ap200 -AuthPathTotal $apTot -SigHits $sigH -ExploitHits $expH `
            -ProxyHit $prox -BadMethodHit $bmth -ProtoHit $prot

        if ($reason) {
            $cats = @()
            if ($reason.Reasons -contains 'enum')  { $cats += 'A' }
            if ($reason.Reasons -contains 'error') { $cats += 'B' }
            if ($reason.Reasons -contains 'brute') { $cats += 'C' }
            if ($reason.Reasons -contains 'sig')   { $cats += 'S' }
            if ($reason.Reasons -contains 'login') { $cats += 'L' }
            $map[$ip] = $cats
        }
    }

    $map
}

# 既存の exclude-ip.txt 行・今回の抽出IP・分類マップから、新しい exclude-ip.txt の行配列を組み立てる純関数。
# 実ファイルI/Oは行わない。説明コメントは保持し、集計コメント(# Count/# (A)〜(L)/# Total)は既存累計＋今回新規分で再計算する。
# 集計コメントの件数は分類別の延べ数（1IPが複数分類に該当すると各分類で計上）。Total は重複なしの実IP数。
function Build-ScanExcludeContent {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()] [AllowNull()]                        $ExistingLines,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [AllowNull()] $AdditionalIps,
        [Parameter(Mandatory)] [hashtable]                            $CategoryMap
    )

    $descComments = [System.Collections.Generic.List[string]]::new()
    $existingIps  = [System.Collections.Generic.List[string]]::new()
    $cumA = 0; $cumB = 0; $cumC = 0; $cumS = 0; $cumL = 0

    foreach ($l in @($ExistingLines)) {
        $t = "$l".Trim()
        if ($t -eq '') { continue }
        if ($t.StartsWith('#')) {
            # 集計コメント（ラベル＋数字のみの行）は累計値を読み取って破棄し、後で作り直す。
            # 説明コメントはこれらに一致しないため、そのまま保持される。
            if     ($t -match '^#\s*Count\s*$')         { }
            elseif ($t -match '^#\s*\(A\)\s*(\d+)\s*$') { $cumA = [int]$matches[1] }
            elseif ($t -match '^#\s*\(B\)\s*(\d+)\s*$') { $cumB = [int]$matches[1] }
            elseif ($t -match '^#\s*\(C\)\s*(\d+)\s*$') { $cumC = [int]$matches[1] }
            elseif ($t -match '^#\s*\(S\)\s*(\d+)\s*$') { $cumS = [int]$matches[1] }
            elseif ($t -match '^#\s*\(L\)\s*(\d+)\s*$') { $cumL = [int]$matches[1] }
            elseif ($t -match '^#\s*Total\s*(\d+)\s*$') { }
            else                                        { $descComments.Add($l) }
        } else {
            $existingIps.Add($t)
        }
    }

    # 今回新たに加わるIP（既存リストに無いもの）の該当分類を加算。複数該当は各分類で計上。
    $existingSet = @{}
    foreach ($ip in $existingIps) { $existingSet[$ip] = $true }
    foreach ($ip in @($AdditionalIps)) {
        if (-not $existingSet.ContainsKey($ip)) {
            foreach ($cat in @($CategoryMap[$ip])) {
                switch ($cat) {
                    'A' { $cumA++ }
                    'B' { $cumB++ }
                    'C' { $cumC++ }
                    'S' { $cumS++ }
                    'L' { $cumL++ }
                }
            }
        }
    }

    # 既存IP＋抽出IPを重複排除し IP昇順に整列。
    $mergedIps = Sort-ScanIp -Ip (@($existingIps) + @($AdditionalIps)) -Unique

    # Total は累計の実IP数（重複なし）。分類別件数の合計とは一致しないことがある。
    $cumTotal = $mergedIps.Count

    $countComments = @(
        '# Count'
        '# (A)'.PadRight(8)   + $cumA
        '# (B)'.PadRight(8)   + $cumB
        '# (C)'.PadRight(8)   + $cumC
        '# (S)'.PadRight(8)   + $cumS
        '# (L)'.PadRight(8)   + $cumL
        '# Total'.PadRight(8) + $cumTotal
    )

    # 出力順：説明コメント → 集計コメント → IP（昇順）。
    [string[]](@($descComments) + @($countComments) + @($mergedIps))
}
