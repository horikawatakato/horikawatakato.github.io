# Get-DockerAccessLog.ps1 の設定ファイル
# 以下の必須変数に接続・出力情報を設定
$ServerIp       = ''
$Ec2Host        = 
$MyIp           = ''
$KeyPath        = ''
$Ec2User        = ''
$ProjectDir     = ''
$LocalLog       = ""
$ComposeService = ''

# スキャン判定しきい値
# 共通：判定対象とする最低リクエスト数
$ScanMinTotal      = 30
# 共通：ピークレートを算出する窓幅（分）
$ScanRateWindowMin = 1
# 共通：ピークレート（最も混雑した窓での1分あたり要求数）の下限（件/分）
$ScanRatePerMin    = 10
# (A) 列挙スキャン
$ScanMinPath       = 20
$Scan404Count      = 20
$Scan200Ratio      = 0.1
# (B) 高エラー型
$ScanErrCount      = 30
$ScanErrRatio      = 0.5
# (B) 5xx をエラー量に加味する重み
$Scan5xxWeight     = 0.5
# (C) クレデンシャル総当たり
$BruteOnePath      = 50
$BruteAuthErr      = 20
# (C) 認証系パスの判定パターン
$AuthPathRegex     = '(?i)(wp-login|xmlrpc|/wp-json|/admin|/login|/signin|/user/login|/api/(login|auth|token|session|oauth)|/\.env|/actuator|/graphql)'
