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

# スキャン判定しきい値（未設定なら ScanExclude.ps1 側の既定値で補完）
# 共通：判定対象とする最低リクエスト数（A/B/C に適用。S/L は対象外）
$ScanMinTotal      = 30
# 共通：ピークレートを算出する窓幅（分）
$ScanRateWindowMin = 1
# 共通：ピークレート（最も混雑した窓での1分あたり要求数）の下限（件/分）。A/B/C に適用
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
# (C) クレデンシャル総当たり：単一パス集中の件数
$BruteOnePath      = 50
# (C) 経路2：同一パス上の認証エラー（401/403/429）の件数
$BruteAuthErr      = 20
# (C) 経路1：単一ログインフォームへの POST 集中の件数
$BrutePost         = 20
# (C) 経路1・経路2 の集中パス判定に使うログインフォーム。/api/* や /graphql は含めない
# （自サービス固有のログインAPIがあれば追加可）
$LoginFormRegex    = '(?i)(/login|/signin|/user/login|/admin/login|wp-login|/administrator/index)'
# (L) ログイン探索：異なるログインページ種類数の下限
$BruteAuthVariety  = 3
# (L) ログイン探索：認証パス上の200成功率の上限（これ以上の成功率なら正規利用とみなし除外）
$AuthSuccessRatioMax = 0.5
# (L) ログイン探索の種類数集計に使う認証系パス
$AuthPathRegex     = '(?i)(/admin|/login|/signin|/user/login|/api/(login|auth|token|session|oauth)|/graphql)'
# (L) 種類数集計から除外する API 認証エンドポイント
$ApiAuthRegex      = '(?i)/api/(login|auth|token|session|oauth)'
# (S) 攻撃ファイルパス
$ScanSigRegex      = '(?i)(/\.env|/\.git|/\.aws|/\.ssh|/\.svn|/\.htpasswd|/\.vscode|wp-login\.php|xmlrpc\.php|wp-config\.php|/wp-content/plugins/|/wp-includes/|/wp-admin/|/vendor/phpunit|eval-stdin\.php|/cgi-bin/.*(\.\./|%2e%2e|/bin/sh|php-cgi)|/boaform|/solr/|/manager/html|/hudson|/_ignition|/credentials\.json|/phpmyadmin|/adminer|/druid|/jolokia|/struts|/actuator|/wp-json)'
# (S) 攻撃トークン（クエリ含むリクエスト原文をデコードして評価）
$ScanExploitRegex  = '(?i)(\$\{jndi:|\.\./\.\.|%2e%2e|union\s+select|\bor\s+1=1\b|<script|/etc/passwd|/bin/sh|cmd=|base64_|/win\.ini)'
# (S) 絶対URI（プロキシ探索）
$ScanProxyRegex    = '(?i)^[A-Z]+\s+[a-z][a-z0-9+.\-]*://'
# (S) 異常メソッド
$ScanBadMethodRegex = '(?i)^(CONNECT|PROPFIND|DEBUG|TRACE|TRACK|SEARCH|MKCOL|MOVE)\s'
# (S) 確定プロトコルシグネチャ（SMB/RAT/マイニング）
$ScanProtoRegex    = '(?i)(SMBr|\\xFESMB|\\xFFSMB|Gh0st|mining\.subscribe|mining\.authorize)'
