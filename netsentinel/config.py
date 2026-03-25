"""
NetSentinel configuration constants.
All magic numbers, port classifications, scoring weights, and patterns live here.
No other module should hardcode these values.
"""

# =============================================================================
# SCORING CONFIGURATION
# =============================================================================

# Domain weights for overall grade calculation
DOMAIN_WEIGHTS = {
    'network': 0.25,
    'tls': 0.30,
    'http': 0.25,
    'dns': 0.20
}

# Severity penalty points
SEVERITY_PENALTIES = {
    'critical': 25,
    'high': 15,
    'medium': 8,
    'low': 3,
    'info': 0
}

# Letter grade thresholds (score >= threshold)
GRADE_THRESHOLDS = {
    'A': 90,
    'B': 75,
    'C': 60,
    'D': 45,
    # Below 45 is F
}

# =============================================================================
# PORT CONFIGURATION
# =============================================================================

# Dangerous ports with service name and severity
DANGEROUS_PORTS = {
    21: ('FTP', 'high'),
    23: ('Telnet', 'critical'),
    25: ('SMTP', 'high'),
    445: ('SMB', 'critical'),
    3389: ('RDP', 'high'),
    6379: ('Redis', 'critical'),
    27017: ('MongoDB', 'critical'),
    9200: ('Elasticsearch', 'critical'),
    5432: ('PostgreSQL', 'high'),
    3306: ('MySQL', 'high'),
}

# UDP ports to scan (targeted, not full range)
UDP_SCAN_PORTS = [53, 161, 123, 500]

# Top 1000 TCP ports (Nmap list)
TOP_1000_PORTS = [
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37,
    42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106,
    109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199,
    211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 389,
    406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500,
    512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593,
    616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705,
    711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873,
    880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995,
    999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025,
    1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038,
    1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051,
    1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064,
    1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077,
    1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090,
    1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105,
    1106, 1107, 1108, 1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122, 1123,
    1124, 1126, 1130, 1131, 1132, 1137, 1138, 1141, 1145, 1147, 1148, 1149, 1151,
    1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175, 1183, 1185, 1186, 1187,
    1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236, 1244, 1247,
    1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322,
    1328, 1334, 1352, 1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503,
    1521, 1524, 1533, 1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688,
    1700, 1717, 1718, 1719, 1720, 1721, 1723, 1755, 1761, 1782, 1783, 1801, 1805,
    1812, 1839, 1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935, 1947, 1971, 1972,
    1974, 1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008,
    2009, 2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041,
    2042, 2043, 2045, 2046, 2047, 2048, 2049, 2065, 2068, 2099, 2100, 2103, 2105,
    2106, 2107, 2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161, 2170, 2179, 2190,
    2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366, 2381, 2382, 2383,
    2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605,
    2607, 2608, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869,
    2875, 2909, 2910, 2920, 2967, 2968, 2998, 3000, 3001, 3003, 3005, 3006, 3007,
    3011, 3013, 3017, 3030, 3031, 3052, 3071, 3077, 3128, 3168, 3211, 3221, 3260,
    3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323, 3324, 3325, 3333, 3351,
    3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517, 3527, 3546,
    3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814,
    3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920,
    3945, 3971, 3986, 3995, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045,
    4111, 4125, 4126, 4129, 4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445, 4446,
    4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998, 5000, 5001, 5002, 5003, 5004,
    5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101, 5102,
    5120, 5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405,
    5414, 5431, 5432, 5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633,
    5666, 5678, 5679, 5718, 5730, 5800, 5801, 5802, 5810, 5811, 5815, 5822, 5825,
    5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911,
    5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987, 5988, 5989,
    5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059,
    6100, 6101, 6106, 6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547,
    6565, 6566, 6567, 6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779,
    6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007, 7019,
    7025, 7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496, 7512, 7625,
    7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000,
    8001, 8002, 8007, 8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080,
    8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100,
    8180, 8181, 8192, 8193, 8194, 8200, 8222, 8254, 8290, 8291, 8292, 8300, 8333,
    8383, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701, 8800, 8873,
    8888, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071,
    9080, 9081, 9090, 9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200, 9207,
    9220, 9290, 9415, 9418, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595,
    9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943, 9944, 9968, 9998,
    9999, 10000, 10001, 10002, 10003, 10004, 10009, 10010, 10012, 10024, 10025,
    10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628, 10629,
    10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782,
    13783, 14000, 14238, 14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742,
    16000, 16001, 16012, 16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988,
    18040, 18101, 18988, 19101, 19283, 19315, 19350, 19780, 19801, 19842, 20000,
    20005, 20031, 20221, 20222, 20828, 21571, 22939, 23502, 24444, 24800, 25734,
    25735, 26214, 27000, 27352, 27353, 27355, 27356, 27715, 28201, 30000, 30718,
    30951, 31038, 31337, 32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775,
    32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354,
    33899, 34571, 34572, 34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176,
    44442, 44443, 44501, 45100, 48080, 49152, 49153, 49154, 49155, 49156, 49157,
    49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175, 49176, 49400, 49999,
    50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500, 50636, 50800, 51103,
    51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555, 55600,
    56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900, 62078, 63331,
    64623, 64680, 65000, 65129, 65389,
]

# =============================================================================
# OWASP TOP 10 2021 MAPPING
# =============================================================================

OWASP_MAPPING = {
    'A01': 'Broken Access Control',
    'A02': 'Cryptographic Failures',
    'A03': 'Injection',
    'A04': 'Insecure Design',
    'A05': 'Security Misconfiguration',
    'A06': 'Vulnerable and Outdated Components',
    'A07': 'Identification and Authentication Failures',
    'A08': 'Software and Data Integrity Failures',
    'A09': 'Security Logging and Monitoring Failures',
    'A10': 'Server-Side Request Forgery'
}

# =============================================================================
# SECRET DETECTION PATTERNS
# =============================================================================

SECRET_PATTERNS = {
    'aws_access_key': r'AKIA[0-9A-Z]{16}',
    'aws_secret_key': r'[A-Za-z0-9/+=]{40}',
    'stripe_live_key': r'sk_live_[0-9a-zA-Z]{24,}',
    'stripe_test_key': r'sk_test_[0-9a-zA-Z]{24,}',
    'github_token': r'ghp_[0-9a-zA-Z]{36}',
    'github_oauth': r'gho_[0-9a-zA-Z]{36}',
    'generic_api_key': r'[aA][pP][iI]_?[kK][eE][yY]\s*[=:]\s*["\'][^"\']+["\']',
    'generic_secret': r'[sS][eE][cC][rR][eE][tT]\s*[=:]\s*["\'][^"\']+["\']',
    'generic_password': r'[pP][aA][sS][sS][wW][oO][rR][dD]\s*[=:]\s*["\'][^"\']+["\']',
    'private_key': r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
}

# =============================================================================
# TLS CONFIGURATION
# =============================================================================

# Weak TLS ciphers
WEAK_CIPHERS = [
    'RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'ANON',
    'MD5', 'SHA1'  # Weak hash algorithms in cipher suites
]

# Deprecated TLS versions with severity
DEPRECATED_TLS = {
    'SSLv2': 'critical',
    'SSLv3': 'critical',
    'TLSv1.0': 'high',
    'TLSv1.1': 'medium',
}

# =============================================================================
# HTTP SECURITY CONFIGURATION
# =============================================================================

# HTTP security headers to check: header -> (issue_type, severity)
SECURITY_HEADERS = {
    'Content-Security-Policy': ('missing', 'medium'),
    'X-Frame-Options': ('missing', 'medium'),
    'X-Content-Type-Options': ('missing', 'low'),
    'Referrer-Policy': ('missing', 'low'),
    'Permissions-Policy': ('missing', 'info'),
    'Strict-Transport-Security': ('missing', 'medium'),
}

# Sensitive paths to check for exposure
SENSITIVE_PATHS = [
    '/.env', '/.git/config', '/wp-config.php',
    '/config.php', '/server-status', '/.htaccess',
    '/.svn/entries', '/web.config', '/phpinfo.php',
    '/adminer.php', '/.DS_Store', '/backup.sql',
    '/database.sql', '/.bash_history', '/.ssh/id_rsa',
    '/composer.json', '/package.json', '/.npmrc',
    '/yarn.lock', '/Gemfile', '/requirements.txt',
    '/config.yml', '/config.yaml', '/settings.py',
    '/local_settings.py', '/secrets.yml', '/credentials.json',
    '/.aws/credentials', '/.docker/config.json',
]

# Default routes when no manifest available
DEFAULT_ROUTES = [
    '/', '/api', '/api/v1', '/admin', '/health',
    '/login', '/graphql', '/swagger', '/docs',
    '/.env', '/.git/config'
]

# =============================================================================
# DNS CONFIGURATION
# =============================================================================

# DKIM selectors to check
DKIM_SELECTORS = ['default', 'google', 'mail', 'selector1', 'selector2', 'k1']

# Subdomain wordlist (common subdomains for enumeration)
SUBDOMAIN_WORDLIST = [
    # Core infrastructure
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
    'ns3', 'ns4', 'dns', 'dns1', 'dns2', 'mx', 'mx1', 'mx2', 'relay', 'email',
    
    # Development & staging
    'admin', 'api', 'dev', 'staging', 'test', 'beta', 'demo', 'app', 'mobile',
    'stage', 'stg', 'uat', 'qa', 'development', 'testing', 'sandbox', 'preview',
    'preprod', 'pre-prod', 'prod', 'production', 'live', 'release', 'alpha',
    
    # Static content & CDN
    'cdn', 'static', 'assets', 'img', 'images', 'media', 'video', 'download',
    'downloads', 'files', 'content', 'resources', 'css', 'js', 'fonts', 'upload',
    'uploads', 'storage', 'cache', 's3', 'cloudfront', 'edge', 'origin',
    
    # Services & APIs
    'api1', 'api2', 'api3', 'apiv1', 'apiv2', 'rest', 'graphql', 'ws', 'websocket',
    'socket', 'stream', 'feed', 'rss', 'webhook', 'webhooks', 'callback', 'oauth',
    'auth', 'login', 'sso', 'identity', 'id', 'accounts', 'account', 'signup',
    'register', 'signin', 'gateway', 'proxy', 'lb', 'loadbalancer', 'nginx',
    
    # Internal tools
    'jenkins', 'ci', 'build', 'deploy', 'gitlab', 'github', 'bitbucket', 'git',
    'svn', 'cvs', 'repo', 'repository', 'sonar', 'nexus', 'artifactory', 'maven',
    'npm', 'docker', 'registry', 'k8s', 'kubernetes', 'rancher', 'consul', 'vault',
    'terraform', 'ansible', 'puppet', 'chef', 'saltstack', 'jenkins-ci',
    
    # Monitoring & logging
    'monitor', 'monitoring', 'status', 'health', 'healthcheck', 'metrics', 'stats',
    'grafana', 'kibana', 'elasticsearch', 'elk', 'logstash', 'prometheus', 'nagios',
    'zabbix', 'splunk', 'datadog', 'newrelic', 'sentry', 'rollbar', 'bugsnag',
    'pagerduty', 'opsgenie', 'victorops', 'alerts', 'logs', 'logging',
    
    # Databases
    'db', 'db1', 'db2', 'db3', 'database', 'mysql', 'postgres', 'postgresql',
    'mongo', 'mongodb', 'redis', 'memcached', 'elastic', 'solr', 'cassandra',
    'couchdb', 'neo4j', 'influxdb', 'clickhouse', 'mariadb', 'oracle', 'mssql',
    'sqlserver', 'rds', 'aurora', 'dynamodb', 'sql',
    
    # Management & admin
    'cpanel', 'whm', 'plesk', 'webmin', 'phpmyadmin', 'pma', 'adminer', 'pgadmin',
    'admin1', 'admin2', 'administrator', 'management', 'manager', 'console',
    'control', 'controlpanel', 'panel', 'dashboard', 'portal', 'backend', 'cms',
    'wp-admin', 'wordpress', 'drupal', 'joomla', 'magento', 'shopify', 'woocommerce',
    
    # Security
    'vpn', 'vpn1', 'vpn2', 'firewall', 'fw', 'waf', 'security', 'secure', 'ssl',
    'tls', 'cert', 'certs', 'certificates', 'pki', 'ca', 'radius', 'ldap', 'ad',
    'kerberos', 'saml', 'oidc', 'keycloak', 'okta', 'auth0', 'duo', '2fa', 'mfa',
    
    # Communication
    'chat', 'im', 'irc', 'slack', 'teams', 'zoom', 'meet', 'conference', 'webex',
    'voip', 'sip', 'pbx', 'asterisk', 'freeswitch', 'forum', 'forums', 'community',
    'discourse', 'support', 'help', 'helpdesk', 'ticket', 'tickets', 'jira',
    'zendesk', 'freshdesk', 'intercom', 'crisp', 'drift',
    
    # Cloud & hosting
    'cloud', 'aws', 'azure', 'gcp', 'digitalocean', 'linode', 'vultr', 'heroku',
    'netlify', 'vercel', 'cloudflare', 'fastly', 'akamai', 'vps', 'server',
    'server1', 'server2', 'server3', 'host', 'hosting', 'shared', 'dedicated',
    'colo', 'datacenter', 'dc1', 'dc2', 'us', 'eu', 'asia', 'ap', 'na', 'sa',
    'us-east', 'us-west', 'eu-west', 'ap-south', 'ap-northeast',
    
    # Analytics & marketing
    'analytics', 'tracking', 'pixel', 'gtm', 'ga', 'google', 'facebook', 'fb',
    'twitter', 'linkedin', 'instagram', 'youtube', 'tiktok', 'marketing', 'ads',
    'adserver', 'campaign', 'crm', 'salesforce', 'hubspot', 'mailchimp', 'sendgrid',
    'mandrill', 'postmark', 'ses', 'newsletter', 'blog', 'news', 'press',
    
    # E-commerce
    'shop', 'store', 'cart', 'checkout', 'payment', 'payments', 'pay', 'billing',
    'invoice', 'invoices', 'order', 'orders', 'shipping', 'fulfillment', 'inventory',
    'catalog', 'products', 'services', 'pricing', 'subscribe', 'subscription',
    
    # Documentation & knowledge
    'docs', 'doc', 'documentation', 'wiki', 'kb', 'knowledge', 'knowledgebase',
    'faq', 'guide', 'guides', 'tutorial', 'tutorials', 'learn', 'learning',
    'training', 'academy', 'university', 'edu', 'education', 'school',
    
    # Mobile & apps
    'ios', 'android', 'm', 'mobi', 'pda', 'wap', 'apps',
    'appstore', 'playstore', 'native', 'hybrid', 'cordova', 'phonegap', 'ionic',
    'react-native', 'flutter', 'expo', 'fabric', 'crashlytics',
    
    # Legacy & misc
    'old', 'legacy', 'archive', 'archives', 'backup', 'backups', 'temp', 'tmp',
    'cdn1', 'cdn2', 'edge1', 'edge2', 'node1', 'node2', 'node3',
    'cluster', 'cluster1', 'cluster2', 'master', 'slave', 'primary', 'secondary',
    'replica', 'failover', 'standby', 'hot', 'cold', 'warm',
    
    # Region/location specific
    'local', 'internal', 'intranet', 'extranet', 'corp', 'corporate', 'office',
    'hq', 'headquarters', 'remote', 'branch', 'site1', 'site2', 'location1',
    'lab', 'labs', 'research', 'rd', 'eng', 'engineering', 'ops', 'devops',
    'sre', 'platform', 'infra', 'infrastructure',
    
    # Protocols & services
    'http', 'https', 'sftp', 'ssh', 'telnet', 'rdp', 'vnc', 'nfs',
    'smb', 'cifs', 'iscsi', 'san', 'nas', 'syslog', 'snmp', 'ntp', 'dhcp',
    'tftp', 'rsync', 'rsyncd', 'netbios', 'wins', 'ipp', 'cups', 'print',
    'printer', 'printers', 'fax', 'scan', 'scanner',
    
    # Web server related
    'apache', 'httpd', 'iis', 'tomcat', 'weblogic', 'websphere', 'jboss', 'wildfly',
    'glassfish', 'jetty', 'undertow', 'caddy', 'lighttpd', 'haproxy', 'traefik',
    'envoy', 'istio', 'linkerd', 'kong', 'zuul', 'ambassador',
    
    # Data & BI
    'data', 'bigdata', 'hadoop', 'spark', 'kafka', 'airflow', 'luigi', 'nifi',
    'etl', 'dwh', 'warehouse', 'datalake', 'lake', 'bi', 'tableau', 'powerbi',
    'looker', 'metabase', 'superset', 'redash', 'report', 'reports', 'reporting',
    
    # CRM & ERP
    'erp', 'sap', 'oracle-erp', 'dynamics', 'netsuite', 'odoo', 'zoho', 'sage',
    'quickbooks', 'xero', 'hr', 'hrm', 'hris', 'payroll', 'time', 'timesheet',
    'leave', 'expenses', 'travel', 'procurement', 'asset', 'assets',
    
    # Version control & CI/CD
    'code', 'source', 'src', 'vcs', 'scm', 'hg', 'mercurial', 'bazaar', 'fossil',
    'phabricator', 'gerrit', 'review', 'code-review', 'pr', 'mr', 'pipeline',
    'pipelines', 'workflow', 'workflows', 'action', 'actions', 'runner', 'runners',
    
    # Messaging & queues
    'mq', 'rabbitmq', 'activemq', 'zeromq', 'sqs', 'sns', 'pubsub', 'queue',
    'queues', 'worker', 'workers', 'job', 'jobs', 'task', 'tasks', 'celery',
    'sidekiq', 'resque', 'bull', 'agenda', 'cron', 'scheduler', 'scheduled',
    
    # Search
    'search', 'find', 'lookup', 'index', 'indexer', 'crawler', 'spider', 'bot',
    'scraper', 'algolia', 'typesense', 'meilisearch', 'sphinxsearch',
    
    # Gaming & media
    'game', 'games', 'gaming', 'play', 'player', 'match', 'matchmaking', 'lobby',
    'server-browser', 'leaderboard', 'achievements', 'music', 'audio', 'podcast',
    'radio', 'tv', 'vod', 'broadcast', 'rtmp', 'hls', 'dash', 'webrtc',
    
    # IoT & embedded
    'iot', 'mqtt', 'coap', 'sensor', 'sensors', 'device', 'devices', 'gateway-iot',
    'hub', 'edge-device', 'embedded', 'firmware', 'ota', 'update', 'updates',
    
    # Miscellaneous common
    'www1', 'www2', 'www3', 'web', 'web1', 'web2', 'web3', 'site', 'sites',
    'home', 'homepage', 'main', 'index', 'default', 'root', 'public', 'private',
    'members', 'member', 'user', 'users', 'profile', 'profiles', 'settings',
    'config', 'configuration', 'setup', 'install', 'installer', 'wizard',
    'connect', 'link', 'links', 'redirect', 'go', 'url', 'short', 'bit', 'tiny',
    'click', 'track', 'open', 'ping', 'pong', 'echo', 'debug', 'trace', 'log',
    'error', 'errors', '404', '500', 'crash', 'exception', 'exceptions',
    'events', 'event', 'hook', 'hooks', 'trigger', 'triggers', 'notify',
    'notification', 'notifications', 'alert', 'warn', 'warning', 'info',
    
    # Numbers and variations
    'v1', 'v2', 'v3', 'v4', 'version1', 'version2', 'new', 'next', 'prev',
    'previous', 'current', 'latest', 'stable', 'nightly', 'canary', 'edge-release',
    'rc', 'rc1', 'rc2', 'snapshot', 'trunk', 'head', 'tip',
    
    # Geographical
    'north', 'south', 'east', 'west', 'central', 'northeast', 'northwest',
    'southeast', 'southwest', 'pacific', 'atlantic', 'emea', 'apac', 'latam',
    'amer', 'americas', 'europe', 'africa', 'australia', 'india', 'china',
    'japan', 'korea', 'brazil', 'canada', 'uk', 'de', 'fr', 'es', 'it', 'nl',
    'be', 'ch', 'at', 'pl', 'ru', 'ua', 'mx', 'ar', 'co', 'cl', 'pe',
]

# =============================================================================
# SCANNER SETTINGS
# =============================================================================

SCANNER_CONFIG = {
    'port_scan_concurrency': 500,
    'port_scan_timeout': 1.0,
    'subdomain_concurrency': 200,
    'banner_grab_timeout': 3.0,
    'http_timeout': 10.0,
    'dns_timeout': 5.0,
}

# User agent for HTTP requests
USER_AGENT = 'NetSentinel-Scanner/1.0'

# =============================================================================
# DASHBOARD SETTINGS
# =============================================================================

DASHBOARD_PORT = 8742
STORAGE_DIR = '~/.netsentinel'

# =============================================================================
# CVSS 3.1 CONFIGURATION
# =============================================================================

# CVSS 3.1 metric values for score calculation
CVSS_METRICS = {
    'attack_vector': {
        'N': ('Network', 0.85),
        'A': ('Adjacent', 0.62),
        'L': ('Local', 0.55),
        'P': ('Physical', 0.20),
    },
    'attack_complexity': {
        'L': ('Low', 0.77),
        'H': ('High', 0.44),
    },
    'privileges_required': {
        'N': ('None', 0.85),
        'L': ('Low', 0.62),
        'H': ('High', 0.27),
    },
    'user_interaction': {
        'N': ('None', 0.85),
        'R': ('Required', 0.62),
    },
    'scope': {
        'U': ('Unchanged', None),
        'C': ('Changed', None),
    },
    'confidentiality': {
        'H': ('High', 0.56),
        'L': ('Low', 0.22),
        'N': ('None', 0.0),
    },
    'integrity': {
        'H': ('High', 0.56),
        'L': ('Low', 0.22),
        'N': ('None', 0.0),
    },
    'availability': {
        'H': ('High', 0.56),
        'L': ('Low', 0.22),
        'N': ('None', 0.0),
    },
}

# =============================================================================
# BANNER SIGNATURES FOR SERVICE DETECTION
# =============================================================================

BANNER_SIGNATURES = {
    'SSH': [r'^SSH-', r'OpenSSH'],
    'FTP': [r'^220.*FTP', r'^220.*FileZilla', r'^220.*vsftpd', r'^220.*ProFTPD'],
    'SMTP': [r'^220.*SMTP', r'^220.*Postfix', r'^220.*Sendmail', r'^220.*Exim'],
    'HTTP': [r'^HTTP/', r'Server:', r'<!DOCTYPE', r'<html'],
    'POP3': [r'^\+OK.*POP3', r'^\+OK Dovecot'],
    'IMAP': [r'^\* OK.*IMAP', r'Dovecot'],
    'MySQL': [r'^.\x00\x00\x00\n', r'mysql_native_password'],
    'PostgreSQL': [r'FATAL:', r'PostgreSQL'],
    'Redis': [r'-ERR', r'\$\d+\r\n', r'\+PONG'],
    'MongoDB': [r'MongoDB', r'It looks like you are trying'],
    'Telnet': [r'^\xff\xfd', r'^\xff\xfb', r'login:'],
    'RDP': [r'^\x03\x00\x00'],
}

# =============================================================================
# DATABASE ERROR PATTERNS FOR SQL INJECTION DETECTION
# =============================================================================

DATABASE_ERROR_PATTERNS = [
    r'SQL syntax.*MySQL',
    r'Warning.*mysql_',
    r'MySqlException',
    r'valid MySQL result',
    r'PostgreSQL.*ERROR',
    r'Warning.*pg_',
    r'valid PostgreSQL result',
    r'Npgsql\.',
    r'ORA-\d{5}',
    r'Oracle error',
    r'Microsoft OLE DB Provider for SQL Server',
    r'ODBC SQL Server Driver',
    r'SQLServer JDBC Driver',
    r'Microsoft SQL Native Client error',
    r'SQLSTATE\[',
    r'SQLException',
    r'JDBCException',
    r'Unclosed quotation mark',
    r'quoted string not properly terminated',
    r'sqlite3\.OperationalError',
    r'SQLite\.Exception',
    r'SQLite error',
    r'near ".*": syntax error',
    r'SQLITE_ERROR',
]
