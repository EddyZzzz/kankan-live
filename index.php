<?php

date_default_timezone_set('Asia/Shanghai');

define('LOCAL_HTTPS_PROXY_PREFIX', getenv('KK_PROXY_PREFIX') !== false
    ? getenv('KK_PROXY_PREFIX')
    : '');
const LIVE_URL_CACHE_TTL = 600;

function toLocalProxyUrl($url) {
    if (LOCAL_HTTPS_PROXY_PREFIX === '') return $url;
    return stripos($url, 'https://') === 0
        ? LOCAL_HTTPS_PROXY_PREFIX . substr($url, 8)
        : $url;
}

function getLiveUrlCacheFile($channelId) {
    $dir = sys_get_temp_dir() . '/kankan-live-url-' . substr(sha1(__FILE__), 0, 12);
    if (!is_dir($dir)) mkdir($dir, 0700, true);
    return $dir . '/channel-' . intval($channelId) . '.url';
}

function readCachedLiveUrl($channelId) {
    $file = getLiveUrlCacheFile($channelId);
    if (!is_file($file) || time() - filemtime($file) >= LIVE_URL_CACHE_TTL) return false;
    $url = trim((string) file_get_contents($file));
    return stripos($url, 'https://') === 0 ? $url : false;
}

function writeCachedLiveUrl($channelId, $url) {
    $file = getLiveUrlCacheFile($channelId);
    if (file_put_contents($file, $url, LOCK_EX) !== false) @chmod($file, 0600);
}

function clearCachedLiveUrl($channelId) {
    $file = getLiveUrlCacheFile($channelId);
    if (is_file($file)) @unlink($file);
}

$channelMap = [
    'dfws' => 1,   // 东方卫视
    'shxwzh' => 2, // 上海新闻综合
    'shds' => 4,   // 上海都市
    'dycj' => 5,   // 第一财经
    'hhxd' => 9,   // 哈哈炫动
    'wxty' => 10,  // 五星体育
    'mdy' => 11,   // 上海魔都眼
    'jsrw' => 12,  // 上海新纪实
];
$id = isset($_GET['id']) ? $_GET['id'] : 'wxty';
if (!isset($channelMap[$id])) die('无效频道ID');
$channelId = $channelMap[$id];

// ==================== TS 代理（保留以备不时之需，本脚本默认不代理 TS）====================
if (isset($_GET['ts_url'])) {
    $ts_url = urldecode($_GET['ts_url']);
    $path = parse_url($ts_url, PHP_URL_PATH);
    $filename = basename($path);
    if (!preg_match('/^[a-zA-Z0-9\.]+$/', $filename)) {
        http_response_code(400);
        exit('Invalid filename');
    }
    $cache_dir = __DIR__ . '/ts_cache';
    if (!is_dir($cache_dir)) mkdir($cache_dir, 0755, true);
    $cache_file = $cache_dir . '/' . $filename;
    $cache_ttl = 86400;

    if (file_exists($cache_file) && (time() - filemtime($cache_file)) < $cache_ttl) {
        $fp = fopen($cache_file, 'rb');
        if ($fp && flock($fp, LOCK_SH)) {
            $data = '';
            while (!feof($fp)) $data .= fread($fp, 8192);
            flock($fp, LOCK_UN);
            fclose($fp);
            if ($data) {
                header('Content-Type: video/MP2T');
                header('Cache-Control: max-age=' . $cache_ttl);
                echo $data;
                exit;
            }
        }
        if ($fp) fclose($fp);
    }

    $headers = [
        'User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.97 Safari/537.36 SE 2.X MetaSr 1.0',
        'Accept: */*', 'Accept-Language: zh-CN,zh;q=0.9',
        'Origin: https://live.kankanews.com', 'Referer: https://live.kankanews.com/',
        'Connection: keep-alive',
    ];
    $ch = curl_init(toLocalProxyUrl($ts_url));
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_HTTPHEADER => $headers,
    ]);
    $data = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($data === false || $httpCode !== 200) {
        http_response_code(502);
        echo "无法获取 TS 分片";
        exit;
    }

    $fp = fopen($cache_file, 'wb');
    if ($fp && flock($fp, LOCK_EX)) {
        fwrite($fp, $data);
        flock($fp, LOCK_UN);
        fclose($fp);
    } else if ($fp) fclose($fp);

    header('Content-Type: video/MP2T');
    header('Cache-Control: max-age=' . $cache_ttl);
    echo $data;
    exit;
}

// ==================== 辅助函数 ====================
function getnonce($len = 8) {
    $alphabet = '0123456789abcdefghijklmnopqrstuvwxyz';
    $nonce = '';
    for ($i = 0; $i < $len; $i++) {
        $nonce .= $alphabet[random_int(0, strlen($alphabet) - 1)];
    }
    return $nonce;
}


function getuuid($len = 21) {
    return substr(strtr(base64_encode(random_bytes(16)), '+/', '-_'), 0, $len);
}

function rsaAsn1Integers($der) {
    $ints = [];
    $len = strlen($der);
    for ($i = 0; $i + 2 < $len;) {
        if ($der[$i] !== "\x02") { $i++; continue; }
        $l = ord($der[$i + 1]);
        $start = $i + 2;
        if ($l & 0x80) {
            $n = $l & 0x7f;
            $l = 0;
            for ($j = 0; $j < $n; $j++) $l = ($l << 8) | ord($der[$start + $j]);
            $start += $n;
        }
        if ($start + $l <= $len) {
            $ints[] = bin2hex(ltrim(substr($der, $start, $l), "\x00"));
            $i = $start + $l;
        } else {
            $i++;
        }
    }
    return $ints;
}

function rsaHexToDec($hex) {
    $dec = '0';
    $hex = ltrim(strtolower($hex), '0');
    if ($hex === '') return '0';
    for ($i = 0; $i < strlen($hex); $i++) {
        $dec = bcadd(bcmul($dec, '16'), (string) hexdec($hex[$i]));
    }
    return $dec;
}

function rsaDecToHex($dec) {
    if (bccomp($dec, '0') <= 0) return '0';
    $hex = '';
    while (bccomp($dec, '0') > 0) {
        $hex = dechex((int) bcmod($dec, '16')) . $hex;
        $dec = bcdiv($dec, '16', 0);
    }
    return $hex;
}

function rsaPublicDecryptChunk($chunkBin, $nHex, $eHex) {
    $cHex = bin2hex($chunkBin);
    if (function_exists('gmp_init') && function_exists('gmp_powm')) {
        $m = gmp_powm(gmp_init($cHex, 16), gmp_init($eHex, 16), gmp_init($nHex, 16));
        $mHex = gmp_strval($m, 16);
    } else {
        $m = bcpowmod(rsaHexToDec($cHex), rsaHexToDec($eHex), rsaHexToDec($nHex));
        $mHex = rsaDecToHex($m);
    }
    $block = hex2bin(str_pad($mHex, 256, '0', STR_PAD_LEFT)); // 128 字节
    if (strlen($block) !== 128) return '';
    if ($block[0] !== "\x00" || $block[1] !== "\x01") return '';
    $j = 2;
    while ($j < 128 && $block[$j] === "\xFF") $j++;
    if ($j >= 128 || $block[$j] !== "\x00") return '';
    return substr($block, $j + 1);
}

function rsaDecrypt($str) {
    $pubKey = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDP5hzPUW5RFeE2xBT1ERB3hHZI\nVotn/qatWhgc1eZof09qKjElFN6Nma461ZAwGpX4aezKP8Adh4WJj4u2O54xCXDt\nwzKRqZO2oNZkuNmF2Va8kLgiEQAAcxYc8JgTN+uQQNpsep4n/o1sArTJooZIF17E\ntSqSgXDcJ7yDj5rc7wIDAQAB\n-----END PUBLIC KEY-----";
    $der = base64_decode(preg_replace('/-----[^-]+-----|\s+/', '', $pubKey));
    $ints = rsaAsn1Integers($der);
    if (count($ints) < 2) return false;
    list($nHex, $eHex) = $ints;
    $encData = base64_decode($str);
    $result = '';
    for ($i = 0; $i + 128 <= strlen($encData); $i += 128) {
        $result .= rsaPublicDecryptChunk(substr($encData, $i, 128), $nHex, $eHex);
    }
    return $result;
}

function getLiveUrl($channelId, $forceRefresh = false, &$cacheHit = null) {
    $cacheHit = false;
    if (!$forceRefresh) {
        $cached = readCachedLiveUrl($channelId);
        if ($cached !== false) {
            $cacheHit = true;
            return $cached;
        }
    }
    $t = time();
    $nonce = getnonce(8);
    $uuid = getuuid();
    $version = '2.42.21';
    $secret = '28c8edde3d61a0411511d3b1866f0636';
    $signStr = "Api-Version=v1&channel_id={$channelId}&nonce={$nonce}&platform=pc&timestamp={$t}&version={$version}&{$secret}";
    $sign = md5(md5($signStr));
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? '';
    if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) $clientIp = $_SERVER['HTTP_X_FORWARDED_FOR'];
    elseif (isset($_SERVER['HTTP_CLIENT_IP'])) $clientIp = $_SERVER['HTTP_CLIENT_IP'];
    $headers = [
        "Api-Version: v1", "Nonce: {$nonce}", "M-Uuid: {$uuid}",
        "Platform: pc", "Version: {$version}", "Timestamp: {$t}", "Sign: {$sign}",
        "Origin: https://live.kankanews.com", "Referer: https://live.kankanews.com/",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.97 Safari/537.36 SE 2.X MetaSr 1.0",
        "X-Forwarded-For: {$clientIp}", "Client-Ip: {$clientIp}",
    ];
    $apiUrl = toLocalProxyUrl("https://kapi.kankanews.com/content/pc/tv/channel/detail?channel_id={$channelId}");
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $apiUrl, CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => $headers,
        CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => false, CURLOPT_TIMEOUT => 10,
    ]);
    $resp = curl_exec($ch);
    curl_close($ch);
    if (!$resp) return false;
    $data = json_decode($resp, true);
    if (empty($data['result']['live_address'])) return false;
    $liveUrl = rsaDecrypt($data['result']['live_address']);
    if ($liveUrl) writeCachedLiveUrl($channelId, $liveUrl);
    return $liveUrl;
}

function fetchContent($url) {
    $ch = curl_init(toLocalProxyUrl($url));
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_HTTPHEADER => [
            'User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.97 Safari/537.36 SE 2.X MetaSr 1.0',
            'Accept: */*', 'Accept-Language: zh-CN,zh;q=0.9',
            'Origin: https://live.kankanews.com', 'Referer: https://live.kankanews.com/',
        ],
    ]);
    $data = curl_exec($ch);
    curl_close($ch);
    return $data !== false ? $data : null;
}

function toAbsoluteUrl($base, $relative) {
    if (preg_match('/^https?:\/\//i', $relative)) return $relative;
    $parts = parse_url($base);
    $baseDir = dirname($parts['path']) . '/';
    if ($relative[0] === '/') $relative = ltrim($relative, '/');
    return $parts['scheme'] . '://' . $parts['host'] . $baseDir . $relative;
}

function rewritePlaylistTagUris($line, $base) {
    return preg_replace_callback('/URI="([^"]+)"/i', function ($matches) use ($base) {
        return 'URI="' . toAbsoluteUrl($base, $matches[1]) . '"';
    }, $line);
}


function getFlatM3u8($url, $depth = 0) {
    if ($depth > 5) return '';
    $content = fetchContent($url);
    if (!$content) return '';
    $lines = explode("\n", $content);
    $output = [];
    $i = 0;
    while ($i < count($lines)) {
        $line = trim($lines[$i]);
        if (strpos($line, '#EXT-X-STREAM-INF') !== false) {
            $i++;
            if ($i >= count($lines)) break;
            $subUrl = trim($lines[$i]);
            if ($subUrl === '' || strpos($subUrl, '#') === 0) continue;
            $absSub = toAbsoluteUrl($url, $subUrl);
            $subContent = getFlatM3u8($absSub, $depth + 1);
            if ($subContent) {
                return $subContent;
            }
        } elseif (strpos($line, '#EXTINF:') === 0) {
            $output[] = $line;
            $i++;
            if ($i >= count($lines)) break;
            $tsUrl = trim($lines[$i]);
            if ($tsUrl !== '' && $tsUrl[0] !== '#') {
                $absTs = toAbsoluteUrl($url, $tsUrl);
                $output[] = $absTs;
            } else {
                $output[] = $tsUrl;
            }
        } else {
            $output[] = rewritePlaylistTagUris($line, $url);
        }
        $i++;
    }
    return implode("\n", $output);
}

$cacheHit = false;
$liveUrl = getLiveUrl($channelId, false, $cacheHit);
if (!$liveUrl) die('获取直播地址失败');

$finalM3u8 = getFlatM3u8($liveUrl);
if (!$finalM3u8 && $cacheHit) {
    clearCachedLiveUrl($channelId);
    $liveUrl = getLiveUrl($channelId, true, $cacheHit);
    if ($liveUrl) $finalM3u8 = getFlatM3u8($liveUrl);
}
if (!$finalM3u8) die('无法解析 M3U8 列表');

header('Content-Type: application/vnd.apple.mpegurl');
header('Cache-Control: no-cache, no-store, must-revalidate');
header('X-Live-Url-Cache: ' . ($cacheHit ? 'HIT' : 'MISS'));
echo $finalM3u8;
?>
