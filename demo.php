<?php
require __DIR__ . '/code.php';
if ($argc < 2) {
    usage();
}

switch ($argv[1]) {
    // 生成并打印
    case 'dump':
        # 基数从1开始
        $base = 1;
        $n = 0;
        while ($n < $argv[2]) {
            $encode = Code::gen(3, $base);
            echo 'code: ' . implode('-', str_split($encode, 4)) . chr(10);

            if (!Code::check($encode) || strlen($encode) != 12) {
                echo 'check failed' . chr(10);
                exit;
            }
            $base ++;
            $n ++;
        }
        break;
    // 只生成. 用来测性能
    case 'gen':
        # 基数从1开始
        $base = 1;
        $n = 0;
        while ($n < $argv[2]) {
            $encode = Code::gen(3, $base);
            $base ++;
            $n ++;
        }
        break;
    // 随机校验暴力破解成功率
    case 'check':
        $i = 0;
        while ($i < $argv[2]) {
            $code = gen_rand_code();
            if (Code::check($code)) {
                echo "valid $code\n";
            }
            $i ++;
        }
        break;
    default:
        usage();
}

function gen_rand_code() {
    static $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $i = 0;
    $code = '';
    while ($i < 12) {
        $code .= $chars[rand(0, 25)];
        $i ++;
    }
    return $code;
}

function usage() {
    global $argv;
    echo "Usage:
    {$argv[0]} gen <产生多少个>     # 用于性能测试
    {$argv[0]} dump <产生多少个>    # 用于输出结果
    {$argv[0]} check <验证多少次>   # 用于测试暴力破解成功率\n";
    exit;
}
