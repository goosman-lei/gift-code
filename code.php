<?php
# 算法结构: 基础要素 | 校验和 | 位混淆 | 编码转换

# 目标码数量: 10亿
# 目标码范围: 12位纯字母全大写 => 目标码可能性 = pow(26, 12) = 95428956661682176 = 95428956亿
# 二进制长度: pow(2, 56) = 72057594037927936 = 72057594亿. 选择56个二进制位做基础数据, 可保证算法结果是12位字母
# 编码转换采用进制转换大法

# 礼品码目标量级10亿, 选择32位存储, 支持40亿.
# 24位校验位分配:
#   礼品码类型 8位
#   校验和     4位
#   签名码     12位

# 基础数据定义
#   基础数据   := <礼品码类型 8位> <目标码0-7位 8位> <目标码8-15位 8位> <校验和 4位> <目标码16-23位 8位> <签名码 12位> <目标码24-31位 8位>
#   礼品码类型 := 0-127的数字, 表示128种活动. 其中最高位算法保留为1. 确保结果为12位字母.
#   校验和     := 0-15的数字, 根据校验算法, 产生的校验和
#   签名码     := 0-4095的数字, 每种校验算法, 提供固定1个签名码
#   目标码     := 1亿开始顺序增长的数字. 应用层控制

# Demo实现
class Code {
    const DEBUG = 0;

    const SIGN          = 0x842;                            # 可替换
    const BASE_26_CHARS = 'ACNMSWEYXTQZILGDKHFPOJRUVB';     # 可替换. 保证是不重复的26个大写字母即可

    public static function gen($type, $target) {
        $type   = $type & 0x7F;
        $target = $target & 0xFFFFFFFF;
        $sign   = self::SIGN;
        $sum    = self::get_sum($sign, $target);

        if (self::DEBUG) {
            printf("\tEncoding eles: type[%-4d 0X%02X] sum[%-2d 0X%01X] sign[%-4d 0X%02X] target[%d]\n",
                $type, $type, $sum, $sum, $sign, $sign, $target);
        }

        # 基础数据   := <礼品码类型 7位> <目标码0-7位 8位> <目标码8-15位 8位> <校验和 4位> <目标码16-23位 8位> <签名码 12位> <目标码24-31位 8位>
        $code   = ($type << 48) | (($target & 0xFF000000) << 16) | (($target & 0xFF0000) << 16) | ($sum << 28) | (($target & 0xFF00) << 12) | ($sign << 8) | ($target & 0xFF);
        if (self::DEBUG) {
            printf("\tEncoding mixed: 0X%07X %d\n", $code, $code);
        }

        # 混淆
        $code   = self::confuse_encode($code);
        if (self::DEBUG) {
            printf("\tEncoding confuse: 0X%07X %d\n", $code, $code);
        }

        # 补最高位
        $code |= 0x80000000000000;
        if (self::DEBUG) {
            printf("\tEncoding replenish: 0X%07X %d\n", $code, $code);
        }

        return self::convertToNBase(self::BASE_26_CHARS, $code);
    }

    public static function check($code) {
        $code = self::convertFromNBase(self::BASE_26_CHARS, $code);
        if (self::DEBUG) {
            printf("\tDecoding from nbase: 0X%07X %d\n", $code, $code);
        }

        # 去最高位
        $code &= 0x7FFFFFFFFFFFFF;
        if (self::DEBUG) {
            printf("\tDecoding replenish: 0X%07X %d\n", $code, $code);
        }

        $code = self::confuse_decode($code);
        if (self::DEBUG) {
            printf("\tDecoding confuse: 0X%07X %d\n", $code, $code);
        }

        # 基础数据   := <礼品码类型 7位> <目标码0-7位 8位> <目标码8-15位 8位> <校验和 4位> <目标码16-23位 8位> <签名码 12位> <目标码24-31位 8位>
        $type     = $code >> 48 & 0x7F;
        $target_0 = ($code >> 40) & 0xFF;
        $target_1 = ($code >> 32) & 0xFF;
        $sum      = ($code >> 28) & 0xF;
        $target_2 = ($code >> 20) & 0xFF;
        $sign     = ($code >> 8) & 0xFFF;
        $target_3 = $code & 0xFF;
        $target   = ($target_0 << 24) | ($target_1 << 16) | ($target_2 << 8) | $target_3;

        if (self::DEBUG) {
            printf("\tDecoding eles: type[%-4d 0X%02X] sum[%-2d 0X%01X] sign[%-4d 0X%02X] target[%d]\n",
                $type, $type, $sum, $sum, $sign, $sign, $target);
        }

        if (self::SIGN != $sign) {
            return FALSE;
        }

        return self::check_sum($sign, $target, $sum);
    }

    public static function get_sum($sign, $target) {
        $sum = 0;
        $tmp = ($sign << 32) | $target;
        $ele_0 = $tmp & 0x00000000F;
        $ele_1 = ($tmp & 0x0000000F0) >> 4;
        $ele_2 = ($tmp & 0x000000F00) >> 8;
        $ele_3 = ($tmp & 0x00000F000) >> 12;
        $ele_4 = ($tmp & 0x0000F0000) >> 16;
        $ele_5 = ($tmp & 0x000F00000) >> 20;
        $ele_6 = ($tmp & 0x00F000000) >> 24;
        $ele_7 = ($tmp & 0x0F0000000) >> 28;
        $ele_8 = ($tmp & 0xF00000000) >> 32;
        $sum = $ele_0 + $ele_1 + $ele_2 + $ele_3 + $ele_4 + $ele_5 + $ele_6 + $ele_7 + $ele_8;
        $sum = $sum & 0xF;
        return $sum;
    }

    public static function check_sum($sign, $target, $user_sum) {
        if (self::DEBUG) printf("\tCheck sum: sign[%d 0X%01X], user-sum[%d 0X%01X], calc-sum[%d 0X%01X], target[%d]\n",
            $sign, $sign, $user_sum, $user_sum, $calc_sum, $calc_sum, $target);
        $calc_sum = self::get_sum($sign, $target);
        return $calc_sum == $user_sum;
    }

    public static function confuse_encode($code) {
        // 参与混淆的只有55位, 最高位在混淆后补位
        $bin_code = sprintf("%055s", decbin($code));

        // 每5位一组, 分11组
        $bin_code_arr = str_split($bin_code, 5);
        if (self::DEBUG >= 2) printf("\t\t%05s\n\n", implode(' ', $bin_code_arr));

        # 整组交换
        # 0 <==> 5
        # 1 <==> 9
        # 10 <==> 7
        # 6 <==> 8
        # 4 <==> 2
        # 3
        self::swap($bin_code_arr, 0, 5);
        if (self::DEBUG >= 2) printf("\t\t%05s\n", implode(' ', $bin_code_arr));
        self::swap($bin_code_arr, 1, 9);
        if (self::DEBUG >= 2) printf("\t\t%05s\n", implode(' ', $bin_code_arr));
        self::swap($bin_code_arr, 10, 7);
        if (self::DEBUG >= 2) printf("\t\t%05s\n", implode(' ', $bin_code_arr));
        self::swap($bin_code_arr, 3, 8);
        if (self::DEBUG >= 2) printf("\t\t%05s\n", implode(' ', $bin_code_arr));
        self::swap($bin_code_arr, 4, 2);
        if (self::DEBUG >= 2) printf("\t\t%05s\n", implode(' ', $bin_code_arr));

        return bindec(implode($bin_code_arr));
    }

    public static function confuse_decode($code) {
        // 目前实现是可逆运算
        return self::confuse_encode($code);
    }

    public static function swap(&$array, $a, $b) {
        $tmp = $array[$a];
        $array[$a] = $array[$b];
        $array[$b] = $tmp;
    }

    /**
     * convertToNBase 
     * 十进制转N进制
     * @param string $charTable N进制字母表
     * @param int $number 十进制数字
     * @return string
     */
    protected static function convertToNBase($charTable, $number) {
        $nbase  = strlen($charTable);
        $result = '';
        while ($number > 0) {
            $result = $charTable[bcmod($number, $nbase)] . $result;
            $number = bcdiv($number, $nbase);
        }
        return $result;
    }

    /**
     * convertFromNBase 
     * N进制字母表
     * @param string $charTable N进制字母表
     * @param string $number N进制字符串
     * @return int
     */
    protected static function convertFromNBase($charTable, $number) {
        $nbase  = strlen($charTable);
        $length = strlen($number);
        $offset = 0;
        $result = 0;
        while ($offset < $length) {
            $result += pow($nbase, $offset) * strpos($charTable, $number[$length - $offset - 1]);
            $offset ++;
        }
        return $result;
    }
}