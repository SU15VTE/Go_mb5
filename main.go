package main

import (
	"fmt"
	"strconv"
)

const (
	A   = 0x67452301
	B   = 0xefcdab89
	C   = 0x98badcfe
	D   = 0x10325476
	S11 = 7
	S12 = 12
	S13 = 17
	S14 = 22
	S21 = 5
	S22 = 9
	S23 = 14
	S24 = 20
	S31 = 4
	S32 = 11
	S33 = 16
	S34 = 23
	S41 = 6
	S42 = 10
	S43 = 15
	S44 = 21
)

func FF(a, b, c, d uint32, x uint32, s uint32, ac uint32) uint32 {
	a += ((b & c) | (^b & d)) + x + ac
	a = ((a << s) | (a >> (32 - s)))
	a += b
	return a
}

func GG(a, b, c, d uint32, x uint32, s uint32, ac uint32) uint32 {
	a += ((b & d) | (c & ^d)) + x + ac
	a = ((a << s) | (a >> (32 - s)))
	a += b
	return a
}

func HH(a, b, c, d uint32, x uint32, s uint32, ac uint32) uint32 {
	a += (b ^ c ^ d) + x + ac
	a = ((a << s) | (a >> (32 - s)))
	a += b
	return a
}

func II(a, b, c, d uint32, x uint32, s uint32, ac uint32) uint32 {
	a += (c ^ (b | ^d)) + x + ac
	a = ((a << s) | (a >> (32 - s)))
	a += b
	return a
}
func StringToBinary(str string) []byte {
	var bytekey []byte = []byte(str)
	var binary []byte
	for _, b := range bytekey {
		for i := 0; i < 8; i++ {
			bit := (b >> uint(7-i)) & 1
			binary = append(binary, byte(bit))
		}
	}
	return binary
}

//对内容进行补位操作
//result = N*512+448 //bit
func Pad(binary []byte) []byte {
	L := len(binary)
	tail := GetTail(L)
	if L%512 != 448 {
		Lpad := 448 - L%512
		padding := make([]byte, Lpad)
		padding[0] = 1
		result := append(binary, padding...)
		result = append(result, tail...)
		return result
	} else {
		padding := make([]byte, 512)
		padding[0] = 1
		result := append(binary, padding...)
		result = append(result, tail...)
		return result
	}
}

//创造长度以小端序的byte数组
func GetTail(L int) []byte {
	data := make([]byte, 8)
	for i := 0; i < 8; i++ {
		data[i] = byte(L >> (i * 8) & 0xff)
	}
	tail := make([]byte, 0)
	for _, b := range data {
		for i := 0; i < 8; i++ {
			bit := (b >> uint(7-i)) & 1
			tail = append(tail, byte(bit))
		}
	}
	return tail
}

//初始化一个md5缓冲区，为后续的轮运算做准备
func InitBuf() []uint32 {
	buf := make([]uint32, 4)
	buf[0] = A
	buf[1] = B
	buf[2] = C
	buf[3] = D
	return buf
}

//把512位的binary byte数组转换成以字节为单位的64位的byte数组
func BinToByte(b []byte) []byte {
	byteSlice := make([]byte, len(b)/8)
	for i := 0; i < len(byteSlice); i++ {
		byteSlice[i] = b[i*8]<<7 |
			b[i*8+1]<<6 |
			b[i*8+2]<<5 |
			b[i*8+3]<<4 |
			b[i*8+4]<<3 |
			b[i*8+5]<<2 |
			b[i*8+6]<<1 |
			b[i*8+7]
	}
	return byteSlice
}

//把上面的64位数组以每四个个字节为单位拼接，组成一个新的数组，经历这几步后，数组的变化为：512位的binary数组 -> 64位的字节数组 -> 16位的4字节数组
func ConvertToUint32Array(data []byte) []uint32 {
	var result []uint32
	for i := 0; i < len(data); i += 4 {
		word := uint32(data[i]) | uint32(data[i+1])<<8 | uint32(data[i+2])<<16 | uint32(data[i+3])<<24
		result = append(result, word)
	}
	return result
}

//处理小端序结果
func GetReuslt(data []uint32) string {
	var result string
	for i := 0; i < 4; i++ {
		hexStr := strconv.FormatUint(uint64(data[i]), 16)
		var str string
		for i := 8; i > 1; i = i - 2 {
			str += hexStr[i-2 : i]
		}
		result += str
	}
	return result
}

//md5的主要算法，经历这4轮运算，将输出的A,B,C,D和初始化的A,B,C,D相加，得到结果
func MD5(buf []uint32, x []uint32) []uint32 {
	a := buf[0]
	b := buf[1]
	c := buf[2]
	d := buf[3]
	a = FF(a, b, c, d, x[0], S11, 0xd76aa478)
	d = FF(d, a, b, c, x[1], S12, 0xe8c7b756)
	c = FF(c, d, a, b, x[2], S13, 0x242070db)
	b = FF(b, c, d, a, x[3], S14, 0xc1bdceee)
	a = FF(a, b, c, d, x[4], S11, 0xf57c0faf)
	d = FF(d, a, b, c, x[5], S12, 0x4787c62a)
	c = FF(c, d, a, b, x[6], S13, 0xa8304613)
	b = FF(b, c, d, a, x[7], S14, 0xfd469501)
	a = FF(a, b, c, d, x[8], S11, 0x698098d8)
	d = FF(d, a, b, c, x[9], S12, 0x8b44f7af)
	c = FF(c, d, a, b, x[10], S13, 0xffff5bb1)
	b = FF(b, c, d, a, x[11], S14, 0x895cd7be)
	a = FF(a, b, c, d, x[12], S11, 0x6b901122)
	d = FF(d, a, b, c, x[13], S12, 0xfd987193)
	c = FF(c, d, a, b, x[14], S13, 0xa679438e)
	b = FF(b, c, d, a, x[15], S14, 0x49b40821)

	/* Round 2 */
	a = GG(a, b, c, d, x[1], S21, 0xf61e2562)
	d = GG(d, a, b, c, x[6], S22, 0xc040b340)
	c = GG(c, d, a, b, x[11], S23, 0x265e5a51)
	b = GG(b, c, d, a, x[0], S24, 0xe9b6c7aa)
	a = GG(a, b, c, d, x[5], S21, 0xd62f105d)
	d = GG(d, a, b, c, x[10], S22, 0x2441453)
	c = GG(c, d, a, b, x[15], S23, 0xd8a1e681)
	b = GG(b, c, d, a, x[4], S24, 0xe7d3fbc8)
	a = GG(a, b, c, d, x[9], S21, 0x21e1cde6)
	d = GG(d, a, b, c, x[14], S22, 0xc33707d6)
	c = GG(c, d, a, b, x[3], S23, 0xf4d50d87)
	b = GG(b, c, d, a, x[8], S24, 0x455a14ed)
	a = GG(a, b, c, d, x[13], S21, 0xa9e3e905)
	d = GG(d, a, b, c, x[2], S22, 0xfcefa3f8)
	c = GG(c, d, a, b, x[7], S23, 0x676f02d9)
	b = GG(b, c, d, a, x[12], S24, 0x8d2a4c8a)

	/* Round 3 */
	a = HH(a, b, c, d, x[5], S31, 0xfffa3942)
	d = HH(d, a, b, c, x[8], S32, 0x8771f681)
	c = HH(c, d, a, b, x[11], S33, 0x6d9d6122)
	b = HH(b, c, d, a, x[14], S34, 0xfde5380c)
	a = HH(a, b, c, d, x[1], S31, 0xa4beea44)
	d = HH(d, a, b, c, x[4], S32, 0x4bdecfa9)
	c = HH(c, d, a, b, x[7], S33, 0xf6bb4b60)
	b = HH(b, c, d, a, x[10], S34, 0xbebfbc70)
	a = HH(a, b, c, d, x[13], S31, 0x289b7ec6)
	d = HH(d, a, b, c, x[0], S32, 0xeaa127fa)
	c = HH(c, d, a, b, x[3], S33, 0xd4ef3085)
	b = HH(b, c, d, a, x[6], S34, 0x4881d05)
	a = HH(a, b, c, d, x[9], S31, 0xd9d4d039)
	d = HH(d, a, b, c, x[12], S32, 0xe6db99e5)
	c = HH(c, d, a, b, x[15], S33, 0x1fa27cf8)
	b = HH(b, c, d, a, x[2], S34, 0xc4ac5665)

	/* Round 4 */
	a = II(a, b, c, d, x[0], S41, 0xf4292244)
	d = II(d, a, b, c, x[7], S42, 0x432aff97)
	c = II(c, d, a, b, x[14], S43, 0xab9423a7)
	b = II(b, c, d, a, x[5], S44, 0xfc93a039)
	a = II(a, b, c, d, x[12], S41, 0x655b59c3)
	d = II(d, a, b, c, x[3], S42, 0x8f0ccc92)
	c = II(c, d, a, b, x[10], S43, 0xffeff47d)
	b = II(b, c, d, a, x[1], S44, 0x85845dd1)
	a = II(a, b, c, d, x[8], S41, 0x6fa87e4f)
	d = II(d, a, b, c, x[15], S42, 0xfe2ce6e0)
	c = II(c, d, a, b, x[6], S43, 0xa3014314)
	b = II(b, c, d, a, x[13], S44, 0x4e0811a1)
	a = II(a, b, c, d, x[4], S41, 0xf7537e82)
	d = II(d, a, b, c, x[11], S42, 0xbd3af235)
	c = II(c, d, a, b, x[2], S43, 0x2ad7d2bb)
	b = II(b, c, d, a, x[9], S44, 0xeb86d391)
	buf[0] += a
	buf[1] += b
	buf[2] += c
	buf[3] += d

	return buf
}

func main() {
	str := "Hello World"
	b := StringToBinary(str)
	padding := Pad(b)
	buf := InitBuf()
	Array := BinToByte(padding)
	x := ConvertToUint32Array(Array)
	resultArray := MD5(buf, x)
	result := GetReuslt(resultArray)
	fmt.Println(result)
}
