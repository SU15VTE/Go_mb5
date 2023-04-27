# Go_md5
## <<网络安全原理>>实验三
这次我没有写成cli，在main.go下把main函数的 **str** 改为你需要加密的字符串即可。
## 加密过程
### 将读取的内容填充
第一步，将字符串读取，然后将其转化为二进制的byte数组。然后再将二进制数组填充到 **Len%512=448** 的长度，填充的内容需要首位为1，作为标记位，后面全部填充0。填充完这个部分后，我们还需要填充多64个bit的数组，这个数组存放的是我们的初始数据的长度的(单位为bit，如"SU15VTE"的长度为7*8)，以小端序  (低位字节在前，高位字节在后)  的形式存放。在完成填充后，我们会得到N个块，每个块的长度为512个bit。

### 初始化MD5缓冲区
我们需要ABCD四个标准幻数，这四个幻数以小端序的形式存放，我们设置一个长度为4的数组作为缓冲区，将四个标准幻数存入缓冲区。接下来我们将在缓冲区内进行一系列的轮运算，最后得到我们的结果

### 轮运算
我们将经历这四轮运算

``` golang
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
```

最后我们将得到的a,b,c,d与初始化的buf相加，得到我们的md5结果。

### 对结果的处理
因为我们的buf是以小端序的形式存放的，因此我们在读取时要从高位字节开始读取。

## 有关S和K表的生成
我的代码中没有给出常量表的生成过程，而在 [
RFC 1321 MD5 Message-Digest Algorithm](https://www.ietf.org/rfc/rfc1321.txt)的 Page4 中有写到：>>>    This step uses a 64-element table T[1 ... 64] constructed from the
   sine function. Let T[i] denote the i-th element of the table, which
   is equal to the integer part of 4294967296 times abs(sin(i)), where i
   is in radians. The elements of the table are given in the appendix. >>>

   也就是T表的值是这样生成的：
   ``` golang
   	// 生成T表
	T := make([]uint32, 64)
	for i := 0; i < 64; i++ {
		T[i] = uint32(math.Floor(math.Abs(math.Sin(float64(i+1))) * 4294967296))
	}
	
	fmt.Println("T table:")
	for i := 0; i < 64; i += 4 {
		fmt.Printf("%08x %08x %08x %08x\n", T[i], T[i+1], T[i+2], T[i+3])
	}
    /***
d76aa478 e8c7b756 242070db c1bdceee
f57c0faf 4787c62a a8304613 fd469501
698098d8 8b44f7af ffff5bb1 895cd7be
6b901122 fd987193 a679438e 49b40821
f61e2562 c040b340 265e5a51 e9b6c7aa
d62f105d 02441453 d8a1e681 e7d3fbc8
21e1cde6 c33707d6 f4d50d87 455a14ed
a9e3e905 fcefa3f8 676f02d9 8d2a4c8a
fffa3942 8771f681 6d9d6122 fde5380c
a4beea44 4bdecfa9 f6bb4b60 bebfbc70
289b7ec6 eaa127fa d4ef3085 04881d05
d9d4d039 e6db99e5 1fa27cf8 c4ac5665
f4292244 432aff97 ab9423a7 fc93a039
655b59c3 8f0ccc92 ffeff47d 85845dd1
6fa87e4f fe2ce6e0 a3014314 4e0811a1
f7537e82 bd3af235 2ad7d2bb eb86d391
***/
   ```
至于S表，这是实现设定好的表，没有生成的过程。
编写md5算法的过程中，我们只需要考虑填充和各个block转换的部分就可以了，算法文档已经给得很细了。