// sm3信息摘要算法实现

use core::mem::size_of;

// 按SM3标准填充数据
//
// SM3的输入数据其实可以精确到比特，这里的msg只实现了精确到字节的输入填充
// 最多可以处理2^64个比特的输入
fn fill_message(msg: &[u8], vec: &mut Vec<u8>) {
    if size_of::<usize>() >= 64 {
        // 最多2^64个比特，(2^64)/8个字节
        assert!(msg.len() < (2usize << (64 - 3)));
    }
    // 先将消息复制到填充输出
    vec.extend_from_slice(msg);
    // 将“1”添加到消息的末尾，再添加k个“0”，(k+1+l)(mod512)=448
    vec.push(0x80u8); // 添加一个“1”
    // 标准的k以位为单位，这里的“k”以字节为单位
    let k = (512 / 8 + (448 / 8) - 1 - msg.len() % (512 / 8)) % (512 / 8);
    vec.resize(msg.len() + 1 + k, 0); // 添加k个“0”
    // 添加一个64位比特串，是长度l的二进制表示
    let l = (msg.len() as u64) * 8;
    vec.extend_from_slice(&l.to_be_bytes());
}

// 置换函数P0
fn p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}
// 置换函数P1
fn p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}

// 消息扩展。输入b，输出w、w1
fn message_extend(b: [u8; 64]) -> ([u32; 68], [u32; 64]) {
    let mut w = [0u32; 68]; // W0到W67
    for i in 0..=15 {
        w[i] = u32::from_be_bytes([b[4*i], b[4*i + 1], b[4*i + 2], b[4*i + 3]]);
    }
    for j in 16..=67 {
        w[j] = p1(w[j - 16] ^ w[j - 9] ^ (w[j - 3].rotate_left(15))) 
            ^ (w[j - 13].rotate_left(7)) ^ w[j - 6];
    }
    let mut w1 = [0u32; 64];
    for j in 0..=63 {
        w1[j] = w[j] ^ w[j + 4];
    }
    (w, w1)
}

// 常量tj
fn t(j: usize) -> u32 {
    match j {
        0 ..= 15 => 0x79cc4519,
        16 ..= 63 => 0x7a879d8a,
        _ => unreachable!()
    }
}

// 布尔函数ffj
fn ff(x: u32, y: u32, z: u32, j: usize) -> u32 {
    match j {
        0 ..= 15 => x ^ y ^ z,
        16 ..= 63 => (x & y) | (x & z) | (y & z),
        _ => unreachable!()
    }
}
// 布尔函数ggj
fn gg(x: u32, y: u32, z: u32, j: usize) -> u32 {
    match j {
        0 ..= 15 => x ^ y ^ z,
        16 ..= 63 => (x & y) | (!x & z),
        _ => unreachable!()
    }
}

// 压缩函数。输入vi和bi，输出vi+1
fn compress_function(vi: [u32; 8], b: [u8; 64]) -> [u32; 8] {
    let (w, w1) = message_extend(b);
    let vi_0 = vi.clone();
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = vi;
    for j in 0..=63 {
        let tj = t(j);
        let ss1 = a.rotate_left(12).wrapping_add(e).wrapping_add(tj.rotate_left(j as u32)).rotate_left(7);
        let ss2 = ss1 ^ (a.rotate_left(12));
        let tt1 = ff(a, b, c, j).wrapping_add(d).wrapping_add(ss2).wrapping_add(w1[j]);
        let tt2 = gg(e, f, g, j).wrapping_add(h).wrapping_add(ss1).wrapping_add(w[j]);
        d = c;
        c = b.rotate_left(9);
        b = a;
        a = tt1;
        h = g;
        g = f.rotate_left(19);
        f = e;
        e = p0(tt2);
    }
    [a ^ vi_0[0], b ^ vi_0[1], c ^ vi_0[2], d ^ vi_0[3], e ^ vi_0[4], f ^ vi_0[5], g ^ vi_0[6], h ^ vi_0[7]]
}

const IV: [u32; 8] = [
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
];

// 迭代压缩
fn iter_compress(msg: &mut [u8]) -> [u32; 8] {
    // v的初始值
    let mut v: [u32; 8] = IV;
    for i in 0..(msg.len() / 64) {
        // 辣鸡rust……
        let bi = [
            msg[64*i+0], msg[64*i+1], msg[64*i+2], msg[64*i+3], msg[64*i+4], msg[64*i+5], msg[64*i+6], msg[64*i+7], 
            msg[64*i+8], msg[64*i+9], msg[64*i+10], msg[64*i+11], msg[64*i+12], msg[64*i+13], msg[64*i+14], msg[64*i+15],
            msg[64*i+16], msg[64*i+17], msg[64*i+18], msg[64*i+19],msg[64*i+20], msg[64*i+21], msg[64*i+22], msg[64*i+23], 
            msg[64*i+24], msg[64*i+25], msg[64*i+26], msg[64*i+27], msg[64*i+28], msg[64*i+29], msg[64*i+30], msg[64*i+31], 
            msg[64*i+32], msg[64*i+33], msg[64*i+34], msg[64*i+35], msg[64*i+36], msg[64*i+37], msg[64*i+38], msg[64*i+39], 
            msg[64*i+40], msg[64*i+41], msg[64*i+42], msg[64*i+43], msg[64*i+44], msg[64*i+45], msg[64*i+46], msg[64*i+47], 
            msg[64*i+48], msg[64*i+49], msg[64*i+50], msg[64*i+51], msg[64*i+52], msg[64*i+53], msg[64*i+54], msg[64*i+55], 
            msg[64*i+56], msg[64*i+57], msg[64*i+58], msg[64*i+59], msg[64*i+60], msg[64*i+61], msg[64*i+62], msg[64*i+63]
        ];
        v = compress_function(v, bi);
    }
    v
}

// 完整的sm3摘要算法
//
// sm3算法最高支持2^64个位（2^61个字节）的消息输入。如果不满足，函数会panic
fn sm3(input: &[u8]) -> [u32; 8] {
    let mut filled = Vec::new();
    fill_message(input, &mut filled);
    iter_compress(&mut filled)
}

fn main() {
    let message = "abc";
    println!("Hash of '{}' is {:x?}", message, sm3(message.as_bytes()));
    let message = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    println!("Hash of '{}' is {:x?}", message, sm3(message.as_bytes()));
}

#[cfg(test)]
mod tests {
    #[test]
    fn fill_message_1() {
        let input: [u8; 3] = [0b01100001, 0b01100010, 0b01100011];
        let mut output = Vec::new();
        super::fill_message(&input, &mut output);
        let mut expected = vec![0b01100001, 0b01100010, 0b01100011, 0b10000000];
        for _ in 0..((424 / 8) - 1) {
            expected.push(0u8)
        }
        for _ in 0..7 {
            expected.push(0);
        }
        expected.push(0b011000);
        assert_eq!(output, expected);
    }
    #[test]
    fn hash_value() {
        let message = "abc";
        let mut filled = Vec::new();
        super::fill_message(message.as_bytes(), &mut filled);
        let ans = super::iter_compress(&mut filled);
        assert_eq!(ans, [0x66c7f0f4, 0x62eeedd9, 0xd1f2d46b, 0xdc10e4e2, 0x4167c487, 0x5cf2f7a2, 0x297da02b, 0x8f4ba8e0]);
        let message = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
        let mut filled = Vec::new();
        super::fill_message(message.as_bytes(), &mut filled);
        let ans = super::iter_compress(&mut filled);
        assert_eq!(ans, [0xdebe9ff9, 0x2275b8a1, 0x38604889, 0xc18e5a4d, 0x6fdb70e5, 0x387e5765, 0x293dcba3, 0x9c0c5732]);
    }
}
