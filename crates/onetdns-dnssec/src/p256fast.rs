/*!
 * @brief P-256 ECDSA 검증 전용 고속 경로.
 *
 * @details DNSSEC은 알고리즘 13을 가장 많이 쓰고, 질의 한 건이 여러 서명을 검증하므로
 *          이 곡선의 검증 비용이 곧 CPU 예산이다. 몽고메리 형태 유한체와 야코비 좌표,
 *          그리고 생성점 사전 계산 테이블로 일반 라이브러리 경로보다 빠르게 만든다.
 * @note 리틀엔디언 limb 4개로 256비트를 담는다. 배열 인덱스 0이 최하위다.
 * @warning 여기 있는 연산은 상수 시간이 아니다. 검증은 공개 값만 다루므로 의도적으로
 *          허용한 것이며, 이 코드로 서명을 만들면 비밀 스칼라가 새어 나간다.
 */

/** @brief 곡선의 소수 모듈러스. */
const P: [u64; 4] = [
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_ffff_0000_0001,
];

/** @brief 2^512 mod P. 일반 정수를 몽고메리 형태로 올릴 때 곱한다. */
const R2: [u64; 4] = [
    0x0000_0000_0000_0003,
    0xffff_fffb_ffff_ffff,
    0xffff_ffff_ffff_fffe,
    0x0000_0004_ffff_fffd,
];

/** @brief 곡선 계수 b를 몽고메리 형태로 미리 올려 둔 값. */
const B_MONT: [u64; 4] = [
    0xd89c_df62_29c4_bddf,
    0xacf0_05cd_7884_3090,
    0xe5a2_20ab_f721_2ed6,
    0xdc30_061d_0487_4834,
];

/** @brief 생성점 x좌표(몽고메리 형태). */
const GX_MONT: [u64; 4] = [
    0x79e7_30d4_18a9_143c,
    0x75ba_95fc_5fed_b601,
    0x79fb_732b_7762_2510,
    0x1890_5f76_a537_55c6,
];
/** @brief 생성점 y좌표(몽고메리 형태). */
const GY_MONT: [u64; 4] = [
    0xddf2_5357_ce95_560a,
    0x8b4a_b8e4_ba19_e45c,
    0xd2e8_8688_dd21_f325,
    0x8571_ff18_2588_5d85,
];

/** @brief 유한체 덧셈. 올림이 나거나 결과가 P 이상이면 한 번 빼서 범위로 되돌린다. */
fn fe_add(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let v = u128::from(a[i]) + u128::from(b[i]) + carry;
        r[i] = v as u64;
        carry = v >> 64;
    }

    if carry != 0 || !fe_lt(&r, &P) {
        fe_sub_p(&mut r);
    }
    r
}

/** @brief 유한체 뺄셈. 빌림이 나면 P를 더해 되돌린다. */
fn fe_sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut borrow = 0i128;
    for i in 0..4 {
        let v = i128::from(a[i]) - i128::from(b[i]) - borrow;
        r[i] = v as u64;
        borrow = if v < 0 { 1 } else { 0 };
    }
    if borrow != 0 {
        let mut carry = 0u128;
        for i in 0..4 {
            let v = u128::from(r[i]) + u128::from(P[i]) + carry;
            r[i] = v as u64;
            carry = v >> 64;
        }
    }
    r
}

/** @brief 제자리에서 P를 뺀다. 빌림은 버린다. 호출 조건상 결과가 항상 범위 안이다. */
fn fe_sub_p(r: &mut [u64; 4]) {
    let mut borrow = 0i128;
    for i in 0..4 {
        let v = i128::from(r[i]) - i128::from(P[i]) - borrow;
        r[i] = v as u64;
        borrow = if v < 0 { 1 } else { 0 };
    }
}

/** @brief 부호 없는 크기 비교. 최상위 limb부터 본다. */
fn fe_lt(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/** @brief 0인지. 야코비 좌표에서 z가 0이면 무한원점이라 자주 쓰인다. */
fn fe_is_zero(a: &[u64; 4]) -> bool {
    a == &[0u64; 4]
}

/**
 * @brief 몽고메리 곱셈(CIOS). 결과도 몽고메리 형태다.
 * @details P가 특수 형태라 몽고메리 상수 n0'가 1이다. 그래서 각 라운드의 m이 곱셈 없이
 *          t[0] 그 자체이고, 일반 곡선보다 라운드당 곱셈이 하나씩 준다.
 */
fn fe_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut t = [0u64; 6];
    for &ai in a.iter() {
        let ai = u128::from(ai);

        let mut carry = 0u128;
        for j in 0..4 {
            let v = u128::from(t[j]) + ai * u128::from(b[j]) + carry;
            t[j] = v as u64;
            carry = v >> 64;
        }
        let v = u128::from(t[4]) + carry;
        t[4] = v as u64;
        t[5] = (v >> 64) as u64;

        let m = u128::from(t[0]);

        let mut carry = (u128::from(t[0]) + m * u128::from(P[0])) >> 64;
        for j in 1..4 {
            let v = u128::from(t[j]) + m * u128::from(P[j]) + carry;
            t[j - 1] = v as u64;
            carry = v >> 64;
        }
        let v = u128::from(t[4]) + carry;
        t[3] = v as u64;
        t[4] = t[5] + (v >> 64) as u64;
    }
    let mut r = [t[0], t[1], t[2], t[3]];
    if t[4] != 0 || !fe_lt(&r, &P) {
        fe_sub_p(&mut r);
    }
    r
}

/** @brief 제곱. 전용 경로 없이 곱셈을 그대로 쓴다. */
fn fe_sqr(a: &[u64; 4]) -> [u64; 4] {
    fe_mul(a, a)
}

/** @brief 일반 정수를 몽고메리 형태로 올린다. */
fn to_mont(a: &[u64; 4]) -> [u64; 4] {
    fe_mul(a, &R2)
}

/** @brief 몽고메리 형태를 일반 정수로 내린다. 1을 곱하면 몽고메리 축약만 남는다. */
fn from_mont(a: &[u64; 4]) -> [u64; 4] {
    fe_mul(a, &[1, 0, 0, 0])
}

/**
 * @brief 유한체 역원. 페르마 소정리로 a^(P-2)를 계산한다.
 * @details 확장 유클리드 대신 거듭제곱을 쓰는 이유는 분기가 지수 비트에만 의존해 코드가
 *          단순해지기 때문이다. 지수는 상수라 입력에 따라 갈리지 않는다.
 */
fn fe_inv(a: &[u64; 4]) -> [u64; 4] {
    let exp: [u64; 4] = [
        0xffff_ffff_ffff_fffd,
        0x0000_0000_ffff_ffff,
        0x0000_0000_0000_0000,
        0xffff_ffff_0000_0001,
    ];
    let one_mont = to_mont(&[1, 0, 0, 0]);
    let mut result = one_mont;
    let mut started = false;
    for limb in exp.iter().rev() {
        for bit in (0..64).rev() {
            if started {
                result = fe_sqr(&result);
            }
            if (limb >> bit) & 1 == 1 {
                if started {
                    result = fe_mul(&result, a);
                } else {
                    result = *a;
                    started = true;
                }
            }
        }
    }
    result
}

/**
 * @brief 빅엔디언 32바이트를 유한체 원소로 읽는다.
 * @return 길이가 32가 아니거나 P 이상이면 None. 범위를 넘는 좌표를 그대로 받으면
 *         같은 점을 두 가지로 표현할 수 있게 돼 검증이 헐거워진다.
 */
fn fe_from_be(be: &[u8]) -> Option<[u64; 4]> {
    if be.len() != 32 {
        return None;
    }
    let mut l = [0u64; 4];
    for i in 0..4 {
        let mut v = 0u64;
        for j in 0..8 {
            v = (v << 8) | u64::from(be[i * 8 + j]);
        }
        l[3 - i] = v;
    }
    if !fe_lt(&l, &P) {
        return None;
    }
    Some(l)
}

/** @brief 유한체 원소를 빅엔디언 32바이트로 쓴다. */
fn fe_to_be(a: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        let v = a[3 - i];
        for j in 0..8 {
            out[i * 8 + j] = (v >> (56 - 8 * j)) as u8;
        }
    }
    out
}

/** @brief 몽고메리 형태의 1. 야코비 좌표의 z 초기값으로 쓴다. */
const ONE_MONT: [u64; 4] = [
    0x0000_0000_0000_0001,
    0xffff_ffff_0000_0000,
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_fffe,
];

/** @brief 곡선의 위수. 서명 성분 r, s가 1 이상 N 미만인지 보는 데 쓴다. */
const N: [u64; 4] = [
    0xf3b9_cac2_fc63_2551,
    0xbce6_faad_a717_9e84,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_0000_0000,
];

/** @brief 2배. 점 연산 공식이 작은 배수를 자주 쓴다. */
fn fe_dbl(a: &[u64; 4]) -> [u64; 4] {
    fe_add(a, a)
}
/** @brief 3배. */
fn fe_mul3(a: &[u64; 4]) -> [u64; 4] {
    fe_add(&fe_dbl(a), a)
}
/** @brief 4배. */
fn fe_mul4(a: &[u64; 4]) -> [u64; 4] {
    fe_dbl(&fe_dbl(a))
}
/** @brief 8배. */
fn fe_mul8(a: &[u64; 4]) -> [u64; 4] {
    fe_dbl(&fe_mul4(a))
}

/**
 * @brief 야코비 좌표의 점. 아핀 좌표로는 x/z^2, y/z^3이다.
 * @details 점 덧셈마다 역원을 구하지 않으려고 쓴다. 역원은 마지막에 한 번만 계산한다.
 */
#[derive(Clone, Copy)]
struct Jac {
    /** @brief 야코비 x. */
    x: [u64; 4],
    /** @brief 야코비 y. */
    y: [u64; 4],
    /** @brief 야코비 z. 0이면 무한원점이다. */
    z: [u64; 4],
}

/** @brief 무한원점. z가 0인 것이 판별 조건이고 x, y 값은 의미가 없다. */
const INF: Jac = Jac {
    x: ONE_MONT,
    y: ONE_MONT,
    z: [0, 0, 0, 0],
};

impl Jac {
    /** @brief 무한원점인지. */
    fn is_inf(&self) -> bool {
        fe_is_zero(&self.z)
    }

    /**
     * @brief 점 2배.
     * @details a가 -3인 곡선 전용 공식이다. P-256이 그 조건을 만족해 일반식보다 곱셈이 적다.
     */
    fn double(&self) -> Jac {
        if self.is_inf() {
            return INF;
        }
        let delta = fe_sqr(&self.z);
        let gamma = fe_sqr(&self.y);
        let beta = fe_mul(&self.x, &gamma);
        let alpha = fe_mul3(&fe_mul(&fe_sub(&self.x, &delta), &fe_add(&self.x, &delta)));
        let x3 = fe_sub(&fe_sqr(&alpha), &fe_mul8(&beta));
        let z3 = fe_sub(&fe_sub(&fe_sqr(&fe_add(&self.y, &self.z)), &gamma), &delta);
        let y3 = fe_sub(
            &fe_mul(&alpha, &fe_sub(&fe_mul4(&beta), &x3)),
            &fe_mul8(&fe_sqr(&gamma)),
        );
        Jac {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /**
     * @brief 점 덧셈.
     * @details x가 같아 h가 0이 되는 두 경우를 구분해야 한다. y도 같으면(r이 0) 같은 점이라
     *          2배 공식으로 넘기고, 다르면 서로의 역원이라 무한원점이다. 이 분기를 빠뜨리면
     *          그 입력에서 0으로 나누는 꼴이 돼 틀린 점이 나온다.
     */
    fn add(&self, other: &Jac) -> Jac {
        if self.is_inf() {
            return *other;
        }
        if other.is_inf() {
            return *self;
        }
        let z1z1 = fe_sqr(&self.z);
        let z2z2 = fe_sqr(&other.z);
        let u1 = fe_mul(&self.x, &z2z2);
        let u2 = fe_mul(&other.x, &z1z1);
        let s1 = fe_mul(&fe_mul(&self.y, &other.z), &z2z2);
        let s2 = fe_mul(&fe_mul(&other.y, &self.z), &z1z1);
        let h = fe_sub(&u2, &u1);
        let r = fe_sub(&s2, &s1);
        if fe_is_zero(&h) {
            if fe_is_zero(&r) {
                return self.double();
            }
            return INF;
        }
        let hh = fe_sqr(&h);
        let i = fe_mul4(&hh);
        let j = fe_mul(&h, &i);
        let rr = fe_dbl(&r);
        let v = fe_mul(&u1, &i);
        let x3 = fe_sub(&fe_sub(&fe_sqr(&rr), &j), &fe_dbl(&v));
        let y3 = fe_sub(&fe_mul(&rr, &fe_sub(&v, &x3)), &fe_dbl(&fe_mul(&s1, &j)));
        let z3 = fe_mul(
            &fe_sub(&fe_sub(&fe_sqr(&fe_add(&self.z, &other.z)), &z1z1), &z2z2),
            &h,
        );
        Jac {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /** @brief 역원. y를 뒤집으면 된다. wNAF의 음수 곳에서 쓴다. */
    fn neg(&self) -> Jac {
        Jac {
            x: self.x,
            y: fe_sub(&P, &self.y),
            z: self.z,
        }
    }

    /**
     * @brief 아핀 x좌표. 검증은 이 값만 필요하므로 y는 복원하지 않는다.
     * @return 무한원점이면 None. 그 경우 서명은 검증 실패다.
     */
    fn affine_x(&self) -> Option<[u64; 4]> {
        if self.is_inf() {
            return None;
        }
        let zinv = fe_inv(&self.z);
        let zinv2 = fe_sqr(&zinv);
        Some(from_mont(&fe_mul(&self.x, &zinv2)))
    }
}

/** @brief 아핀 좌표를 z가 1인 야코비 점으로 올린다. */
fn affine_to_jac(x_mont: [u64; 4], y_mont: [u64; 4]) -> Jac {
    Jac {
        x: x_mont,
        y: y_mont,
        z: ONE_MONT,
    }
}

/** @brief 생성점. */
const G_JAC: Jac = Jac {
    x: GX_MONT,
    y: GY_MONT,
    z: ONE_MONT,
};

/**
 * @brief 공개키 좌표를 읽어 곡선 위의 점인지 확인한다.
 * @details 곡선 방정식을 실제로 대입해 본다. 확인하지 않고 받으면 곡선 밖 점을 넣는
 *          공격이 성립한다.
 * @return 좌표가 범위를 벗어나거나 곡선 위가 아니면 None.
 */
fn public_point(qx_be: &[u8], qy_be: &[u8]) -> Option<Jac> {
    let x = fe_from_be(qx_be)?;
    let y = fe_from_be(qy_be)?;
    let xm = to_mont(&x);
    let ym = to_mont(&y);

    let lhs = fe_sqr(&ym);
    let x3 = fe_mul(&fe_sqr(&xm), &xm);
    let three_x = fe_mul3(&xm);
    let rhs = fe_add(&fe_sub(&x3, &three_x), &B_MONT);
    if lhs != rhs {
        return None;
    }
    Some(affine_to_jac(xm, ym))
}

/**
 * @brief 단순 double-and-add 스칼라 곱. 테스트에서 wNAF 경로의 기준으로만 쓴다.
 * @note 생산 경로가 아니다. 최적화된 lincomb이 이 값과 어긋나면 그쪽이 틀린 것이다.
 */
#[cfg(test)]
fn scalar_mul(p: &Jac, k_be: &[u8]) -> Jac {
    let mut acc = INF;
    let mut started = false;
    for &byte in k_be {
        for bit in (0..8).rev() {
            if started {
                acc = acc.double();
            }
            if (byte >> bit) & 1 == 1 {
                acc = if started { acc.add(p) } else { *p };
                started = true;
            }
        }
    }
    acc
}

/** @brief 생성점 구간 크기. 테이블을 한 번만 만들어 두고 재사용하므로 크게 잡는다. */
const WG: u32 = 8;
/** @brief 공개키 구간 크기. 검증마다 새로 만들어야 해서 테이블 생성 비용과 균형을 맞춘다. */
const WQ: u32 = 5;

/** @brief 1P, 3P, 5P 식의 홀수 배수 테이블. wNAF 자릿값이 항상 홀수라 짝수는 필요 없다. */
fn odd_multiples(p: &Jac, w: u32) -> Vec<Jac> {
    let n = 1usize << (w - 2);
    let mut table = Vec::with_capacity(n);
    table.push(*p);
    let twice = p.double();
    for i in 1..n {
        table.push(table[i - 1].add(&twice));
    }
    table
}

/**
 * @brief 생성점 사전 계산 테이블. 최초 검증 때 한 번만 만든다.
 * @details 생성점은 고정이라 프로세스 수명 동안 재사용할 수 있다. 검증마다 다시 만들면
 *          구간을 크게 잡은 이득이 사라진다.
 */
fn g_table() -> &'static [Jac] {
    /** @brief 미리 계산해 둔 테이블. 곱셈마다 다시 만들면 그것이 비용이다. */
    static T: std::sync::OnceLock<Vec<Jac>> = std::sync::OnceLock::new();
    T.get_or_init(|| odd_multiples(&G_JAC, WG))
}

/**
 * @brief 스칼라를 폭 w의 부호 있는 구간 형태로 전개한다.
 *
 * @details 0이 아닌 자릿값 사이에 최소 w-1개의 0이 오도록 만들어, 같은 비트 수에서
 *          덧셈 횟수를 줄인다. 자릿값이 절반을 넘으면 음수로 바꾸고 그만큼 스칼라를
 *          되올린다. 음수 곳은 점의 역원으로 처리한다.
 * @return 자릿값 배열과 실제로 채워진 길이. 배열은 256비트 스칼라가 만들 수 있는
 *         최대 자릿수만큼 잡아 둔다.
 */
fn wnaf(be: &[u8], w: u32) -> ([i32; 257], usize) {
    let mut k = [0u64; 4];
    for i in 0..4 {
        let mut v = 0u64;
        for j in 0..8 {
            v = (v << 8) | u64::from(be[i * 8 + j]);
        }
        k[3 - i] = v;
    }
    let base = 1i64 << w;
    let half = 1i64 << (w - 1);
    let mut digits = [0i32; 257];
    let mut i = 0usize;
    while k != [0u64; 4] && i < 257 {
        if k[0] & 1 == 1 {
            let mut d = (k[0] & ((1u64 << w) - 1)) as i64;
            if d >= half {
                d -= base;
            }
            digits[i] = d as i32;
            if d >= 0 {
                let mut borrow = d as u64;
                for limb in k.iter_mut() {
                    let (v, b) = limb.overflowing_sub(borrow);
                    *limb = v;
                    borrow = u64::from(b);
                    if borrow == 0 {
                        break;
                    }
                }
            } else {
                let mut carry = (-d) as u64;
                for limb in k.iter_mut() {
                    let (v, c) = limb.overflowing_add(carry);
                    *limb = v;
                    carry = u64::from(c);
                    if carry == 0 {
                        break;
                    }
                }
            }
        }
        for j in 0..3 {
            k[j] = (k[j] >> 1) | (k[j + 1] << 63);
        }
        k[3] >>= 1;
        i += 1;
    }
    (digits, i)
}

/**
 * @brief u1*G + u2*Q를 한 번의 훑기로 계산한다(Shamir 트릭).
 * @details 두 스칼라를 따로 곱한 뒤 더하면 2배 연산을 두 벌 한다. 자릿수를 같이 훑으면
 *          2배는 한 벌이면 되고 덧셈만 각각 붙는다.
 */
fn lincomb(u1_be: &[u8], u2_be: &[u8], q: &Jac) -> Jac {
    let gt = g_table();
    let qt = odd_multiples(q, WQ);
    let (ng, leng) = wnaf(u1_be, WG);
    let (nq, lenq) = wnaf(u2_be, WQ);
    let len = leng.max(lenq);
    let pick = |table: &[Jac], d: i32| -> Jac {
        let idx = ((d.unsigned_abs() - 1) / 2) as usize;
        if d > 0 {
            table[idx]
        } else {
            table[idx].neg()
        }
    };
    let mut acc = INF;
    for i in (0..len).rev() {
        acc = acc.double();
        if ng[i] != 0 {
            acc = acc.add(&pick(gt, ng[i]));
        }
        if nq[i] != 0 {
            acc = acc.add(&pick(&qt, nq[i]));
        }
    }
    acc
}

/**
 * @brief ECDSA 검증에 쓸 R의 x좌표를 위수로 줄여 돌려준다.
 * @details x좌표는 P 기준이라 N보다 클 수 있다. 서명의 r과 견주려면 N으로 줄여야 한다.
 *          P와 N의 차이가 작아 한 번 빼는 것으로 충분하다.
 * @return 공개키가 곡선 위가 아니거나 결과가 무한원점이면 None.
 */
pub(crate) fn lincomb_rx(
    u1_be: &[u8],
    u2_be: &[u8],
    qx_be: &[u8],
    qy_be: &[u8],
) -> Option<[u8; 32]> {
    let q = public_point(qx_be, qy_be)?;
    let r = lincomb(u1_be, u2_be, &q);
    let x = r.affine_x()?;

    let mut xn = x;
    if !fe_lt(&xn, &N) {
        let mut borrow = 0i128;
        for i in 0..4 {
            let v = i128::from(xn[i]) - i128::from(N[i]) - borrow;
            xn[i] = v as u64;
            borrow = if v < 0 { 1 } else { 0 };
        }
    }
    Some(fe_to_be(&xn))
}

/**
 * @brief P-256 ECDSA 서명을 검증한다.
 *
 * @details 스칼라 산술은 p256 크레이트에 맡기고, 비용이 몰리는 점 연산만 여기 경로로
 *          돌린다. r과 s는 위수 범위 안이어야 하고 0이면 안 된다. 0을 허용하면 어떤
 *          공개키로도 통과하는 서명이 생긴다.
 * @param pubkey   비압축 좌표 64바이트. DNSKEY의 알고리즘 13 공개키 형식 그대로다.
 * @param digest32 서명 대상의 SHA-256 해시.
 * @param sig      r과 s를 각각 32바이트로 이은 64바이트.
 * @return 검증되면 Ok. 길이·범위·곡선 확인 중 하나라도 어긋나면 Err.
 */
pub(crate) fn verify(pubkey: &[u8], digest32: &[u8; 32], sig: &[u8]) -> Result<(), ()> {
    use p256::elliptic_curve::ff::Field;
    use p256::elliptic_curve::ops::{Invert, Reduce};
    use p256::elliptic_curve::PrimeField;
    use p256::Scalar;
    if sig.len() != 64 || pubkey.len() != 64 {
        return Err(());
    }
    let r_bytes: [u8; 32] = sig[..32].try_into().map_err(|_| ())?;
    let s_bytes: [u8; 32] = sig[32..].try_into().map_err(|_| ())?;
    let r = Option::<Scalar>::from(Scalar::from_repr(r_bytes.into())).ok_or(())?;
    let s = Option::<Scalar>::from(Scalar::from_repr(s_bytes.into())).ok_or(())?;
    if bool::from(r.is_zero()) || bool::from(s.is_zero()) {
        return Err(());
    }
    let z = Scalar::reduce_bytes(digest32.into());
    let s_inv = Option::<Scalar>::from(s.invert_vartime()).ok_or(())?;
    let u1 = z * s_inv;
    let u2 = r * s_inv;
    let rx = lincomb_rx(
        u1.to_repr().as_slice(),
        u2.to_repr().as_slice(),
        &pubkey[..32],
        &pubkey[32..],
    )
    .ok_or(())?;
    if rx.as_slice() == r.to_repr().as_slice() {
        Ok(())
    } else {
        Err(())
    }
}

/** @brief 유한체·점 연산과 검증 결과를 p256 크레이트에 대조해 고정한다. */
#[cfg(test)]
mod tests {
    use super::*;

    /**
     * @brief 대조용 곱셈. 넓은 곱을 만든 뒤 느린 방식으로 나머지를 구한다.
     * @details 최적화된 몽고메리 경로와 독립적으로 구현해야 대조에 의미가 있다.
     */
    fn ref_mulmod(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        let mut wide = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let v = u128::from(wide[i + j]) + u128::from(a[i]) * u128::from(b[j]) + carry;
                wide[i + j] = v as u64;
                carry = v >> 64;
            }
            wide[i + 4] = carry as u64;
        }
        barrett_like_mod(&wide)
    }

    /** @brief 512비트를 최상위 비트부터 한 칸씩 내리며 나머지를 구한다. 느리지만 단순하다. */
    fn barrett_like_mod(wide: &[u64; 8]) -> [u64; 4] {
        let mut rem = [0u64; 4];
        for bit in (0..512).rev() {
            let mut carry = 0u64;
            for limb in rem.iter_mut() {
                let nc = *limb >> 63;
                *limb = (*limb << 1) | carry;
                carry = nc;
            }
            let hi = carry;
            let wb = (wide[bit / 64] >> (bit % 64)) & 1;
            rem[0] |= wb;

            if hi == 1 || !fe_lt(&rem, &P) {
                fe_sub_p(&mut rem);
            }
        }
        rem
    }

    /** @brief p256 크레이트로 구한 k*G의 x좌표. 이 구현의 스칼라 곱의 기준값이다. */
    fn p256_scalar_g_x(k_be: &[u8; 32]) -> Option<[u8; 32]> {
        use p256::elliptic_curve::group::GroupEncoding;
        use p256::elliptic_curve::PrimeField;
        let sc = Option::<p256::Scalar>::from(p256::Scalar::from_repr((*k_be).into()))?;
        let pt = p256::ProjectivePoint::GENERATOR * sc;
        let enc = pt.to_affine().to_bytes();
        let mut x = [0u8; 32];
        x.copy_from_slice(&enc[1..33]);
        Some(x)
    }

    /** @brief 검증 한 건의 소요를 측정하는 측정 전용. 판정하지 않으므로 기본 실행에서 뺀다. */
    #[test]
    #[ignore = "타이밍 측정 전용: cargo test --release -- --ignored --nocapture"]
    fn timing() {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
        use sha2::Digest as _;
        let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let vk = VerifyingKey::from(&sk);
        let pk = vk.to_encoded_point(false);
        let pubkey = pk.as_bytes()[1..].to_vec();
        let digest: [u8; 32] = sha2::Sha256::digest(b"timing").into();
        let sig: Signature = sk.sign_prehash(&digest).unwrap();
        let raw = sig.to_bytes();
        assert!(verify(&pubkey, &digest, &raw).is_ok());
        let n = 3000u32;
        let t = std::time::Instant::now();
        for _ in 0..n {
            let _ = std::hint::black_box(verify(
                std::hint::black_box(&pubkey),
                &digest,
                std::hint::black_box(&raw),
            ));
        }
        let us = t.elapsed().as_micros() as f64 / f64::from(n);
        println!("p256fast::verify: {us:.1} us/op");
    }

    /**
     * @brief 이 구현의 검증기가 p256 크레이트와 수락·거부까지 똑같이 갈리는지 대조한다.
     * @details 정상 서명을 통과시키는 것만으로는 부족하다. 변조된 서명을 이 구현만 통과시키면
     *          그게 곧 우회다. 그래서 양쪽 판정이 같은지를 본다.
     */
    #[test]
    fn verify_differential_against_p256() {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
        use sha2::Digest as _;
        for round in 0u32..1000 {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&round.to_le_bytes());
            seed[31] = 3;
            let sk = SigningKey::from_slice(&seed).unwrap();
            let vk = VerifyingKey::from(&sk);
            let pk = vk.to_encoded_point(false);
            let pubkey = &pk.as_bytes()[1..];
            let digest: [u8; 32] = sha2::Sha256::digest(format!("msg {round}")).into();
            let sig: Signature = sk.sign_prehash(&digest).unwrap();
            let raw = sig.to_bytes();

            assert!(
                verify(pubkey, &digest, &raw).is_ok(),
                "accept round {round}"
            );

            let mut bad = raw.to_vec();
            bad[(round as usize) % 64] ^= 1;
            let mine = verify(pubkey, &digest, &bad).is_ok();
            let theirs = Signature::from_slice(&bad)
                .map(|s2| {
                    use p256::ecdsa::signature::hazmat::PrehashVerifier;
                    vk.verify_prehash(&digest, &s2).is_ok()
                })
                .unwrap_or(false);
            assert_eq!(mine, theirs, "tamper round {round}");

            let mut d2 = digest;
            d2[(round as usize) % 32] ^= 1;
            assert!(verify(pubkey, &d2, &raw).is_err(), "wrong digest {round}");
        }
    }

    /** @brief 점 연산 자체가 맞는지. 생성점 스칼라 곱을 크레이트 값과 비교한다. */
    #[test]
    fn scalar_g_matches_p256() {
        for round in 1u32..40 {
            let mut kb = [0u8; 32];
            kb[28..].copy_from_slice(&round.to_be_bytes());
            kb[0] = (round as u8).wrapping_mul(13).wrapping_add(1);
            let mine = scalar_mul(&G_JAC, &kb).affine_x().map(|x| fe_to_be(&x));
            let want = p256_scalar_g_x(&kb);
            assert_eq!(mine, want, "round {round}");
        }
    }

    /** @brief 몽고메리 왕복과 작은 곱, 경계값(p-1)이 맞는지. 실패 시 원인을 좁혀 준다. */
    #[test]
    fn field_basic_diagnostics() {
        let a = [0x1234_5678u64, 0xabcd, 0, 0];
        assert_eq!(from_mont(&to_mont(&a)), a, "roundtrip");

        let six = from_mont(&fe_mul(&to_mont(&[2, 0, 0, 0]), &to_mont(&[3, 0, 0, 0])));
        assert_eq!(six, [6, 0, 0, 0], "2*3");

        let r_mod_p = [
            0x0000_0000_0000_0001u64,
            0xffff_ffff_0000_0000,
            0xffff_ffff_ffff_ffff,
            0x0000_0000_ffff_fffe,
        ];
        assert_eq!(to_mont(&[1, 0, 0, 0]), r_mod_p, "to_mont(1)=R mod p");

        let pm1 = super::fe_sub(&P, &[1, 0, 0, 0]);
        let got = from_mont(&fe_mul(&to_mont(&a), &to_mont(&pm1)));
        let want = super::fe_sub(&P, &a);
        assert_eq!(got, want, "a*(p-1)=p-a  got={got:x?} want={want:x?}");
    }

    /** @brief 몽고메리 곱셈을 독립 구현과 대조한다. 경계값 조합까지 포함한다. */
    #[test]
    fn field_mul_matches_reference() {
        let cases: [[u64; 4]; 5] = [
            [1, 0, 0, 0],
            [0xdead_beef, 0x1234, 0, 0],
            [
                0xffff_ffff_ffff_fffe,
                0x0000_0000_ffff_ffff,
                0,
                0xffff_ffff_0000_0001,
            ],
            [0x1111_2222_3333_4444, 0x5555_6666_7777_8888, 0x9999, 0xaaaa],
            P,
        ];
        for a in &cases {
            for b in &cases {
                let am = if fe_lt(a, &P) { *a } else { fe_sub(a, &P) };
                let bm = if fe_lt(b, &P) { *b } else { fe_sub(b, &P) };

                let got = from_mont(&fe_mul(&to_mont(&am), &to_mont(&bm)));
                let want = ref_mulmod(&am, &bm);
                assert_eq!(got, want, "a={am:?} b={bm:?}");
            }
        }
    }

    /** @brief 역원을 곱하면 1이 되는지. 아핀 좌표 복원이 이 연산에 걸려 있다. */
    #[test]
    fn field_inverse_roundtrip() {
        let a = [0x1234_5678_9abc_def0u64, 0x2, 0x3, 0x4];
        let am = to_mont(&a);
        let inv = fe_inv(&am);
        let prod = from_mont(&fe_mul(&am, &inv));
        assert_eq!(prod, [1, 0, 0, 0], "a * a^-1 == 1");
    }

    /** @brief limb 순서를 뒤집어 읽고 쓰는 과정이 왕복에서 보존되는지. */
    #[test]
    fn bytes_roundtrip() {
        let be: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
        let f = fe_from_be(&be).unwrap();
        assert_eq!(fe_to_be(&f), be);
    }
}
