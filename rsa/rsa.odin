package rsa

import "core:fmt"
import "core:slice"
import "core:mem"

import "core:math/big"
import "core:math/rand"
import "core:crypto/hash"

PAD :: 0xac
MAX_LEN :: 253 // NOTE: just to be safe
FIXED_EXPONENT :: 65337

Key_Public :: struct {
    n : big.Int,
    e : big.Int,
}

Key_Private :: struct {
    n : big.Int,
    d : big.Int,
}

keygen :: proc () -> (key_prv : Key_Private, key_pub : Key_Public) {
    p, q, p1, q1, ln : big.Int
    defer big.destroy(&p, &q, &p1, &q1, &ln)
    big.set(&key_pub.e, FIXED_EXPONENT)

    for {
        big.internal_random_prime(&p, 1024, -1, {})
        big.internal_random_prime(&q, 1024, -1, {})

        big.int_mul(&key_prv.n, &p, &q)
        big.copy(&key_pub.n, &key_prv.n)

        big.int_sub_digit(&p1, &p, 1)
        big.int_sub_digit(&q1, &q, 1)

        big.internal_int_lcm(&ln, &p1, &q1)

        big.internal_invmod(&key_prv.d, &key_pub.e, &ln)

        if zero, _ := big.is_zero(&key_prv.d); zero { continue }

        return
    }
}

internal_powmod :: proc (input : []u8, pow : ^big.Int, mod : ^big.Int) -> (result : []u8) {
    input_int, result_int : big.Int
    defer big.destroy(&input_int, &result_int)

    big.int_from_bytes_little(&input_int, input)

    big.internal_powmod(&result_int, &input_int, pow, mod)

    size, _ := big.int_to_bytes_size(&result_int)
    result = make([]u8, size)
    big.int_to_bytes_little(&result_int, result)

    return
}

encrypt :: proc (key : ^Key_Public, data : []u8) -> (cipher : []u8, ok : bool) {
    (len(data) < MAX_LEN) or_return

    mdata : [dynamic]u8
    defer delete(mdata)

    append(&mdata, PAD)
    append(&mdata, cast(u8)len(data))
    append(&mdata, ..data)

    return internal_powmod(mdata[:], &key.e, &key.n), true
}

decrypt :: proc (key : ^Key_Private, cipher : []u8) -> (data : []u8, ok : bool = true) {
    mdata := internal_powmod(cipher, &key.d, &key.n)
    defer delete(mdata)

    (len(mdata) >= 2)       or_return
    (mdata[0] == PAD)       or_return
    (mdata[1] < MAX_LEN)    or_return

    data = make([]u8, mdata[1])
    mem.copy(raw_data(data), raw_data(mdata[2:]), len(mdata) - 2)

    return
}

encrypt_value :: proc (key : ^Key_Public, value : $ty) -> (cipher : []u8, ok : bool) {
    value := value
    bytes := slice.bytes_from_ptr(&value, size_of(ty))
    return encrypt(key, bytes)
}

decrypt_value :: proc (key : ^Key_Private, cipher : []u8, $ty : typeid) -> (value : ty, ok : bool = true) {
    data := decrypt(key, cipher) or_return
    defer delete(data)

    (len(data) == size_of(ty)) or_return

    value = (cast(^ty)raw_data(data))^
    return
}

sign :: proc (key : ^Key_Private, data : []u8) -> (signature : []u8) {
    hash := hash.hash_bytes(.SHA256, data)
    defer delete(hash)

    return internal_powmod(hash, &key.d, &key.n)
}

sign_raw :: proc (key : ^Key_Private, hash : []u8) -> (signature : []u8) {
    return internal_powmod(hash, &key.d, &key.n)
}

sign_value :: proc (key : ^Key_Private, value : $ty) -> (signature : []u8) {
    value := value
    return sign(key, slice.bytes_from_ptr(&value, size_of(ty)))
}

verify :: proc (key : ^Key_Public, data : []u8, signature : []u8) -> bool {
    hash := hash.hash_bytes(.SHA256, data)
    defer delete(hash)

    hash2 := internal_powmod(signature, &key.e, &key.n)
    defer delete(hash2)

    return slice.equal(hash, hash2)
}

verify_value :: proc (key : ^Key_Public, value : $ty, signature : []u8) -> bool {
    value := value
    return verify(key, slice.bytes_from_ptr(&value, size_of(ty)), signature)
}

blindGenerate :: proc (key : ^Key_Public) -> (r : big.Int, r1 : big.Int) {
    g : big.Int
    defer big.destroy(&g)

    for true {
        big.internal_random(&r, 2047)
        big.gcd(&g, &r, &key.n)

        if coprime, _ := big.eq(&g, 1); coprime { break }
    }

    big.internal_invmod(&r1, &r, &key.n)
    return
}

blindMask :: proc (key : ^Key_Public, r : ^big.Int, data : []u8) -> (masked : []u8) {
    re, data_int, masked_int : big.Int
    defer big.destroy(&re, &data_int, &masked_int)

    big.internal_powmod(&re, r, &key.e, &key.n)
    big.int_from_bytes_little(&data_int, data)
    big.internal_mulmod(&masked_int, &data_int, &re, &key.n)

    size, _ := big.int_to_bytes_size(&masked_int)
    masked = make([]u8, size)
    big.int_to_bytes_little(&masked_int, masked)

    return
}

blindUnmask :: proc (key : ^Key_Public, r1 : ^big.Int, maskedSignature : []u8) -> (signature : []u8) {
    masked_int, signature_int : big.Int
    defer big.destroy(&masked_int, &signature_int)

    big.int_from_bytes_little(&masked_int, maskedSignature)
    big.internal_mulmod(&signature_int, &masked_int, r1, &key.n)

    size, _ := big.int_to_bytes_size(&signature_int)
    signature = make([]u8, size)
    big.int_to_bytes_little(&signature_int, signature)

    return
}
