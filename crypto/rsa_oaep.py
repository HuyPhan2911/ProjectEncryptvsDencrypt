# rsa.py
# =====================================================
# RSA-OAEP-SHA256 - THUẦN PYTHON (KHÔNG DÙNG THỦ VIỆN)
# Demo học thuật với bảo mật tốt hơn
# =====================================================

import os
import hashlib
import random
import json


class RSA_OAEP:
    """
    RSA-OAEP-SHA256 implementation thuần Python
    ----------------------------------------
    - RSA: Mã hóa bất đối xứng
    - OAEP: Optimal Asymmetric Encryption Padding
    - SHA256: Hàm băm an toàn
    """

    def __init__(self, key_size=2048):
        """
        Khởi tạo RSA
        """
        self.key_size = key_size
        self.public_key = None   # (e, n)
        self.private_key = None  # (d, n)
        
        # Đường dẫn lưu khóa
        self.keys_dir = "keys"
        self.public_key_file = os.path.join(self.keys_dir, "public_key.json")
        self.private_key_file = os.path.join(self.keys_dir, "private_key.json")
        
        os.makedirs(self.keys_dir, exist_ok=True)



    def _gcd(self, a, b):
        """Ước chung lớn nhất (GCD)"""
        while b:
            a, b = b, a % b
        return a

    def _egcd(self, a, b):
     
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = self._egcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    def _mod_inverse(self, a, m):
        """Nghịch đảo modular: a^(-1) mod m"""
        gcd, x, _ = self._egcd(a, m)
        if gcd != 1:
            raise ValueError("Không tồn tại nghịch đảo modular")
        return x % m

    def _is_prime(self, n, k=5):
        """
        Kiểm tra số nguyên tố bằng Miller-Rabin
        k: số lần kiểm tra (độ chính xác)
        """
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False


        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

    
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
            
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        
        return True

    def _generate_prime(self, bits):
        """Tạo số nguyên tố có độ dài bits"""
        while True:
           
            num = random.getrandbits(bits)
            num |= (1 << bits - 1) | 1  
            
            if self._is_prime(num):
                return num

  

    def generate_keys(self):
        """
        Tạo cặp khóa RSA
        """
        print(f"🔑 Đang tạo khóa RSA {self.key_size} bits...")
        
        # Độ dài mỗi số nguyên tố
        prime_bits = self.key_size // 2
        
        # Tạo 2 số nguyên tố p, q
        print("   Tạo số nguyên tố p...")
        p = self._generate_prime(prime_bits)
        
        print("   Tạo số nguyên tố q...")
        q = self._generate_prime(prime_bits)
        
        # Đảm bảo p != q
        while p == q:
            q = self._generate_prime(prime_bits)
        
        # Tính n và φ(n)
        n = p * q
        phi = (p - 1) * (q - 1)
      
        e = 65537
        if self._gcd(e, phi) != 1:

            e = 3
            while self._gcd(e, phi) != 1:
                e += 2
        

        print("   Tính khóa bí mật d...")
        d = self._mod_inverse(e, phi)
        
        # Lưu khóa
        self.public_key = (e, n)
        self.private_key = (d, n)
        
        print("Tạo khóa thành công!")
        return self.public_key, self.private_key

    def save_keys(self):
        """Lưu khóa vào file JSON"""
        if not self.public_key or not self.private_key:
            raise ValueError("Chưa có khóa để lưu")
        
        # Lưu khóa công khai
        with open(self.public_key_file, 'w') as f:
            json.dump({
                'e': self.public_key[0],
                'n': self.public_key[1],
                'key_size': self.key_size
            }, f, indent=2)
        
        # Lưu khóa bí mật
        with open(self.private_key_file, 'w') as f:
            json.dump({
                'd': self.private_key[0],
                'n': self.private_key[1],
                'key_size': self.key_size
            }, f, indent=2)
        
        print(f"Đã lưu khóa tại: {self.keys_dir}/")

    def load_keys(self):
        """Tải khóa từ file"""
        try:
            # Tải khóa công khai
            with open(self.public_key_file, 'r') as f:
                pub = json.load(f)
                self.public_key = (pub['e'], pub['n'])
                self.key_size = pub['key_size']
            
            # Tải khóa bí mật
            with open(self.private_key_file, 'r') as f:
                priv = json.load(f)
                self.private_key = (priv['d'], priv['n'])
            
            return True
        except FileNotFoundError:
            return False


    def _mgf1(self, seed, length):
        """
        Mask Generation Function 1 (MGF1) với SHA256
        """
        hlen = 32  # SHA256 = 32 bytes
        mask = b''
        counter = 0
        
        while len(mask) < length:
            c = counter.to_bytes(4, 'big')
            mask += hashlib.sha256(seed + c).digest()
            counter += 1
        
        return mask[:length]

    def _xor_bytes(self, a, b):
        """XOR hai chuỗi bytes"""
        return bytes(x ^ y for x, y in zip(a, b))

    def _oaep_encode(self, message, n):
        """
        OAEP Encoding
        message: plaintext cần mã hóa
        n: modulus RSA
        """
        k = (n.bit_length() + 7) // 8  
        mlen = len(message)
        hlen = 32  
        
        # Kiểm tra độ dài
        max_mlen = k - 2 * hlen - 2
        if mlen > max_mlen:
            raise ValueError(f"Message quá dài. Max: {max_mlen} bytes")
        
        # Label hash (để trống)
        lhash = hashlib.sha256(b'').digest()
        
        # Padding string
        ps_len = k - mlen - 2 * hlen - 2
        ps = b'\x00' * ps_len
        
        # DB = lHash || PS || 0x01 || M
        db = lhash + ps + b'\x01' + message
        
        # Random seed
        seed = os.urandom(hlen)
        
        # dbMask = MGF(seed, k - hLen - 1)
        db_mask = self._mgf1(seed, k - hlen - 1)
        
        # maskedDB = DB xor dbMask
        masked_db = self._xor_bytes(db, db_mask)
        
        # seedMask = MGF(maskedDB, hLen)
        seed_mask = self._mgf1(masked_db, hlen)
        
        # maskedSeed = seed xor seedMask
        masked_seed = self._xor_bytes(seed, seed_mask)
        
        # EM = 0x00 || maskedSeed || maskedDB
        em = b'\x00' + masked_seed + masked_db
        
        return em

    def _oaep_decode(self, em, n):
        """
        OAEP Decoding
        """
        k = (n.bit_length() + 7) // 8
        hlen = 32  # SHA256 = 32 bytes
        
        # Kiểm tra độ dài
        if len(em) != k or k < 2 * hlen + 2:
            raise ValueError("Decoding error: Invalid length")
        
        # Tách EM
        y = em[0]
        masked_seed = em[1:hlen + 1]
        masked_db = em[hlen + 1:]
        
        if y != 0:
            raise ValueError("Decoding error: First byte not 0x00")
        
        # seedMask = MGF(maskedDB, hLen)
        seed_mask = self._mgf1(masked_db, hlen)
        
        # seed = maskedSeed xor seedMask
        seed = self._xor_bytes(masked_seed, seed_mask)
        
        # dbMask = MGF(seed, k - hLen - 1)
        db_mask = self._mgf1(seed, k - hlen - 1)
        
        # DB = maskedDB xor dbMask
        db = self._xor_bytes(masked_db, db_mask)
        
        # Kiểm tra lHash
        lhash = hashlib.sha256(b'').digest()
        lhash_check = db[:hlen]
        
        if lhash != lhash_check:
            raise ValueError("Decoding error: Hash mismatch")
        
        # Tìm 0x01 separator
        i = hlen
        while i < len(db) and db[i] == 0:
            i += 1
        
        if i >= len(db) or db[i] != 1:
            raise ValueError("Decoding error: No 0x01 separator")
        
        # Message bắt đầu sau 0x01
        message = db[i + 1:]
        
        return message



    def _int_to_bytes(self, x, length):
        """Chuyển số nguyên thành bytes"""
        return x.to_bytes(length, 'big')

    def _bytes_to_int(self, b):
        """Chuyển bytes thành số nguyên"""
        return int.from_bytes(b, 'big')

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Mã hóa dữ liệu bằng RSA-OAEP
        """
        if not self.public_key:
            if not self.load_keys():
                raise ValueError("Không tìm thấy khóa công khai")
        
        e, n = self.public_key
        k = (n.bit_length() + 7) // 8
        max_chunk_size = k - 2 * 32 - 2  
        
        # Mã hóa từng chunk
        encrypted_chunks = []
        
        for i in range(0, len(plaintext), max_chunk_size):
            chunk = plaintext[i:i + max_chunk_size]
            
            # OAEP encode
            em = self._oaep_encode(chunk, n)
            
            # Chuyển thành số nguyên
            m = self._bytes_to_int(em)
            
            # RSA encryption: c = m^e mod n
            c = pow(m, e, n)
            
            # Chuyển thành bytes với độ dài cố định k
            c_bytes = self._int_to_bytes(c, k)
            encrypted_chunks.append(c_bytes)
        
        return b''.join(encrypted_chunks)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Giải mã dữ liệu RSA-OAEP
        """
        if not self.private_key:
            if not self.load_keys():
                raise ValueError("Không tìm thấy khóa bí mật")
        
        d, n = self.private_key
        k = (n.bit_length() + 7) // 8
        
        # Giải mã từng chunk
        decrypted_chunks = []
        
        for i in range(0, len(ciphertext), k):
            chunk = ciphertext[i:i + k]
            
            # Chuyển thành số nguyên
            c = self._bytes_to_int(chunk)
            
            # RSA decryption: m = c^d mod n
            m = pow(c, d, n)
            
            # Chuyển thành bytes
            em = self._int_to_bytes(m, k)
            
            # OAEP decode
            message = self._oaep_decode(em, n)
            decrypted_chunks.append(message)
        
        return b''.join(decrypted_chunks)

    # =====================================================
    # PHẦN 5: HELPER FUNCTIONS
    # =====================================================

    def get_public_key_pem(self) -> str:
        """Lấy khóa công khai dạng text"""
        if not self.public_key:
            if not self.load_keys():
                raise ValueError("Không có khóa")
        
        e, n = self.public_key
        return f"""-----BEGIN RSA PUBLIC KEY-----
Key Size: {self.key_size} bits
e (exponent): {e}
n (modulus): {n}
-----END RSA PUBLIC KEY-----"""

    def get_private_key_pem(self) -> str:
        """Lấy khóa bí mật dạng text"""
        if not self.private_key:
            if not self.load_keys():
                raise ValueError("Không có khóa")
        
        d, n = self.private_key
        return f"""-----BEGIN RSA PRIVATE KEY-----
Key Size: {self.key_size} bits
d (private exponent): {d}
n (modulus): {n}
-----END RSA PRIVATE KEY-----"""



rsa_instance = RSA_OAEP()

def encrypt(data: bytes) -> bytes:
    """Wrapper function cho mã hóa"""
    return rsa_instance.encrypt(data)

def decrypt(data: bytes) -> bytes:
    """Wrapper function cho giải mã"""
    return rsa_instance.decrypt(data)