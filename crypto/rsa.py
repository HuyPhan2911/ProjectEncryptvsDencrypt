# rsa.py
# =====================================================
# THUẬT TOÁN RSA – MÃ HÓA BẤT ĐỐI XỨNG
# Demo học thuật – KHÔNG dùng cho bảo mật thực tế
# =====================================================

class RSA:
    """
    RSA – Rivest–Shamir–Adleman
    ----------------------------------------
    RSA là thuật toán mã hóa bất đối xứng:
        - Khóa công khai (e, n): dùng để mã hóa
        - Khóa bí mật (d, n): dùng để giải mã

    Công thức:
        Mã hóa:    C = M^e mod n
        Giải mã:   M = C^d mod n

    Trong đó:
        p, q  : hai số nguyên tố
        n     : n = p * q
        φ(n)  : (p-1)(q-1)
        e     : số mũ công khai
        d     : nghịch đảo modular của e theo φ(n)
    """

    def __init__(self, p=61, q=53, e=17):
        """
        Khởi tạo RSA với các tham số nhỏ để minh họa
        """
        # Hai số nguyên tố (demo)
        self.p = p
        self.q = q

        # Tính n
        self.n = p * q

        # Hàm Euler φ(n)
        self.phi = (p - 1) * (q - 1)

        # Số mũ công khai
        self.e = e

        # Tính số mũ bí mật d
        self.d = self._mod_inverse(e, self.phi)

    # -------------------------------------------------
    # TÍNH NGHỊCH ĐẢO MODULAR
    # -------------------------------------------------

    def _egcd(self, a, b):
        """
        Thuật toán Euclid mở rộng
        Trả về (gcd, x, y) sao cho: ax + by = gcd(a, b)
        """
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = self._egcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    def _mod_inverse(self, a, m):
        """
        Tìm nghịch đảo modular của a theo modulo m
        """
        gcd, x, _ = self._egcd(a, m)
        if gcd != 1:
            raise ValueError("Không tồn tại nghịch đảo modular")
        return x % m

    # -------------------------------------------------
    # MÃ HÓA
    # -------------------------------------------------

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Mã hóa từng byte dữ liệu bằng khóa công khai (e, n)
        """
        result = []

        for b in plaintext:
            # C = M^e mod n
            c = pow(b, self.e, self.n)
            result.append(c)

        # Chuyển danh sách số nguyên sang bytes
        return bytes(result)

    # -------------------------------------------------
    # GIẢI MÃ
    # -------------------------------------------------

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Giải mã từng byte dữ liệu bằng khóa bí mật (d, n)
        """
        result = []

        for b in ciphertext:
            # M = C^d mod n
            m = pow(b, self.d, self.n)
            result.append(m)

        return bytes(result)
