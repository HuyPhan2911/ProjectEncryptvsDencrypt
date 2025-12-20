# tdes.py
# =====================================================
# THUẬT TOÁN 3DES (TRIPLE DES) – CHẾ ĐỘ EDE
# Demo học thuật – KHÔNG dùng cho bảo mật thực tế
# =====================================================

from .des import DES

class TripleDES:
    """
    Triple DES (3DES)
    ----------------------------------------
    3DES sử dụng thuật toán DES 3 lần liên tiếp
    theo mô hình EDE (Encrypt – Decrypt – Encrypt)

    Công thức mã hóa:
        C = E(K3, D(K2, E(K1, P)))

    Công thức giải mã:
        P = D(K1, E(K2, D(K3, C)))

    Kích thước khối: 64-bit (8 byte)
    Độ dài khóa:
        - 16 byte  → 3DES 2-key (K1, K2, K1)
        - 24 byte  → 3DES 3-key (K1, K2, K3)
    """

    def __init__(self, key: bytes):
        # Kiểm tra độ dài khóa hợp lệ
        if len(key) not in (16, 24):
            raise ValueError("Khóa 3DES phải có độ dài 16 hoặc 24 byte")

        # Phân tách khóa
        if len(key) == 16:
            # 3DES 2-key: K1, K2, K1
            k1 = key[:8]
            k2 = key[8:16]
            k3 = k1
        else:
            # 3DES 3-key: K1, K2, K3
            k1 = key[:8]
            k2 = key[8:16]
            k3 = key[16:24]

        # Khởi tạo 3 đối tượng DES
        self.des1 = DES(k1)
        self.des2 = DES(k2)
        self.des3 = DES(k3)

    # -----------------------------
    # MÃ HÓA 1 KHỐI 64-BIT
    # -----------------------------

    def encrypt_block(self, block: bytes) -> bytes:
        """
        Mã hóa 1 khối 8 byte theo mô hình EDE
        """
        block = self.des1.encrypt_block(block)   # E(K1)
        block = self.des2.decrypt_block(block)   # D(K2)
        block = self.des3.encrypt_block(block)   # E(K3)
        return block

    # -----------------------------
    # GIẢI MÃ 1 KHỐI 64-BIT
    # -----------------------------

    def decrypt_block(self, block: bytes) -> bytes:
        """
        Giải mã 1 khối 8 byte (ngược lại quá trình mã hóa)
        """
        block = self.des3.decrypt_block(block)   # D(K3)
        block = self.des2.encrypt_block(block)   # E(K2)
        block = self.des1.decrypt_block(block)   # D(K1)
        return block

    # -----------------------------
    # CHẾ ĐỘ ECB (MINH HỌA)
    # -----------------------------

    def encrypt(self, data: bytes) -> bytes:
        """
        Mã hóa dữ liệu theo chế độ ECB
        Chia dữ liệu thành các khối 8 byte
        """
        result = b""
        for i in range(0, len(data), 8):
            block = data[i:i+8]
            if len(block) < 8:
                block += b'\x00' * (8 - len(block))  # padding đơn giản
            result += self.encrypt_block(block)
        return result

    def decrypt(self, data: bytes) -> bytes:
        """
        Giải mã dữ liệu theo chế độ ECB
        """
        result = b""
        for i in range(0, len(data), 8):
            result += self.decrypt_block(data[i:i+8])
        return result.rstrip(b'\x00')
