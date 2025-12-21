import rsa
import os

# Tên thư mục để chứa file khóa
KEY_DIR = "keys_storage"

def ensure_key_dir():
    """Tạo thư mục chứa khóa nếu chưa có"""
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR)

def generate_and_save_keys(name):
    """
    Sinh khóa và LƯU vào file .pem
    Ví dụ: alice_pub.pem, alice_priv.pem
    """
    print(f"...Đang sinh khóa mới cho {name} (1024 bit)...")
    pub, priv = rsa.newkeys(1024)
    
    # Lưu Public Key
    with open(f"{KEY_DIR}/{name}_pub.pem", "wb") as f:
        f.write(pub.save_pkcs1('PEM'))
    
    # Lưu Private Key
    with open(f"{KEY_DIR}/{name}_priv.pem", "wb") as f:
        f.write(priv.save_pkcs1('PEM'))
        
    print(f"-> Đã lưu cặp khóa của {name} vào thư mục '{KEY_DIR}'")
    return pub, priv

def load_keys(name):
    """
    Đọc khóa từ file (nếu đã có)
    """
    try:
        with open(f"{KEY_DIR}/{name}_pub.pem", "rb") as f:
            pub = rsa.PublicKey.load_pkcs1(f.read())
        
        with open(f"{KEY_DIR}/{name}_priv.pem", "rb") as f:
            priv = rsa.PrivateKey.load_pkcs1(f.read())
            
        print(f"-> Đã nạp thành công khóa cũ của {name}.")
        return pub, priv
    except FileNotFoundError:
        return None, None

# --- CÁC HÀM LOGIC CŨ (GIỮ NGUYÊN) ---
def encrypt_message(message, pub_key):
    return rsa.encrypt(message.encode('utf-8'), pub_key)

def decrypt_message(crypto, priv_key):
    try:
        return rsa.decrypt(crypto, priv_key).decode('utf-8')
    except:
        return "[Lỗi] Sai khóa hoặc dữ liệu hỏng!"

def sign_document(message, priv_key):
    return rsa.sign(message.encode('utf-8'), priv_key, 'SHA-256')

def verify_document(message, signature, pub_key):
    try:
        rsa.verify(message.encode('utf-8'), signature, pub_key)
        return True
    except:
        return False

# --- CHƯƠNG TRÌNH CHÍNH ---
def main():
    ensure_key_dir()
    print("\n=== BÀI TẬP 2: RSA PRO (CÓ LƯU FILE KHÓA) ===")
    
    # 1. Kiểm tra xem đã có khóa chưa, nếu chưa thì tạo mới
    alice_pub, alice_priv = load_keys("alice")
    if not alice_pub:
        alice_pub, alice_priv = generate_and_save_keys("alice")

    bob_pub, bob_priv = load_keys("bob")
    if not bob_pub:
        bob_pub, bob_priv = generate_and_save_keys("bob")

    while True:
        print("\n" + "-"*40)
        print("MENU:")
        print("1. Alice gửi tin mật (Confidentiality)")
        print("2. Alice ký số (Authentication)")
        print("3. Hiển thị thông tin khóa (New)")
        print("4. Thoát")
        
        choice = input("Chọn: ")

        if choice == '1':
            msg = input("Nhập tin nhắn: ")
            cipher = encrypt_message(msg, bob_pub)
            print(f"\n[Alice] Cipher (hex): {cipher.hex()[:30]}...")
            
            # Bob giải mã
            plain = decrypt_message(cipher, bob_priv)
            print(f"[Bob] Giải mã: {plain}")

        elif choice == '2':
            doc = input("Nhập văn bản: ")
            sig = sign_document(doc, alice_priv)
            print(f"\n[Alice] Chữ ký (hex): {sig.hex()[:30]}...")
            
            valid = verify_document(doc, sig, alice_pub)
            print(f"[Check] Kết quả xác thực: {'HỢP LỆ' if valid else 'GIẢ MẠO'}")
            
        elif choice == '3':
            # In ra một phần khóa để thấy nó "ngầu"
            print(f"\nAlice Public Key (n):\n{str(alice_pub.n)[:50]}...")
            print(f"Alice Private Key (d):\n{str(alice_priv.d)[:50]}...")
            print("(Các file khóa .pem nằm trong thư mục 'keys_storage')")

        elif choice == '4':
            break

if __name__ == "__main__":
    main()