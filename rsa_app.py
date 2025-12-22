import os
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
import json

from utils import read_file, write_file
from crypto.rsa_oaep import RSA_OAEP

app = Flask(__name__)

OUTPUT_DIR = "outputs"
KEYS_DIR = "keys"
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(KEYS_DIR, exist_ok=True)

# Instance RSA toàn cục
rsa_crypto = RSA_OAEP()


@app.route("/", methods=["GET"])
def index():

    has_keys = rsa_crypto.load_keys()
    
    keys_info = None
    if has_keys:
        try:
            public_key_pem = rsa_crypto.get_public_key_pem()
            keys_info = {
                'public_key': public_key_pem,
                'key_size': rsa_crypto.key_size,
                'has_private': rsa_crypto.private_key is not None
            }
        except:
            has_keys = False
    
    return render_template(
        "rsa.html",
        has_keys=has_keys,
        keys_info=keys_info
    )


@app.route("/generate-keys", methods=["POST"])
def generate_keys():
    """Tạo cặp khóa RSA mới"""
    try:
        key_size = int(request.form.get("key_size", 2048))
        
        # Tạo instance mới với key_size
        rsa_crypto.key_size = key_size
        rsa_crypto.generate_keys()
        rsa_crypto.save_keys()
        
        return jsonify({
            "success": True,
            "message": f"Đã tạo cặp khóa RSA {key_size} bits thành công!",
            "public_key": rsa_crypto.get_public_key_pem()
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Lỗi tạo khóa: {str(e)}"
        }), 400


@app.route("/import-public-key", methods=["POST"])
def import_public_key():
    """Import khóa công khai để mã hóa"""
    try:
        key_data = request.form.get("public_key")
        
        if not key_data:
            return jsonify({
                "success": False,
                "error": "Thiếu dữ liệu khóa công khai"
            }), 400
        
        # Parse JSON
        key_json = json.loads(key_data)
        
        # Set public key
        rsa_crypto.public_key = (key_json['e'], key_json['n'])
        rsa_crypto.key_size = key_json['key_size']
        
        # Lưu vào file (chỉ public key)
        with open(rsa_crypto.public_key_file, 'w') as f:
            json.dump(key_json, f, indent=2)
        
        return jsonify({
            "success": True,
            "message": "Đã import khóa công khai thành công!"
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Lỗi import khóa: {str(e)}"
        }), 400


@app.route("/import-private-key", methods=["POST"])
def import_private_key():
    """Import khóa bí mật để giải mã"""
    try:
        key_data = request.form.get("private_key")
        
        if not key_data:
            return jsonify({
                "success": False,
                "error": "Thiếu dữ liệu khóa bí mật"
            }), 400
        
        # Parse JSON
        key_json = json.loads(key_data)
        
        # Set private key
        rsa_crypto.private_key = (key_json['d'], key_json['n'])
        rsa_crypto.key_size = key_json['key_size']
        
        # Lưu vào file
        with open(rsa_crypto.private_key_file, 'w') as f:
            json.dump(key_json, f, indent=2)
        
        return jsonify({
            "success": True,
            "message": "Đã import khóa bí mật thành công!"
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Lỗi import khóa: {str(e)}"
        }), 400


@app.route("/encrypt", methods=["POST"])
def encrypt():
    """Mã hóa file - CHỈ CẦN KHÓA CÔNG KHAI"""
    try:
        # Kiểm tra có file khóa công khai không
        use_input_key = request.form.get("use_input_key") == "true"
        
        if use_input_key:
            # Nhập khóa công khai từ form
            public_key_data = request.form.get("public_key_input")
            if not public_key_data:
                return jsonify({
                    "success": False,
                    "error": "Thiếu khóa công khai"
                }), 400
            
            try:
                key_json = json.loads(public_key_data)
                rsa_crypto.public_key = (key_json['e'], key_json['n'])
                rsa_crypto.key_size = key_json['key_size']
            except:
                return jsonify({
                    "success": False,
                    "error": " Khóa công khai không đúng định dạng"
                }), 400
        else:
            # Dùng khóa đã lưu
            if not os.path.exists(rsa_crypto.public_key_file):
                return jsonify({
                    "success": False,
                    "error": "Chưa có khóa công khai. Vui lòng tạo khóa hoặc import!"
                }), 400
            
            with open(rsa_crypto.public_key_file, 'r') as f:
                key_json = json.load(f)
                rsa_crypto.public_key = (key_json['e'], key_json['n'])
                rsa_crypto.key_size = key_json['key_size']
        
        # Lấy file
        input_file = request.files.get("input_file")
        if not input_file:
            return jsonify({
                "success": False,
                "error": "Thiếu file đầu vào"
            }), 400
        
        # Tên file output
        output_filename = request.form.get("output_file")
        if not output_filename:
            original_name = secure_filename(input_file.filename)
            output_filename = f"{original_name}.enc"
        
        output_path = os.path.join(OUTPUT_DIR, output_filename)
        
        # Đọc và mã hóa
        data = read_file(input_file)
        encrypted_data = rsa_crypto.encrypt(data)
        
        # Ghi file
        write_file(output_path, encrypted_data)
        
        return jsonify({
            "success": True,
            "message": "Mã hóa thành công!",
            "output_file": output_path,
            "original_size": len(data),
            "encrypted_size": len(encrypted_data)
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Lỗi mã hóa: {str(e)}"
        }), 400


@app.route("/decrypt", methods=["POST"])
def decrypt():
    """Giải mã file - CẦN KHÓA BÍ MẬT"""
    try:
        # Kiểm tra nhập khóa bí mật
        use_input_key = request.form.get("use_input_key") == "true"
        
        if use_input_key:
            # Nhập khóa bí mật từ form
            private_key_data = request.form.get("private_key_input")
            if not private_key_data:
                return jsonify({
                    "success": False,
                    "error": "Thiếu khóa bí mật"
                }), 400
            
            try:
                key_json = json.loads(private_key_data)
                rsa_crypto.private_key = (key_json['d'], key_json['n'])
                rsa_crypto.key_size = key_json['key_size']
            except:
                return jsonify({
                    "success": False,
                    "error": "Khóa bí mật không đúng định dạng"
                }), 400
        else:
            # Dùng khóa đã lưu
            if not os.path.exists(rsa_crypto.private_key_file):
                return jsonify({
                    "success": False,
                    "error": "Chưa có khóa bí mật. Vui lòng tạo khóa hoặc import!"
                }), 400
            
            with open(rsa_crypto.private_key_file, 'r') as f:
                key_json = json.load(f)
                rsa_crypto.private_key = (key_json['d'], key_json['n'])
                rsa_crypto.key_size = key_json['key_size']
        
        # Lấy file
        input_file = request.files.get("input_file")
        if not input_file:
            return jsonify({
                "success": False,
                "error": "Thiếu file đầu vào"
            }), 400
        
        # Tên file output
        output_filename = request.form.get("output_file")
        if not output_filename:
            original_name = secure_filename(input_file.filename)
            if original_name.endswith('.enc'):
                output_filename = original_name[:-4] + '.dec'
            else:
                output_filename = f"{original_name}.dec"
        
        output_path = os.path.join(OUTPUT_DIR, output_filename)
        
        # Đọc và giải mã
        data = read_file(input_file)
        decrypted_data = rsa_crypto.decrypt(data)
        
        # Ghi file
        write_file(output_path, decrypted_data)
        
        return jsonify({
            "success": True,
            "message": "Giải mã thành công!",
            "output_file": output_path,
            "encrypted_size": len(data),
            "decrypted_size": len(decrypted_data)
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Lỗi giải mã: {str(e)}"
        }), 400


@app.route("/export-public-key", methods=["GET"])
def export_public_key():
    """Export khóa công khai dạng JSON"""
    try:
        if not os.path.exists(rsa_crypto.public_key_file):
            return jsonify({
                "success": False,
                "error": " Chưa có khóa công khai"
            }), 400
        
        with open(rsa_crypto.public_key_file, 'r') as f:
            public_key = json.load(f)
        
        return jsonify({
            "success": True,
            "public_key": json.dumps(public_key, indent=2)
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Lỗi: {str(e)}"
        }), 400


@app.route("/export-private-key", methods=["GET"])
def export_private_key():
    """Export khóa bí mật dạng JSON"""
    try:
        if not os.path.exists(rsa_crypto.private_key_file):
            return jsonify({
                "success": False,
                "error": "Chưa có khóa bí mật"
            }), 400
        
        with open(rsa_crypto.private_key_file, 'r') as f:
            private_key = json.load(f)
        
        return jsonify({
            "success": True,
            "private_key": json.dumps(private_key, indent=2)
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Lỗi: {str(e)}"
        }), 400


@app.route("/download-keys", methods=["GET"])
def download_keys():
    """Tải xuống cả 2 khóa"""
    try:
        if not rsa_crypto.load_keys():
            return jsonify({
                "success": False,
                "error": "Chưa có khóa"
            }), 400
        
        with open(rsa_crypto.public_key_file, 'r') as f:
            public_key = json.load(f)
        
        with open(rsa_crypto.private_key_file, 'r') as f:
            private_key = json.load(f)
        
        return jsonify({
            "success": True,
            "public_key": json.dumps(public_key, indent=2),
            "private_key": json.dumps(private_key, indent=2),
            "key_size": rsa_crypto.key_size
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Lỗi: {str(e)}"
        }), 400


if __name__ == "__main__":
    print("=" * 60)
    print("RSA-OAEP-SHA256 Encryption/Decryption Server")
    print("=" * 60)
    print("Truy cập: http://127.0.0.1:5001")
    print("=" * 60)
    app.run(debug=True, port=5001)