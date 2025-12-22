import os
import io
from flask import Flask, render_template, request, send_file
from utils import read_file, write_file
from crypto import aes, des, tripledes, rsa

app = Flask(__name__)

# =============================
# CẤU HÌNH THƯ MỤC OUTPUT
# =============================
OUTPUT_DIR = "outputs"
os.makedirs(OUTPUT_DIR, exist_ok=True)


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_template("index.html")

    # =============================
    # LẤY DỮ LIỆU TỪ FORM
    # =============================
    input_file = request.files.get("input_file")
    output_filename = request.form.get("output_file")
    algorithm = request.form.get("algorithm")
    action = request.form.get("action")
    key = request.form.get("key")

    if not input_file or not output_filename:
        return render_template(
            "index.html",
            error="❌ Thiếu file đầu vào hoặc tên file xuất"
        )

    # =============================
    # ĐỌC FILE
    # =============================
    try:
        data = read_file(input_file)
    except Exception as e:
        return render_template(
            "index.html",
            error=f"❌ Lỗi đọc file: {str(e)}"
        )

    # =============================
    # XỬ LÝ THEO THUẬT TOÁN
    # =============================
    try:
        if algorithm == "aes":
            if action == "encrypt":
                result = aes.encrypt(data, key)
            elif action == "decrypt":
                result = aes.decrypt(data, key)
            else:
                raise ValueError("Action không hợp lệ")

        elif algorithm == "des":
            result = des.encrypt(data, key) if action == "encrypt" else des.decrypt(data, key)

        elif algorithm == "tripledes":
            result = tripledes.encrypt(data, key) if action == "encrypt" else tripledes.decrypt(data, key)

        elif algorithm == "rsa":
            result = rsa.encrypt(data) if action == "encrypt" else rsa.decrypt(data)

        else:
            raise ValueError("Thuật toán chưa được hỗ trợ")

    except Exception as e:
        return render_template(
            "index.html",
            error=f"❌ Lỗi xử lý: {str(e)}"
        )

    # =============================
    # GHI FILE VÀ TRẢ VỀ TRÌNH DUYỆT
    # =============================
    try:
        # Lưu file trong folder outputs
        output_path = os.path.join(OUTPUT_DIR, output_filename)
        write_file(output_path, result)

        # Trả file trực tiếp về browser
        return send_file(
            io.BytesIO(result),
            as_attachment=True,
            download_name=output_filename,
            mimetype="application/octet-stream"
        )

    except Exception as e:
        return render_template(
            "index.html",
            error=f"❌ Lỗi ghi hoặc trả file: {str(e)}"
        )


if __name__ == "__main__":
    print("📂 Thư mục làm việc:", os.getcwd())
    print("📂 File sẽ được lưu tại:", os.path.abspath(OUTPUT_DIR))
    app.run(debug=True)
