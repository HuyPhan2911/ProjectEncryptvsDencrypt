# utils.py

BLOCK_SIZE = 16


def read_file(file_storage):
    return file_storage.read()


def write_file(filename, data):
    with open(filename, "wb") as f:
        f.write(data)


def pkcs7_pad(data):
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]
