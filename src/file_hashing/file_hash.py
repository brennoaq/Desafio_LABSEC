import hashlib

class FileHashing:
    def hash_file(self, file):
        readable_hash = hashlib.sha256(file).hexdigest()
        return readable_hash