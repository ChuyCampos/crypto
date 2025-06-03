from Crypto.Util.Padding import pad, unpad

class FileManager:
    def __init__(self, filename):
        self.filename = filename

    def read_file(self, mode='rb'):
        try:
            with open(self.filename, mode) as file:
                content = file.read()
                if mode == 'r':
                    # Convert text content to bytes
                    content = content.encode('utf-8')
                return content
        except FileNotFoundError:
            return f"File '{self.filename}' not found."

    def write_file(self, content, mode='wb'):
        with open(self.filename, mode) as file:
            file.write(content)
        return f"Content written to '{self.filename}'."

    def append_to_file(self, content, mode='ab'):
        with open(self.filename, mode) as file:
            file.write(content)
        return f"Content appended to '{self.filename}'."

    def split_by_delimiter(self, content, delimiter):
        return content.split(delimiter)

    def join_by_delimiter(self, parts, delimiter):
        return delimiter.join(parts)
