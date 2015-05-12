import os


class LocalS3Key(object):
    def __init__(self, path, name):
        self.path = path
        self.name = name

    def set_contents_from_string(self, string):
        with open(self.path, 'w') as file_handle:
            file_handle.write(string)

    def get_contents_as_string(self):
        with open(self.path) as file_handle:
            return file_handle.read()

    def exists(self):
        return os.path.isfile(self.path)

    def set_metadata(self):
        pass


class LocalS3Bucket(object):
    def __init__(self, path):
        self.path = path

    def get_key(self, path):
        key = LocalS3Key(os.path.join(self.path, path), path)
        if key.exists():
            return key
        else:
            return None

    def new_key(self, path):
        return LocalS3Key(self, os.path.join(self.path, path))

    def list(self, prefix=None):
        path = self.path
        if prefix:
            path = os.path.join(path, prefix)
        for item in os.listdir(path):
            yield LocalS3Key(os.path.join(path, item), os.path.join(prefix, item))
