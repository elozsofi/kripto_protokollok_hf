import os
import base64


class CommandHandler:
    def __init__(self, root_dir: str):
        self.root = os.path.abspath(root_dir)
        self.cwd = self.root

    def _safe_path(self, path):
        new_path = os.path.abspath(os.path.join(self.cwd, path))
        if not new_path.startswith(self.root):
            raise Exception("Access denied")
        return new_path

    def pwd(self):
        rel = os.path.relpath(self.cwd, self.root)
        return rel if rel != "." else "/"

    def lst(self):
        items = os.listdir(self.cwd)
        joined = "\n".join(items)
        return base64.b64encode(joined.encode()).decode()

    def chd(self, dirname):
        new_path = self._safe_path(dirname)
        if not os.path.isdir(new_path):
            raise Exception("Directory does not exist")
        self.cwd = new_path

    def mkd(self, dirname):
        new_path = self._safe_path(dirname)
        if os.path.exists(new_path):
            raise Exception("Already exists")
        os.mkdir(new_path)

    def delete(self, name):
        path = self._safe_path(name)
        if os.path.isdir(path):
            if os.listdir(path):
                raise Exception("Directory not empty")
            os.rmdir(path)
        else:
            os.remove(path)