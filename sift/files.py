import os
import hashlib


FRAGMENT_SIZE = 1024


def split_file(path):
	with open(path, "rb") as f:
		while True:
			chunk = f.read(FRAGMENT_SIZE)
			if not chunk:
				break
			yield chunk


def compute_file_hash(path):
	h = hashlib.sha256()
	size = 0

	with open(path, "rb") as f:
		while True:
			chunk = f.read(4096)
			if not chunk:
				break
			h.update(chunk)
			size += len(chunk)

	return h.digest(), size
