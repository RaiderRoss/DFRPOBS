"""Storage backend that gives every stored file a random name on disk.

Replaces ``randomfilestorage.storage.RandomFileSystemStorage``. That package is
unmaintained and its ``get_available_name()`` predates Django 1.11, which added
the ``max_length`` argument -- under Django 4.2 every upload raises:

    TypeError: get_available_name() got an unexpected keyword argument 'max_length'

Behaviour is otherwise unchanged: the on-disk name is random, so it leaks
nothing about the evidence it holds. The original filename is kept separately
on PDE.filename.
"""

import posixpath
import os

from django.core.exceptions import SuspiciousFileOperation
from django.core.files.storage import FileSystemStorage
from django.utils.crypto import get_random_string

RANDOM_FILENAME_LENGTH = 60


class RandomFileSystemStorage(FileSystemStorage):

    def get_valid_name(self, name):
        _, file_ext = os.path.splitext(name)
        return "%s%s" % (get_random_string(RANDOM_FILENAME_LENGTH).lower(), file_ext)

    def get_available_name(self, name, max_length=None):
        dir_name, file_name = os.path.split(name)
        _, file_ext = os.path.splitext(file_name)

        # Trim the random component rather than the extension or the directory,
        # both of which callers depend on (see pde.views.serve_pde, which
        # matches on the "pde/files/" prefix).
        root_length = RANDOM_FILENAME_LENGTH
        if max_length is not None:
            overflow = len(posixpath.join(dir_name, "x" * root_length + file_ext)) - max_length
            if overflow > 0:
                root_length -= overflow
            if root_length < 1:
                raise SuspiciousFileOperation(
                    'Storage cannot find an available filename for "%s". '
                    "max_length=%s is too short for the directory and extension."
                    % (name, max_length)
                )

        while True:
            candidate = posixpath.join(
                dir_name, "%s%s" % (get_random_string(root_length).lower(), file_ext)
            )
            if not self.exists(candidate):
                return candidate
