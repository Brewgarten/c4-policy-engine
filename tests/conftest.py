import shutil
import tempfile

import pytest


@pytest.fixture
def temporaryDatabasePaths(request, monkeypatch):
    """
    Create a new temporary directory and set c4.system.db.BACKUP_PATH
    and c4.system.db.DATABASE_PATH to it
    """
    newpath = tempfile.mkdtemp(dir="/dev/shm")
#     newpath = tempfile.mkdtemp(dir="/tmp")
    monkeypatch.setattr("c4.system.db.BACKUP_PATH", newpath)
    monkeypatch.setattr("c4.system.db.DATABASE_PATH", newpath)

    def removeTemporaryDirectory():
        shutil.rmtree(newpath)
    request.addfinalizer(removeTemporaryDirectory)
    return newpath
