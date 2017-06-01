import logging
import os
import shlex
import shutil
import subprocess
import tempfile
import time

import pytest

from c4.backends.sharedSQLite import SharedSqliteDBBackend
from c4.system.backend import Backend, BackendInfo


logging.basicConfig(format='%(asctime)s [%(levelname)s] <%(processName)s> [%(name)s(%(filename)s:%(lineno)d)] - %(message)s', level=logging.INFO)
log = logging.getLogger(__name__)

# TODO: enable SharedSqliteDBBackend
# IMPORTANT: we currently focus using the etcd backend exclusively and as such only parameterize for that
@pytest.fixture(params=["EtcdBackend"])
def backend(request):
    """
    Parameterized testing backend
    """
    if request.param == "EtcdBackend":

        try:
            from c4.backends.etcdBackend import EtcdBackend
        except ImportError as importError:
            pytest.skip("could not find etcd Python bindings: " + str(importError))

        if not os.path.exists("/opt/etcd/etcd"):
            pytest.skip("could not find etcd installation in '/opt/etcd/'")

        newpath = tempfile.mkdtemp(dir="/tmp")

        # set up etcd process
        etcdCommand = shlex.split("/opt/etcd/etcd --data-dir {dataDir}".format(dataDir=newpath))
        etcdProcess = subprocess.Popen(etcdCommand, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        def finalizeBackend():
            # stop etcd process
            etcdProcess.terminate()
            etcdProcess.wait()

            # remove data directory
            shutil.rmtree(newpath)

        # make sure etcd process is started
        clusterHealthCommand = shlex.split("/opt/etcd/etcdctl cluster-health")
        end = time.time() + 5
        while time.time() < end:
            if subprocess.call(clusterHealthCommand, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
                break
            time.sleep(0.1)
        else:
            finalizeBackend()
            raise RuntimeError("Could not set up etcd process")

        infoProperties = {
            "client.host": "localhost",
            "client.port": 2379,
        }
        info = BackendInfo("c4.backends.etcdBackend.EtcdBackend", properties=infoProperties)
        testBackendImplementation = EtcdBackend(info)

    elif request.param == "SharedSqliteDBBackend":

        newpath = tempfile.mkdtemp(dir="/dev/shm")
        infoProperties = {
            "path.database": newpath,
            "path.backup": newpath
        }
        info = BackendInfo("c4.backends.sharedSQLite.SharedSqliteDBBackend", properties=infoProperties)
        testBackendImplementation = SharedSqliteDBBackend(info)

        def finalizeBackend():
            # remove data directory
            shutil.rmtree(newpath)

    # set backend
    testBackend = Backend(implementation=testBackendImplementation)

    request.addfinalizer(finalizeBackend)
    return testBackend

@pytest.fixture
def temporaryIPCPath(request, monkeypatch):
    """
    Create a new temporary directory and set c4.messaging.zeromqMessaging.DEFAULT_IPC_PATH to it
    """
    newpath = tempfile.mkdtemp(dir="/dev/shm")
#     newpath = tempfile.mkdtemp(dir="/tmp")
    monkeypatch.setattr("c4.messaging.zeromqMessaging.DEFAULT_IPC_PATH", newpath)

    def removeTemporaryDirectory():
        shutil.rmtree(newpath)
    request.addfinalizer(removeTemporaryDirectory)
    return newpath
