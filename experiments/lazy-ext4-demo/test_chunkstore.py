import json
import os
import tempfile
import unittest

from chunkstore import ChunkStore, InjectedCrash


class ChunkStoreTest(unittest.TestCase):
    size = 16 * 1024 * 1024
    chunk_size = 1024 * 1024

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.local = os.path.join(self.temporary.name, "local")
        self.remote = os.path.join(self.temporary.name, "remote")
        self.store = ChunkStore(self.local, self.remote, self.size, self.chunk_size)

    def tearDown(self):
        self.temporary.cleanup()

    def write_chunk(self, index, byte):
        path = self.store.cache_path(index)
        with open(path, "wb") as stream:
            stream.write(byte * self.chunk_size)
        with open(self.store.dirty_path(index), "wb"):
            pass

    def head_generation(self):
        with open(self.store.head_path, "r", encoding="utf-8") as stream:
            return json.load(stream)["generation"]

    def test_manifest_and_head_crash_boundaries_are_retryable(self):
        self.write_chunk(2, b"a")
        with self.assertRaises(InjectedCrash):
            self.store.commit("after-manifest")

        self.assertEqual(self.head_generation(), 0)
        cold = ChunkStore(
            os.path.join(self.temporary.name, "cold"),
            self.remote,
            self.size,
            self.chunk_size,
        )
        self.assertEqual(cold.manifest["generation"], 0)
        self.assertEqual(cold.manifest["chunks"], {})
        self.assertEqual(len(self.store.dirty_names()), 1)

        result = self.store.commit()
        self.assertEqual(result.generation, 1)
        self.assertEqual(len(self.store.dirty_names()), 0)

        self.write_chunk(2, b"b")
        with self.assertRaises(InjectedCrash):
            self.store.commit("after-head")

        self.assertEqual(self.head_generation(), 2)
        published = ChunkStore(
            os.path.join(self.temporary.name, "published"),
            self.remote,
            self.size,
            self.chunk_size,
        )
        self.assertEqual(published.manifest["generation"], 2)
        self.assertEqual(len(self.store.dirty_names()), 1)

        retry_store = ChunkStore(self.local, self.remote, self.size, self.chunk_size)
        retry = retry_store.commit()
        self.assertTrue(retry.recovered)
        self.assertEqual(retry.generation, 2)
        self.assertEqual(len(retry_store.dirty_names()), 0)
        self.assertEqual(retry_store.verify()["verified_objects"], 1)


if __name__ == "__main__":
    unittest.main()
