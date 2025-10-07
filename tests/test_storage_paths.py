import sqlite3
import unittest

from app import storage


class GenerateDirectPathTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute(
            """
            CREATE TABLE files (
                id TEXT PRIMARY KEY,
                direct_path TEXT
            )
            """
        )

    def tearDown(self):
        self.conn.close()

    def test_removes_traversal_components(self):
        direct_path = storage._generate_unique_direct_path(
            self.conn, "../nested/../evil name.mp4", "abc"
        )
        self.assertNotIn("..", direct_path)
        self.assertNotIn("/", direct_path)
        self.assertTrue(direct_path.endswith(".mp4"))

    def test_reserved_names_receive_suffix(self):
        direct_path = storage._generate_unique_direct_path(self.conn, "hosting", "abc")
        self.assertEqual(direct_path, "hosting-1")

    def test_unique_suffix_added_when_conflict_exists(self):
        self.conn.execute(
            "INSERT INTO files (id, direct_path) VALUES (?, ?)",
            ("existing", "report.pdf"),
        )
        direct_path = storage._generate_unique_direct_path(
            self.conn, "report.pdf", "new"
        )
        self.assertEqual(direct_path, "report-1.pdf")


if __name__ == "__main__":
    unittest.main()
