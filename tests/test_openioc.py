import contextlib
import importlib
import io
import os
import sys
import types
import unittest
from unittest import mock


class FakeIndicatorNode(list):
    def __init__(self, operator):
        super().__init__()
        self.operator = operator


class FakeIOC:
    def __init__(self, description, author):
        self.description = description
        self.author = author
        self.top_level_indicator = FakeIndicatorNode("TOP")
        self.root = {"description": description, "author": author}


class FakeIocApi:
    IOC = FakeIOC

    @staticmethod
    def make_indicator_node(operator):
        return FakeIndicatorNode(operator)

    @staticmethod
    def make_indicatoritem_node(**kwargs):
        return kwargs

    @staticmethod
    def write_ioc(root, output_dir):
        return None


fake_ioc_writer = types.ModuleType("ioc_writer")
fake_ioc_writer.ioc_api = FakeIocApi()
sys.modules["ioc_writer"] = fake_ioc_writer

openioc = importlib.import_module("openioc")


def flatten_indicator_items(node):
    items = []
    for child in node:
        if isinstance(child, dict):
            items.append(child)
        else:
            items.extend(flatten_indicator_items(child))
    return items


class OpenIOCTests(unittest.TestCase):
    def test_create_metadata_skips_empty_pe_indicator_group(self):
        parent = FakeIndicatorNode("ROOT")
        metadata = {
            "malfilename": "sample.exe",
            "malfilesize": "",
            "malmd5": "",
            "malsha1": "",
            "malsha256": "",
            "malsha512": "",
            "malfiletype": "",
            "iocimports": [],
            "iocexports": [],
            "badpesections": [],
            "versioninfo": {},
        }

        openioc.createMetaData(None, parent, metadata)

        self.assertEqual(1, len(parent))
        self.assertEqual("AND", parent[0].operator)

    def test_create_dynamic_indicators_uses_correct_mutex_search_path(self):
        parent = FakeIndicatorNode("ROOT")
        dynamic = {
            "droppedfiles": [],
            "processes": [],
            "regkeys": [],
            "mutexes": ["Global\\MutexName"],
        }

        openioc.createDynamicIndicators(None, parent, dynamic)

        items = flatten_indicator_items(parent)
        self.assertIn(openioc.MUTEX_NAME_SEARCH_PATH, [item["search"] for item in items])

    def test_load_dotenv_if_available_uses_project_env_file(self):
        fake_dotenv = types.ModuleType("dotenv")
        fake_loader = mock.Mock(return_value=True)
        fake_dotenv.load_dotenv = fake_loader

        with mock.patch.dict(sys.modules, {"dotenv": fake_dotenv}):
            result = openioc.load_dotenv_if_available()

        self.assertTrue(result)
        fake_loader.assert_called_once_with(os.path.join(os.path.dirname(openioc.__file__), ".env"))

    def test_collect_bad_pe_sections_honors_suspicious_section_list(self):
        pe_sections = [
            {"name": ".text", "size_of_data": 100, "entropy": 1.0},
            {"name": ".UPX", "size_of_data": 200, "entropy": 7.5},
            {"name": ".weird", "size_of_data": 300, "entropy": 6.2},
        ]

        bad_sections = openioc.collect_bad_pe_sections(
            pe_sections,
            good_sections=[".text"],
            suspicious_sections=[".UPX"],
        )

        self.assertEqual([[".UPX", 200, "7.5"]], bad_sections)

    def test_fetch_cuckoo_report_passes_timeout_to_urlopen(self):
        fake_response = contextlib.nullcontext(io.StringIO('{"ok": true}'))

        with mock.patch.object(openioc.urllib.request, "urlopen", return_value=fake_response) as urlopen_mock:
            result = openioc.fetch_cuckoo_report(
                "https://example.test/tasks/report/1",
                {"Authorization": "Bearer token"},
                object(),
                12.5,
            )

        self.assertEqual({"ok": True}, result)
        self.assertEqual(12.5, urlopen_mock.call_args.kwargs["timeout"])

    def test_get_request_timeout_falls_back_on_invalid_value(self):
        with mock.patch.dict(os.environ, {"CUCKOO_API_TIMEOUT": "invalid"}):
            timeout = openioc.get_request_timeout()

        self.assertEqual(openioc.DEFAULT_REQUEST_TIMEOUT, timeout)


if __name__ == "__main__":
    unittest.main()
