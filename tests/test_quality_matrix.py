import ast
import importlib
import pathlib
import typing
import unittest


class QualityTests(unittest.TestCase):
    def test_python_matrix_covers_all_supported_minor_versions(self):
        workflow = pathlib.Path('.github/workflows/ci.yml').read_text(encoding='utf-8')
        self.assertIn("python: ['3.9', '3.10', '3.11', '3.12', '3.13']", workflow)
    def test_public_module_functions_have_resolvable_annotations(self):
        for path in pathlib.Path('apklab').glob('*.py'):
            if path.stem == '__main__': continue
            module = importlib.import_module('apklab.'+path.stem)
            tree = ast.parse(path.read_text(encoding='utf-8'))
            for node in tree.body:
                if not isinstance(node, ast.FunctionDef) or node.name.startswith('_'): continue
                with self.subTest(module=path.stem, function=node.name):
                    hints = typing.get_type_hints(getattr(module,node.name))
                    self.assertIn('return',hints)
                    for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
                        self.assertIn(arg.arg,hints)
