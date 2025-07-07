import ast
import hashlib
import re
import ipaddress
from pathlib import Path


def load_function(path, name):
    """Load a single function definition from a python file without executing
    the rest of the file."""
    with open(path, 'r') as f:
        source = f.read()
    module = ast.parse(source, filename=path)
    for node in module.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            func_module = ast.Module(body=[node], type_ignores=[])
            code = compile(func_module, filename=path, mode='exec')
            globals_dict = {
                'hashlib': hashlib,
                're': re,
                'ipaddress': ipaddress,
            }
            namespace = {}
            exec(code, globals_dict, namespace)
            return namespace[name]
    raise ValueError(f"Function {name} not found in {path}")


BASE_DIR = Path(__file__).resolve().parents[1]


def test_compute_md5(tmp_path):
    compute_md5 = load_function(BASE_DIR / 'get_dml.py', 'compute_md5')
    test_file = tmp_path / 'sample.txt'
    content = b'hello world'
    test_file.write_bytes(content)
    expected = hashlib.md5(content).hexdigest()
    assert compute_md5(str(test_file)) == expected


def test_valid_ip():
    valid_ip = load_function(BASE_DIR / 'scramble_dml.py', 'valid_ip')
    # function treats octet value 0 as invalid, so use 1-255 range
    assert valid_ip('192.168.1.1') is True
    assert valid_ip('256.1.1.1') is False
    assert valid_ip('bad.ip') is False


def test_valid_ipv6():
    valid_ipv6 = load_function(BASE_DIR / 'scramble_dml.py', 'valid_ipv6')
    assert valid_ipv6('::1') == '::1'
    assert valid_ipv6('gibberish') is None


def test_swap():
    swap = load_function(BASE_DIR / 'scramble_dml.py', 'swap')
    line = 'addr=192.168.0.5'
    result = swap(line, r'(192\.168\.0\.5)', [{'192.168.0.5': '10.0.0.1'}])
    assert '10.0.0.1' in result


def test_fuzzySwap():
    fuzzySwap = load_function(BASE_DIR / 'scramble_dml.py', 'fuzzySwap')
    line = 'Hostname: MyHOST'
    result = fuzzySwap(line, [{'myhost': 'other'}])
    assert result == 'Hostname: other'


def test_substitutes():
    substitutes = load_function(BASE_DIR / 'scramble_dml.py', 'substitutes')
    swaps, uniques = substitutes('fake', 'orig', [], [])
    assert swaps == [{'orig': 'fake'}]
    assert uniques == ['orig']
    swaps2, uniques2 = substitutes('fake', 'orig', uniques, swaps)
    assert swaps2 == swaps
    assert uniques2 == uniques


def test_findMatch():
    findMatch = load_function(BASE_DIR / 'scramble_dml.py', 'findMatch')
    line = 'attribute name="hostname">testhost<'
    matches = findMatch(line, r'attribute\sname=\"hostname\">(\S+)<')
    assert matches == ('testhost',)
