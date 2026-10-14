import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from kev_diff import compare, validate, load_catalog, InvalidCatalog
from markdown_report import render_markdown, block
ROOT=Path(__file__).resolve().parents[1]

class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.a=json.loads((ROOT/'examples/before.json').read_text())
        self.b=json.loads((ROOT/'examples/after.json').read_text())
    def reject(self, change):
        change(self.a)
        with self.assertRaises(InvalidCatalog): validate(self.a)
    def test_example(self):
        r=compare(self.a,self.b)
        self.assertEqual(r['summary'],dict(added=1,changed=1,removed=1))
        self.assertEqual([f['field'] for f in r['changes'][0]['fields']],['dueDate','extension'])
    def test_unchanged(self): self.assertEqual(compare(self.a,self.a)['changes'],[])
    def test_key_order(self):
        b=copy.deepcopy(self.a);b['vulnerabilities'][0]=dict(reversed(list(b['vulnerabilities'][0].items())))
        self.assertEqual(compare(self.a,b)['changes'],[])
    def test_duplicate_cve(self): self.reject(lambda a:a['vulnerabilities'].__setitem__(1,a['vulnerabilities'][0]))
    def test_count(self): self.reject(lambda a:a.__setitem__('count',3))
    def test_bool_count(self): self.reject(lambda a:a.__setitem__('count',True))
    def test_invalid_date(self): self.reject(lambda a:a['vulnerabilities'][0].__setitem__('dueDate','2099-02-30'))
    def test_missing_required(self): self.reject(lambda a:a['vulnerabilities'][0].pop('requiredAction'))
    def test_invalid_cve(self): self.reject(lambda a:a['vulnerabilities'][0].__setitem__('cveID','CVE-2099-1'))
    def test_naive_release(self): self.reject(lambda a:a.__setitem__('dateReleased','2099-01-01T12:00:00'))
    def test_four_digit_fraction(self):
        self.a['dateReleased']='2026-10-13T19:10:43.6568Z';validate(self.a)
    def test_fraction_order(self):
        self.a['dateReleased']='2026-10-13T19:10:43.123456789Z'
        self.b['dateReleased']='2026-10-13T19:10:43.123456788Z'
        with self.assertRaises(InvalidCatalog):compare(self.a,self.b)
    def test_timezone_equivalence(self):
        self.a['dateReleased']='2026-10-13T12:10:43.6568-07:00'
        self.b['dateReleased']='2026-10-13T19:10:43.6568Z';compare(self.a,self.b)
    def test_reversed(self):
        with self.assertRaises(InvalidCatalog): compare(self.b,self.a)
    def test_filter_exact(self): self.assertEqual(compare(self.a,self.b,vendors=['Example'])['changes'],[])
    def test_filter_case(self): self.assertEqual(compare(self.a,self.b,vendors=['example vendor'])['summary']['added'],1)
    def test_vendor_rename_retained(self):
        b=copy.deepcopy(self.a);b['vulnerabilities'][0]['vendorProject']='Different Vendor'
        self.assertEqual(compare(self.a,b,vendors=['Example Vendor'])['summary']['changed'],1)
    def test_removed_is_absent(self):
        r=compare(self.a,self.b);self.assertIsNone(next(c for c in r['changes'] if c['kind']=='removed')['after'])
    def test_optional_null_vs_absent(self):
        b=copy.deepcopy(self.a);b['vulnerabilities'][0]['newField']=None
        f=compare(self.a,b)['changes'][0]['fields'][0]
        self.assertFalse(f['beforePresent']);self.assertTrue(f['afterPresent'])
    def test_new_metadata(self):
        b=copy.deepcopy(self.a);b['newMeta']={'x':1}
        self.assertEqual(compare(self.a,b)['catalogMetadataChanges'][0]['field'],'newMeta')
    def test_array_order_significant(self):
        self.a['vulnerabilities'][0]['cwes']=['CWE-1','CWE-2'];b=copy.deepcopy(self.a)
        b['vulnerabilities'][0]['cwes'].reverse()
        self.assertEqual(compare(self.a,b)['summary']['changed'],1)
    def test_optional_unknown_flag(self):
        self.a['vulnerabilities'][0]['knownRansomwareCampaignUse']='Future Value';validate(self.a)
    def test_cwe_type(self): self.reject(lambda a:a['vulnerabilities'][0].__setitem__('cwes',[1]))
    def load_bytes(self,data):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'input.json';p.write_bytes(data);return load_catalog(p)
    def test_duplicate_json_key(self):
        with self.assertRaises(InvalidCatalog):self.load_bytes(b'{"count":1,"count":2}')
    def test_invalid_utf8(self):
        with self.assertRaises(UnicodeError):self.load_bytes(b'\xff')
    def test_nonfinite_json(self):
        with self.assertRaises(InvalidCatalog):self.load_bytes(b'{"x":NaN}')
    def test_high_precision_number_rejected(self):
        data=json.dumps(self.a).replace('"extension": {"label": "before"}', '"extension": 0.100000000000000000000000001')
        with self.assertRaises(InvalidCatalog):self.load_bytes(data.encode())
    def test_exponent_rejected(self):
        with self.assertRaises(InvalidCatalog):self.load_bytes(b'{"x":1e30}')
    def test_programmatic_float_rejected(self):
        self.a['vulnerabilities'][0]['extension']=0.1
        with self.assertRaises(InvalidCatalog):compare(self.a,self.b)
    def test_big_integer_preserved(self):
        self.a['vulnerabilities'][0]['extension']=100000000000000000000000000000001
        b=copy.deepcopy(self.a);b['vulnerabilities'][0]['extension']+=1
        self.assertEqual(compare(self.a,b)['summary']['changed'],1)
    def test_long_timestamp_fraction(self):
        self.a['dateReleased']='2026-10-13T19:10:43.1234567890123456789012345678901Z'
        self.b['dateReleased']='2026-10-13T19:10:43.1234567890123456789012345678900Z'
        with self.assertRaises(InvalidCatalog):compare(self.a,self.b)
    def test_hash(self): self.assertEqual(len(self.load_bytes(json.dumps(self.a).encode())[1]),64)
    def test_utf8_bom(self): self.assertEqual(self.load_bytes(b'\xef\xbb\xbf'+json.dumps(self.a).encode())[0],self.a)
    def test_no_mutation(self):
        before=copy.deepcopy(self.a);compare(self.a,self.b);self.assertEqual(self.a,before)
    def test_cli(self):
        r=subprocess.run([sys.executable,str(ROOT/'kev_diff.py'),str(ROOT/'examples/before.json'),str(ROOT/'examples/after.json')],capture_output=True)
        self.assertEqual(r.returncode,0);self.assertEqual(json.loads(r.stdout)['summary']['changed'],1)
    def test_cli_error_no_stdout(self):
        r=subprocess.run([sys.executable,str(ROOT/'kev_diff.py'),'/missing','/missing'],capture_output=True)
        self.assertEqual(r.returncode,2);self.assertEqual(r.stdout,b'');self.assertIn(b'Input error',r.stderr)
    def test_markdown_counts(self):
        text=render_markdown(compare(self.a,self.b))
        self.assertIn('Added: 1 | Changed: 1 | Removed: 1',text)
        self.assertIn('CVE-2099-0001 (changed)',text)
    def test_markdown_empty(self):
        self.assertIn('No record changes matched',render_markdown(compare(self.a,self.a)))
    def test_markdown_fence_injection(self):
        value='```\n<img src=x onerror=alert(1)>\n``````'
        text=block(value)
        self.assertTrue(text.startswith('```````json\n'))
        self.assertTrue(text.endswith('```````\n'))
        self.assertEqual(json.loads(text.split('\n',1)[1].rsplit('\n',2)[0]),value)
    def test_markdown_control_characters(self):
        text=block('control\x1b[31m\rtext')
        self.assertNotIn('\x1b',text);self.assertIn('\\u001b',text)
    def test_markdown_full_records(self):
        self.b['vulnerabilities'][0]['notes']='[link](https://example.invalid) <script>alert(1)</script>'
        r=compare(self.a,self.b);text=render_markdown(r)
        self.assertIn(json.dumps(r['changes'][0]['after'],sort_keys=True,indent=2).splitlines()[1].strip(),text)
        self.assertEqual(text.count('### CVE-'),3)
    def test_markdown_cli(self):
        r=subprocess.run([sys.executable,str(ROOT/'kev_diff.py'),str(ROOT/'examples/before.json'),str(ROOT/'examples/after.json'),'--format','markdown'],capture_output=True)
        self.assertEqual(r.returncode,0);self.assertTrue(r.stdout.startswith(b'# Apex KEV change review'))
    def test_cli_blank_filter(self):
        r=subprocess.run([sys.executable,str(ROOT/'kev_diff.py'),str(ROOT/'examples/before.json'),str(ROOT/'examples/after.json'),'--vendor',''],capture_output=True)
        self.assertEqual(r.returncode,2);self.assertEqual(r.stdout,b'')

if __name__=='__main__': unittest.main()
