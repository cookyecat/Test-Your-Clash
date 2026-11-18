import ast,pathlib,time,math,unittest,urllib.parse
source=ast.parse(pathlib.Path('helper/collector.py').read_text())
function=next(n for n in source.body if isinstance(n,ast.FunctionDef) and n.name=='https_sample')
class Classification(unittest.TestCase):
 def sample(self,result):
  env={'time':time,'math':math,'urllib':urllib,'STABILITY_TARGETS':{'test':{'url':'https://example.test/','expected':'204'}},'mihomo':lambda *a:result}
  exec(compile(ast.Module(body=[function],type_ignores=[]),'collector-classification','exec'),env)
  return env['https_sample']('node / 测试','test',5000)
 def test_transport_and_internal_errors(self):
  for response in [{'_error':'offline'},{'_status':401},{'_status':500},{}]:self.assertEqual(self.sample(response)['state'],'error')
 def test_measured_failure_and_success(self):
  self.assertEqual(self.sample({'_status':504})['state'],'fail')
  self.assertEqual(self.sample({'delay':42})['ms'],42)
if __name__=='__main__':unittest.main()
