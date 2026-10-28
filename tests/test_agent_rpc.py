# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Real pipe/process fixtures exercise RPC bounds without touching a server."""
import dataclasses
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest import mock
import uuid

from sovagrid_connect.agent_rpc import AgentRPC, RPCError, Stage, _CALL_SCRIPT, _REMOTE_COMMON, _STAGE_SCRIPT, _STAGE_CONTROL
from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.installer import COMPONENTS
from test_enrollment_protocol import CAS, RID, EID, SID, target
from test_installer import REQUIRED

CHILD = r'''
import hashlib,json,pathlib,subprocess,sys,time
config=json.loads(pathlib.Path(sys.argv[1]).read_text()); kind=sys.argv[2]; privileged=sys.argv[3]=='yes'
mode=config.get('mode','normal')
if mode=='sleep': time.sleep(60)
if mode=='flood': sys.stdout.buffer.write(b'x'*100000);sys.stdout.buffer.flush();time.sleep(60)
if mode=='orphan':
    subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],stdin=subprocess.DEVNULL,stdout=sys.stdout,stderr=subprocess.DEVNULL)
    print('{}',flush=True);sys.exit(0)
if mode=='raw': sys.stdout.write(config['raw']);sys.exit(config.get('exit',0))
if kind=='preflight':
    uid=0 if privileged else config.get('uid',0)
    value={'protocol':1,'ok':True,'euid':uid,'ubuntu_version':'26.04','python_version':'3.14.0','systemd_version':'257'}
elif kind=='stage':
    header=json.loads(sys.stdin.buffer.readline(4097));data=sys.stdin.buffer.read()
    assert len(data)==header['archive_size'] and hashlib.sha256(data).hexdigest()==header['stage']['sha256']
    value={'protocol':1,'ok':True,'stage':header['stage']}
elif kind=='control':
    body=json.load(sys.stdin)
    value=({'protocol':1,'ok':True,'stage':body['stage']} if body['action'] in ('recover','recover_cleanup')
           else {'protocol':1,'ok':True,'cleaned':True})
else:
    body=json.load(sys.stdin); pathlib.Path(sys.argv[1]).with_suffix('.received').write_text(json.dumps(body))
    value={'protocol':1,'ok':True,'cas':config['cas'],'target':None,'services':{'tunnel':False,'agent':False}}
    if config.get('reply') is not None:value=config['reply']
sys.stdout.write(json.dumps(value,separators=(',',':'))+'\n');sys.stdout.flush()
'''


def make_bundle(path):
    files=dict(REQUIRED)
    files['sovagrid-blueprint/deploy/remote_agent.py']=b'# SOVAGRID_REMOTE_AGENT_HELPER_V1\nprint("fixture")\n'
    manifest={'format':1,'components':{component:{'commit':'a'*40,'file_count':sum(name.startswith(component+'/') for name in files)} for component in COMPONENTS},
              'sha256':{name:hashlib.sha256(data).hexdigest() for name,data in files.items()}}
    files['sovagrid-bundle.json']=json.dumps(manifest).encode()
    with tarfile.open(path,'w:gz') as archive:
        for name,data in files.items():
            info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o644
            archive.addfile(info,io.BytesIO(data))
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RPCProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.fixture=self.root/'fixture.py';self.fixture.write_text(CHILD)
        self.config=self.root/'config.json'
        self.settings={'cas':CAS};self.update()
        self.calls=[];self.children=[];self.started=threading.Event()
        # These tests replace OpenSSH with real bounded child processes. They
        # never invoke a password dialog; a Windows source checkout has no
        # packaged Askpass executable. The packaged helper has its own smoke.
        prompt=mock.patch('sovagrid_connect.installer.helper_path',return_value=str(self.root/'unused-prompt'))
        prompt.start();self.addCleanup(prompt.stop)

    def tearDown(self):
        for child in self.children:
            if child.poll() is None:AgentRPC._kill(child);child.wait(timeout=5)
            job=getattr(child,'_sovagrid_rpc_job',None)
            if job:job.close()
        self.temp.cleanup()

    def update(self,**values):
        self.settings.update(values);self.config.write_text(json.dumps(self.settings))

    def spawn(self,argv,**kwargs):
        self.calls.append((argv,kwargs))
        command=argv[-1]
        script=shlex.split(command)[-1]
        kind=('stage' if 'header=sys.stdin.buffer.readline(4097)' in script else
              'control' if "operation=value['action']" in script else
              'rpc' if "choices={'target-preview'" in script else 'preflight')
        child=subprocess.Popen([sys.executable,str(self.fixture),str(self.config),kind,
            'yes' if command.startswith('sudo -n -- ') else 'no'],**kwargs)
        self.children.append(child);self.started.set()
        return child

    def rpc(self,**kwargs):
        return AgentRPC(ConnectionOptions('fixture.invalid',kwargs.pop('user','exampleuser')),role=kwargs.pop('role','target'),popen=self.spawn,**kwargs)

    def assert_reaped(self):
        self.assertTrue(all(child.poll() is not None and child.stdout.closed and child.stdin.closed for child in self.children))
        self.assertFalse([thread for thread in threading.enumerate() if thread.name in ('sovagrid-rpc-reader','sovagrid-rpc-writer')])

    def test_actual_euid_determines_sudo_prefix_and_fixed_json_channel(self):
        self.update(uid=1000)
        rpc=self.rpc(user='root')
        result=rpc.preflight()
        self.assertEqual(result['euid'],0)
        self.assertFalse(self.calls[0][0][-1].startswith('sudo'))
        self.assertTrue(self.calls[1][0][-1].startswith('sudo -n -- /usr/bin/python3 -I -c '))
        request={'protocol':1,'request_id':RID}
        result=rpc.call('target-status',request)
        self.assertIsNone(result['target'])
        self.assertEqual(json.loads(self.config.with_suffix('.received').read_text())['payload'],request)
        self.assertEqual(len(self.children),3)
        self.assertTrue(self.calls[-1][0][-1].startswith('sudo -n -- '))
        self.assertNotIn(RID,self.calls[-1][0][-1])
        self.assert_reaped()

    def test_invalid_requests_and_wrong_role_never_spawn_or_serialize_private_data(self):
        rpc=self.rpc()
        for action,payload in [('hub-preview',{'protocol':1}),('target-status',{'protocol':1,'request_id':RID,'agent_token':'private-request-canary'}),
                               (['target-status'],{})]:
            with self.assertRaises(RPCError):rpc.call(action,payload)
        self.assertEqual(self.calls,[])

    def test_output_flood_and_stalled_writer_are_bounded_and_reaped(self):
        self.update(mode='flood');rpc=self.rpc();rpc._prefix=''
        before=time.monotonic()
        with self.assertRaises(RPCError) as caught:rpc.call('target-status',{'protocol':1,'request_id':RID})
        self.assertEqual(caught.exception.code,'INVALID_REPLY')
        self.assertLess(time.monotonic()-before,3);self.assert_reaped()
        self.update(mode='sleep');before=time.monotonic()
        with self.assertRaises(RPCError) as caught:rpc._exchange('fixed-fixture',(b'x'*2097152,),0.15,prefix='')
        self.assertEqual(caught.exception.code,'TIMEOUT')
        self.assertLess(time.monotonic()-before,3);self.assert_reaped()

    def test_cancel_is_responsive_and_worker_reaps_real_child(self):
        self.update(mode='sleep');rpc=self.rpc();rpc._prefix='';errors=[]
        def run():
            try:rpc.call('target-status',{'protocol':1,'request_id':RID})
            except RPCError as error:errors.append(error)
        worker=threading.Thread(target=run);worker.start();self.assertTrue(self.started.wait(3))
        before=time.monotonic();rpc.cancel();self.assertLess(time.monotonic()-before,.1)
        worker.join(3);self.assertFalse(worker.is_alive())
        self.assertEqual(errors[0].code,'CANCELLED');self.assert_reaped()
        with self.assertRaises(RPCError):rpc.preflight()

    def test_orphaned_stdout_holder_does_not_outlive_deadline(self):
        self.update(mode='orphan');rpc=self.rpc();rpc._prefix='';rpc._timeouts['target-status']=.25
        before=time.monotonic()
        with self.assertRaises(RPCError) as caught:rpc.call('target-status',{'protocol':1,'request_id':RID})
        self.assertEqual(caught.exception.code,'TIMEOUT')
        self.assertLess(time.monotonic()-before,3);self.assert_reaped()

    def test_late_cancel_after_reply_does_not_deliver_success(self):
        rpc=self.rpc();rpc._prefix='';original=rpc._public
        def cancel_after_reply(*args):
            value=original(*args);rpc.cancel();return value
        with mock.patch.object(rpc,'_public',side_effect=cancel_after_reply):
            with self.assertRaises(RPCError) as caught:rpc.call('target-status',{'protocol':1,'request_id':RID})
        self.assertEqual(caught.exception.code,'CANCELLED');self.assert_reaped()

    def test_raw_remote_output_and_nonzero_success_are_never_accepted_or_echoed(self):
        rpc=self.rpc();rpc._prefix=''
        for raw,code in [('remote-output-canary',1),('{"protocol":1,"ok":false,"error":"remote-output-canary"}',1),
                         ('['*1500+']'*1500,0),
                         ('{"protocol":1,"ok":true,"cas":{}}',1)]:
            self.update(mode='raw',raw=raw,exit=code)
            with self.assertRaises(RPCError) as caught:rpc.call('target-status',{'protocol':1,'request_id':RID})
            self.assertNotIn('remote-output-canary',str(caught.exception))
        self.assert_reaped()

    def test_stage_checkpoint_precedes_ssh_and_recovery_needs_remote_proof(self):
        bundle=self.root/'bundle.tar.gz';digest=make_bundle(bundle);rpc=self.rpc();saved=[]
        def checkpoint(descriptor):
            self.assertEqual(self.calls,[]);saved.append(descriptor)
        stage=rpc.stage_target(bundle,digest,checkpoint=checkpoint)
        self.assertEqual(stage.descriptor(),saved[0])
        self.assertEqual(stage.sha256,digest)
        restored=self.rpc()
        recovered=restored.recover_stage(stage.descriptor())
        self.assertIsNot(recovered,stage)
        with self.assertRaises(RPCError):restored.cleanup_stage(stage)
        with self.assertRaises(RPCError):restored.cleanup_stage(dataclasses.replace(recovered,remote_dir='/etc'))
        restored.cleanup_stage(recovered)
        with self.assertRaises(RPCError):restored.cleanup_stage(recovered)
        rpc.cleanup_stage(stage);self.assert_reaped()

    def test_recovered_cleanup_capability_cannot_execute_a_helper(self):
        bundle=self.root/'bundle.tar.gz';digest=make_bundle(bundle);rpc=self.rpc()
        stage=rpc.stage_target(bundle,digest)
        restored=self.rpc();cleanup=restored.recover_stage(stage.descriptor(),for_cleanup=True)
        calls=len(self.calls)
        with self.assertRaises(RPCError) as caught:
            restored.call('target-status',{'protocol':1,'request_id':RID},stage=cleanup)
        self.assertEqual(caught.exception.code,'STAGE_INCOMPLETE')
        self.assertEqual(len(self.calls),calls)
        restored.cleanup_stage(cleanup);self.assert_reaped()

    def test_modified_bundle_and_arbitrary_stage_never_reach_ssh(self):
        bundle=self.root/'bundle.tar.gz';make_bundle(bundle);rpc=self.rpc()
        with self.assertRaises(RPCError):rpc.stage_target(bundle,'0'*64)
        with self.assertRaises(RPCError):rpc.cleanup_stage(Stage('/etc','a'*64,'b'*64,'c'*64,'a'*32))
        self.assertEqual(self.calls,[])


@unittest.skipUnless(os.name=='posix','Remote bootstrap verifies Linux/POSIX filesystem rules')
class PreexecutionTrustTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=Path.cwd())
        self.root=Path(self.temp.name);self.source=self.root/'source';self.source.mkdir()
        self.marker=self.root/'managed';self.marker.write_bytes(b'');self.marker.chmod(0o600)
        self.canary=self.root/'must-not-execute'
        code=('# SOVAGRID_REMOTE_AGENT_HELPER_V1\nfrom pathlib import Path\n'
              f'Path({str(self.canary)!r}).write_text("executed")\n').encode()
        self.files={component+'/fixture.txt':b'fixture' for component in COMPONENTS}
        self.files['sovagrid-blueprint/deploy/remote_agent.py']=code
        for name,data in self.files.items():
            path=self.source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);path.chmod(0o644)
        manifest={'format':1,'components':{component:{'commit':'a'*40,'file_count':sum(name.startswith(component+'/') for name in self.files)} for component in COMPONENTS},
                  'sha256':{name:hashlib.sha256(data).hexdigest() for name,data in self.files.items()}}
        (self.source/'sovagrid-bundle.json').write_text(json.dumps(manifest))
        self.lstat,self.fstat=os.lstat,os.fstat

    def tearDown(self):self.temp.cleanup()

    def root_stat(self,call,*args,**kwargs):
        values=list(call(*args,**kwargs));values[4]=0
        return os.stat_result(values)

    def execute(self,payload=None):
        # Only UID ownership is simulated so an unprivileged CI can exercise
        # actual nofollow/inode/mode/hash checks and the real pre-exec wrapper.
        script=_CALL_SCRIPT.replace("'/opt/sovagrid-src'",repr(str(self.source))).replace(
            "'/opt/sovagrid-src/'",repr(str(self.source)+'/')).replace(
            "'/var/lib/sovagrid/.managed-by-run-sh'",repr(str(self.marker)))
        request={'role':'hub','action':'hub-preview','stage':None,'payload':payload or {'protocol':1}}
        incoming=io.TextIOWrapper(io.BytesIO(json.dumps(request).encode()))
        output=io.BytesIO();outgoing=io.TextIOWrapper(output,write_through=True)
        with mock.patch.object(sys,'stdin',incoming),mock.patch.object(sys,'stdout',outgoing),mock.patch.object(sys,'argv',[]), \
             mock.patch.object(os,'geteuid',return_value=0), \
             mock.patch.object(os,'lstat',side_effect=lambda *a,**k:self.root_stat(self.lstat,*a,**k)), \
             mock.patch.object(os,'fstat',side_effect=lambda *a,**k:self.root_stat(self.fstat,*a,**k)):
            try:exec(compile(script,'trusted-bootstrap','exec'),{'__name__':'__main__'})
            except SystemExit:pass
        return output.getvalue()

    def test_verified_helper_runs_but_changed_bytes_never_execute_before_selfcheck(self):
        self.execute();self.assertTrue(self.canary.exists());self.canary.unlink()
        helper=self.source/'sovagrid-blueprint/deploy/remote_agent.py'
        helper.write_bytes(helper.read_bytes()+b'\n# changed after preview\n')
        value=json.loads(self.execute())
        self.assertEqual(value['error'],'SOURCE_CHANGED');self.assertFalse(self.canary.exists())

    def test_group_writable_or_linked_source_is_rejected_before_execution(self):
        helper=self.source/'sovagrid-blueprint/deploy/remote_agent.py'
        helper.chmod(0o666)
        self.assertEqual(json.loads(self.execute())['ok'],False);self.assertFalse(self.canary.exists())
        helper.chmod(0o644)
        renamed=helper.with_suffix('.saved');helper.rename(renamed);helper.symlink_to(renamed)
        self.assertEqual(json.loads(self.execute())['ok'],False);self.assertFalse(self.canary.exists())

    def test_changed_caller_source_cas_blocks_even_a_self_consistent_installed_helper(self):
        value=json.loads(self.execute({'protocol':1,'expected':CAS}))
        self.assertEqual(value['error'],'STALE_PREVIEW')
        self.assertFalse(self.canary.exists())


@unittest.skipUnless(os.name=='posix','Remote staging uses Ubuntu POSIX filesystem locks')
class InterruptedUploadTests(unittest.TestCase):
    def test_live_upload_lock_then_partial_recovery_is_cleanup_only(self):
        # Simulate root UID only; real files, pipes and flock execute unchanged
        # in an isolated fixed-prefix filesystem instead of the real /var/tmp.
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temporary:
            root=Path(temporary);public=root/'scratch';public.mkdir();public.chmod(0o1777)
            identifier=uuid.uuid4().hex
            descriptor={'remote_dir':str(public/('sovagrid-agent-enroll.'+identifier)),
                'stage_id':identifier,'sha256':'a'*64,'source_manifest_sha256':'b'*64,'helper_sha256':'c'*64}
            shim=r'''
_real_lstat=os.lstat;_real_fstat=os.fstat
def _root_stat(call,*args,**kwargs):
    value=list(call(*args,**kwargs));value[4]=0;return os.stat_result(value)
os.lstat=lambda *args,**kwargs:_root_stat(_real_lstat,*args,**kwargs)
os.fstat=lambda *args,**kwargs:_root_stat(_real_fstat,*args,**kwargs)
os.geteuid=lambda:0
'''
            def local_script(original):
                script=_REMOTE_COMMON+shim+original[len(_REMOTE_COMMON):]
                return script.replace('/var/tmp',str(public)).replace("inspect('/var',directory=True)",f"inspect({str(root)!r},directory=True)")
            producer=subprocess.Popen([sys.executable,'-I','-c',local_script(_STAGE_SCRIPT)],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True)
            header={'protocol':1,'stage':descriptor,'archive_size':100000}
            producer.stdin.write(json.dumps(header).encode()+b'\n'+b'x');producer.stdin.flush()
            stage=Path(descriptor['remote_dir']);marker=stage/'stage.json'
            deadline=time.monotonic()+3
            while not marker.exists() and producer.poll() is None and time.monotonic()<deadline:time.sleep(.01)
            self.assertTrue(marker.exists())
            lstat,fstat=os.lstat,os.fstat
            def root_stat(call,*args,**kwargs):
                values=list(call(*args,**kwargs));values[4]=0;return os.stat_result(values)
            def control(action):
                stream=io.BytesIO();output=io.TextIOWrapper(stream,write_through=True)
                incoming=io.TextIOWrapper(io.BytesIO(json.dumps({'stage':descriptor,'action':action}).encode()))
                namespace={'__name__':'__main__'}
                with mock.patch.object(sys,'stdin',incoming),mock.patch.object(sys,'stdout',output), \
                     mock.patch.object(os,'geteuid',return_value=0), \
                     mock.patch.object(os,'lstat',side_effect=lambda *a,**k:root_stat(lstat,*a,**k)), \
                     mock.patch.object(os,'fstat',side_effect=lambda *a,**k:root_stat(fstat,*a,**k)):
                    try:exec(compile(local_script(_STAGE_CONTROL),'trusted-stage-control','exec'),namespace)
                    except SystemExit:pass
                    finally:
                        lock=namespace.get('lock_fd')
                        if lock is not None:os.close(lock)
                return json.loads(stream.getvalue())
            try:
                self.assertEqual(control('recover_cleanup')['error'],'STAGE_BUSY')
                self.assertTrue(stage.exists())
            finally:
                producer.kill();producer.wait(timeout=3);producer.stdin.close();producer.stdout.close()
            self.assertEqual(control('recover')['error'],'STAGE_INCOMPLETE')
            recovered=control('recover_cleanup')
            self.assertEqual(recovered,{'protocol':1,'ok':True,'stage':descriptor})
            self.assertEqual(control('cleanup'),{'protocol':1,'ok':True,'cleaned':True})
            self.assertFalse(stage.exists())


if __name__=='__main__':unittest.main()
