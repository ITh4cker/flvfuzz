# Multithreaded FLV fuzzer 0.1 by Wojciech Pawlikowski (C) 2011
#
# Todo:
#	+ write smart fuzzing for different codecs and fuzz only stuff within the frame (i.e. AAC)
#	+ more deterministic approach
#	+ multiple samples support
#	+ simple code coverage which tells the minimal set of samples
#	+ better multithreading
#	+ configuration via commandline
#
# Requirements:
#	+ python 2.7 (because pydbg won't work with later versions)
#	+ flvlib
#	+ haxe (in your PATH)
#	+ pydbg
#	+ flashplayer.exe in current directory
#	+ good flv sample called 'sample.flv'
#
# Usage:
#	+ C:\WORK\flvfuzz.py

from flvlib.constants import TAG_TYPE_AUDIO, TAG_TYPE_VIDEO, TAG_TYPE_SCRIPT, FRAME_TYPE_KEYFRAME
from flvlib.astypes import MalformedFLV, FLVObject
from flvlib.tags import FLV, EndOfFile, AudioTag, VideoTag, ScriptTag
from pydbg import *
from pydbg.defines import *
import os, sys, stat, random, binascii, time, threading

# CHANGE STUFF HERE
 
fuzz_audiotag = False									# fuzz audio ?
fuzz_videotag = True									# fuzz video ?
fuzz_keyframe = False									# fuzz keyframe ?
fuzz_vector = 20									# bigger = lower number of fuzzed frames
fuzz_factor = 10									# how much data should be fuzzed
fuzz_timeout = 30									# timeout in seconds
fuzz_threads = 20									# number of concurrent threads

# STOP CHANGES HERE

class FuzzGenerator:
	def __init__(self, buf):
		self.values = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
		self.buf = buf
	
	def _fuzz_for_real(self, buf):
		test = []
	
		for i in xrange(0, len(buf)):
			test += binascii.b2a_hex(buf[i])
				
		for i in xrange(0, fuzz_factor):
			test[random.randint(0, len(buf))] = random.choice(self.values)
	
		tmp = ''
		for i in test:
			tmp += i
	
		buf = binascii.a2b_hex(tmp)
		
		return buf	
	
	def fuzz(self, offset, size):
		frame_content = self.buf[offset:offset + size]
		fuzzed_buf = self._fuzz_for_real(frame_content)
	
		tmp1 = self.buf[:offset]
		tmp2 = self.buf[offset + size:]
		
		self.buf = tmp1 + fuzzed_buf + tmp2
		
		return self.buf
		
class CheckAudioTag(AudioTag):
	def parse(self):
		parent = self.parent_flv
		AudioTag.parse(self)
		
		x = random.randint(0, fuzz_vector)
		
		if fuzz_audiotag and (x == fuzz_vector):
			f = FuzzGenerator(parent.buffer)
			parent.buffer = f.fuzz(self.offset, self.size)
		
class CheckVideoTag(VideoTag):
	def parse(self):
		parent = self.parent_flv
		VideoTag.parse(self)

		if self.frame_type == FRAME_TYPE_KEYFRAME and not fuzz_keyframe:
			return

		x = random.randint(0, fuzz_vector)
		
		if fuzz_videotag and (x == fuzz_vector):
			f = FuzzGenerator(parent.buffer)
			parent.buffer = f.fuzz(self.offset, self.size)
			
class CheckScriptTag(ScriptTag):
	def parse(self):
		parent = self.parent_flv
		ScriptTag.parse(self)
		
tag_to_class = {
	TAG_TYPE_AUDIO:	CheckAudioTag,
	TAG_TYPE_VIDEO: CheckVideoTag,
	TAG_TYPE_SCRIPT: CheckScriptTag
}

class MyFLV(FLV):
	def __init__(self, f):
		FLV.__init__(self, f)
		
		try:
			st_size = os.stat(self.f.name)[6]
		except:
			print '[-] Could not stat() original file'
			return
		
		self.buffer = self.f.read(st_size)
		self.f.seek(0L)
		
	def tag_type_to_class(self, tag_type):
		try:
			return tag_to_class[tag_type]
		except KeyError:
			raise MalformedFLV("Invalid tag type: %d", tag_type)

class FuzzThread(threading.Thread):
	def __init__(self, test_id):
		threading.Thread.__init__(self)
		
		self.keep_file = False
		self.test_id = test_id
		self.current_testcase = 'sample_%d.flv' % test_id
		self.sample_deleted = False
		self.lock = threading.Lock()
		self.event = threading.Event()
		
		self.dbg = pydbg()
		self.dbg.pydbg_log = self.log
		self.dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, self.handle_av)
		self.dbg.set_callback(USER_CALLBACK_DEBUG_EVENT, self.handle_timeout)
		
	def log(self, msg):
		print '[Execute->pydbg]: %s' % msg
		
	def handle_av(self, dbg):
		crash_bin = utils.crash_binning.crash_binning()
		crash_bin.record_crash(dbg)
		print '[*] Test sample: %s generated A/V' % self.current_testcase
		print crash_bin.crash_synopsis()
		
		self.keep_file = True
		
		dbg.terminate_process()
		return DBG_EXCEPTION_NOT_HANDLED

	def handle_timeout(self, dbg):
		if time.time() - dbg.start_time > fuzz_timeout:
			dbg.terminate_process()
			
			if not self.keep_file:
				os.system('del player_%d.swf %s 2> nul' % (self.test_id, self.current_testcase))
			
			self.event.set()
			
			return DBG_CONTINUE

	def create_testcase(self):
		try:
			f = open('sample.flv', 'rb')
		except IOError, (errno, strerror):
			print '[-] Could not open sample file: %s' % strerror
			return
		
		flv = MyFLV(f)
		tag_iterator = flv.iter_tags()
		
		try:
			while True:
				tag = tag_iterator.next()
		except MalformedFLV, e:
			msg = e[0] % e[1:]
			print '[-] Not a valid FLV file: %s' % msg
			return
		except EndOfFile:
			print '[-] Unexpected end-of-file'
			return
		except StopIteration:
			pass
		
		f.close()
		
		try:
			f = open(self.current_testcase, 'wb')
		except IOError, (errno, strerror):
			print '[-] Could not open destination file: %s' % strerror
			return

		f.write(flv.buffer)
		f.close()
		
	def prepare_swf(self):
		try:
			self.lock.acquire()
			
			fname = 'compile_%d.hxml'% self.test_id
			try:
				f = open(fname, 'w')
			except IOError, (errno, strerror):
				print '[-] Could not create compile.hxml file: %s' % strerror
				return
			
			f.write('''
				-swf player_%d.swf
				-main FLVPlayer_%d
			''' % (self.test_id, self.test_id))
			
			f.close()
			
			fname = 'FLVPlayer_%d.hx' % self.test_id
			try:
				f = open(fname, 'w')
			except IOError, (errno, strerror):
				print '[-] Could not create FLVPlayer_id.hx: %s' % strerror
				return
			
			f.write('''
				import flash.media.Video;
				import flash.net.NetConnection;
				import flash.net.NetStream;
				
				class FLVPlayer_%d {
					private var mc : flash.display.MovieClip;
					private var myVideo : Video;
					
					public function new() {
						mc = flash.Lib.current;
						myVideo = new Video();
						var myNetConnect : NetConnection = new NetConnection();
						myNetConnect.connect(null);
						var myNetStream : NetStream = new NetStream(myNetConnect);
						myVideo.attachNetStream(myNetStream);
						mc.addChild(myVideo);
						trace(myVideo);
						myNetStream.play('%s');
					}
					
					public static function main() {
						new FLVPlayer_%d();
					}
				}
			''' % (self.test_id, self.current_testcase, self.test_id))
			f.close()
			
			os.system('haxe compile_%d.hxml'% self.test_id)
			os.unlink('FLVPlayer_%d.hx' % self.test_id)
			os.unlink('compile_%d.hxml' % self.test_id)
			
			self.lock.release()	
		except Exception, e:
			print '[-] Unknown error: %s' % e[0]
			return
		
	def run(self):
		self.create_testcase()
		self.prepare_swf()
		
		player_no = 'player_%d.swf' % self.test_id
		
		self.dbg.load('flashplayer.exe', command_line=player_no)
		self.dbg.start_time = time.time()
		self.dbg.run()
		
		self.event.wait()
	
def main():
	test_id = 0
	threads = []
	
	while True:
		for i in range(fuzz_threads):
			tid = FuzzThread(test_id)
			tid.start()
			threads.append(tid)
			
			test_id = test_id + 1
		
		for t in threads:
			t.join()
	
if __name__ == '__main__':
	main()
