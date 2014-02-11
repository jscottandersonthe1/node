// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

// Flags: --stack-size=128

function _callstack() {
  try { capture.error } catch (e) {
    return e.stack;
  }
}
var replacementPreparer = function (error, trace) {
  return trace;
};
 
var callstack = function () {
  var capture;
  var oldPreparer = Error.prepareStackTrace;
  Error.prepareStackTrace = replacementPreparer;
  try { capture.error } catch (e) {
    capture = e.stack;
  }
  Error.prepareStackTrace = oldPreparer;
  return capture;
};

//process.exit(0);
var assert = require('assert');
var vm = require('vm');
var os = require('os');
var s;
var dp = 0;

if (true)
	s = 'console.error("inscript", dp++, os.freemem(), process.memoryUsage()); vm.runInNewContext(s, { vm: vm, s: s, console: console, callstack: callstack, dp: dp, os: os, process: process});';
else
	s = 'vm.runInNewContext(s, { vm: vm, s: s });';

assert.throws(function() {
  eval(s);
  console.error('returned from script');
}, /Maximum call stack/);
