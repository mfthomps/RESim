'''
 * This software was created by United States Government employees
 * and may not be copyrighted.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
'''
import json
'''
Long bit arrays
'''
def setbit(a, n): return a | (1<<n)
def append(a, v): return (a<<1) | v
def getbit(a, n): 
   value = a & (1<<n)
   if value != 0:
       return 1
   else:
       return 0

def dump(a):
    return json.dumps(a)

def load(string):
    return json.loads(string)

def do_or(a, b):
    return a | b

def do_and(a, b):
    return a & b

def do_not(a):
    return ~a 

def countbits(a): return bin(a).count('1')
def activebits(a):
    s=bin(a)[2:][::-1]
    return [i for i, d in enumerate(s) if d== '1']

'''
arr = 0
arr = setbit(arr, 100)
print('10 is %d  100 is %d' % (getbit(arr,10), getbit(arr,100)))
print('101 is %d  1 is %d' % (getbit(arr,101), getbit(arr,1)))
s = dump(arr)
a = load(s)
print('10 is %d  100 is %d' % (getbit(a,10), getbit(a,100)))
'''
