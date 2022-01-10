import subprocess
import os 

def build_dummy():
    op = subprocess.Popen(['gcc', '-O0', '-lm', '-fno-stack-protector', '-fno-tree-vectorize', '-o', '/home/sgx/isl/t3_3/a.out', '-static', '-g', '/home/sgx/isl/t3_3/dummy.c'])
    op.wait()

def run_tracer(guess, correct):
    op_file = guess+'_'+correct
    op = subprocess.Popen(['./run_single.sh '+guess+' '+op_file], shell=True)
    op.wait()
    return op_file

def run_diff(file1, file2):
    str=os.popen('diff -q ./traces/'+file1+' ./traces/'+file2).read()
    return len(str)

os.chdir("/home/sgx/isl/t3_3/test")
build_dummy()
file1 = run_tracer("magic", "magicbeans") + '.txt'
file2 = run_tracer("qwert", "magicbeans") + '.txt'
l = run_diff(file1, file2)
if l == 0:
    print("The traces matched. Your setup is Ok!")
else:
    print("Oh oh...The traces were different. Check your setup.")
