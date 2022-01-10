import os
import csv

SAME_LENGTH = True
guesses = []
correct = []
op = []
def run_diff(file1, file2):
    str=os.popen('diff -q ./traces/'+file1+' ./traces/'+file2).read()
    return len(str)
sum = 0

def diff_all(guesses, correct):
    for c1 in correct:
        for g1 in guesses:
            f1 = g1 + '_' + c1 + '.txt'
            for c2 in correct:
                for g2 in guesses:
                    f2 = g2 + '_' + c2 + '.txt'
                    global sum
                    if f1 != f2:
                        diff = run_diff(f1,f2)
                        sum = sum + diff
                        op.append((g1, g2, c1, c2, diff))
    
def diff_same_length():
    for l in range(1, 16):
        guesses_len = [guess for guess in guesses if len(guess) == l]
        diff_all(guesses_len, correct)
    global sum
    if sum == 0:
        print("Traces matched for all guesses of same length")
    else:
        print("Traces did not match for guesses of same length")


def write_op():
    with open("diff_traces.csv", "w") as out:
        csv_out = csv.writer(out)
        csv_out.writerow(['guess1','guess2', 'correct1', 'correct2','diff_output'])
        for row in op:
            csv_out.writerow(row)

def load_testset():
    global guesses
    global correct
    with open('/home/sgx/isl/t3_3/test/public_test_set.csv') as f:
        reader = csv.reader(f)
        tuples = [tuple(row) for row in reader]
        guesses = [row[0] for row in tuples][1:]
        correct = [row[1] for row in tuples][1:]

    guesses = list(set(guesses))
    correct = list(set(correct))
os.chdir("/home/sgx/isl/t3_3/test")

load_testset()

if SAME_LENGTH:
    diff_same_length()
else:
    diff_all(guesses, correct)
    if sum == 0:
        print("Traces matched for all guesses")
    else:
        print("Traces did not match for all guesses ")

write_op()