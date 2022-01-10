import os
import subprocess
import csv 

guesses = []
correct = []
f = []
# sum = 0
wrong_op=0

def run_tracer(guess,correct):
    op = subprocess.Popen(['./run_single.sh '+guess+' '+guess+'_'+correct], shell=True)
    op.wait()

def hexdump():
    p='/home/sgx/isl/t3_3/oput'
    if(os.path.isfile(p)):
        cmd="hexdump -v -e '/1 \"%01X\"' "+p
        str=os.popen(cmd).read()
        return ord(str)
    else:
        return 47

def run_all_guesses(correct):
    for g in guesses:
        run_tracer(g, correct)
        o = hexdump()
        f.append((g, correct, o-48))
        global wrong_op
        if g == correct:
            if o != 49:
                wrong_op = wrong_op + 1
                print(g, correct, o, 1)
        else:
            if o != 48:
                wrong_op = wrong_op + 1
                print(g, correct, o, 0)


def run_correct_password():
    for c in correct:
        #create password.txt with c 
        l = 16 - len(c) - 1 
        d = '$'*l
        try:
            os.remove("../password.txt")
        except OSError:
            pass

        with open("../password.txt","w") as p:
            p.write(d+c+d)
        run_all_guesses(c)

def load_testset():
    global guesses
    global correct
    with open('public_test_set.csv') as f:
        reader = csv.reader(f)
        tuples = [tuple(row) for row in reader]
        guesses = [row[0] for row in tuples]
        correct = [row[1] for row in tuples]

    guesses = list(set(guesses))
    correct = list(set(correct))

def write_csv():
    with open("/home/sgx/isl/t3_3/test/functionality.csv", "w") as out:
        csv_out = csv.writer(out)
        csv_out.writerow(['guess','correct1', 'output'])
        for row in f:
            csv_out.writerow(row)

os.chdir("/home/sgx/isl/t3_3/test")
load_testset()
run_correct_password()

if wrong_op == 0:
    print("The functionality is correct")
else:
    print("The functionality is wrong")

write_csv()