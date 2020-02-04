#!/usr/bin/env pythn

import os
import subprocess

MUTEC_REPO= "/home/fivosts/Repos/SEAL/workspace/mutec"
SRC_REPO = "/home/fivosts/Repos/SEAL/native/src/"


def iterate_folder(folder_name):

	for file in os.listdir(MUTEC_REPO + folder_name):
		if not os.path.isdir(MUTEC_REPO + folder_name + "/" + file):
			move_file(MUTEC_REPO + folder_name + "/" + file, SRC_REPO + folder_name + "/" + file.split('.')[0] + ".cpp")
			compile_and_run(MUTEC_REPO + "/results" + folder_name + "/" + file + ".log")

	return

def move_file(target, destination):

	execute_command("cp {} {}".format(target, destination))
	return


def compile_and_run(output_name):

	os.chdir(MUTEC_REPO + "/build")
	execute_command("make")
	execute_command("make install")
	os.chdir("/home/fivosts/Repos/SEAL/native/tests/build")
	execute_command("make")
	outstr = execute_command("/home/fivosts/Repos/SEAL/native/bin/sealtest --gtest_filter=Encryptor*")
	outf = open(output_name, 'w')
	for line in outstr:
		outf.write(line)
	outf.close()

	os.chdir(SRC_REPO + "/seal/")
	execute_command("git checkout " + SRC_REPO + "/seal/*")

	os.chdir(SRC_REPO)

	return

def execute_command(str_command):

	try:
		process = subprocess.Popen(str_command.split(), stdout=subprocess.PIPE)
		output, error = process.communicate(timeout = 10)
	except subprocess.TimeoutExpired:
		process.kill()
		return ""
	out = output.decode("utf-8")
	print(out)

	return out

def analyze_results():

	os.chdir(MUTEC_REPO + "/seal")
	seal_num = execute_command("ls | wc -l")

	os.chdir(MUTEC_REPO + "/seal")
	util_num = execute_command("ls | wc -l")

	print("From {} mutations: ".format(seal_num + util_num))

# iterate_folder("/seal")
iterate_folder("/seal/util")
