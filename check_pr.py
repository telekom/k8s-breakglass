import subprocess
import json
import time
import sys

def run(cmd):
    return subprocess.check_output(cmd, shell=True, text=True)

def check_pr(pr_num):
    print(f"Checking PR {pr_num}...")
    while True:
        comments = json.loads(run(f"gh api repos/telekom/k8s-breakglass/pulls/{pr_num}/comments"))
        if comments:
            print(f"Found comments on PR {pr_num}!")
            return comments
        status = json.loads(run(f"gh pr status --json statusCheckRollup -q .currentBranch.statusCheckRollup"))
        print("Status is:", status)
        break
    return []

if __name__ == "__main__":
    pr_num = sys.argv[1]
    check_pr(pr_num)
