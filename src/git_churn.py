import subprocess
import sys
import json
import csv
from git import Repo

# replace with wherever the git-churn executable ends up
GIT_CHURN_LOCATION = "/shared/rc/sfs/bin/git-churn"

def git_churn_by_file(local_repo: str, vuln_file: str, repo_name: str, output_location: str):
    """ Runs git-churn on each file.

    Args:
        local_repo (str): location of repository
        vuln_file (str): file with the cves in it
        repo_name (str): name of the repo
        output_location (str): directory to store the runs in 
    """
    data = []
    with open(vuln_file, 'r') as f:
        data = json.load(f)
    cves = []
    # find all relevant to this repo
    for cve in data:
        if cve["repo"] == repo_name:
            cves.append(cve)
    # get all renames
    alias_lists = []
    with open("/home/user/Recidivism-Metrics/renames/" + repo_name.replace("/", "_") + ".csv") as f:
        reader = csv.reader(f)
        for equivalent_names in reader:
            alias_lists.append(set(equivalent_names))
    # find all involved files, including renames
    valid = set()
    for cve in cves:
        for entry in cve["patch_files"]:
            is_a_rename = False
            for equivalent_name_set in alias_lists:
                if entry.strip() in equivalent_name_set:
                    valid = valid.union(equivalent_name_set)
                    is_a_rename = True
                    break
            if not is_a_rename:
                valid.add(entry.strip())
        for commit in cve["vuln_commits"]:
            for file in commit["files"]:
                is_a_rename = False
                for equivalent_name_set in alias_lists:
                    if file.strip() in equivalent_name_set:
                        valid = valid.union(equivalent_name_set)
                        is_a_rename = True
                        break
                if not is_a_rename:
                    valid.add(file.strip())
    for file in valid:
        result = subprocess.check_output([GIT_CHURN_LOCATION, '--repo', local_repo, '-f', file], text=True)
        result = result.replace("\x1b[34;1m", "")
        result = result.replace("\x1b[36;1m", "")
        result = result.replace("\x1b[32;1m", "")
        result = result.replace("\x1b[33;1m", "")
        result = result.replace("\x1b[35;1m", "")
        result = result.replace("\x1b[37;1m", "")
        result = result.replace("\x1b[0m", "")
        target_file = output_location + "/" + file.replace("/", "_SEP_").split(".")[0] + ".txt"
        with open(target_file, "w+") as out:
            out.write(result)
    print("Finished " + repo_name)

def main():
    local_repo = sys.argv[1]
    vuln_file = sys.argv[2]
    repo_name = sys.argv[3]
    output_location = sys.argv[4]
    git_churn_by_file(local_repo, vuln_file, repo_name, output_location)

if __name__ == "__main__":
    main()