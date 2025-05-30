import subprocess
import json
import sys
import csv
from git import Repo


def run_scc(project_directory: str, output_file: str, vuln_file: str, repo_name: str, commit_hash: str) -> None:
    """Run SCC operations (with ULoc calculations included) at 
    the specified directory and writing to the provided 
    output destiation

    Args:
        project_directory (str): the root directory of the project to analyze
        output_file (str): the file to write the output CSV-formatted data to
        vuln_file (str): file with cves and involved files
        repo_name (str): name of the specific repo
        commit_hash (str): hash of commit to run on
    """
    # checkout the specific commit
    print("Checking out " + commit_hash + "...")
    repo = Repo(project_directory)
    git_cmd = repo.git
    git_cmd.checkout(commit_hash)
    # run SCC
    print("Running scc on " + repo_name + " for " + commit_hash + "...")
    out = subprocess.getoutput(
        f"/shared/rc/sfs/bin/scc {project_directory} --uloc --by-file --format csv")
    by_line = out.split("\n")
    included = []
    # include headers
    included.append(by_line[0])
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
    with open("renames/" + repo_name.replace("/", "_") + ".csv") as f:
        reader = csv.reader(f)
        for equivalent_names in reader:
            alias_lists.append(set(equivalent_names))
    # find all involved files, including renames
    valid = set()
    print("Finding involved files for " + repo_name + "...")
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
    print("Iterating through complexity files for involved file matches for " + repo_name + " at " + commit_hash + "...")
    for line in by_line:
        entries = line.split(",")
        if entries == [""]:
            continue
        entries[1] = entries[1][len(project_directory):]
        # only add to complexity calculations if file is involved
        if entries[1] in valid:
            csv_data = ""
            for item in entries:
                csv_data += item + ","
            csv_data = csv_data[:-1]
            included.append(csv_data)
    print("Writing complexity data for " + repo_name + " at " + commit_hash + " to file...")
    with open(output_file, "w+") as out_file:
        for item in included:
            out_file.write(item + "\n")

def main():
    project_directory = sys.argv[1]
    output_file = sys.argv[2]
    vuln_file = sys.argv[3]
    repo_name = sys.argv[4]
    commit = sys.argv[5]
    run_scc(project_directory, output_file, vuln_file, repo_name, commit)


if __name__ == '__main__':
    main()
