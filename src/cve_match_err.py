import json
import sys
from datetime import datetime

def formatter(cve_info_file: str, project_cve_file: str, repo_name: str, output_file: str):
    """Creates a new json file that combines severity and CWE type data
    with the commit data.

    Args:
        cve_info_file (str): path to severity and CWE type json
        project_cve_file (str): path to commit data json
        repo_name (str): the name of the current repo
        output_file (str): destination for the constructed json
    """
    with open(project_cve_file) as commits: # Read the CVE revised file
        commit_data = json.load(commits)
    with open(cve_info_file) as cve_file: # Read the Severity data in
        cve_data = json.load(cve_file)
    output = []
    for cve in commit_data: # For each CVE in the big Revised json
        if cve["repo"] == repo_name: # If the Repo is the repo we want to look at
            current_cve_id = cve["cve_id"] # Set current CVE to the one we are looking at 
            matching_cve_data = None # Default to no matches
            for vuln in cve_data: # Look through all the vulnerabilities in the CVSS records
                if vuln["cve_id"] == current_cve_id:
                    matching_cve_data = vuln
                    break
            if matching_cve_data == None:
                print("ERROR: no matching CVE found for " + current_cve_id)
                continue
            storage_object = {}
            storage_object["cve_id"] = current_cve_id
            storage_object["patch_date"] = cve["patch_commit_date"]
            storage_object["patch_files"] = cve["patch_files"]
            vuln_files = []
            earliest_vuln_date = None
            for commit in cve["vuln_commits"]:
                current_commit_datetime = datetime.fromisoformat(commit["date"])
                if earliest_vuln_date == None or current_commit_datetime < earliest_vuln_date:
                    earliest_vuln_date = current_commit_datetime
                for file in commit["files"]:
                    vuln_files.append(file)
            storage_object["earliest_vuln_date"] = str(earliest_vuln_date)
            storage_object["vuln_files"] = vuln_files
            storage_object["impact"] = matching_cve_data["impact"]
            cwes = []
            for each in matching_cve_data["cwe_info"]["problemtype_data"]:
                for value in each["description"]:
                    cwes.append(value["value"])
            storage_object["cwes"] = cwes
            output.append(storage_object)
    output = sorted(output, key=lambda cve: cve["patch_date"])
    fix_set = set()
    cwe_first_patch_date = {}
    file_first_patch_date = {}
    for cve in output:
        cve["fix_duplicate_type"] = False
        cve["fix_duplicated_types"] = []
        cve["intro_duplicate_type"] = False
        cve["intro_duplicated_types"] = []
        cve["file_fixed_before_fixed_again"] = False
        cve["files_fixed_before_fixed_again"] = []
        for cwe in cve["cwes"]:
            if cwe in fix_set:
                cve["fix_duplicate_type"] = True
                cve["fix_duplicated_types"].append(cwe)
            fix_set.add(cwe)
            if cwe not in cwe_first_patch_date.keys():
                cwe_first_patch_date[cwe] = cve["patch_date"]
        for file in cve["patch_files"]:
            if file not in file_first_patch_date.keys():
                file_first_patch_date[file] = cve["patch_date"]
            else:
                cve["file_fixed_before_fixed_again"] = True
                cve["files_fixed_before_fixed_again"].append(file)
    output = sorted(output, key=lambda cve: cve["earliest_vuln_date"])
    for cve in output:
        cve["file_fixed_before_vuln_again"] = False
        cve["files_fixed_before_vuln_again"] = []
        for cwe in cve["cwes"]:
            if cwe in cwe_first_patch_date.keys() and cwe_first_patch_date[cwe] < cve["earliest_vuln_date"]:
                cve["intro_duplicate_type"] = True
                cve["intro_duplicated_types"].append(cwe)
        for file in cve["patch_files"]:
            if file in file_first_patch_date.keys() and file_first_patch_date[file] < cve["earliest_vuln_date"]:
                cve["file_fixed_before_vuln_again"] = True
                cve["files_fixed_before_vuln_again"].append(file)
    with open(output_file, "+w") as out_file:
        json.dump(output, out_file, indent=0)
    print("Finished " + repo_name + "!")

def main():
    cve_file = sys.argv[1]
    commit_file = sys.argv[2]
    repo = sys.argv[3]
    output = sys.argv[4]
    formatter(cve_file, commit_file, repo, output)

if __name__ == "__main__":
    main()