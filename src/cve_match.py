import json
import sys
from datetime import datetime
from dateutil import parser

def formatter(cve_info_file: str, project_cve_file: str, repo_name: str, output_file: str):
    """Creates a new json file that combines severity and CWE type data
    with the commit data.

    Args:
        cve_info_file (str): path to severity and CWE type json
        project_cve_file (str): path to commit data json
        repo_name (str): the name of the current repo
        output_file (str): destination for the constructed json
    """
    # Open the CVE data
    with open(project_cve_file) as commits:
        commit_data = json.load(commits)
    # Open the CVE Severity Data
    with open(cve_info_file) as cve_file:
        cve_data = json.load(cve_file)
    
    output = []
    loaded = set()
    for cve in commit_data:
        if cve["repo"] == repo_name:
            current_cve_id = cve["cve_id"]
            matching_cve_data = None
            for vuln in cve_data:
                if vuln["cve_id"] == current_cve_id:
                    matching_cve_data = vuln
                    break
            if matching_cve_data is None:
                print("ERROR: No matching CVE found for " + current_cve_id)
                continue
            if cve["cve_id"] in loaded:
                # Find the one to edit
                target = None
                for entry in output:
                    if entry["cve_id"] == current_cve_id:
                        target = entry
                if target is None:
                    print("ERROR: Match error in multiple Patch Events")
                    continue
                # Update the entry patch data
                target["patch_date"].append(cve["patch_commit_date"])
                target["patch_files"] += cve["patch_files"]
                target["patch_files"] = list(set(target["patch_files"]))
                if parser.parse(cve["patch_commit_date"]) < parser.parse(target["earliest_patch_date"]):
                    target["earliest_patch_date"] = cve["patch_commit_date"]
                
                # Update entry vuln data
                for commit in cve["vuln_commits"]:
                    current_commit_datetime = parser.parse(commit["date"])
                    # print(target["earliest_vuln_date"])
                    # print("DOne")
                    if target["earliest_vuln_date"] is None or target["earliest_vuln_date"] == "None" or current_commit_datetime < parser.parse( target["earliest_vuln_date"]):
                        target["earliest_vuln_date"] = str(current_commit_datetime)
                    for file in commit["files"]:
                        if file not in target["vuln_files"]:
                            target["vuln_files"].append(file)
                    
            else:
                storage_object = {}
                storage_object["cve_id"] = current_cve_id
                loaded.add(cve["cve_id"])
                storage_object["patch_date"] = [cve["patch_commit_date"]]
                storage_object["patch_files"] = list(set(cve["patch_files"]))
                storage_object["earliest_patch_date"] = cve["patch_commit_date"]
                vuln_files = set()
                earliest_vuln_date = None
                for commit in cve["vuln_commits"]:
                    current_commit_datetime = parser.parse(commit["date"])
                    if earliest_vuln_date is None or current_commit_datetime < earliest_vuln_date:
                        earliest_vuln_date = current_commit_datetime
                    for file in commit["files"]:
                        vuln_files.add(file)
                storage_object["earliest_vuln_date"] = str(earliest_vuln_date)
                storage_object["vuln_files"] = list(vuln_files)
                storage_object["impact"] = matching_cve_data["impact"]
                cwes = set()
                for each in matching_cve_data["cwe_info"]["problemtype_data"]:
                    for value in each["description"]:
                        cwes.add(value["value"])
                storage_object["cwes"] = list(cwes)
                output.append(storage_object)
    # Should be all valid in base FAF case
    output = sorted(output, key=lambda cve: parser.parse(cve["earliest_patch_date"]))
    cwe_first_patch_date = {}
    file_first_patch_date = {}
    for cve in output:
        # Handle errant cases: If intro after patch, set to patch
        try:
            if parser.parse(cve["earliest_vuln_date"]) > parser.parse(cve["earliest_patch_date"]):
                cve["earliest_vuln_date"] = cve["earliest_patch_date"]
        except:
            pass
        cve["fix_duplicate_type"] = False
        cve["fix_duplicate_types"] = []
        cve["intro_duplicate_type"] = False 
        cve["intro_duplicated_types"] = []
        cve["file_fixed_before_fixed_again"] = False
        cve["files_fixed_before_fixed_again"] = []  
        cve["file_fixed_before_vuln_again"] = False
        cve["files_fixed_before_vuln_again"] = []
        for cwe in cve["cwes"]:
            if cwe in cwe_first_patch_date:
                cve["fix_duplicate_type"] = True
                cve["fix_duplicate_types"].append(cwe)
            else:
                cwe_first_patch_date[cwe] = cve["earliest_patch_date"]
        for file in cve["patch_files"]:
            if file in file_first_patch_date:
                cve["file_fixed_before_fixed_again"] = True
                cve["files_fixed_before_fixed_again"].append(file)
            else:
                file_first_patch_date[file] = cve["earliest_patch_date"]
    temp_set = []
    for cve in output:
        if cve["earliest_vuln_date"] != "None":
            temp_set.append(cve)
    temp_set_sorted = sorted(temp_set, key=lambda cve: parser.parse(cve["earliest_vuln_date"]))
    for cve in temp_set_sorted:
        for cwe in cve["cwes"]:
            if cwe in cwe_first_patch_date and parser.parse(cwe_first_patch_date[cwe]) < parser.parse(cve["earliest_vuln_date"]):
                cve["intro_duplicate_type"] = True
                cve["intro_duplicated_types"].append(cwe)
        for file in cve["patch_files"]:
            if file in file_first_patch_date and parser.parse(file_first_patch_date[file]) < parser.parse(cve["earliest_vuln_date"]):
                cve["file_fixed_before_vuln_again"] = True
                cve["files_fixed_before_vuln_again"].append(file)
    # If the results show 0 OAFs, likely due to the references being disconnected here (temp_set vs output)
    with open(output_file, "w+") as out_file:
        json.dump(output, out_file, indent = 0)
    print("Finished " + repo_name + "!")


def main():
    cve_file = sys.argv[1]
    commit_file = sys.argv[2]
    repo = sys.argv[3]
    output = sys.argv[4]
    formatter(cve_file, commit_file, repo, output)

if __name__ == "__main__":
    main()