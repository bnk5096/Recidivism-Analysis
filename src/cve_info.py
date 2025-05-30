import json
import sys
from git import Repo

def cves_with_dates_and_files(patch_vuln_file: str, repos_location: str, output_file: str):
    """ Convert patch_vuln_file to format with all involved files.

    Args:
        patch_vuln_file (str): path to the JSONL file with patches and inducing commits
        repos_location (str): directory containing repositories
        output_file (str): destination file
    """
    # Container for final data
    cves = []
    # Repos and count
    counts = {}
    with open(patch_vuln_file) as patches:
        for entry in patches:
            cve = {}
            patch_obj = json.loads(entry)
            current_repo_name = patch_obj["repo"]
            current_repo = Repo(repos_location + "/" + current_repo_name)
            patch_commit_hash = patch_obj["patch_commit"]
            patch_commit_obj = current_repo.commit(patch_commit_hash)
            cve["cve_id"] = patch_obj["cve_id"]
            cve["repo"] = current_repo_name
            cve["patch_commit"] = patch_commit_hash
            cve["patch_commit_date"] = str(patch_commit_obj.committed_datetime)
            cve["patch_files"] = []
            # Find and add patching files
            try:
                prev_commit = current_repo.commit(patch_commit_hash + "^1")
            except:
                print("Skipping " + cve["cve_id"] + " in repo " + cve["repo"] + " because patch commit " + cve["patch_commit"] + " is parentless")
                continue
            difference = prev_commit.diff(patch_commit_obj)
            for each in difference:
                cve["patch_files"].append(each.a_path)
            cve["vuln_commits"] = []
            # Create an intermediate dictonary to avoid dealing with lots of commit objects
            flipped_dict = {}
            for file in patch_obj["vuln_commits"].keys():
                for commit in patch_obj["vuln_commits"][file]:
                    if commit not in flipped_dict.keys():
                        flipped_dict[commit] = [file]
                    else:
                        flipped_dict[commit].append(file)
            for commit in flipped_dict.keys():
                com_date = str(current_repo.commit(commit).committed_datetime)
                cve["vuln_commits"].append(
                    {"commit": commit, "date": com_date, "files": flipped_dict[commit]})
            cves.append(cve)
            if current_repo_name not in counts.keys():
                counts[current_repo_name] = 0
            counts[current_repo_name] += 1
            print("Finished " + cve["cve_id"])
    singlet_count = 0
    singlet_repos = set()
    for repo in counts.keys():
        if counts[repo] == 1:
            singlet_count += 1
            singlet_repos.add(repo)
    print("There are " + str(singlet_count) + " one-CVE repos. Removing from data set...")
    cves_singlets_removed = []
    for entry in cves:
        if entry["repo"] not in singlet_repos:
            cves_singlets_removed.append(entry)
    print("Removed the following repos:")
    for repo in singlet_repos:
        print(repo)
    with open(output_file, "w+") as out_file:
        json.dump(cves_singlets_removed, out_file)


def main():
    patch_vuln_file = sys.argv[1]
    repos_location = sys.argv[2]
    output_file = sys.argv[3]
    cves_with_dates_and_files(patch_vuln_file, repos_location, output_file)


if __name__ == "__main__":
    main()
