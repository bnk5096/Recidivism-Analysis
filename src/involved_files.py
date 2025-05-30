import json
import csv
from git import Repo

# class for storing a project mapped to its vulnerability-involved files
class Project:

    def __init__(self):
        self.inducing_files = {}
        self.patching_files = {}

    def add_patching_file(self, file, commit):
        if file not in self.patching_files.keys():
            self.patching_files[file] = [commit]
        else:
            self.patching_files[file].append(commit)
    
    def add_inducing_file(self, file, commit):
        if file not in self.inducing_files.keys():
            self.inducing_files[file] = [commit]
        else:
            self.inducing_files[file].append(commit)

# generates a json of involved files
# patches: path to a patch and inducing commit file
# repos_location: folder containing all cloned repos
# output_file: destination for results
def generate_involved_files(patches, repos_location, output_file):
    projects = {}
    repo_objects = {}
    with open(patches) as patch_file:
        # for item in patch file
        for line in patch_file:
            patch_obj = json.loads(line)
            current_repo_name = patch_obj["repo"]
            if current_repo_name not in projects.keys():
                # create the project object
                projects[current_repo_name] = Project()
            # add inducing files and commits marked as inducing for these files
            for inducing_file in patch_obj["vuln_commits"].keys():
                for commit in patch_obj["vuln_commits"][inducing_file]:
                    projects[current_repo_name].add_inducing_file(inducing_file, commit)
            # get the git python repo object
            if current_repo_name not in repo_objects.keys():
                repo_objects[current_repo_name] = Repo(repos_location + "/" + current_repo_name)
            # add the patch commit to the project object, finding the changed files
            patch_commit_hash = patch_obj["patch_commit"]
            patch_commit_obj = repo_objects[current_repo_name].commit(patch_commit_hash)
            prev_commit = repo_objects[current_repo_name].commit(patch_commit_hash + "^1")
            difference = prev_commit.diff(patch_commit_obj)
            for each in difference:
                projects[current_repo_name].add_patching_file(each.a_path, patch_commit_hash)
    projects_as_dicts = {}
    for name in projects.keys():
        projects_as_dicts[name] = {"patching_files": projects[name].patching_files, "inducing_files": projects[name].inducing_files}
    with open(output_file, "w+") as out_file:
        json.dump(projects_as_dicts, out_file)

# reformats to include renames
# involved_file: file of involved files
# rename_file: file of rename history
# out_file: destination file
# repo_name: name of the repo
def involved_with_renames(involved_file, rename_file, out_file, repo_name):
    all_projects = []
    with open(involved_file) as ifile:
        all_projects = json.load(ifile)
    # find the specific project
    project = {}
    for each in all_projects:
        project = each
        if repo_name in project.keys():
            break
    if repo_name not in project.keys():
        print("Invalid repo name, skipping")
        return
    # create the new storage object
    project_w_renames = {}
    project_w_renames["patching_files"] = set()
    project_w_renames["inducing_files"] = set()
    with open(rename_file) as rfile:
        reader = csv.reader(rfile)
        for row in reader:
            row_tup = tuple(row)
            for name in row:
                # add the rename data to the object if any of the names are found
                if name in project["patching_files"].keys():
                    project_w_renames["patching_files"].add(row_tup)
                if name in project["inducing_files"].keys():
                    project_w_renames["inducing_files"].add(row_tup)
    with open(out_file, "w+") as out:
        json.dump(project_w_renames, out)

def main():
    generate_involved_files("../mega-foss/src/slurm/drill_scripts/production_ready/patch_vuln_match.jsonl", "../", "involved_files/test.json")

if __name__ == "__main__":
    main()