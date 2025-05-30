import json

def get_repo_list(in_file: str, out_file: str):
    """ Get the list of repos from the viable patch file.
    
    Args: 
        in_file (str): file containing all potential patches and repos they belong to
        out_file (str): destination file
    """
    patch_list = []
    with open(in_file) as file:
        patch_list = json.load(file)
    repo_set = set()
    for patch in patch_list:
        repo_set.add(patch["repo"])
    repo_list = sorted(list(repo_set))
    with open(out_file, "w+", newline='') as file:
        for repo in repo_list:
            file.write(repo + "\n")

def main():
    get_repo_list("../mega-foss/src/slurm/drill_scripts/viable_patches.json", "input_data/repo_list.txt")

if __name__ == "__main__":
    main()