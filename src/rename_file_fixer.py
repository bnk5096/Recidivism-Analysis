import subprocess

def rename_file_fixer(file_folder: str, old_repo_file: str, out_file: str):
    """ Generate a sublist, removing successfully completed repos.

    Args:
        file_folder (str): folder containing successful files
        old_repo_file (str): master list file
        out_file (str): file to store generated sub-list at
    """
    # get everything in that directory
    file_list = subprocess.run(
        ["ls", file_folder], capture_output=True, text=True).stdout
    # split on new line and convert to a set for performance reasons
    file_list = set(file_list.split("\n"))
    difference = set()
    with open(old_repo_file) as f:
        for repo in f:
            # if the repo isn't in the file list, add to the new group
            if repo.strip().replace("/", "_") + ".csv" not in file_list:
                difference.add(repo)
    # convert to list so it can be sorted
    difference = sorted(list(difference))
    # write that list to new file
    with open(out_file, "w+") as f:
        for repo in difference:
            f.write(repo)
        f.write("")


def main():
    rename_file_fixer("renames", "input_data/repo_list.txt",
                      "input_data/repo_list_two.txt")


if __name__ == "__main__":
    main()
